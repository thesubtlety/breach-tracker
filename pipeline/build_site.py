"""Render data/incidents.jsonl into site/: a single static page plus JSON and CSV
downloads. No build tool, no framework; the page filters client-side.

    python pipeline/build_site.py
"""
from __future__ import annotations

import csv
import json
import os
import sys
from xml.sax.saxutils import escape
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_DIR, INCIDENTS_PATH, SITE_DIR, read_jsonl, today  # noqa: E402
from actors import actor_key, actor_registry, claim_groups  # noqa: E402
from orgs import org_id, registry, vendor_id, vendor_names, vendor_registry  # noqa: E402
from pages import FIELD_NAMES, LABELS, SITE_NAME, TECHNIQUE_NAMES, robots, sitemap, write_pages  # noqa: E402

HEALTH_PATH = DATA_DIR / "source_health.json"
SITE_URL = (os.environ.get("SITE_URL") or "https://www.thesubtlety.com/breach-tracker/").rstrip("/") + "/"
RECENT_DAYS = 730
FEED_DAYS = 30
VENDOR_FEED_MIN = 3  # a feed per vendor named this often
FIRST_ROWS = 50  # newest rows inlined in the page so the table renders before any fetch
NEW_WINDOW_DAYS = 90  # a backfilled 2015 notice first seen today is not news

# Shown as hover text and in the page glossary. Keep in step with prompts/extract.md.
GLOSSARY = {
    "initial_access": {
        "phishing": "Email or SMS lure leading to credential theft or malware.",
        "vishing_or_social_engineering": "Phone or help-desk impersonation, MFA fatigue, pretexting.",
        "stolen_or_valid_credentials": "Reused, leaked, infostealer-sourced or brute-forced credentials; valid account abuse with no stated phishing step.",
        "exploit_public_facing_app": "A CVE or unpatched internet-facing system: VPN, firewall, file transfer, web app.",
        "supply_chain_or_third_party": "Came in through a vendor, integration, token, package or managed service provider.",
        "misconfiguration_or_exposure": "Open bucket or database, public repo, wrong permissions, no authentication.",
        "insider": "Employee or contractor acting intentionally.",
        "lost_or_stolen_device": "Laptop, drive or phone.",
        "physical_or_paper": "Break-in, misdirected mail, improper disposal.",
        "malware_other": "Malware present but the entry vector was not stated.",
        "unknown": "The available sources do not establish how the breach occurred. Expected for most regulator filings; never inferred.",
    },
    "evidence_level": {
        "org_confirmed": "The organization said so: an 8-K, a notice, or a statement quoted in full.",
        "regulator_filing": "A breach report to HHS or a state attorney general. Gives who, when and how many; usually silent on how.",
        "press_report": "A news article. Usually the only source that names a root cause or technology. The quote is checked against the article; the article's own claims are not independently verified.",
        "actor_claimed": "A ransomware group's leak-site post. A claim, not a confirmation.",
    },
    "origin": {
        "regulator": "Built from the filing's checkboxes by a fixed mapping. No model involved.",
        "extracted": "A language model read the source and filled the fields; a verbatim quote is required for any stated mechanism.",
        "imported": "Mapped from an existing coded dataset (VCDB). Not re-read. The date is the incident date, not a disclosure date.",
    },
    "control_failure": {
        "unpatched_known_vuln": "A fix existed and was not applied.",
        "zero_day": "No vendor fix was available when the vulnerability was exploited. Distinct from a known vulnerability the organization had not patched.",
        "missing_mfa": "The abused account had no second factor.",
        "weak_or_reused_password": "Guessable, default or previously leaked password.",
        "excessive_privilege": "An account or token could reach far more than its job needed.",
        "exposed_service_or_storage": "Open to the internet with no authentication: bucket, database, admin panel.",
        "unrotated_secret_or_token": "A long-lived key or token stayed valid after it should have been retired.",
        "eol_software": "Software past end of support, no fixes available.",
        "staff_deceived": "Social engineering worked on a person.",
        "insider_access_abuse": "Legitimate access used for an illegitimate purpose.",
        "vendor_control_failure": "The failing control belonged to a third party.",
        "unknown": "The sources do not establish which weakness was exploited. Most do not say.",
    },
    "entry_asset": {
        "vpn_or_edge_device": "VPN, firewall, gateway or other perimeter appliance.",
        "web_application": "An internet-facing application or its server.",
        "remote_desktop": "RDP, VNC or remote-support tooling.",
        "email_account": "A mailbox or mail platform.",
        "saas_or_cloud_console": "A cloud or SaaS tenant reached through its own login.",
        "api_or_integration_token": "A programmatic credential: API key, OAuth token, service account.",
        "endpoint": "A laptop, workstation or server reached directly.",
        "physical": "In person, or a device that was taken.",
        "unknown": "Not stated.",
    },
    "actor_variety": {
        "organized_crime": "Criminals running a repeatable operation, almost always for money: ransomware and extortion crews.",
        "state_affiliated": "Working for or on behalf of a government, usually for espionage.",
        "activist": "Ideologically motivated.",
        "former_employee": "Someone who used to have legitimate access.",
        "unaffiliated": "An individual with no known group.",
        "end_user": "An employee without elevated access, usually by mistake.",
        "system_admin": "An employee with elevated access.",
        "other": "Stated, but none of the above.",
        "unknown": "Not stated and not a known group.",
    },
    "third_party": {
        "vendor_product": "A flaw or backdoor in a vendor product running in the victim's own environment.",
        "vendor_hosted_data": "The vendor held the victim's data and was breached, or the victim's account on the vendor platform was abused.",
        "vendor_connection": "The vendor's access, credentials or tokens into the victim were used.",
    },
    "confidence": {
        "high": "Mechanism and cause are directly supported by the quoted text.",
        "medium": "Supported, with some interpretation.",
        "low": "A check failed: the quote was not found verbatim, or the value was reset.",
    },
}

CSV_COLS = ["id", "org_id", "first_seen", "updated_at", "disclosed_date", "incident_date", "discovered_date", "org_name", "org_type", "org_country",
            "initial_access", "entry_asset", "control_failure", "credential_source", "cve", "veris_action",
            "root_cause", "technology_involved", "attack_techniques", "third_party_involved", "third_party_archetype", "third_party_vendor",
            "actor_name", "actor_category", "actor_variety", "actor_motive", "actor_country",
            "impact_type", "ransomware", "data_types", "records_affected",
            "evidence_level", "confidence", "reviewed", "summary", "source_url"]

TEMPLATE = (Path(__file__).parent.parent / "site" / "template.html")


def origin(r: dict) -> str:
    if r.get("imported_from"):
        return "imported"
    return "regulator" if r["extracted_by"]["model"] == "deterministic" else "extracted"


def first_seen(r: dict) -> str:
    return r.get("first_seen") or r["extracted_by"]["run_date"]


def newsworthy(r: dict, window_start: str) -> bool:
    return origin(r) != "imported" and r["disclosed_date"] >= window_start


def coverage(rows: list[dict]) -> list[dict]:
    """What the dataset actually spans, per origin: readers should not mistake a young
    pipeline for the history of breaches."""
    out = []
    for o in ("regulator", "extracted", "imported"):
        sub = [r for r in rows if origin(r) == o]
        if sub:
            out.append({"origin": o, "n": len(sub), "from": min(r["disclosed_date"] for r in sub),
                        "to": max(r["disclosed_date"] for r in sub)})
    return out


def feed(rows: list[dict], since: str, generated: str, title: str = f"{SITE_NAME}: new and updated records",
         path: str = "feed.xml", window_days: int = NEW_WINDOW_DAYS) -> str:
    """Atom feed of records first recorded or changed since `since`, newest change first.
    Imported dataset rows are left out: a bulk import is not news."""
    window = (date.fromisoformat(since) - timedelta(days=window_days)).isoformat()
    items = [r for r in rows if newsworthy(r, window) and max(first_seen(r), r.get("updated_at") or "") >= since]
    items.sort(key=lambda r: (max(first_seen(r), r.get("updated_at") or ""), r["disclosed_date"]), reverse=True)
    entries = []
    for r in items[:100]:
        changed = max(first_seen(r), r.get("updated_at") or "")
        kind = "updated" if (r.get("updated_at") or "") > first_seen(r) else "new"
        head = f"{r['org_name']}: {r['initial_access'].replace('_', ' ')} ({r['evidence_level'].replace('_', ' ')})"
        body = " ".join(filter(None, [r.get("summary"), f"Disclosed {r['disclosed_date']}.",
                                      f"{r['records_affected']:,} records." if r.get("records_affected") else None,
                                      f"Source: {r['sources'][0]['url']}" if r.get("sources") else None]))
        entries.append(f"""  <entry>
    <id>{SITE_URL}#id={r['id']}</id>
    <title>{escape(head)}</title>
    <link href="{SITE_URL}#id={r['id']}"/>
    <updated>{changed}T00:00:00Z</updated>
    <category term="{kind}"/>
    <summary>{escape(body)}</summary>
  </entry>""")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>{escape(title)}</title>
  <id>{SITE_URL}{path}</id>
  <link href="{SITE_URL}"/>
  <link rel="self" href="{SITE_URL}{path}"/>
  <updated>{generated}T00:00:00Z</updated>
{chr(10).join(entries)}
</feed>
"""


HORIZONS = (1, 5, 21, 63, 126, 250)  # trading days: next day, week, month, quarter, half year, year


def price_reaction(series: dict, spy: dict) -> dict | None:
    """Return vs the close on the filing day (8-Ks are mostly filed after the bell), or
    the last close before it, at each horizon, raw and net of SPY."""
    closes = series.get("closes") or {}
    filed = series.get("filed")
    if not closes or not filed:
        return None
    days = sorted(closes)
    before = [d for d in days if d <= filed]
    if not before:
        return None
    base_day = before[-1]
    i0 = days.index(base_day)
    base, spy_base = closes[base_day], spy.get(base_day)
    out = {"ticker": series["ticker"], "base_day": base_day, "returns": {}}
    for h in HORIZONS:
        if i0 + h < len(days):
            d = days[i0 + h]
            raw = closes[d] / base - 1
            adj = raw - (spy[d] / spy_base - 1) if spy_base and d in spy else None
            out["returns"][str(h)] = {"day": d, "raw": round(raw, 4), "adj": round(adj, 4) if adj is not None else None}
    return out if out["returns"] else None


def kev_context(r: dict, kev: dict) -> list[dict]:
    anchor = r.get("incident_date") or r["disclosed_date"]
    out = []
    for c in r.get("cve") or []:
        k = kev.get(c.upper()) or {}
        added = k.get("added")
        lead = (date.fromisoformat(anchor) - date.fromisoformat(added)).days if added else None
        out.append({"cve": c.upper(), "kev_added": added, "name": k.get("name"), "days_listed_before_incident": lead,
                    "product": " ".join(filter(None, [k.get("vendor"), k.get("product")])) or None})
    return out


def with_context(rows: list[dict], kev: dict, prices: dict) -> list[dict]:
    """Site rows carry a `derived` block the schema does not: KEV listing dates for the
    record's CVEs and the filer's share-price reaction. The committed store never does."""
    spy = prices.get("_SPY", {})
    vendor_name = {v["id"]: v["name"] for v in vendor_registry(rows)}
    out = []
    for r in rows:
        r.setdefault("org_id", org_id(r["org_name"]))
        d = {}
        names = vendor_names((r.get("third_party") or {}).get("vendor"))
        if names:
            d["vendors"] = [{"id": vendor_id(n), "name": vendor_name.get(vendor_id(n), n)} for n in names]
        if actor_key((r.get("actor") or {}).get("name")):
            d["actor_id"] = actor_key(r["actor"]["name"])
        if claim_groups(r):
            d["claim_groups"] = claim_groups(r)
        if r.get("cve") and kev:
            d["kev"] = kev_context(r, kev)
        pr = prices.get(r["id"])
        if pr and pr.get("closes"):
            reaction = price_reaction(pr, spy)
            if reaction:
                d["price"] = reaction
        out.append(dict(r, derived=d) if d else r)
    return out


def current_model(rows: list[dict], since: str) -> str | None:
    """The model behind recent extractions, for the about block; the env can change."""
    c = Counter(r["extracted_by"]["model"].split(":")[-1] for r in rows
                if origin(r) == "extracted" and r["extracted_by"]["run_date"] >= since)
    return c.most_common(1)[0][0] if c else None


def claim_only(r: dict) -> bool:
    """Only a leak-site post says this happened. Kept in the store so a later filing or
    article can confirm it, never published on its own: that would be re-serving
    Ransomware.live's victim list, which their terms forbid."""
    return bool(r.get("sources")) and all(s["type"] == "ransomware_leak_site" for s in r["sources"])


def main() -> int:
    all_rows = read_jsonl(INCIDENTS_PATH)
    ext = DATA_DIR / "external"
    kev = json.loads((ext / "kev.json").read_text()) if (ext / "kev.json").exists() else {}
    prices = json.loads((ext / "prices.json").read_text()) if (ext / "prices.json").exists() else {}
    rows = with_context([r for r in all_rows if not claim_only(r)], kev, prices)
    withheld = len(all_rows) - len(rows)
    SITE_DIR.mkdir(exist_ok=True)

    compact = dict(ensure_ascii=False, separators=(",", ":"))
    (SITE_DIR / "incidents.json").write_text(json.dumps(rows, **compact))
    # Only organizations with something to say beyond the one row; the page builds the rest from rows.
    all_orgs = registry(rows, prices)
    orgs = [o for o in all_orgs if o["incidents"] > 1 or o["ticker"] or o["sec_filer"]]
    (SITE_DIR / "orgs.json").write_text(json.dumps(orgs, **compact))
    vendors = vendor_registry(rows)
    for v in vendors:
        v["feed"] = v["incidents"] >= VENDOR_FEED_MIN
    (SITE_DIR / "vendors.json").write_text(json.dumps(vendors, **compact))
    claims = json.loads((ext / "claim_stats.json").read_text()) if (ext / "claim_stats.json").exists() else None
    actors = actor_registry(rows, {g["group"]: g for g in (claims or {}).get("groups", [])})
    (SITE_DIR / "actors.json").write_text(json.dumps(actors, **compact))
    urls = write_pages(rows, all_orgs, vendors, SITE_DIR, SITE_URL, actors, today())
    (SITE_DIR / "sitemap.xml").write_text(sitemap(urls, SITE_URL, today()))
    (SITE_DIR / "robots.txt").write_text(robots(SITE_URL))
    (SITE_DIR / "stats.json").write_text(json.dumps({"records": len(rows), "organizations": len({r["org_id"] for r in rows}), "generated": today()}))
    feeds = SITE_DIR / "feeds"
    feeds.mkdir(exist_ok=True)
    for f in feeds.glob("vendor-*.xml"):
        f.unlink()
    year_ago = (date.today() - timedelta(days=365)).isoformat()
    for v in vendors:
        if v["incidents"] >= VENDOR_FEED_MIN:
            mine = [r for r in rows if any(x["id"] == v["id"] for x in (r.get("derived") or {}).get("vendors", []))]
            (feeds / f"vendor-{v['id']}.xml").write_text(
                feed(mine, year_ago, today(), f"{SITE_NAME}: incidents behind {v['name']}", f"feeds/vendor-{v['id']}.xml", 3650))
    recent_cutoff = (date.today() - timedelta(days=RECENT_DAYS)).isoformat()
    week_ago = (date.today() - timedelta(days=7)).isoformat()
    window = (date.today() - timedelta(days=NEW_WINDOW_DAYS)).isoformat()
    recent = [r for r in rows if r["disclosed_date"] >= recent_cutoff]
    (SITE_DIR / "recent.json").write_text(json.dumps(recent, **compact))
    (SITE_DIR / "feed.xml").write_text(feed(rows, (date.today() - timedelta(days=FEED_DAYS)).isoformat(), today()))
    with (SITE_DIR / "incidents.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            flat = dict(r)
            for k in ("technology_involved", "cve", "data_types", "attack_techniques"):
                flat[k] = "; ".join(r.get(k) or [])
            tp, a = r.get("third_party") or {}, r.get("actor") or {}
            flat.update(third_party_involved=tp.get("involved"), third_party_archetype=tp.get("archetype"), third_party_vendor=tp.get("vendor"),
                        actor_name=a.get("name"), actor_category=a.get("category"), actor_variety=a.get("variety"),
                        actor_motive=a.get("motive"), actor_country=a.get("country"))
            flat["source_url"] = r["sources"][0]["url"] if r.get("sources") else ""
            w.writerow(flat)

    health = json.loads(HEALTH_PATH.read_text()) if HEALTH_PATH.exists() else {}
    stats = {
        "total": len(rows),
        "recent": len(recent),
        "withheld_claims": withheld,
        "generated": today(),
        "week_ago": week_ago,
        "new_window": window,
        "added_last_7_days": sum(1 for r in rows if newsworthy(r, window) and first_seen(r) >= week_ago),
        "backfilled_last_7_days": sum(1 for r in rows if not newsworthy(r, window) and first_seen(r) >= week_ago),
        "updated_last_7_days": sum(1 for r in rows if newsworthy(r, window) and (r.get("updated_at") or "") >= week_ago and first_seen(r) < week_ago),
        "reviewed": sum(1 for r in rows if r.get("reviewed")),
        "known_initial_access": sum(1 for r in rows if r["initial_access"] != "unknown"),
        "date_range": [min(r["disclosed_date"] for r in rows), max(r["disclosed_date"] for r in rows)] if rows else None,
        "by_initial_access": Counter(r["initial_access"] for r in rows).most_common(),
        "by_org_type": Counter(r["org_type"] for r in rows).most_common(),
        "by_org_country": Counter(r.get("org_country") or "unknown" for r in rows).most_common(),
        "kev_loaded": bool(kev),
        "by_evidence": Counter(r["evidence_level"] for r in rows).most_common(),
        "by_source": Counter(t for r in rows for t in {s["type"] for s in r["sources"]}).most_common(),
        "by_control_failure": Counter(r.get("control_failure", "unknown") for r in rows).most_common(),
        "by_actor_variety": Counter((r.get("actor") or {}).get("variety", "unknown") for r in rows).most_common(),
        "known_control_failure": sum(1 for r in rows if r.get("control_failure", "unknown") != "unknown"),
        "third_party_involved": sum(1 for r in rows if (r.get("third_party") or {}).get("involved") is True),
        "ransomware": sum(1 for r in rows if r.get("ransomware") is True),
        "with_price_reaction": sum(1 for r in rows if (r.get("derived") or {}).get("price")),
        "with_kev": sum(1 for r in rows if (r.get("derived") or {}).get("kev")),
        "organizations": len({r["org_id"] for r in rows}),
        "vendors": len(vendors),
        "vendor_feed_min": VENDOR_FEED_MIN,
        "with_techniques": sum(1 for r in rows if r.get("attack_techniques")),
        "technique_names": TECHNIQUE_NAMES,
        "labels": LABELS,
        "field_names": FIELD_NAMES,
        "claims": claims,
        "actors": len(actors),
        "with_letter": sum(1 for r in rows if (r.get("letter") or {}).get("outcome") == "extracted"),
        "current_model": current_model(rows, week_ago),
        "kev_updated": max((v.get("added") or "" for v in kev.values()), default=None),
        "coverage": coverage(rows),
        "health": {"run_at": health.get("run_at"), "counts": (health.get("health") or {}).get("counts", {}),
                   "problems": (health.get("health") or {}).get("problems", []),
                   "skipped": (health.get("health") or {}).get("skipped", [])},
        "glossary": GLOSSARY,
    }
    first = sorted(rows, key=lambda r: r["disclosed_date"], reverse=True)[:FIRST_ROWS]
    html = (TEMPLATE.read_text().replace("/*__STATS__*/{}", json.dumps(stats, ensure_ascii=False))
            .replace("/*__FIRST__*/[]", json.dumps(first, **compact)).replace("__SITE_URL__", SITE_URL))
    (SITE_DIR / "index.html").write_text(html)
    print(f"site: {len(rows)} incidents ({len(recent)} in first load, {withheld} claim-only withheld), {len(urls)} entity pages -> {SITE_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
