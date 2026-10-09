"""Weekly run: collect -> dedupe -> (deterministic or LLM) extract -> merge -> write.

    python pipeline/run.py --since-days 8
    python pipeline/run.py --since-days 8 --only sec_edgar,rss --limit 20 --dry-run
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (CANDIDATES_PATH, INCIDENTS_PATH, MERGE_WINDOW_DAYS, PROCESSED_PATH,  # noqa: E402
                    PROMPT_VERSION, make_id, normalize_org, read_jsonl, today, validate, write_jsonl)
from actors import default_actor, default_third_party, enrich_actor  # noqa: E402
from dedupe import dedupe  # noqa: E402
from fetch_text import fetch_text  # noqa: E402
from sources import collect  # noqa: E402

log = logging.getLogger("run")

# Regulator checkbox -> our enum. Only mappings that are unambiguous; everything
# else stays "unknown" rather than guessing.
HHS_BREACH_TYPE = {
    "Hacking/IT Incident": ("unknown", "hacking"),
    "Theft": ("lost_or_stolen_device", "physical"),
    "Loss": ("lost_or_stolen_device", "error"),
    "Improper Disposal": ("physical_or_paper", "error"),
    "Unauthorized Access/Disclosure": ("unknown", "unknown"),
}
MAINE_DESC = {
    "External system breach (hacking)": ("unknown", "hacking"),
    "Insider wrongdoing": ("insider", "misuse"),
    "Loss or theft of device or media": ("lost_or_stolen_device", "physical"),
    "Inadvertent disclosure": ("unknown", "error"),
    "Internal system breach": ("unknown", "unknown"),
}
MAINE_ORG_TYPE = {
    "Financial Services": "financial", "Education": "education", "Healthcare": "healthcare",
    "Government Entity in Maine": "government", "Other Commercial": "other",
    "Federal Government": "government",
}
MAINE_DATA_TYPES = {  # substrings of Maine's "Information Acquired" field -> data_types
    "social security": "personal", "driver": "personal", "date of birth": "personal", "name": "personal",
    "financial account": "financial", "credit": "financial", "debit": "financial", "bank": "financial",
    "medical": "medical", "health": "medical", "insurance": "medical",
    "password": "credentials", "username": "credentials", "account credentials": "credentials",
}
HHS_ENTITY_TYPE = {
    "Healthcare Provider": "healthcare", "Health Plan": "healthcare",
    "Business Associate": "professional_services", "Healthcare Clearing House": "healthcare",
}


_ITEM_RE = re.compile(r"item\s*(1\.05|8\.01|7\.01)", re.I)
_INCIDENT_RE = re.compile(r"unauthori[sz]ed (access|activity|party)|cybersecurity incident|ransomware|"
                          r"threat actor|intrusion|encrypted|exfiltrat", re.I)


def looks_like_incident_8k(text: str) -> bool:
    """Cheap prefilter so we don't pay a model to skip merger agreements that mention
    'cybersecurity incident' in reps and warranties. Requires an incident-bearing Item
    and incident language within ~3k characters of it."""
    for m in _ITEM_RE.finditer(text):
        window = text[m.start(): m.start() + 3000]
        if _INCIDENT_RE.search(window):
            return True
    return False


def mostly_english(text: str) -> bool:
    """Non-English sources are out of scope (README); every model we tried extracts
    them anyway, so refuse before paying for the call."""
    letters = [ch for ch in text if ch.isalpha()]
    return not letters or sum(ch.isascii() for ch in letters) / len(letters) >= 0.8


def _int(s) -> int | None:
    try:
        return int(str(s).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def deterministic_record(c: dict, run_date: str) -> dict | None:
    """Regulator rows with no narrative: build the record from checkboxes, no LLM."""
    hints = c.get("structured_hint") or {}
    h = hints.get(c["source_type"], hints) if c["source_type"] in hints else hints
    actor, third_party, data_types, entry, discovered, ransomware = default_actor(), default_third_party(), [], "unknown", None, None
    if c["source_type"] == "hhs_portal":
        ia, veris = HHS_BREACH_TYPE.get((h.get("breach_type") or "").split(",")[0].strip(), ("unknown", "unknown"))
        org_type = HHS_ENTITY_TYPE.get(h.get("covered_entity_type") or "", "healthcare")
        records = _int(h.get("individuals_affected"))
        tech = [t.strip() for t in (h.get("location") or "").split(",") if t.strip()][:4]
        data_types = ["medical"]  # every HHS row is protected health information by definition
        if veris == "hacking" and tech == ["Email"]:
            entry = "email_account"
        if (h.get("business_associate_present") or "").strip().lower() == "yes":
            third_party = {"involved": True, "archetype": "vendor_hosted_data", "vendor": None}
        if ia == "insider":
            actor = {"category": "internal", "variety": "unknown", "motive": "unknown", "name": None, "country": None}
    elif c["source_type"] == "state_ag":
        ia, veris = ("unknown", "unknown")
        for k, v in MAINE_DESC.items():
            if k.lower() in (h.get("breach_description") or "").lower():
                ia, veris = v
                break
        org_type = MAINE_ORG_TYPE.get(h.get("org_type_raw") or "", "unknown")
        records = _int(h.get("persons_affected"))
        tech = []
        acquired = (h.get("information_acquired") or "").lower()
        data_types = sorted({v for k, v in MAINE_DATA_TYPES.items() if k in acquired})
        from sources import _iso
        discovered = _iso(h.get("date_discovered"))
        if ia == "insider":
            actor = {"category": "internal", "variety": "unknown", "motive": "unknown", "name": None, "country": None}
    elif c["source_type"] == "ransomware_leak_site":
        # An actor claim tells you the group and that extortion is under way. It does not
        # tell you how they got in. Record exactly that much.
        ia, veris = ("unknown", "hacking")
        org_type, records, tech = "unknown", None, []
        actor = enrich_actor({"name": h.get("group"), "category": "external", "variety": "organized_crime", "motive": "financial"})
        ransomware = True
    else:
        return None
    is_claim = c["source_type"] == "ransomware_leak_site"
    rec = {
        "id": make_id(c["org_name"], c["disclosed_date"]),
        "schema_version": "1.1",
        "org_name": c["org_name"],
        "org_type": org_type,
        "org_country": c.get("org_country", "US"),
        "disclosed_date": c["disclosed_date"],
        "incident_date": None,
        "discovered_date": discovered,
        "initial_access": ia,
        "initial_access_attack_id": None,
        "veris_action": veris,
        "entry_asset": entry,
        "control_failure": "unknown",
        "credential_source": None,
        "cve": [],
        "root_cause": None,
        "technology_involved": tech,
        "third_party": third_party,
        "actor": actor,
        "impact_type": "disruption_or_ransomware" if is_claim else "unknown",
        "ransomware": ransomware,
        "data_types": data_types,
        "records_affected": records,
        "evidence_level": "actor_claimed" if is_claim else "regulator_filing",
        "confidence": "medium",
        "supporting_quote": None,
        "summary": None,
        "sources": [{"url": s["url"], "type": s["type"], "title": s.get("title"), "fetched_at": None}
                    for s in c.get("all_sources", [])],
        "extracted_by": {"model": "deterministic", "prompt_version": PROMPT_VERSION, "run_date": run_date},
        "reviewed": False,
        "notes": ("leak-site claim via Ransomware.live (Source: Ransomware.live); unverified"
                  if is_claim else "built from regulator checkboxes; no narrative available"),
    }
    errs = validate(rec)
    if errs:
        log.warning("deterministic record invalid for %s: %s", c["org_name"], errs[:2])
        return None
    return rec


def _days(a: str | None, b: str | None) -> int | None:
    if not (a and b):
        return None
    return abs((date.fromisoformat(a[:10]) - date.fromisoformat(b[:10])).days)


def find_record(store: list[dict], org_name: str, disclosed_date: str,
                incident_date: str | None = None) -> dict | None:
    """The existing record a new source belongs to, if any. Same organization and
    either disclosed within MERGE_WINDOW_DAYS of the record, or the same stated
    incident date (a follow-up months later that names the original date). Anything
    else is a new record: the data cannot tell "second breach" from "late coverage
    with no date", and a separate record with the same org name is the honest default.
    The review loop can merge by hand."""
    key = normalize_org(org_name)
    best = None
    for r in store:
        if normalize_org(r["org_name"]) != key:
            continue
        d = _days(r["disclosed_date"], disclosed_date)
        same_incident = incident_date and r.get("incident_date") and _days(r["incident_date"], incident_date) <= 7
        if (d is not None and d <= MERGE_WINDOW_DAYS) or same_incident:
            if best is None or d < _days(best["disclosed_date"], disclosed_date):
                best = r
    return best


def merge_into_store(store: list[dict], new: dict) -> None:
    """Attach to the matching record (see find_record) or append. When attaching, keep
    the richer record under the existing id; union sources; never overwrite reviewed=True."""
    old = next((r for r in store if r["id"] == new["id"]), None) \
        or find_record(store, new["org_name"], new["disclosed_date"], new.get("incident_date"))
    if not old:
        store.append(new)
        return
    new["id"] = old["id"]
    new["disclosed_date"] = min(old["disclosed_date"], new["disclosed_date"])
    if old.get("reviewed"):
        urls = {s["url"] for s in old["sources"]}
        old["sources"] += [s for s in new["sources"] if s["url"] not in urls]
        return
    richness = lambda r: (r["initial_access"] != "unknown", bool(r.get("root_cause")),  # noqa: E731
                          r.get("records_affected") is not None, len(r.get("technology_involved") or []))
    keep, drop = (new, old) if richness(new) >= richness(old) else (old, new)
    urls = {s["url"] for s in keep["sources"]}
    keep["sources"] += [s for s in drop["sources"] if s["url"] not in urls]
    if keep is new:
        store[store.index(old)] = new


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-days", type=int, default=8)
    ap.add_argument("--only", help="comma-separated source names")
    ap.add_argument("--limit", type=int, default=0, help="max LLM extractions this run")
    ap.add_argument("--dry-run", action="store_true", help="collect+dedupe only; no LLM, no writes")
    ap.add_argument("--collect-only", action="store_true",
                    help="fetch sources and append new candidates to the queue; no LLM. Run daily.")
    ap.add_argument("--no-collect", action="store_true",
                    help="process the existing queue only (e.g. after backfill)")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    run_date = today()

    # The queue: data/candidates.jsonl holds raw, unprocessed candidates keyed by URL.
    # Daily collects append; the weekly run drains. This is how we beat shallow RSS feeds.
    # data/processed.jsonl remembers every URL a run has handled (stored, skipped, no
    # text...) so a feed that still lists last week's article doesn't re-queue it.
    queue = read_jsonl(CANDIDATES_PATH)
    queued_urls = {c["source_url"] for c in queue}
    processed = read_jsonl(PROCESSED_PATH)
    processed_urls = {p["url"] for p in processed}
    if not args.no_collect:
        fresh = collect(args.since_days, args.only.split(",") if args.only else None)
        added = []
        for c in fresh:  # one feed can list a URL twice, and Mastodon posts link the same article
            if c["source_url"] not in queued_urls and c["source_url"] not in processed_urls:
                added.append(c)
                queued_urls.add(c["source_url"])
        queue.extend(added)
        log.info("queue: %d existing + %d new (%d already processed) = %d",
                 len(queued_urls), len(added), len(fresh) - len(added), len(queue))
    if args.collect_only:
        write_jsonl(CANDIDATES_PATH, queue)
        return 0

    cands = dedupe(queue)
    log.info("%d candidates after dedupe", len(cands))
    if args.dry_run:
        for c in cands[:50]:
            print(f"{c['disclosed_date']} {c['source_type']:<22} {c['org_name'] or '(unnamed)'!s:<40} {c['source_url']}")
        return 0

    from extract import extract_one, usage_totals  # imported late so --dry-run needs no API key

    store = read_jsonl(INCIDENTS_PATH)
    known_urls = {s["url"] for r in store for s in r["sources"]}
    llm_calls = 0
    handled: set[str] = set()

    def done(c: dict, outcome: str) -> None:
        for s in c.get("all_sources", [{"url": c["source_url"]}]):
            handled.add(s["url"])
            processed.append({"url": s["url"], "outcome": outcome, "date": run_date})

    for c in cands:
        if c["source_url"] in known_urls:
            done(c, "already_stored")
            continue
        existing = find_record(store, c["org_name"], c["disclosed_date"]) if c.get("org_name") else None
        if existing and c["source_type"] in ("hhs_portal", "state_ag", "ransomware_leak_site"):
            # Already have this incident from a richer source; just attach the link.
            existing["sources"].append({"url": c["source_url"], "type": c["source_type"],
                                        "title": c.get("title"), "fetched_at": None})
            done(c, "attached")
            continue

        # Regulator rows and leak-site claims carry no narrative worth an LLM call;
        # build them from their checkboxes. Only 8-Ks, press and posts go to the model.
        if c["source_type"] in ("hhs_portal", "state_ag", "ransomware_leak_site"):
            rec = deterministic_record(c, run_date)
            if rec:
                merge_into_store(store, rec)
            done(c, "stored" if rec else "invalid")
            continue

        if args.limit and llm_calls >= args.limit:
            log.info("limit reached; remaining candidates stay queued for next run")
            break

        text = c.get("text") or fetch_text(c["source_url"])
        if (not text or len(text) < 200) and len((c.get("structured_hint") or {}).get("summary") or "") >= 300:
            # Page blocked (databreaches.net sits behind a bot challenge); the feed
            # summary is the first paragraph and usually names the victim.
            text = c["structured_hint"]["summary"]
            c["structured_hint"]["note"] = "article page unfetchable; extracted from the feed summary only"
        if not text or len(text) < 200:
            log.info("no usable text for %s; dropped", c["source_url"])
            done(c, "no_text")  # don't retry forever; verify_sources tracks fetch failure rate
            continue
        if not mostly_english(text):
            log.info("non-English text; dropped without LLM: %s", c["source_url"])
            done(c, "non_english")
            continue
        if c["source_type"] == "sec_8k" and not looks_like_incident_8k(text):
            log.info("8-K without an incident item; dropped without LLM: %s", c["source_url"])
            done(c, "not_incident_8k")
            continue

        llm_calls += 1
        try:
            rec = extract_one(c, text, run_date)
        except Exception as e:  # noqa: BLE001
            log.exception("extract failed for %s; kept in queue", c["source_url"])
            continue
        if rec:
            merge_into_store(store, rec)
        done(c, "stored" if rec else "skipped")

    store.sort(key=lambda r: (r["disclosed_date"], normalize_org(r["org_name"])), reverse=True)
    write_jsonl(INCIDENTS_PATH, store)
    remaining = [c for c in queue if c["source_url"] not in handled]
    write_jsonl(CANDIDATES_PATH, remaining)
    cutoff = (date.today() - timedelta(days=120)).isoformat()  # feeds never look back that far
    write_jsonl(PROCESSED_PATH, [p for p in processed if p["date"] >= cutoff])
    log.info("store: %d incidents; queue: %d left. LLM calls=%d input_tokens=%d output_tokens=%d",
             len(store), len(remaining), usage_totals["calls"], usage_totals["input"], usage_totals["output"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
