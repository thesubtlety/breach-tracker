"""Static pages for search engines and deep links: one per organization and one per
vendor, plus sitemap.xml and robots.txt. The app stays the search layer; these pages
carry the organization's name and the question in their title so a query like
"<org> breach" can land somewhere. Rebuilt from scratch on every build.

    site/org/<org_id>/index.html      site/vendor/<vendor_id>/index.html
"""
from __future__ import annotations

import re
import shutil
from collections import Counter, defaultdict
from html import escape
from pathlib import Path

SITE_NAME = "Breach Vectors"
PAGE_CAP = 200  # records shown on a technique or sector page; the app has the rest
TECHNIQUE_NAMES = {
    "T1566": "phishing", "T1598": "phishing for information", "T1078": "valid accounts", "T1190": "exploit public-facing application",
    "T1133": "external remote services", "T1021": "remote services", "T1021.001": "remote desktop protocol", "T1195": "supply chain compromise",
    "T1199": "trusted relationship", "T1110": "brute force", "T1621": "MFA fatigue", "T1114": "email collection",
    "T1213": "data from information repositories", "T1530": "data from cloud storage", "T1041": "exfiltration over C2 channel",
    "T1567": "exfiltration to web service", "T1486": "data encrypted for impact", "T1485": "data destruction", "T1489": "service stop",
    "T1491": "defacement", "T1657": "financial theft", "T1552": "unsecured credentials",
}


def technique_name(t: str) -> str:
    return TECHNIQUE_NAMES.get(t) or TECHNIQUE_NAMES.get(t.split(".")[0], "")


def technique_registry(rows: list[dict]) -> list[dict]:
    by: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        for t in r.get("attack_techniques") or []:
            by[t].append(r)
    out = []
    for t, recs in by.items():
        dates = sorted(r["disclosed_date"] for r in recs)
        out.append({"id": t, "name": technique_name(t), "incidents": len(recs), "first": dates[0], "last": dates[-1],
                    "sectors": Counter(r["org_type"] for r in recs if r.get("org_type") not in (None, "unknown")).most_common(5),
                    "initial_access": Counter(r["initial_access"] for r in recs if r.get("initial_access") not in (None, "unknown")).most_common(5)})
    out.sort(key=lambda o: (-o["incidents"], o["id"]))
    return out


def sector_registry(rows: list[dict]) -> list[dict]:
    by: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if r.get("org_type") not in (None, "unknown"):
            by[r["org_type"]].append(r)
    out = []
    for sct, recs in by.items():
        dates = sorted(r["disclosed_date"] for r in recs)
        known = [r for r in recs if r.get("initial_access") not in (None, "unknown")]
        out.append({"id": sct, "name": label(sct), "incidents": len(recs), "first": dates[0], "last": dates[-1],
                    "initial_access": Counter(r["initial_access"] for r in known).most_common(6), "stated": len(known),
                    "ransomware": sum(1 for r in recs if r.get("ransomware") is True),
                    "vendors": Counter(v["name"] for r in recs for v in (r.get("derived") or {}).get("vendors") or []).most_common(5)})
    out.sort(key=lambda o: (-o["incidents"], o["id"]))
    return out
CSS = """
  nav svg { width:18px; height:18px; vertical-align:-3px; margin-right:6px; color:var(--accent); }
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#e3e3e3;--soft:#f5f5f5;--accent:#2b5bd7}
@media(prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--muted:#9a9a9a;--line:#2a2a2a;--soft:#1a1a1a;--accent:#7aa2ff}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:80ch;margin-inline:auto}
a{color:var(--accent)} h1{font-size:24px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 6px} p{margin:0 0 8px}
.muted{color:var(--muted)} .small{font-size:13px} nav{font-size:13px;color:var(--muted);margin-bottom:14px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:8px 0;font-size:14px} dt{color:var(--muted)} dd{margin:0}
blockquote{margin:8px 0;padding:6px 12px;border-left:3px solid var(--line);color:var(--muted);font-style:italic}
ul{padding-left:20px} li{margin:2px 0} .tag{display:inline-block;padding:1px 6px;border:1px solid var(--line);border-radius:10px;font-size:12px;color:var(--muted)}
footer{margin-top:28px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:12px}
"""


# Display labels for stored values. Exports and the API keep the stored value.
LABELS = {
    "phishing": "Phishing", "vishing_or_social_engineering": "Voice phishing or other social engineering",
    "stolen_or_valid_credentials": "Compromised or abused credentials", "exploit_public_facing_app": "Public-facing application exploit",
    "supply_chain_or_third_party": "Supply chain or third party", "misconfiguration_or_exposure": "Misconfiguration or data exposure",
    "insider": "Insider", "lost_or_stolen_device": "Lost or stolen device", "physical_or_paper": "Physical or paper",
    "malware_other": "Malware; entry method unknown", "unknown": "Unknown",
    "org_confirmed": "Organization statement", "regulator_filing": "Regulator filing", "press_report": "News report", "actor_claimed": "Actor claim",
    "data_theft": "Data theft", "disruption_or_ransomware": "Disruption or ransomware", "both": "Data theft and disruption",
    "exposure_no_theft_confirmed": "Data exposed; theft not confirmed",
    "healthcare": "Healthcare", "financial": "Financial", "government": "Government", "education": "Education", "technology_saas": "Technology and SaaS",
    "manufacturing": "Manufacturing", "retail_ecommerce": "Retail and e-commerce", "professional_services": "Professional services", "telecom": "Telecom",
    "energy_utilities": "Energy and utilities", "transportation_logistics": "Transportation and logistics", "nonprofit": "Nonprofit", "other": "Other",
    "unpatched_known_vuln": "Unpatched known vulnerability", "zero_day": "Zero-day exploitation", "missing_mfa": "Missing MFA",
    "weak_or_reused_password": "Weak or reused password", "excessive_privilege": "Excessive privilege", "exposed_service_or_storage": "Exposed service or storage",
    "unrotated_secret_or_token": "Unrotated secret or token", "eol_software": "End-of-life software", "staff_deceived": "Staff deceived",
    "insider_access_abuse": "Insider access abuse", "vendor_control_failure": "Third-party control weakness",
    "organized_crime": "Organized crime", "state_affiliated": "State-affiliated", "activist": "Activist", "former_employee": "Former employee",
    "unaffiliated": "Unaffiliated individual", "end_user": "Employee, end user", "system_admin": "Employee, administrator",
    "external": "External", "internal": "Internal", "partner": "Partner", "financial_motive": "Financial", "espionage": "Espionage", "ideology": "Ideology", "grudge": "Grudge",
    "vendor_product": "Vendor product", "vendor_hosted_data": "Vendor-hosted data", "vendor_connection": "Vendor connection",
    "vpn_or_edge_device": "VPN or edge device", "web_application": "Web application", "remote_desktop": "Remote desktop", "email_account": "Email account",
    "saas_or_cloud_console": "SaaS or cloud console", "api_or_integration_token": "API or integration token", "endpoint": "Endpoint", "physical": "Physical",
    "infostealer": "Infostealer", "leak_or_reuse": "Leak or reuse", "brute_force": "Brute force",
    "hacking": "Hacking", "malware": "Malware", "social": "Social", "misuse": "Misuse", "error": "Error", "environmental": "Environmental",
    "sec_8k": "SEC 8-K", "hhs_portal": "HHS breach portal", "state_ag": "State attorney general", "ransomware_leak_site": "Leak-site claim",
    "company_notice": "Company notice", "press": "News report", "vendor_research": "Vendor research", "mastodon": "Mastodon", "hibp": "Have I Been Pwned",
    "high": "High", "medium": "Medium", "low": "Low",
    "regulator": "Regulator", "extracted": "Extracted", "imported": "Imported",
}
FIELD_NAMES = {
    "initial_access": "Breach mechanism", "evidence_level": "Source type", "control_failure": "Reported security weakness",
    "actor_variety": "Actor type or role", "confidence": "Classification confidence", "third_party": "Third-party role",
    "entry_asset": "Entry asset", "origin": "Record origin", "org_type": "Sector", "impact_type": "Impact",
}


def label(v: str | None) -> str:
    v = v or "unknown"
    return LABELS.get(v) or v.replace("_", " ")


def shell(title: str, description: str, canonical: str, body: str, home: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<meta name="description" content="{escape(description[:300])}">
<link rel="canonical" href="{escape(canonical)}">
<link rel="icon" type="image/svg+xml" href="{home}favicon.svg">
<style>{CSS}</style>
</head>
<body>
<nav><a href="{home}"><svg viewBox="0 0 64 64" aria-hidden="true"><path d="M15.1 46.1 A22 22 0 1 0 15.1 17.9" fill="none" stroke="currentColor" stroke-width="7" stroke-linecap="round"/><path d="M3 32 H26" fill="none" stroke="currentColor" stroke-width="7" stroke-linecap="round"/><path d="M23 19 L44 32 L23 45 Z" fill="currentColor"/></svg>{SITE_NAME}</a></nav>
{body}
<footer>
<p>Built from public breach reports: regulator filings, SEC 8-Ks, notification letters, press. Every stated mechanism carries a quote from its source; "unknown" means no source said. Records are machine-classified and unreviewed unless marked.</p>
<p>Dataset: CC BY-SA 4.0. <a href="{home}">Search and filter all records</a> · <a href="https://github.com/thesubtlety/breach-tracker">Source and method</a></p>
</footer>
<script>document.addEventListener("click", e => {{ const a = e.target.closest("a[href]"); if (a && a.origin !== location.origin) {{ a.target = "_blank"; a.rel = "noopener"; }} }});</script>
</body>
</html>
"""


def _sources(r: dict) -> str:
    items = []
    for s in r.get("sources") or []:
        url = s.get("url") or ""
        if not url.startswith("http"):
            continue
        text = s.get("title") or url
        items.append(f'<li><a href="{escape(url)}" rel="noopener">{escape(text)}</a> <span class="tag">{escape(label(s.get("type")))}</span></li>')
    letter = r.get("letter") or {}
    seen = {s.get("url") for s in r.get("sources") or []}
    if letter.get("outcome") == "extracted" and (letter.get("url") or "").startswith("http") and letter["url"] not in seen:
        items.append(f'<li><a href="{escape(letter["url"])}" rel="noopener">Notification letter</a> <span class="tag">org confirmed</span></li>')
    return f"<ul>{''.join(items)}</ul>" if items else ""


HORIZONS = {"1": "next day", "5": "1 week", "21": "1 month", "63": "3 months", "126": "6 months", "250": "1 year"}


def _price_line(p: dict | None) -> str | None:
    if not p:
        return None
    pct = lambda v: f"{100 * v:+.1f}%"  # noqa: E731
    moves = [f"{HORIZONS.get(h, h)} {pct(x['raw'])}" + (f" ({pct(x['adj'])} vs market)" if x.get("adj") is not None else "")
             for h, x in p["returns"].items()]
    return f"{p['ticker']} from the close on {p['base_day']}: " + " · ".join(moves)


def cut_note(s: str) -> str:
    """Imported and catalogue summaries were stored cut at 280 characters; show that they go on."""
    return s.rstrip() + "…" if len(s) >= 280 and not re.search(r"""[.!?"”')\]]\s*$""", s) else s


def record_block(r: dict, home: str, show_org: bool = False) -> str:
    d = r.get("derived") or {}
    tp = r.get("third_party") or {}
    actor = r.get("actor") or {}
    head = f"{r['disclosed_date']}: {label(r['initial_access'])}"
    if show_org:
        head = f'{r["disclosed_date"]}: <a href="../../org/{escape(r.get("org_id") or "")}/">{escape(r["org_name"])}</a>, {label(r["initial_access"])}'
    rows = [
        ("source type", f"{label(r.get('evidence_level'))} · classification confidence {label(r.get('confidence'))}"),
        ("records affected", f"{r['records_affected']:,}" if r.get("records_affected") else None),
        ("dates", " · ".join(filter(None, [f"intrusion {r['incident_date']}" if r.get("incident_date") else None,
                                            f"discovered {r['discovered_date']}" if r.get("discovered_date") else None]))),
        ("sector", label(r.get("org_type")) if r.get("org_type") not in (None, "unknown") else None),
        ("reported security weakness", label(r.get("control_failure")) if r.get("control_failure") not in (None, "unknown") else None),
        ("technology", ", ".join(r.get("technology_involved") or [])),
        ("CVE", ", ".join(f'<a href="{home}#cve={escape(c)}">{escape(c)}</a>' for c in r.get("cve") or [])),
        ("third party", ", ".join(f'<a href="../../vendor/{escape(v["id"])}/">{escape(v["name"])}</a>' for v in d.get("vendors") or [])
                        or ("yes" if tp.get("involved") is True else None)),
        ("actor", " · ".join(filter(None, [actor.get("name"), label(actor.get("variety")) if actor.get("variety") not in (None, "unknown") else None]))),
        ("impact", " · ".join(filter(None, [label(r.get("impact_type")), "ransomware" if r.get("ransomware") is True else None]))),
        ("data types", ", ".join(r.get("data_types") or [])),
        ("share price", _price_line(d.get("price"))),
        ("ATT&CK", " ".join(f'<a href="https://attack.mitre.org/techniques/{escape(t.replace(".", "/"))}/" rel="noopener">{escape(t)}</a>'
                           for t in r.get("attack_techniques") or [])),
        ("record", f'<a href="{home}#id={escape(r["id"])}">{escape(r["id"])}</a>'),
    ]
    dl = "".join(f"<dt>{k}</dt><dd>{v if k in ('CVE', 'third party', 'ATT&CK', 'record') else escape(v)}</dd>" for k, v in rows if v)
    parts = [f"<h2>{head}</h2>"]
    if r.get("summary"):
        parts.append(f"<p>{escape(cut_note(r['summary']))}</p>")
    if r.get("root_cause"):
        parts.append(f"<p><span class='muted'>Root cause:</span> {escape(r['root_cause'])}</p>")
    if r.get("supporting_quote"):
        parts.append(f"<blockquote>{escape(r['supporting_quote'])}</blockquote>")
    parts.append(f"<dl>{dl}</dl>")
    parts.append(_sources(r))
    if r.get("notes"):
        parts.append(f"<p class='small muted'>{escape(r['notes'])}</p>")
    return "\n".join(parts)


def _facts(o: dict) -> str:
    n = o["incidents"]
    span = o["first"] + (f" to {o['last']}" if o["last"] != o["first"] else "")
    bits = [f"{n} record{'s' if n != 1 else ''}, {span}"]
    if o.get("sector") and o["sector"] != "unknown":
        bits.append(label(o["sector"]))
    if o.get("country"):
        bits.append(o["country"])
    if o.get("ticker"):
        bits.append(f"listed ({o['ticker']})")
    if o.get("largest"):
        bits.append(f"largest count {o['largest']:,}")
    if o.get("ransomware"):
        bits.append(f"{o['ransomware']} ransomware")
    return " · ".join(escape(b) for b in bits)


def org_page(o: dict, recs: list[dict], site_url: str) -> str:
    recs = sorted(recs, key=lambda r: r["disclosed_date"], reverse=True)
    home = "../../"
    n = len(recs)
    title = f"{o['name']} data breach{'es' if n > 1 else ''}: how they got in | {SITE_NAME}"
    known = [r for r in recs if r["initial_access"] != "unknown"]
    desc = (known[0].get("summary") if known and known[0].get("summary") else None) or recs[0].get("summary") or \
        f"{n} publicly reported breach{'es' if n > 1 else ''} at {o['name']}, {o['first']}" + (f" to {o['last']}" if o["last"] != o["first"] else "") + \
        ". Initial access: " + ", ".join(sorted({label(r["initial_access"]) for r in recs})) + "."
    body = [f"<h1>{escape(o['name'])}</h1>", f"<p class='muted small'>{_facts(o)}</p>"]
    if o.get("aliases"):
        body.append(f"<p class='muted small'>Also recorded as {escape('; '.join(o['aliases']))}</p>")
    body.append(f'<p class="small"><a href="{home}#org={escape(o["id"])}">Show these records in the table</a></p>')
    body += [record_block(r, home) for r in recs]
    return shell(title, desc, f"{site_url}org/{o['id']}/", "\n".join(body), home)


def vendor_page(v: dict, recs: list[dict], site_url: str) -> str:
    recs = sorted(recs, key=lambda r: r["disclosed_date"], reverse=True)
    home = "../../"
    n = len(recs)
    title = f"{v['name']}: {n} breach{'es' if n != 1 else ''} at its customers | {SITE_NAME}"
    orgs = sorted({r["org_name"] for r in recs})
    desc = f"Organizations that named {v['name']} as the third party in a breach: " + ", ".join(orgs[:8]) + ("…" if len(orgs) > 8 else "") + "."
    facts = [f"{n} record{'s' if n != 1 else ''} naming it, {v['first']}" + (f" to {v['last']}" if v["last"] != v["first"] else "")]
    facts += [f"{label(a)} ×{c}" for a, c in v.get("archetypes") or []]
    body = [f"<h1>Behind: {escape(v['name'])}</h1>", f"<p class='muted small'>{' · '.join(escape(f) for f in facts)}</p>"]
    if v.get("aliases"):
        body.append(f"<p class='muted small'>Also named as {escape('; '.join(v['aliases']))}</p>")
    if v.get("is_org"):
        body.append(f'<p class="small"><a href="../../org/{escape(v["id"])}/">{escape(v["name"])}\'s own breaches</a></p>')
    body.append(f'<p class="small"><a href="{home}#vendor={escape(v["id"])}">Show these records in the table</a>'
                + (f' · <a href="{home}feeds/vendor-{escape(v["id"])}.xml">Atom feed</a>' if v.get("feed") else "") + "</p>")
    body += [record_block(r, home, show_org=True) for r in recs]
    return shell(title, desc, f"{site_url}vendor/{v['id']}/", "\n".join(body), home)


def record_summary(a: dict) -> str:
    n = a["incidents"]
    s = f"{n} record{'s' if n != 1 else ''}"
    if n:
        parts = [f"{a['claimed']} matched claim{'s' if a['claimed'] != 1 else ''}" if a.get("claimed") else "",
                 f"{a['named']} naming the group in a report" if a.get("named") else ""]
        s += f" ({', '.join(p for p in parts if p)})" + (f", {a['first']}" + (f" to {a['last']}" if a["last"] != a["first"] else ""))
    return s


def actor_page(a: dict, recs: list[dict], site_url: str) -> str:
    recs = sorted(recs, key=lambda r: r["disclosed_date"], reverse=True)
    home = "../../"
    n, c = len(recs), a.get("claims") or {}
    title = f"{a['name']}: {n} breach record{'s' if n != 1 else ''}" + (f" and {c['claims']} leak-site claims" if c else "") + f" | {SITE_NAME}"
    orgs = sorted({r["org_name"] for r in recs})
    desc = (f"Breaches attributed to {a['name']} by a public source or matched to its leak-site claims: " + ", ".join(orgs[:8]) + ("…" if len(orgs) > 8 else "") + "."
            if orgs else f"Leak-site claims by {a['name']} and how many were matched to independent reporting.")
    facts = [label(a["variety"]) if a.get("variety") not in (None, "unknown") else None, a.get("country"), record_summary(a)]
    if c:
        facts.append(f"{c['claims']:,} leak-site claims, {c['last_90_days']:,} in the last 90 days, {c['confirmed']:,} matched ({round(100 * c['rate'])}%)")
    body = [f"<h1>{escape(a['name'])}</h1>", f"<p class='muted small'>{' · '.join(escape(f) for f in facts if f)}</p>"]
    if a.get("aliases"):
        body.append(f"<p class='muted small'>Also named as {escape('; '.join(a['aliases']))}</p>")
    lines = [f"{label(k)} ×{v}" for k, v in a.get("initial_access") or []]
    if lines:
        body.append(f"<p class='small'>Initial access, where a source stated it: {escape(', '.join(lines))}</p>")
    if a.get("sectors"):
        body.append(f"<p class='small'>Victim sectors: {escape(', '.join(f'{label(k)} ×{v}' for k, v in a['sectors']))}</p>")
    if a.get("vendors"):
        body.append(f"<p class='small'>Third parties named: {escape(', '.join(f'{k} ×{v}' for k, v in a['vendors']))}</p>")
    body.append(f'<p class="small"><a href="{home}#actor={escape(a["id"])}">Show these records in the table</a></p>')
    body += [record_block(r, home, show_org=True) for r in recs]
    return shell(title, desc, f"{site_url}actor/{a['id']}/", "\n".join(body), home)


def _capped(recs: list[dict], home: str, link: str) -> list[str]:
    recs = sorted(recs, key=lambda r: r["disclosed_date"], reverse=True)
    out = [record_block(r, home, show_org=True) for r in recs[:PAGE_CAP]]
    if len(recs) > PAGE_CAP:
        out.append(f'<p class="small">Newest {PAGE_CAP} of {len(recs)} records. <a href="{home}#{link}">All of them in the app</a>.</p>')
    return out


def technique_page(t: dict, recs: list[dict], site_url: str) -> str:
    home, n = "../../", len(recs)
    name = f"{t['id']} {t['name']}".strip()
    title = f"{name}: {n} breach{'es' if n != 1 else ''} using this ATT&CK technique | {SITE_NAME}"
    desc = f"Publicly reported breaches where the source describes MITRE ATT&CK {name}, with the sentence that says so."
    facts = [f"{n} record{'s' if n != 1 else ''}, {t['first']}" + (f" to {t['last']}" if t["last"] != t["first"] else "")]
    body = [f"<h1>{escape(name)}</h1>", f"<p class='muted small'>{' · '.join(escape(f) for f in facts)}</p>"]
    if t.get("sectors"):
        body.append(f"<p class='small'>Sectors: {escape(', '.join(f'{label(k)} ×{v}' for k, v in t['sectors']))}</p>")
    if t.get("initial_access"):
        body.append(f"<p class='small'>Initial access on these records: {escape(', '.join(f'{label(k)} ×{v}' for k, v in t['initial_access']))}</p>")
    body.append(f'<p class="small"><a href="https://attack.mitre.org/techniques/{escape(t["id"].replace(".", "/"))}/" rel="noopener">ATT&CK entry</a> · <a href="{home}#tech={escape(t["id"])}">Show these records in the table</a></p>')
    body += _capped(recs, home, f"tech={t['id']}")
    return shell(title, desc, f"{site_url}technique/{t['id']}/", "\n".join(body), home)


def sector_page(sct: dict, recs: list[dict], site_url: str) -> str:
    home, n = "../../", len(recs)
    title = f"{sct['name'].capitalize()} data breaches: {n} on record and how they got in | {SITE_NAME}"
    ia = ", ".join(f"{label(k)} ×{v}" for k, v in sct["initial_access"][:4])
    desc = f"{n} publicly reported {sct['name']} breaches; of the {sct['stated']} that state how, the leading vectors are {ia}." if sct["stated"] else f"{n} publicly reported {sct['name']} breaches."
    facts = [f"{n} records, {sct['first']} to {sct['last']}", f"{sct['stated']} state how", f"{sct['ransomware']} ransomware"]
    body = [f"<h1>{escape(sct['name'].capitalize())}</h1>", f"<p class='muted small'>{' · '.join(escape(f) for f in facts)}</p>"]
    if sct["initial_access"]:
        body.append(f"<p class='small'>Initial access, where stated: {escape(', '.join(f'{label(k)} ×{v}' for k, v in sct['initial_access']))}</p>")
    if sct.get("vendors"):
        body.append(f"<p class='small'>Third parties named most: {escape(', '.join(f'{k} ×{v}' for k, v in sct['vendors']))}</p>")
    body.append(f'<p class="small"><a href="{home}#ot={escape(sct["id"])}">Show these records in the table</a></p>')
    body += _capped(recs, home, f"ot={sct['id']}")
    return shell(title, desc, f"{site_url}sector/{sct['id']}/", "\n".join(body), home)


def _lastmod(recs: list[dict]) -> str:
    return max(max(r.get("first_seen") or "", r.get("updated_at") or "", r["disclosed_date"]) for r in recs)[:10]


def write_pages(rows: list[dict], orgs: list[dict], vendors: list[dict], site_dir: Path, site_url: str,
                actors: list[dict] | None = None, generated: str = "") -> list[tuple[str, str]]:
    """Write every page; return (relative url, lastmod) for the sitemap."""
    by_org: dict[str, list[dict]] = defaultdict(list)
    by_vendor: dict[str, list[dict]] = defaultdict(list)
    by_actor: dict[str, list[dict]] = defaultdict(list)
    by_tech: dict[str, list[dict]] = defaultdict(list)
    by_sector: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_org[r.get("org_id") or ""].append(r)
        for v in (r.get("derived") or {}).get("vendors") or []:
            by_vendor[v["id"]].append(r)
        d = r.get("derived") or {}
        for k in {d.get("actor_id"), *(d.get("claim_groups") or [])} - {None}:
            by_actor[k].append(r)
        for t in r.get("attack_techniques") or []:
            by_tech[t].append(r)
        by_sector[r.get("org_type") or "unknown"].append(r)
    urls = []
    for kind, items, groups, render in (("org", orgs, by_org, org_page), ("vendor", vendors, by_vendor, vendor_page),
                                        ("actor", actors or [], by_actor, actor_page),
                                        ("technique", technique_registry(rows), by_tech, technique_page),
                                        ("sector", sector_registry(rows), by_sector, sector_page)):
        root = site_dir / kind
        shutil.rmtree(root, ignore_errors=True)
        for o in items:
            recs = groups.get(o["id"], [])
            if not recs and not (kind == "actor" and o.get("claims")):
                continue
            d = root / o["id"]
            d.mkdir(parents=True)
            (d / "index.html").write_text(render(o, recs, site_url))
            urls.append((f"{kind}/{o['id']}/", _lastmod(recs) if recs else generated))
    return urls


def sitemap(urls: list[tuple[str, str]], site_url: str, generated: str) -> str:
    entries = [f"  <url><loc>{escape(site_url)}</loc><lastmod>{generated}</lastmod></url>"]
    entries += [f"  <url><loc>{escape(site_url + u)}</loc><lastmod>{m}</lastmod></url>" for u, m in urls]
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "\n".join(entries) + "\n</urlset>\n"


def robots(site_url: str) -> str:
    return f"User-agent: *\nAllow: /\nSitemap: {site_url}sitemap.xml\n"
