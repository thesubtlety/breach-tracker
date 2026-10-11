"""Static pages for search engines and deep links: one per organization and one per
vendor, plus sitemap.xml and robots.txt. The app stays the search layer; these pages
carry the organization's name and the question in their title so a query like
"<org> breach" can land somewhere. Rebuilt from scratch on every build.

    site/org/<org_id>/index.html      site/vendor/<vendor_id>/index.html
"""
from __future__ import annotations

import shutil
from collections import defaultdict
from html import escape
from pathlib import Path

SITE_NAME = "Breach Vectors"
CSS = """
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


def label(v: str | None) -> str:
    return (v or "unknown").replace("_", " ")


def shell(title: str, description: str, canonical: str, body: str, home: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<meta name="description" content="{escape(description[:300])}">
<link rel="canonical" href="{escape(canonical)}">
<style>{CSS}</style>
</head>
<body>
<nav><a href="{home}">{SITE_NAME}</a> · how organizations get breached, from what a public source said</nav>
{body}
<footer>
<p>Built from public breach reports: regulator filings, SEC 8-Ks, notification letters, press. Every stated mechanism carries a quote from its source; "unknown" means no source said. Records are machine-classified and unreviewed unless marked.</p>
<p>Dataset: CC BY-SA 4.0. <a href="{home}">Search and filter all records</a> · <a href="https://github.com/thesubtlety/breach-tracker">Source and method</a></p>
</footer>
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


def record_block(r: dict, home: str, show_org: bool = False) -> str:
    d = r.get("derived") or {}
    tp = r.get("third_party") or {}
    actor = r.get("actor") or {}
    head = f"{r['disclosed_date']}: {label(r['initial_access'])}"
    if show_org:
        head = f'{r["disclosed_date"]}: <a href="../../org/{escape(r.get("org_id") or "")}/">{escape(r["org_name"])}</a>, {label(r["initial_access"])}'
    rows = [
        ("evidence", f"{label(r.get('evidence_level'))} · confidence {label(r.get('confidence'))}"),
        ("records affected", f"{r['records_affected']:,}" if r.get("records_affected") else None),
        ("dates", " · ".join(filter(None, [f"intrusion {r['incident_date']}" if r.get("incident_date") else None,
                                            f"discovered {r['discovered_date']}" if r.get("discovered_date") else None]))),
        ("organization type", label(r.get("org_type")) if r.get("org_type") not in (None, "unknown") else None),
        ("control failure", label(r.get("control_failure")) if r.get("control_failure") not in (None, "unknown") else None),
        ("technology", ", ".join(r.get("technology_involved") or [])),
        ("CVE", ", ".join(f'<a href="{home}#cve={escape(c)}">{escape(c)}</a>' for c in r.get("cve") or [])),
        ("third party", ", ".join(f'<a href="../../vendor/{escape(v["id"])}/">{escape(v["name"])}</a>' for v in d.get("vendors") or [])
                        or ("yes" if tp.get("involved") is True else None)),
        ("actor", " · ".join(filter(None, [actor.get("name"), label(actor.get("variety")) if actor.get("variety") not in (None, "unknown") else None]))),
        ("impact", " · ".join(filter(None, [label(r.get("impact_type")), "ransomware" if r.get("ransomware") is True else None]))),
        ("ATT&CK", " ".join(f'<a href="https://attack.mitre.org/techniques/{escape(t.replace(".", "/"))}/" rel="noopener">{escape(t)}</a>'
                           for t in r.get("attack_techniques") or [])),
        ("record", f'<a href="{home}#id={escape(r["id"])}">{escape(r["id"])}</a>'),
    ]
    dl = "".join(f"<dt>{k}</dt><dd>{v if k in ('CVE', 'third party', 'ATT&CK', 'record') else escape(v)}</dd>" for k, v in rows if v)
    parts = [f"<h2>{head}</h2>"]
    if r.get("summary"):
        parts.append(f"<p>{escape(r['summary'])}</p>")
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
    bits = [f"{n} incident{'s' if n != 1 else ''} on record, {span}"]
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
    body.append(f'<p class="small"><a href="{home}#org={escape(o["id"])}">Open these records in the app</a></p>')
    body += [record_block(r, home) for r in recs]
    return shell(title, desc, f"{site_url}org/{o['id']}/", "\n".join(body), home)


def vendor_page(v: dict, recs: list[dict], site_url: str) -> str:
    recs = sorted(recs, key=lambda r: r["disclosed_date"], reverse=True)
    home = "../../"
    n = len(recs)
    title = f"{v['name']}: {n} breach{'es' if n != 1 else ''} at its customers | {SITE_NAME}"
    orgs = sorted({r["org_name"] for r in recs})
    desc = f"Organizations that named {v['name']} as the third party in a breach: " + ", ".join(orgs[:8]) + ("…" if len(orgs) > 8 else "") + "."
    facts = [f"{n} incident{'s' if n != 1 else ''}, {v['first']}" + (f" to {v['last']}" if v["last"] != v["first"] else "")]
    facts += [f"{label(a)} ×{c}" for a, c in v.get("archetypes") or []]
    body = [f"<h1>Behind: {escape(v['name'])}</h1>", f"<p class='muted small'>{' · '.join(escape(f) for f in facts)}</p>"]
    if v.get("aliases"):
        body.append(f"<p class='muted small'>Also named as {escape('; '.join(v['aliases']))}</p>")
    if v.get("is_org"):
        body.append(f'<p class="small"><a href="../../org/{escape(v["id"])}/">{escape(v["name"])}\'s own breaches</a></p>')
    body.append(f'<p class="small"><a href="{home}#vendor={escape(v["id"])}">Open these records in the app</a>'
                + (f' · <a href="{home}feeds/vendor-{escape(v["id"])}.xml">Atom feed</a>' if v.get("feed") else "") + "</p>")
    body += [record_block(r, home, show_org=True) for r in recs]
    return shell(title, desc, f"{site_url}vendor/{v['id']}/", "\n".join(body), home)


def _lastmod(recs: list[dict]) -> str:
    return max(max(r.get("first_seen") or "", r.get("updated_at") or "", r["disclosed_date"]) for r in recs)[:10]


def write_pages(rows: list[dict], orgs: list[dict], vendors: list[dict], site_dir: Path, site_url: str) -> list[tuple[str, str]]:
    """Write every page; return (relative url, lastmod) for the sitemap."""
    by_org: dict[str, list[dict]] = defaultdict(list)
    by_vendor: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_org[r.get("org_id") or ""].append(r)
        for v in (r.get("derived") or {}).get("vendors") or []:
            by_vendor[v["id"]].append(r)
    urls = []
    for kind, items, groups, render in (("org", orgs, by_org, org_page), ("vendor", vendors, by_vendor, vendor_page)):
        root = site_dir / kind
        shutil.rmtree(root, ignore_errors=True)
        for o in items:
            recs = groups.get(o["id"])
            if not recs:
                continue
            d = root / o["id"]
            d.mkdir(parents=True)
            (d / "index.html").write_text(render(o, recs, site_url))
            urls.append((f"{kind}/{o['id']}/", _lastmod(recs)))
    return urls


def sitemap(urls: list[tuple[str, str]], site_url: str, generated: str) -> str:
    entries = [f"  <url><loc>{escape(site_url)}</loc><lastmod>{generated}</lastmod></url>"]
    entries += [f"  <url><loc>{escape(site_url + u)}</loc><lastmod>{m}</lastmod></url>" for u, m in urls]
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "\n".join(entries) + "\n</urlset>\n"


def robots(site_url: str) -> str:
    return f"User-agent: *\nAllow: /\nSitemap: {site_url}sitemap.xml\n"
