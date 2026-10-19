"""Phase 1: historical collection into the queue (data/candidates.jsonl).

Backfill only *collects*. Extraction happens through the normal weekly run with
`--no-collect --limit N`, so the LLM spend is paced and visible.

    python pipeline/backfill.py --start 2023-12-18 --sources sec_edgar,ransomware_live
    python pipeline/run.py --no-collect --limit 200          # repeat weekly until the queue drains

Notes per source:
- sec_edgar: full-text search is paged (100 hits/page). 2023-12-18 is when Item 1.05
  took effect; earlier 8-Ks exist but the incident-item prefilter in run.py won't match
  them (they used Item 8.01 or nothing), so expect lower yield before that date.
- hhs: the portal's CSV export covers the last 24 months of open cases; older
  rows need the Archive tab, which this script doesn't drive. VCDB covers earlier years.
- maine_ag: maine.gov serves the notices to US addresses only. From elsewhere, run
  pipeline/fetch_maine.py on a US machine and pass the zip here with --maine-zip.
- ransomware_live: PRO API per-month victim lists (needs RANSOMWARE_LIVE_API_KEY).
- rss / mastodon: no history. hackmageddon (fortnightly timelines, 2020 on) and
  konbriefing (yearly lists, 2022 on) stand in for the feeds; each row links the
  original article or company statement, which is what gets read. Rows for an
  organization that already has a record with a stated mechanism are not queued.
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path

from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CANDIDATES_PATH, INCIDENTS_PATH, PROCESSED_PATH, normalize_org, read_jsonl, url_key, write_jsonl  # noqa: E402
from sources import (BROWSER_UA, EFTS, MAINE_DIR, _edgar_hit, _get, california_ag, hhs, hibp, maine_ag,  # noqa: E402
                     oregon_doj, parse_maine_notice, rwl_candidate, rwl_get, south_carolina, vermont_ag, washington_ag)

log = logging.getLogger("backfill")


def month_windows(start: date, end: date):
    cur = start.replace(day=1)
    while cur <= end:
        nxt = (cur.replace(day=28) + timedelta(days=4)).replace(day=1)
        yield cur, min(nxt - timedelta(days=1), end)
        cur = nxt


def sec_edgar_paged(start: date, end: date) -> list[dict]:
    out: list[dict] = []
    for a, b in month_windows(start, end):
        offset = 0
        while True:
            # EFTS pages with `from` (100 hits each); it silently ignores `page`.
            params = {"q": '"cybersecurity incident"', "forms": "8-K",
                      "startdt": a.isoformat(), "enddt": b.isoformat(), "from": offset}
            r = _get(EFTS, params=params)
            if not r:
                break
            body = r.json().get("hits", {})
            hits = body.get("hits", [])
            out += [c for c in (_edgar_hit(h, b.isoformat()) for h in hits) if c]
            total = (body.get("total") or {}).get("value", 0)
            offset += len(hits)
            time.sleep(0.2)
            if not hits or offset >= total:
                break
        log.info("sec_edgar %s..%s: %d so far", a, b, len(out))
    return out


def ransomware_live_history(start: date, end: date) -> list[dict]:
    """PRO API, one request per month: /victims/?year=YYYY&month=MM."""
    if not os.environ.get("RANSOMWARE_LIVE_API_KEY"):
        log.warning("ransomware_live: RANSOMWARE_LIVE_API_KEY not set; skipped")
        return []
    out: list[dict] = []
    for a, _ in month_windows(start, end):
        out += [c for c in (rwl_candidate(v) for v in rwl_get("/victims/", year=a.year, month=f"{a.month:02d}")) if c]
        time.sleep(1)
        log.info("ransomware_live %s: %d so far", a, len(out))
    return out


def maine_from_zip(path: str, start: date) -> list[dict]:
    """Notices fetched elsewhere with pipeline/fetch_maine.py (maine.gov is US-only)."""
    import re
    import zipfile

    out: list[dict] = []
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if re.search(r"^[0-9a-f-]{36}\.s?html$", n, re.I)]
        for n in names:
            c = parse_maine_notice(z.read(n).decode("utf-8", "replace"), MAINE_DIR + n)
            if c and date.fromisoformat(c["disclosed_date"]) >= start:
                out.append(c)
    log.info("maine zip: %d notice pages, %d candidates since %s", len(names), len(out), start)
    return out


# ---------------------------------------------------------------------------
# Hackmageddon: fortnightly "Cyber Attacks Timeline" posts, one HTML table each, served
# through the site's WordPress API. Rows link the original article.
# ---------------------------------------------------------------------------
HM_API = "https://www.hackmageddon.com/wp-json/wp/v2/posts"
HM_DROP_CLASS = {"H", "CW", "N/A", "Hacktivism", "Cyber Warfare"}
HM_DROP_ATTACK = re.compile(r"ddos|defacement|coordinated inauthentic|malicious spam|^fake\b", re.I)
UNNAMED_TARGET = re.compile(r"^(\d|multiple|undisclosed|unknown|several|various|single|unnamed|android|windows|ios|"
                            r"users|individuals|customers|organizations|over|at least|more than|nearly|dozens|hundreds|"
                            r"thousands|some|numerous|a (number|dozen|few))\b", re.I)


def _hm_date(s: str | None, post_date: str) -> str:
    try:
        d = datetime.strptime((s or "").strip(), "%d/%m/%Y").date()
    except ValueError:
        return post_date
    return d.isoformat() if abs((date.fromisoformat(post_date) - d).days) <= 120 else post_date


def parse_hackmageddon_post(content_html: str, post_date: str) -> list[dict]:
    out: list[dict] = []
    for table in BeautifulSoup(content_html, "lxml").find_all("table"):
        rows = table.find_all("tr")
        hdr = [c.get_text(" ", strip=True) for c in rows[0].find_all(["th", "td"])] if rows else []
        if "Target" not in hdr or "Link" not in hdr:
            continue
        for tr in rows[1:]:
            cells = tr.find_all(["td", "th"])
            if len(cells) != len(hdr):
                continue
            d = dict(zip(hdr, [c.get_text(" ", strip=True) for c in cells]))
            a = cells[hdr.index("Link")].find("a", href=True)
            target = d.get("Target", "")
            if not a or not a["href"].startswith("http") or not target or UNNAMED_TARGET.match(target):
                continue
            if d.get("Attack Class", "").strip() in HM_DROP_CLASS or HM_DROP_ATTACK.search(d.get("Attack", "")):
                continue
            country = d.get("Country", "").strip()
            actor = d.get("Author", "").strip()
            out.append({
                "org_name": target, "disclosed_date": _hm_date(d.get("Date Reported"), post_date),
                "source_type": "press", "source_url": a["href"], "title": f"Hackmageddon timeline: {target}",
                "text": None,
                "structured_hint": {"timeline": "hackmageddon", "summary": d.get("Description", "")[:1500] or None,
                                    "attack": d.get("Attack") or None, "actor": actor if actor and actor != "?" else None},
                "evidence_level_hint": "press_report",
                "org_country": country if re.fullmatch(r"[A-Z]{2}", country) else "unknown",
            })
    return out


def _hm_get(params: dict):
    return _get(HM_API, params=params, headers={"User-Agent": BROWSER_UA})


def hackmageddon(start: date, end: date) -> list[dict]:
    posts: list[tuple[str, str]] = []
    for page in range(1, 30):
        r = _hm_get({"search": '"cyber attacks timeline"', "per_page": 100, "page": page, "_fields": "slug,date",
                     "after": f"{start}T00:00:00", "before": f"{end + timedelta(days=60)}T00:00:00"})
        batch = r.json() if r else []
        if not isinstance(batch, list) or not batch:
            break
        posts += [(p["slug"], p["date"][:10]) for p in batch if "cyber-attacks-timeline" in p["slug"]]
        if len(batch) < 100:
            break
        time.sleep(1)
    out: list[dict] = []
    for slug, post_date in posts:
        # The API 500s on a few large posts; one retry, then move on.
        r = _hm_get({"slug": slug, "_fields": "slug,content"}) or (time.sleep(3), _hm_get({"slug": slug, "_fields": "slug,content"}))[1]
        body = r.json() if r else []
        if not body:
            log.warning("hackmageddon: %s unavailable; skipped", slug)
            continue
        rows = parse_hackmageddon_post(body[0]["content"]["rendered"], post_date)
        out += [c for c in rows if start.isoformat() <= c["disclosed_date"] <= end.isoformat()]
        time.sleep(1)
    log.info("hackmageddon: %d timeline posts, %d candidates", len(posts), len(out))
    return out


# ---------------------------------------------------------------------------
# KonBriefing: one page per year listing attacks with the organization, place and a
# link, often to the organization's own statement. Pages exist from 2022.
# ---------------------------------------------------------------------------
KB_YEAR = "https://konbriefing.com/en-topics/cyber-attacks-{}.html"
SOCIAL_LINK = re.compile(r"https?://(www\.)?(twitter\.com|x\.com|facebook\.com|linkedin\.com|instagram\.com)/", re.I)
KB_COUNTRY = {"USA": "US", "Canada": "CA", "United Kingdom": "GB", "Germany": "DE", "France": "FR", "Italy": "IT",
              "Spain": "ES", "Netherlands": "NL", "Switzerland": "CH", "Austria": "AT", "Australia": "AU",
              "India": "IN", "Japan": "JP", "Brazil": "BR", "Mexico": "MX", "Belgium": "BE", "Sweden": "SE"}


def _kb_date(s: str) -> str | None:
    for fmt in ("%B %d, %Y", "%B %Y"):
        try:
            return datetime.strptime(s.strip(), fmt).date().isoformat()
        except ValueError:
            pass
    return None


def parse_konbriefing(html: str) -> list[dict]:
    out: list[dict] = []
    # Each <article> box leaves a div unclosed, so a whole-page parse nests every later
    # box inside the earlier ones. Split first, parse each box alone.
    for chunk in re.split(r'(?=<article[^>]*\bid="Res)', html)[1:]:
        box = BeautifulSoup(chunk.split("</article>", 1)[0], "lxml")
        lines = [t.strip() for t in box.get_text("\n").split("\n") if t.strip()]
        k = next((i for i, t in enumerate(lines) if _kb_date(t)), None)
        if k is None or len(lines) < k + 3:
            continue
        org, _, place = lines[k + 2].partition(" - ")
        links = [a["href"] for a in box.find_all("a", href=True)
                 if a["href"].startswith("http") and "konbriefing" not in a["href"] and not SOCIAL_LINK.match(a["href"])]
        if not org.strip() or not links:
            continue
        country = re.sub(r"\s*\(.*?\)\s*$", "", place).rsplit(",", 1)[-1].strip()
        out.append({
            "org_name": org.strip(), "disclosed_date": _kb_date(lines[k]), "source_type": "press",
            "source_url": links[0], "title": f"KonBriefing: {lines[k + 1]}", "text": None,
            "structured_hint": {"timeline": "konbriefing", "summary": f"{lines[k + 1]}. {lines[k + 2]}", "place": place or None},
            "evidence_level_hint": "press_report", "org_country": KB_COUNTRY.get(country, "unknown"),
        })
    return out


def konbriefing(start: date, end: date) -> list[dict]:
    out: list[dict] = []
    for year in range(start.year, end.year + 1):
        r = _get(KB_YEAR.format(year), headers={"User-Agent": BROWSER_UA})
        if not r or str(year) not in r.url:
            log.warning("konbriefing: no page for %d", year)
            continue
        rows = parse_konbriefing(r.text)
        out += [c for c in rows if start.isoformat() <= c["disclosed_date"] <= end.isoformat()]
        log.info("konbriefing %d: %d rows, %d in range", year, len(rows), len(out))
        time.sleep(1)
    return out


def drop_settled(cands: list[dict], store: list[dict], processed_keys: set[str]) -> list[dict]:
    """Nothing to gain from a model call: the URL was already handled, or a press item
    names an organization whose record in the merge window already states a mechanism."""
    from run import find_record
    index: dict[str, list[dict]] = defaultdict(list)
    for r in store:
        index[normalize_org(r["org_name"])].append(r)
    keep: list[dict] = []
    for c in cands:
        if url_key(c["source_url"]) in processed_keys:
            continue
        if c["source_type"] == "press" and c.get("org_name"):
            rec = find_record(store, c["org_name"], c["disclosed_date"], index=index)
            if rec and rec["initial_access"] != "unknown":
                continue
        keep.append(c)
    return keep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2023-12-18")
    ap.add_argument("--end", default=date.today().isoformat())
    ap.add_argument("--sources", default="sec_edgar,hhs,maine_ag")
    ap.add_argument("--maine-pages", type=int, default=400)
    ap.add_argument("--maine-zip", help="zip from fetch_maine.py; parsed offline instead of fetching")
    ap.add_argument("--ca-pages", type=int, default=120, help="California AG list pages to walk (50 rows each)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    start, end = date.fromisoformat(args.start), date.fromisoformat(args.end)
    wanted = set(args.sources.split(","))

    new: list[dict] = []
    if "sec_edgar" in wanted:
        new += sec_edgar_paged(start, end)
    if "hhs" in wanted:
        new += hhs(start)
    if args.maine_zip:
        new += maine_from_zip(args.maine_zip, start)
    if "california_ag" in wanted:
        new += california_ag(start, max_pages=args.ca_pages)
    if "hibp" in wanted:
        new += hibp(start)
    if "maine_ag" in wanted:
        new += maine_ag(start, max_pages=args.maine_pages)
    if "washington_ag" in wanted:
        new += washington_ag(start)
    if "oregon_doj" in wanted:
        new += oregon_doj(start)
    if "south_carolina" in wanted:
        new += south_carolina(start)
    if "vermont_ag" in wanted:
        new += vermont_ag(start)
    if "ransomware_live" in wanted:
        new += ransomware_live_history(start, end)
    if "hackmageddon" in wanted:
        new += hackmageddon(start, end)
    if "konbriefing" in wanted:
        new += konbriefing(start, end)

    store = read_jsonl(INCIDENTS_PATH)
    processed = {p["key"] for p in read_jsonl(PROCESSED_PATH)} | {url_key(s["url"]) for r in store for s in r["sources"]}
    kept = drop_settled(new, store, processed)
    log.info("backfill: %d of %d candidates already handled or settled; dropped", len(new) - len(kept), len(new))
    new = kept
    queue = read_jsonl(CANDIDATES_PATH)
    seen = {c["source_url"] for c in queue}
    added = []
    for c in new:
        if c["source_url"] not in seen:
            added.append(c)
            seen.add(c["source_url"])
    queue.extend(added)
    write_jsonl(CANDIDATES_PATH, queue)
    log.info("backfill: %d collected, %d new queued (queue now %d)", len(new), len(added), len(queue))
    return 0


if __name__ == "__main__":
    sys.exit(main())
