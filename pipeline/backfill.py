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
- rss / mastodon: no history. Use Hackmageddon's timelines or the VCDB import for the past.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CANDIDATES_PATH, read_jsonl, write_jsonl  # noqa: E402
from sources import (EFTS, MAINE_DIR, _edgar_hit, _get, california_ag, hhs, hibp, maine_ag,  # noqa: E402
                     parse_maine_notice, rwl_candidate, rwl_get)

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
    if "ransomware_live" in wanted:
        new += ransomware_live_history(start, end)

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
