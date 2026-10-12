"""Source verification. Three checks, one JSON report, non-zero exit on the things
that should stop a run.

1. health   — each fetcher returns candidates with required fields; a source that
              returns zero twice in a row fails the run (quiet-week vs broken-source).
2. links    — sample stored records; HEAD/GET their source URLs; report link rot.
3. quotes   — sample stored records with a supporting_quote; re-fetch and confirm the
              quote is still verbatim in the page. Catches drift and fabrication
              that slipped past post_check (e.g. the page changed).

    python pipeline/verify_sources.py                 # all checks
    python pipeline/verify_sources.py --checks health # just the canary

Writes data/source_health.json (committed, so consecutive-zero detection has history).
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import re
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_DIR, INCIDENTS_PATH, now_iso, read_jsonl  # noqa: E402
from sources import ALL_SOURCES, _get, disabled_sources  # noqa: E402

log = logging.getLogger("verify")
HEALTH_PATH = DATA_DIR / "source_health.json"
REQUIRED = ("org_name", "disclosed_date", "source_type", "source_url")
# Sources where "" org_name is normal (the LLM names the victim later).
UNNAMED_OK = {"rss", "mastodon"}


def check_health(since_days: int) -> dict:
    prev = json.loads(HEALTH_PATH.read_text()) if HEALTH_PATH.exists() else {}
    prev_counts = (prev.get("health") or {}).get("counts", {})
    until, since = date.today(), date.today() - timedelta(days=since_days)
    counts, problems = {}, []
    skipped = disabled_sources()
    for name, fn in ALL_SOURCES.items():
        if name in skipped:
            counts[name] = None
            continue
        try:
            cands = fn(since, until)
        except Exception as e:  # noqa: BLE001
            cands, problems = [], problems + [f"{name}: crashed: {e}"]
        counts[name] = len(cands)
        bad = [c for c in cands if any(not c.get(k) for k in REQUIRED if not (k == "org_name" and name in UNNAMED_OK))]
        if bad:
            problems.append(f"{name}: {len(bad)}/{len(cands)} candidates missing required fields")
        if cands and name not in UNNAMED_OK and sum(1 for c in cands if c.get("org_name")) / len(cands) < 0.8:
            problems.append(f"{name}: org_name empty on >20% of rows (selector drift?)")
        if len(cands) == 0 and prev_counts.get(name, 1) == 0:
            problems.append(f"{name}: zero candidates two runs in a row")
    return {"counts": counts, "previous_counts": prev_counts, "problems": problems,
            "skipped": sorted(skipped)}


def check_links(sample: int) -> dict:
    rows = read_jsonl(INCIDENTS_PATH)
    urls = sorted({s["url"] for r in rows for s in r.get("sources", []) if s["url"].startswith("http")})
    random.seed(date.today().toordinal())
    picked = random.sample(urls, min(sample, len(urls)))
    dead = []
    for u in picked:
        r = _get(u)
        if r is None or r.status_code >= 400:
            dead.append(u)
    return {"checked": len(picked), "dead": dead, "dead_rate": round(len(dead) / len(picked), 3) if picked else 0}


def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def letter_text(url: str) -> str | None:
    from letters import pdf_text
    from sources import BROWSER_UA
    r = _get(url, headers={"User-Agent": BROWSER_UA}, timeout=60)
    return pdf_text(r.content) if r else None


def check_quotes(sample: int) -> dict:
    from fetch_text import fetch_text

    rows = [r for r in read_jsonl(INCIDENTS_PATH) if r.get("supporting_quote") and not r.get("imported_from")]
    random.seed(date.today().toordinal() + 1)
    picked = random.sample(rows, min(sample, len(rows)))
    results = {"checked": 0, "confirmed": 0, "missing": [], "unfetchable": 0}
    for r in picked:
        letter = r.get("letter") or {}
        url = letter["url"] if letter.get("outcome") == "extracted" and letter.get("url") else r["sources"][0]["url"]
        text = letter_text(url) if url.lower().endswith(".pdf") else fetch_text(url)
        if not text:
            results["unfetchable"] += 1
            continue
        results["checked"] += 1
        if _ws(r["supporting_quote"]) in _ws(text):
            results["confirmed"] += 1
        else:
            results["missing"].append({"id": r["id"], "org": r["org_name"], "url": url})
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checks", default="health,links,quotes")
    ap.add_argument("--since-days", type=int, default=30)
    ap.add_argument("--sample", type=int, default=20)
    ap.add_argument("--strict", action="store_true", help="exit 1 on health problems (use in CI)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    checks = set(args.checks.split(","))

    report = {"run_at": now_iso()}
    if "health" in checks:
        report["health"] = check_health(args.since_days)
    if "links" in checks:
        report["links"] = check_links(args.sample)
    if "quotes" in checks:
        report["quotes"] = check_quotes(args.sample)

    DATA_DIR.mkdir(exist_ok=True)
    HEALTH_PATH.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    problems = (report.get("health") or {}).get("problems", [])
    if problems:
        log.warning("health problems: %s", problems)
        return 1 if args.strict else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
