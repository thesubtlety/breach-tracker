"""Re-run extraction for records already in the store, after a guard or prompt fix.
Records are rebuilt from their own first non-leak-site source; the merge keeps the richer
result, so a worse re-read never replaces a better record.

    python pipeline/reextract.py --note "records_affected not found"   # notes match
    python pipeline/reextract.py --id <id> --id <id>
    python pipeline/reextract.py --model openai:gpt-6-luna --note ...  # all extracted by that model
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import INCIDENTS_PATH, read_jsonl, today, write_jsonl  # noqa: E402
from fetch_text import fetch_text  # noqa: E402

log = logging.getLogger("reextract")


def candidate_from(rec: dict) -> dict | None:
    srcs = [s for s in rec["sources"] if s["type"] != "ransomware_leak_site"]
    if not srcs:
        return None
    s = srcs[0]
    return {"org_name": rec["org_name"], "disclosed_date": rec["disclosed_date"], "source_type": s["type"],
            "evidence_level_hint": rec["evidence_level"], "source_url": s["url"], "title": s.get("title"),
            "structured_hint": {}, "org_country": rec["org_country"],
            "all_sources": [{"url": x["url"], "type": x["type"], "title": x.get("title")} for x in rec["sources"]]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", action="append", default=[])
    ap.add_argument("--note", help="substring of notes")
    ap.add_argument("--model", help="extracted_by.model to select")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    store = read_jsonl(INCIDENTS_PATH)
    todo = [r for r in store if not r.get("imported_from") and r["extracted_by"]["model"] != "deterministic"
            and (not args.id or r["id"] in args.id)
            and (not args.note or args.note in (r.get("notes") or ""))
            and (not args.model or r["extracted_by"]["model"] == args.model)][:args.limit]
    log.info("%d records selected", len(todo))
    if args.dry_run or not todo:
        for r in todo:
            print(r["disclosed_date"], r["org_name"], r["sources"][0]["url"])
        return 0

    from extract import extract_one, usage_totals
    from run import merge_into_store

    run_date, n_ok = today(), 0
    for r in todo:
        c = candidate_from(r)
        text = fetch_text(c["source_url"]) if c else None
        if not text:
            log.warning("no text for %s (%s)", r["org_name"], c and c["source_url"])
            continue
        new = extract_one(c, text, run_date)
        if not new:
            log.warning("re-extraction skipped %s", r["org_name"])
            continue
        before = r.get("records_affected")
        merge_into_store(store, new)
        after = next(x for x in store if x["id"] == r["id"])
        n_ok += 1
        log.info("%s: records_affected %s -> %s, initial_access %s", r["org_name"], before, after.get("records_affected"), after["initial_access"])
    write_jsonl(INCIDENTS_PATH, store)
    log.info("re-extracted %d of %d; usage %s", n_ok, len(todo), usage_totals)
    return 0


if __name__ == "__main__":
    sys.exit(main())
