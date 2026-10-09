"""Human review loop. Walks unreviewed records, shows what the model saw, and writes
your verdict back to data/incidents.jsonl.

    python pipeline/review.py                      # non-unknown extractions first (the risky ones)
    python pipeline/review.py --all                # everything unreviewed, newest first
    python pipeline/review.py --org acme           # one organization
    python pipeline/review.py --merge ID1 ID2      # fold record ID2 into ID1 (duplicate)

At each record: Enter = confirm as shown; a value name sets initial_access; "u" sets
unknown; "n <text>" adds a note; "d" deletes the record; "s" skips; "q" quits (saved).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import INCIDENTS_PATH, load_schema, read_jsonl, today, write_jsonl  # noqa: E402

IA = load_schema()["properties"]["initial_access"]["enum"]


def show(r: dict) -> None:
    print("\n" + "=" * 88)
    print(f"{r['org_name']}  ({r['org_type']}, {r.get('org_country')})   disclosed {r['disclosed_date']}"
          f"   incident {r.get('incident_date') or '-'}   id {r['id'][:12]}")
    print(f"initial_access: {r['initial_access']}   veris: {r.get('veris_action')}   impact: {r['impact_type']}"
          f"   evidence: {r['evidence_level']}   confidence: {r['confidence']}")
    if r.get("root_cause"):
        print(f"root_cause:     {r['root_cause']}")
    if r.get("technology_involved"):
        print(f"technology:     {', '.join(r['technology_involved'])}")
    if r.get("threat_actor") or r.get("records_affected") is not None:
        print(f"actor: {r.get('threat_actor') or '-'}   records: {r.get('records_affected')}")
    if r.get("summary"):
        print(f"summary:        {r['summary']}")
    if r.get("supporting_quote"):
        print(f'quote:          "{r["supporting_quote"]}"')
    if r.get("notes"):
        print(f"notes:          {r['notes']}")
    print(f"by:             {r['extracted_by']['model']} {r['extracted_by']['prompt_version']} {r['extracted_by']['run_date']}")
    for s in r["sources"]:
        print(f"source:         [{s['type']}] {s['url']}")


def merge(store: list[dict], keep_id: str, drop_id: str) -> None:
    keep = next(r for r in store if r["id"].startswith(keep_id))
    drop = next(r for r in store if r["id"].startswith(drop_id))
    urls = {s["url"] for s in keep["sources"]}
    keep["sources"] += [s for s in drop["sources"] if s["url"] not in urls]
    keep["disclosed_date"] = min(keep["disclosed_date"], drop["disclosed_date"])
    keep["notes"] = "; ".join(filter(None, [keep.get("notes"), f"merged duplicate {drop['id'][:12]} on {today()}"]))
    store.remove(drop)
    print(f"merged {drop['org_name']} into {keep['org_name']}; {len(keep['sources'])} sources")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--org")
    ap.add_argument("--merge", nargs=2, metavar=("KEEP_ID", "DROP_ID"))
    args = ap.parse_args()
    store = read_jsonl(INCIDENTS_PATH)
    if args.merge:
        merge(store, *args.merge)
        write_jsonl(INCIDENTS_PATH, store)
        return 0

    todo = [r for r in store if not r.get("reviewed") and not r.get("imported_from")]
    if args.org:
        todo = [r for r in todo if args.org.lower() in r["org_name"].lower()]
    elif not args.all:
        todo = [r for r in todo if r["initial_access"] != "unknown" or r["extracted_by"]["model"] != "deterministic"]
    todo.sort(key=lambda r: (r["initial_access"] == "unknown", r["disclosed_date"]), reverse=False)
    todo.sort(key=lambda r: r["disclosed_date"], reverse=True)
    print(f"{len(todo)} records to review ({sum(1 for r in todo if r['initial_access'] != 'unknown')} with a stated mechanism)")

    for i, r in enumerate(todo, 1):
        show(r)
        while True:
            try:
                cmd = input(f"[{i}/{len(todo)}] Enter=confirm  <initial_access>|u  n <note>  d  s  q > ").strip()
            except (EOFError, KeyboardInterrupt):
                cmd = "q"
            if cmd == "q":
                write_jsonl(INCIDENTS_PATH, store)
                print("saved")
                return 0
            if cmd == "s":
                break
            if cmd == "d":
                store.remove(r)
                print("deleted")
                break
            if cmd.startswith("n "):
                r["notes"] = "; ".join(filter(None, [r.get("notes"), cmd[2:].strip()]))
                continue
            if cmd == "u":
                cmd = "unknown"
            if cmd in IA:
                if cmd != r["initial_access"]:
                    r["notes"] = "; ".join(filter(None, [r.get("notes"), f"initial_access {r['initial_access']} -> {cmd} by reviewer {today()}"]))
                    r["initial_access"] = cmd
                    if cmd == "unknown":
                        r["initial_access_attack_id"] = None
                cmd = ""
            if cmd == "":
                r["reviewed"] = True
                r["confidence"] = "high"
                break
            print("  options:", ", ".join(IA))
        write_jsonl(INCIDENTS_PATH, store)
    print("done; all saved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
