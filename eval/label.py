"""Run one model over eval/docs.jsonl and save its labels + usage.

    python eval/label.py --provider anthropic --model claude-haiku-5-5
    python eval/label.py --provider openai --model gpt-6-luna
    python eval/label.py --provider anthropic --model claude-opus-5-5 --role reference
    python eval/label.py --provider openai --model gpt-6-astra --role reference

Output: eval/labels/<provider>__<model>.jsonl, one line per doc:
  {doc_id, skipped, repaired, invalid, record (or null), raw}
Reference runs are the same thing with a different filename prefix so compare.py
knows which ones to build silver labels from.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
from common import read_jsonl, today  # noqa: E402

LABELS_DIR = ROOT / "eval" / "labels"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--role", choices=["candidate", "reference"], default="candidate")
    ap.add_argument("--docs", default=str(ROOT / "eval" / "docs.jsonl"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=0.5)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    import extract

    docs = read_jsonl(Path(args.docs))
    if args.limit:
        docs = docs[: args.limit]
    LABELS_DIR.mkdir(parents=True, exist_ok=True)
    safe_model = args.model.replace("/", "_")
    out_path = LABELS_DIR / f"{args.role}__{args.provider}__{safe_model}.jsonl"
    done = {json.loads(l)["doc_id"] for l in out_path.read_text().splitlines()} if out_path.exists() else set()

    start_usage = dict(extract.usage_totals)
    with out_path.open("a") as f:
        for d in docs:
            if d["doc_id"] in done:
                continue
            c = dict(d["candidate"])
            c.setdefault("all_sources", [{"url": c["source_url"], "type": c["source_type"], "title": c.get("title")}])
            stats: dict = {}
            t0 = time.time()
            try:
                rec = extract.extract_one(c, d["text"], today(), args.provider, args.model, stats)
            except Exception as e:  # noqa: BLE001
                logging.exception("failed on %s: %s", d["doc_id"], e)
                rec, stats["error"] = None, str(e)
            row = {"doc_id": d["doc_id"], "skipped": bool(stats.get("skipped")),
                   "repaired": bool(stats.get("repaired")), "invalid": bool(stats.get("invalid")),
                   "error": stats.get("error"), "seconds": round(time.time() - t0, 2),
                   "record": rec, "raw": stats.get("raw")}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            f.flush()
            time.sleep(args.sleep)

    used = {k: extract.usage_totals[k] - start_usage[k] for k in ("input", "output", "calls")}
    meta_path = out_path.with_suffix(".meta.json")
    meta_path.write_text(json.dumps({"provider": args.provider, "model": args.model, "role": args.role,
                                     "docs": len(docs), "usage": used, "date": today()}, indent=2))
    print(f"labels -> {out_path}\nusage: {used}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
