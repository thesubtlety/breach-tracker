"""Build the eval document set: a stratified sample of candidates with their fetched
text, frozen to eval/docs.jsonl so every model sees identical input.

    python eval/sample_docs.py --n 150                      # from data/candidates.jsonl
    python eval/sample_docs.py --n 150 --from-store         # from data/incidents.jsonl sources

Strata are by source_type. Default mix leans toward the sources that go through the
LLM in production (8-K, press); regulator rows are included so the harness also
checks that models don't invent mechanism from a checkbox.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
from common import CANDIDATES_PATH, INCIDENTS_PATH, read_jsonl, write_jsonl  # noqa: E402
from fetch_text import fetch_text  # noqa: E402

DOCS_PATH = ROOT / "eval" / "docs.jsonl"
MIX = {"sec_8k": 0.35, "press": 0.40, "mastodon": 0.05, "state_ag": 0.10, "ransomware_leak_site": 0.10}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--from-store", action="store_true")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    random.seed(args.seed)

    if args.from_store:
        pool = []
        for r in read_jsonl(INCIDENTS_PATH):
            s = r["sources"][0]
            pool.append({"org_name": r["org_name"], "disclosed_date": r["disclosed_date"],
                         "source_type": s["type"], "source_url": s["url"], "title": s.get("title"),
                         "structured_hint": {}, "evidence_level_hint": r["evidence_level"],
                         "org_country": r.get("org_country", "unknown"), "text": None})
    else:
        pool = read_jsonl(CANDIDATES_PATH)

    by_type = defaultdict(list)
    for c in pool:
        by_type[c["source_type"]].append(c)
    docs = []
    for t, share in MIX.items():
        want = round(args.n * share)
        picked = random.sample(by_type[t], min(want, len(by_type[t])))
        for c in picked:
            text = c.get("text") or fetch_text(c["source_url"])
            if not text or len(text) < 200:
                continue
            doc_id = hashlib.sha1(c["source_url"].encode()).hexdigest()[:12]
            docs.append({"doc_id": doc_id, "candidate": c, "text": text})
        print(f"{t}: wanted {want}, have {len(by_type[t])}, kept {sum(1 for d in docs if d['candidate']['source_type'] == t)}")
    write_jsonl(DOCS_PATH, docs)
    print(f"{len(docs)} docs -> {DOCS_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
