"""Score candidate models against silver labels.

Silver = fields where every reference model agrees. Where references disagree, the
doc/field goes to eval/adjudicate.jsonl for a human; answers go in eval/gold.jsonl and
override silver on the next run. So the human only ever reads the hard cases.

    python eval/compare.py                       # uses everything in eval/labels/
    python eval/compare.py --fields initial_access,skip

Reads:  eval/labels/reference__*.jsonl, eval/labels/candidate__*.jsonl, eval/gold.jsonl (optional)
Writes: eval/results.md, eval/adjudicate.jsonl

What the columns mean (all per model, on docs with a silver/gold label for that field):
  acc           exact match with silver
  prec_known    of the docs where the model said initial_access != unknown, how often
                silver agrees. This is the number that matters: wrong-and-confident.
  unknown_rate  how often the model said unknown (silver unknown_rate shown for reference)
  skip_f1       agreement on "this doc is not an incident"
  quote_ok      share of non-unknown extractions whose supporting_quote was verbatim
  repair/invalid share of docs needing a schema repair / still invalid after repair
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
from common import read_jsonl, write_jsonl  # noqa: E402

LABELS_DIR = ROOT / "eval" / "labels"
GOLD_PATH = ROOT / "eval" / "gold.jsonl"
DOCS_PATH = ROOT / "eval" / "docs.jsonl"
ENUM_FIELDS = ["initial_access", "org_type", "evidence_level", "impact_type", "veris_action"]
ALL_FIELDS = ["skip"] + ENUM_FIELDS + ["records_affected", "threat_actor", "root_cause_present", "technology_involved"]


def field_value(row: dict, field: str):
    """Normalize a label row to a comparable value, or None if not applicable."""
    if field == "skip":
        return bool(row.get("skipped"))
    rec = row.get("record")
    if not rec:
        return None
    if field == "root_cause_present":
        return bool(rec.get("root_cause"))
    if field == "threat_actor":
        return (rec.get("threat_actor") or "").strip().lower() or None
    if field == "technology_involved":
        return frozenset(t.strip().lower() for t in rec.get("technology_involved") or [])
    return rec.get(field)


def load_labels(prefix: str) -> dict[str, dict[str, dict]]:
    out = {}
    for p in sorted(LABELS_DIR.glob(f"{prefix}__*.jsonl")):
        name = p.stem.split("__", 1)[1]
        out[name] = {r["doc_id"]: r for r in read_jsonl(p)}
    return out


def build_silver(refs: dict[str, dict[str, dict]], gold: dict[str, dict], fields: list[str]):
    """Return silver[doc_id][field] and a list of disagreements needing adjudication."""
    silver: dict[str, dict] = defaultdict(dict)
    disagreements = []
    doc_ids = set().union(*[set(r) for r in refs.values()]) if refs else set()
    for doc_id in doc_ids:
        for f in fields:
            if doc_id in gold and f in gold[doc_id]:
                silver[doc_id][f] = gold[doc_id][f]
                continue
            vals = {name: field_value(rows[doc_id], f) for name, rows in refs.items() if doc_id in rows}
            if not vals:
                continue
            distinct = {json.dumps(sorted(v) if isinstance(v, frozenset) else v) for v in vals.values()}
            if len(distinct) == 1:
                silver[doc_id][f] = next(iter(vals.values()))
            else:
                disagreements.append({"doc_id": doc_id, "field": f,
                                      "values": {k: (sorted(v) if isinstance(v, frozenset) else v) for k, v in vals.items()}})
    return silver, disagreements


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def score(cand: dict[str, dict], silver: dict[str, dict], fields: list[str]) -> dict:
    out = {}
    for f in fields:
        hits, n, j = 0, 0, 0.0
        for doc_id, truth in silver.items():
            if f not in truth or doc_id not in cand:
                continue
            v = field_value(cand[doc_id], f)
            n += 1
            if f == "technology_involved":
                j += jaccard(v or frozenset(), truth[f] or frozenset())
            elif v == truth[f]:
                hits += 1
        out[f] = round((j if f == "technology_involved" else hits) / n, 3) if n else None
        out[f + "_n"] = n
    # initial_access precision on confident answers, and unknown rate
    known, known_hit, unk, tot = 0, 0, 0, 0
    for doc_id, row in cand.items():
        v = field_value(row, "initial_access")
        if v is None:
            continue
        tot += 1
        if v == "unknown":
            unk += 1
        elif doc_id in silver and "initial_access" in silver[doc_id]:
            known += 1
            known_hit += silver[doc_id]["initial_access"] == v
    out["prec_known"] = round(known_hit / known, 3) if known else None
    out["unknown_rate"] = round(unk / tot, 3) if tot else None
    # skip F1
    tp = fp = fn = 0
    for doc_id, truth in silver.items():
        if "skip" not in truth or doc_id not in cand:
            continue
        p, t = bool(cand[doc_id].get("skipped")), truth["skip"]
        tp += p and t; fp += p and not t; fn += (not p) and t
    out["skip_f1"] = round(2 * tp / (2 * tp + fp + fn), 3) if (tp + fp + fn) else None
    # quote validity, repair, invalid
    nonunk = [r for r in cand.values() if r.get("record") and r["record"].get("initial_access") != "unknown"]
    out["quote_ok"] = round(sum(1 for r in nonunk if "not found" not in (r["record"].get("notes") or "")) / len(nonunk), 3) if nonunk else None
    out["repair"] = round(sum(1 for r in cand.values() if r.get("repaired")) / len(cand), 3) if cand else None
    out["invalid"] = round(sum(1 for r in cand.values() if r.get("invalid") or r.get("error")) / len(cand), 3) if cand else None
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fields", default=",".join(ALL_FIELDS))
    args = ap.parse_args()
    fields = args.fields.split(",")

    refs = load_labels("reference")
    cands = load_labels("candidate")
    gold = {g["doc_id"]: g for g in read_jsonl(GOLD_PATH)} if GOLD_PATH.exists() else {}
    if not refs:
        print("no reference labels in eval/labels/ (run label.py --role reference first)")
        return 1
    silver, disagreements = build_silver(refs, gold, fields)

    docs = {d["doc_id"]: d for d in read_jsonl(DOCS_PATH)} if DOCS_PATH.exists() else {}
    for d in disagreements:
        doc = docs.get(d["doc_id"], {})
        d["source_url"] = doc.get("candidate", {}).get("source_url")
        d["snippet"] = (doc.get("text") or "")[:600]
        d["gold"] = None  # human fills this in, then copies {doc_id, field: value} into gold.jsonl
    write_jsonl(ROOT / "eval" / "adjudicate.jsonl", disagreements)

    silver_unknown = Counter(t.get("initial_access") for t in silver.values() if "initial_access" in t)
    n_ia = sum(silver_unknown.values())
    lines = [f"# Eval results", "",
             f"Reference models: {', '.join(refs)}  ",
             f"Docs with any silver label: {len(silver)}; fields needing adjudication: {len(disagreements)} "
             f"(see eval/adjudicate.jsonl); human gold entries: {len(gold)}  ",
             f"Silver initial_access unknown rate: {round(silver_unknown.get('unknown', 0) / n_ia, 3) if n_ia else 'n/a'}", ""]
    cols = ["model"] + fields + ["prec_known", "unknown_rate", "skip_f1", "quote_ok", "repair", "invalid"]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * len(cols))
    # Reference models are scored too, against the silver they helped make (so inflated), as a sanity row.
    for name, rows in list(cands.items()) + [(f"(ref) {k}", v) for k, v in refs.items()]:
        s = score(rows, silver, fields)
        lines.append("| " + " | ".join([name] + [str(s.get(c, "")) for c in cols[1:]]) + " |")
    lines += ["", "Usage per model (from .meta.json):", ""]
    for p in sorted(LABELS_DIR.glob("*.meta.json")):
        m = json.loads(p.read_text())
        lines.append(f"- {m['role']} {m['provider']}:{m['model']} — {m['usage']}")
    text = "\n".join(lines)
    (ROOT / "eval" / "results.md").write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
