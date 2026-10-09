"""Import UMD's Cyber Events Database 2.0 (cybereventsdatabase.org, CSV/JSON download).

The column names below are a template: run `--inspect` on the file you downloaded,
then fix COLUMN_MAP before importing. The mapping is deliberately conservative; CEDB
codes *effect* (exploitive / disruptive / mixed), *actor type* and *industry*, not
initial access, so nearly every imported record has initial_access = unknown. That is
still useful: it gives org type, date, actor and impact for ~1,200 events/year.

    python pipeline/import_cedb.py --inspect cedb.csv
    python pipeline/import_cedb.py --file cedb.csv --since 2024-01-01 --dry-run
"""
from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import INCIDENTS_PATH, make_id, read_jsonl, today, validate, write_jsonl  # noqa: E402

log = logging.getLogger("import_cedb")
MAPPING_VERSION = "0-template"

# Left: our concept. Right: the CEDB column header, to be confirmed with --inspect.
COLUMN_MAP = {
    "id": "event_id",
    "date": "event_date",
    "org": "organization",
    "industry": "industry",
    "country": "country",
    "actor": "actor",
    "actor_type": "actor_type",
    "event_type": "event_type",        # exploitive / disruptive / mixed
    "event_subtype": "event_subtype",
    "description": "description",
    "source_url": "source_url",
}
INDUSTRY_MAP = {  # CEDB industry labels -> our org_type; extend after --inspect
    "health care": "healthcare", "healthcare": "healthcare", "finance": "financial",
    "financial": "financial", "government": "government", "public administration": "government",
    "education": "education", "information": "technology_saas", "technology": "technology_saas",
    "manufacturing": "manufacturing", "retail": "retail_ecommerce", "utilities": "energy_utilities",
    "energy": "energy_utilities", "transportation": "transportation_logistics",
    "professional": "professional_services", "nonprofit": "nonprofit",
}
EVENT_TYPE_MAP = {"exploitive": "data_theft", "disruptive": "disruption_or_ransomware", "mixed": "both"}


def org_type(label: str) -> str:
    l = (label or "").lower()
    for k, v in INDUSTRY_MAP.items():
        if k in l:
            return v
    return "unknown" if not l else "other"


def map_row(row: dict, run_date: str) -> dict | None:
    g = lambda k: (row.get(COLUMN_MAP[k]) or "").strip()  # noqa: E731
    name, d = g("org"), g("date")[:10]
    if not name or len(d) != 10:
        return None
    url = g("source_url") or "https://cybereventsdatabase.org/"
    country = g("country")[:2].upper()
    out = {
        "id": make_id(name, d),
        "schema_version": "1.0",
        "org_name": name[:200],
        "org_type": org_type(g("industry")),
        "org_country": country if len(country) == 2 and country.isalpha() else "unknown",
        "disclosed_date": d,
        "incident_date": d,
        "initial_access": "unknown",
        "initial_access_attack_id": None,
        "veris_action": "unknown",
        "root_cause": None,
        "technology_involved": [],
        "impact_type": EVENT_TYPE_MAP.get(g("event_type").lower(), "unknown"),
        "records_affected": None,
        "threat_actor": (g("actor")[:80] or None) if g("actor").lower() not in ("", "unknown") else None,
        "evidence_level": "press_report",
        "confidence": "medium",
        "supporting_quote": None,
        "summary": g("description")[:280] or None,
        "sources": [{"url": url, "type": "press", "title": None, "fetched_at": None}],
        "extracted_by": {"model": "import:cedb", "prompt_version": "import-v1", "run_date": run_date},
        "reviewed": False,
        "notes": f"imported from CEDB 2.0 (actor_type={g('actor_type')}, subtype={g('event_subtype')}); not re-extracted",
        "imported_from": {"dataset": "cedb", "record_id": g("id") or name, "license": None,
                          "mapping_version": MAPPING_VERSION},
    }
    return None if validate(out) else out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inspect", metavar="CSV", help="print headers and two rows, then exit")
    ap.add_argument("--file")
    ap.add_argument("--since", default="2024-01-01")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.inspect:
        with open(args.inspect, newline="", encoding="utf-8-sig") as f:
            r = csv.DictReader(f)
            print("headers:", r.fieldnames)
            for i, row in enumerate(r):
                print(row)
                if i >= 1:
                    break
        return 0
    if not args.file:
        ap.error("--file is required (or --inspect)")

    from run import merge_into_store

    run_date = today()
    with open(args.file, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    missing = [v for v in COLUMN_MAP.values() if rows and v not in rows[0]]
    if missing:
        log.error("COLUMN_MAP does not match the file; missing columns: %s. Run --inspect.", missing)
        return 2
    mapped = [m for m in (map_row(r, run_date) for r in rows) if m and m["disclosed_date"] >= args.since]
    log.info("mapped %d of %d rows", len(mapped), len(rows))
    if args.dry_run:
        return 0
    store = read_jsonl(INCIDENTS_PATH)
    for m in mapped:
        merge_into_store(store, m)
    write_jsonl(INCIDENTS_PATH, store)
    log.info("store now %d", len(store))
    return 0


if __name__ == "__main__":
    sys.exit(main())
