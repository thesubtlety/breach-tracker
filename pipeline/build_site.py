"""Render data/incidents.jsonl into site/: a single static page plus JSON and CSV
downloads. No build tool, no framework; the page filters client-side.

    python pipeline/build_site.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import INCIDENTS_PATH, SITE_DIR, read_jsonl, today  # noqa: E402

CSV_COLS = ["disclosed_date", "org_name", "org_type", "org_country", "initial_access",
            "veris_action", "root_cause", "technology_involved", "impact_type", "records_affected",
            "threat_actor", "evidence_level", "confidence", "reviewed", "summary", "source_url"]

TEMPLATE = (Path(__file__).parent.parent / "site" / "template.html")


def main() -> int:
    rows = read_jsonl(INCIDENTS_PATH)
    SITE_DIR.mkdir(exist_ok=True)

    (SITE_DIR / "incidents.json").write_text(json.dumps(rows, ensure_ascii=False))
    with (SITE_DIR / "incidents.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            flat = dict(r)
            flat["technology_involved"] = "; ".join(r.get("technology_involved") or [])
            flat["source_url"] = r["sources"][0]["url"] if r.get("sources") else ""
            w.writerow(flat)

    stats = {
        "total": len(rows),
        "generated": today(),
        "known_initial_access": sum(1 for r in rows if r["initial_access"] != "unknown"),
        "by_initial_access": Counter(r["initial_access"] for r in rows).most_common(),
        "by_org_type": Counter(r["org_type"] for r in rows).most_common(),
        "by_evidence": Counter(r["evidence_level"] for r in rows).most_common(),
    }
    html = TEMPLATE.read_text().replace("/*__STATS__*/", json.dumps(stats))
    (SITE_DIR / "index.html").write_text(html)
    print(f"site: {len(rows)} incidents -> {SITE_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
