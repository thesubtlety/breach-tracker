"""Render data/incidents.jsonl into site/: a single static page plus JSON and CSV
downloads. No build tool, no framework; the page filters client-side.

    python pipeline/build_site.py
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_DIR, INCIDENTS_PATH, SITE_DIR, read_jsonl, today  # noqa: E402

HEALTH_PATH = DATA_DIR / "source_health.json"

# Shown as hover text and in the page glossary. Keep in step with prompts/extract.md.
GLOSSARY = {
    "initial_access": {
        "phishing": "Email or SMS lure leading to credential theft or malware.",
        "vishing_or_social_engineering": "Phone or help-desk impersonation, MFA fatigue, pretexting.",
        "stolen_or_valid_credentials": "Reused, leaked, infostealer-sourced or brute-forced credentials; valid account abuse with no stated phishing step.",
        "exploit_public_facing_app": "A CVE or unpatched internet-facing system: VPN, firewall, file transfer, web app.",
        "supply_chain_or_third_party": "Came in through a vendor, integration, token, package or managed service provider.",
        "misconfiguration_or_exposure": "Open bucket or database, public repo, wrong permissions, no authentication.",
        "insider": "Employee or contractor acting intentionally.",
        "lost_or_stolen_device": "Laptop, drive or phone.",
        "physical_or_paper": "Break-in, misdirected mail, improper disposal.",
        "malware_other": "Malware present but the entry vector was not stated.",
        "unknown": "The source did not say how. This is the expected value for most regulator filings and is never guessed.",
    },
    "evidence_level": {
        "org_confirmed": "The organization said so: an 8-K, a notice, or a statement quoted in full.",
        "regulator_filing": "A breach report to HHS or a state attorney general. Reliable on who and how many; silent on how.",
        "press_report": "A news article. The only place root cause and technology usually appear, and the least verified.",
        "actor_claimed": "A ransomware group's leak-site post. A claim, not a confirmation.",
    },
    "origin": {
        "regulator": "Built from the filing's checkboxes by a fixed mapping. No model involved.",
        "extracted": "A language model read the source and filled the fields; a verbatim quote is required for any stated mechanism.",
        "imported": "Mapped from an existing coded dataset (VCDB). Not re-read. The date is the incident date, not a disclosure date.",
    },
    "confidence": {
        "high": "Mechanism and cause are directly supported by the quoted text.",
        "medium": "Supported, with some interpretation.",
        "low": "A check failed: the quote was not found verbatim, or the value was reset.",
    },
}

CSV_COLS = ["disclosed_date", "org_name", "org_type", "org_country", "initial_access",
            "veris_action", "root_cause", "technology_involved", "impact_type", "records_affected",
            "threat_actor", "evidence_level", "confidence", "reviewed", "summary", "source_url"]

TEMPLATE = (Path(__file__).parent.parent / "site" / "template.html")


def claim_only(r: dict) -> bool:
    """Only a leak-site post says this happened. Kept in the store so a later filing or
    article can confirm it, never published on its own: that would be re-serving
    Ransomware.live's victim list, which their terms forbid."""
    return all(s["type"] == "ransomware_leak_site" for s in r.get("sources", []))


def main() -> int:
    all_rows = read_jsonl(INCIDENTS_PATH)
    rows = [r for r in all_rows if not claim_only(r)]
    withheld = len(all_rows) - len(rows)
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

    week_ago = (date.today() - timedelta(days=7)).isoformat()
    health = json.loads(HEALTH_PATH.read_text()) if HEALTH_PATH.exists() else {}
    stats = {
        "total": len(rows),
        "withheld_claims": withheld,
        "generated": today(),
        "added_last_7_days": sum(1 for r in rows if r["extracted_by"]["run_date"] >= week_ago),
        "reviewed": sum(1 for r in rows if r.get("reviewed")),
        "known_initial_access": sum(1 for r in rows if r["initial_access"] != "unknown"),
        "date_range": [min(r["disclosed_date"] for r in rows), max(r["disclosed_date"] for r in rows)] if rows else None,
        "by_initial_access": Counter(r["initial_access"] for r in rows).most_common(),
        "by_org_type": Counter(r["org_type"] for r in rows).most_common(),
        "by_evidence": Counter(r["evidence_level"] for r in rows).most_common(),
        "health": {"run_at": health.get("run_at"), "counts": (health.get("health") or {}).get("counts", {}),
                   "problems": (health.get("health") or {}).get("problems", []),
                   "skipped": (health.get("health") or {}).get("skipped", [])},
        "glossary": GLOSSARY,
    }
    html = TEMPLATE.read_text().replace("/*__STATS__*/{}", json.dumps(stats, ensure_ascii=False))
    (SITE_DIR / "index.html").write_text(html)
    print(f"site: {len(rows)} incidents ({withheld} claim-only withheld) -> {SITE_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
