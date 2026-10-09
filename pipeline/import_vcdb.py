"""Import the VERIS Community Database into our schema.

VCDB: https://github.com/vz-risk/VCDB  (CC BY-SA 4.0; ~10k incidents, still receiving
2025/2026 entries as of the July 2026 file). We map VERIS coding to our enums
conservatively: where VERIS says "Unknown" we say "unknown". Nothing is re-extracted.

    python pipeline/import_vcdb.py --since-year 2022            # downloads, maps, merges
    python pipeline/import_vcdb.py --file vcdb_1-of-1.json --since-year 2022

Share-alike: a public dataset that includes these records must be published under a
compatible license. See docs/RISKS.md Y8.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from actors import default_third_party, enrich_actor  # noqa: E402
from common import INCIDENTS_PATH, make_id, read_jsonl, today, validate, write_jsonl  # noqa: E402

log = logging.getLogger("import_vcdb")
VCDB_ZIP = "https://raw.githubusercontent.com/vz-risk/VCDB/master/data/joined/vcdb.json.zip"
MAPPING_VERSION = "2"

NAICS2 = {
    "62": "healthcare", "52": "financial", "92": "government", "61": "education",
    "51": "technology_saas", "54": "professional_services", "55": "professional_services",
    "44": "retail_ecommerce", "45": "retail_ecommerce", "31": "manufacturing", "32": "manufacturing",
    "33": "manufacturing", "22": "energy_utilities", "48": "transportation_logistics",
    "49": "transportation_logistics",
}
VCDB_CONF = {"High": "high", "Medium": "medium", "Low": "low"}
EXT_VARIETY = {"Organized crime": "organized_crime", "State-affiliated": "state_affiliated", "Nation-state": "state_affiliated",
               "Activist": "activist", "Former employee": "former_employee", "Unaffiliated": "unaffiliated"}
INT_VARIETY = {"End-user": "end_user", "System admin": "system_admin"}
MOTIVE = {"Financial": "financial", "Espionage": "espionage", "Ideology": "ideology", "Grudge": "grudge"}
VECTOR = {"VPN": "vpn_or_edge_device", "Web application": "web_application", "Desktop sharing": "remote_desktop",
          "Desktop sharing software": "remote_desktop", "3rd party desktop": "remote_desktop", "Physical access": "physical"}
DATA = {"Personal": "personal", "Medical": "medical", "Payment": "financial", "Bank": "financial", "Credentials": "credentials",
        "Internal": "internal", "Secrets": "secrets"}


def actor_of(rec: dict) -> dict:
    a = rec.get("actor", {})
    out = {"category": "unknown", "variety": "unknown", "motive": "unknown", "name": None, "country": None}
    if "external" in a:
        e = a["external"]
        out["category"] = "external"
        out["variety"] = next((EXT_VARIETY[v] for v in e.get("variety", []) if v in EXT_VARIETY), "unknown")
        out["motive"] = next((MOTIVE[m] for m in e.get("motive", []) if m in MOTIVE), "unknown")
        names = [n for n in e.get("name", []) if n and n != "Unknown"]
        out["name"] = names[0][:80] if names else None
        c = [x for x in e.get("country", []) if re.fullmatch(r"[A-Z]{2}", x or "")]
        out["country"] = c[0] if c else None
    elif "internal" in a:
        i = a["internal"]
        out["category"] = "internal"
        out["variety"] = next((INT_VARIETY[v] for v in i.get("variety", []) if v in INT_VARIETY), "other" if i.get("variety") else "unknown")
        out["motive"] = next((MOTIVE[m] for m in i.get("motive", []) if m in MOTIVE), "unknown")
    elif "partner" in a:
        out["category"] = "partner"
        out["motive"] = next((MOTIVE[m] for m in a["partner"].get("motive", []) if m in MOTIVE), "unknown")
    return enrich_actor(out)


def third_party_of(rec: dict) -> dict:
    hvec = set(rec.get("action", {}).get("hacking", {}).get("vector", []))
    if "Partner" in hvec or "partner" in rec.get("actor", {}):
        return {"involved": True, "archetype": "vendor_connection", "vendor": None}
    return default_third_party()


def control_failure_of(action: dict) -> str:
    ev = set(action.get("error", {}).get("variety", []))
    hv = set(action.get("hacking", {}).get("variety", []))
    if ev & {"Misconfiguration", "Publishing error"} or "Exploit misconfig" in hv:
        return "exposed_service_or_storage"
    if "misuse" in action:
        return "insider_access_abuse"
    if "social" in action and not hv - {"Unknown", "Use of stolen creds"}:
        return "staff_deceived"
    return "unknown"


def org_type(naics: str | None) -> str:
    if not naics or naics in ("0", "00", "000000"):
        return "unknown"
    if naics.startswith("813"):
        return "nonprofit"
    return NAICS2.get(naics[:2], "other")


def initial_access(action: dict) -> tuple[str, str | None]:
    """Map VERIS action varieties/vectors to our initial_access + ATT&CK id. Order matters:
    the first matching rule wins, and the rules go from most specific to least."""
    hv = set(action.get("hacking", {}).get("variety", []))
    hvec = set(action.get("hacking", {}).get("vector", []))
    sv = set(action.get("social", {}).get("variety", []))
    ev = set(action.get("error", {}).get("variety", []))
    pv = set(action.get("physical", {}).get("variety", []))
    if "Phishing" in sv:
        return "phishing", "T1566"
    if sv & {"Pretexting", "Influence"}:
        return "vishing_or_social_engineering", "T1598"
    if "Partner" in hvec:
        return "supply_chain_or_third_party", "T1195"
    if hv & {"Use of stolen creds", "Brute force"}:
        return "stolen_or_valid_credentials", "T1078"
    if hv & {"Exploit vuln", "SQLi", "XSS", "Forced browsing"}:
        return "exploit_public_facing_app", "T1190"
    if ev & {"Misconfiguration", "Publishing error"}:
        return "misconfiguration_or_exposure", None
    if ev & {"Misdelivery", "Disposal error"}:
        return "physical_or_paper", None
    if "Loss" in ev or "Theft" in pv:
        return "lost_or_stolen_device", None
    if pv & {"Skimmer", "Tampering"}:
        return "physical_or_paper", None
    if "misuse" in action:
        return "insider", None
    if "malware" in action and not hv - {"Unknown"}:
        return "malware_other", None
    return "unknown", None


def veris_action(action: dict) -> str:
    for k in ("hacking", "malware", "social", "misuse", "error", "physical", "environmental"):
        if k in action:
            return k
    return "unknown"


def impact(rec: dict) -> str:
    attr = rec.get("attribute", {})
    conf = attr.get("confidentiality", {})
    ransomware = "Ransomware" in rec.get("action", {}).get("malware", {}).get("variety", [])
    theft = conf.get("data_disclosure") == "Yes"
    disrupt = "availability" in attr or ransomware
    if theft and disrupt:
        return "both"
    if theft:
        return "data_theft"
    if disrupt:
        return "disruption_or_ransomware"
    if conf:
        return "exposure_no_theft_confirmed"
    return "unknown"


def incident_date(rec: dict) -> str | None:
    t = rec.get("timeline", {}).get("incident", {})
    y, m, d = t.get("year"), t.get("month") or 1, t.get("day") or 1
    if not y:
        return None
    try:
        return f"{int(y):04d}-{int(m):02d}-{int(d):02d}"
    except (TypeError, ValueError):
        return None


def map_record(rec: dict, run_date: str) -> dict | None:
    name = (rec.get("victim", {}).get("victim_id") or "").strip()
    if not name or name.lower() == "unknown":
        return None
    date = incident_date(rec)
    if not date:
        return None
    action = rec.get("action", {})
    ia, attack_id = initial_access(action)
    refs = [u for u in re.split(r"\s+", rec.get("reference") or "") if u.startswith("http")]
    sources = [{"url": u, "type": "state_ag" if "maine.gov" in u or "oag.ca.gov" in u
                else "hhs_portal" if "hhs.gov" in u else "press", "title": None, "fetched_at": None}
               for u in refs[:5]]
    gh = rec.get("plus", {}).get("github")
    if not sources:
        sources = [{"url": f"https://github.com/vz-risk/VCDB/issues/{gh}" if gh else "https://github.com/vz-risk/VCDB",
                    "type": "other", "title": "VCDB record", "fetched_at": None}]
    evidence = "regulator_filing" if any(s["type"] in ("state_ag", "hhs_portal") for s in sources) else "press_report"
    data_total = rec.get("attribute", {}).get("confidentiality", {}).get("data_total")
    data_types = sorted({DATA[d["variety"]] for d in rec.get("attribute", {}).get("confidentiality", {}).get("data", []) if d.get("variety") in DATA})
    hvec = action.get("hacking", {}).get("vector", [])
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", (action.get("hacking", {}).get("cve") or "") + " " + (action.get("malware", {}).get("cve") or ""), re.I)))
    ransomware = "Ransomware" in action.get("malware", {}).get("variety", [])
    country = (rec.get("victim", {}).get("country") or ["unknown"])[0]
    out = {
        "id": make_id(name, date),
        "schema_version": "1.1",
        "org_name": name[:200],
        "org_type": org_type(rec.get("victim", {}).get("industry")),
        "org_country": country if re.fullmatch(r"[A-Z]{2}", country or "") else "unknown",
        "disclosed_date": date,
        "incident_date": date,
        "discovered_date": None,
        "initial_access": ia,
        "initial_access_attack_id": attack_id,
        "veris_action": veris_action(action),
        "entry_asset": next((VECTOR[v] for v in hvec if v in VECTOR), "unknown"),
        "control_failure": control_failure_of(action),
        "credential_source": "unknown" if ia == "stolen_or_valid_credentials" else None,
        "cve": [c.upper() for c in cves][:10],
        "root_cause": None,
        "technology_involved": [],
        "third_party": third_party_of(rec),
        "actor": actor_of(rec),
        "impact_type": impact(rec),
        "ransomware": True if ransomware else None,
        "data_types": data_types,
        "records_affected": int(data_total) if isinstance(data_total, (int, float)) and data_total >= 0 else None,
        "evidence_level": evidence,
        "confidence": VCDB_CONF.get(rec.get("confidence"), "medium"),
        "supporting_quote": None,
        "summary": (rec.get("summary") or "")[:280] or None,
        "sources": sources,
        "extracted_by": {"model": "import:vcdb", "prompt_version": "import-v1", "run_date": run_date},
        "reviewed": False,
        "notes": "imported from VCDB; VERIS coding mapped, not re-extracted. disclosed_date = incident date (VCDB has no disclosure date)",
        "imported_from": {"dataset": "vcdb", "record_id": rec.get("incident_id", ""),
                          "license": "CC BY-SA 4.0", "mapping_version": MAPPING_VERSION},
    }
    errs = validate(out)
    if errs:
        log.debug("invalid %s: %s", name, errs[:2])
        return None
    return out


def load_vcdb(path: str | None) -> list[dict]:
    if path:
        return json.loads(Path(path).read_text())
    import requests

    r = requests.get(VCDB_ZIP, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = next(n for n in z.namelist() if n.endswith(".json"))
        return json.loads(z.read(name))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="local vcdb JSON (skips download)")
    ap.add_argument("--since-year", type=int, default=2022)
    ap.add_argument("--out", default=str(INCIDENTS_PATH))
    ap.add_argument("--exclude-summary-regex",
                    help="skip records whose summary matches, e.g. 'MOVEit' to drop the 2023 "
                         "campaign dump (747 of 749 VCDB 2023 records are MOVEit victims)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    excl = re.compile(args.exclude_summary_regex, re.I) if args.exclude_summary_regex else None
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    from run import merge_into_store

    raw = load_vcdb(args.file)
    run_date = today()
    mapped, skipped = [], 0
    for rec in raw:
        y = rec.get("timeline", {}).get("incident", {}).get("year")
        if not y or int(y) < args.since_year:
            continue
        if excl and excl.search(rec.get("summary") or ""):
            skipped += 1
            continue
        m = map_record(rec, run_date)
        if m:
            mapped.append(m)
        else:
            skipped += 1
    log.info("mapped %d, skipped %d (no victim name/date or invalid)", len(mapped), skipped)
    if args.dry_run:
        from collections import Counter
        print("initial_access:", Counter(m["initial_access"] for m in mapped).most_common())
        print("org_type:", Counter(m["org_type"] for m in mapped).most_common())
        return 0
    out_path = Path(args.out)
    store = read_jsonl(out_path)
    before = len(store)
    for m in mapped:
        merge_into_store(store, m)
    write_jsonl(out_path, store)
    log.info("store %d -> %d records", before, len(store))
    return 0


if __name__ == "__main__":
    sys.exit(main())
