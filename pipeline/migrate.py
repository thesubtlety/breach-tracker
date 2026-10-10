"""One-off schema migrations for data/incidents.jsonl. Idempotent: run as often as you like.

    python pipeline/migrate.py            # 1.0 -> 1.1
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from actors import default_actor, default_third_party, enrich_actor  # noqa: E402
from common import INCIDENTS_PATH, read_jsonl, validate, write_jsonl  # noqa: E402
from extract import derived_techniques  # noqa: E402


def stamp_first_seen(r: dict) -> dict:
    r.setdefault("first_seen", r["extracted_by"]["run_date"])
    return r


def stamp_org_id(r: dict) -> dict:
    """org_id from the current alias map."""
    from orgs import org_id
    r["org_id"] = org_id(r["org_name"])
    return r


def to_1_1(r: dict) -> dict:
    stamp_first_seen(r)
    stamp_org_id(r)
    if not (r.get("schema_version") in ("1.1", "1.2") and "actor" in r):
        name = r.pop("threat_actor", None)
        is_claim = any(s["type"] == "ransomware_leak_site" for s in r.get("sources", []))
        actor = dict(default_actor(), name=name)
        if is_claim and name:
            actor.update(category="external", variety="organized_crime", motive="financial")
        r["actor"] = enrich_actor(actor)
        r.setdefault("third_party", default_third_party())
        if r["third_party"]["involved"] is None and r.get("initial_access") == "supply_chain_or_third_party":
            r["third_party"]["involved"] = True
        r.setdefault("discovered_date", None)
        r.setdefault("entry_asset", "unknown")
        r.setdefault("control_failure", "unknown")
        r.setdefault("credential_source", "unknown" if r.get("initial_access") == "stolen_or_valid_credentials" else None)
        r.setdefault("cve", [])
        r.setdefault("ransomware", True if is_claim else None)
        r.setdefault("data_types", ["medical"] if any(s["type"] == "hhs_portal" for s in r.get("sources", [])) else [])
    r["attack_techniques"] = sorted(set(r.get("attack_techniques") or []) | derived_techniques(r))[:12]
    r["schema_version"] = "1.2"
    return r


def claim_only(r: dict) -> bool:
    return all(s["type"] == "ransomware_leak_site" for s in r.get("sources", []))


def move_claims_out(rows: list[dict]) -> list[dict]:
    """Claim-only records leave the public store for the private claims file, as the
    candidates they were built from."""
    from common import CLAIMS_PATH
    claims = read_jsonl(CLAIMS_PATH)
    urls = {c["source_url"] for c in claims}
    keep = []
    for r in rows:
        if not claim_only(r):
            keep.append(r)
            continue
        s = r["sources"][0]
        if s["url"] not in urls:
            claims.append({"org_name": r["org_name"], "disclosed_date": r["disclosed_date"],
                           "source_type": "ransomware_leak_site", "source_url": s["url"], "title": s.get("title"),
                           "text": None, "structured_hint": {"group": (r.get("actor") or {}).get("name"),
                                                             "attribution": "Source: Ransomware.live"},
                           "evidence_level_hint": "actor_claimed", "org_country": r.get("org_country", "unknown")})
            urls.add(s["url"])
    write_jsonl(CLAIMS_PATH, claims)
    print(f"moved {len(rows) - len(keep)} claim-only records to {CLAIMS_PATH.name} (private)")
    return keep


def main() -> int:
    rows = move_claims_out(read_jsonl(INCIDENTS_PATH))
    out, bad = [], 0
    for r in rows:
        r = to_1_1(r)
        errs = validate(r)
        if errs:
            bad += 1
            print("invalid after migration:", r.get("org_name"), errs[:2])
        out.append(r)
    write_jsonl(INCIDENTS_PATH, out)
    print(f"migrated {len(out)} records to 1.2; {bad} invalid")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
