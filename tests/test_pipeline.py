"""Correctness tests for the parts that silently produce bad data if they regress.
Run: .venv/bin/python -m pytest -q"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))

from common import make_id, normalize_org, validate  # noqa: E402
from dedupe import dedupe  # noqa: E402
from extract import llm_schema, post_check  # noqa: E402
from run import (deterministic_record, find_record, looks_like_incident_8k,  # noqa: E402
                 merge_into_store, mostly_english)
from sources import _hhs_csv_rows, _iso  # noqa: E402
from build_site import claim_only  # noqa: E402
from actors import enrich_actor  # noqa: E402
from migrate import to_1_1  # noqa: E402
import import_vcdb  # noqa: E402


def cand(org, d, st="press", ev="press_report", url=None, hint=None):
    return {"org_name": org, "disclosed_date": d, "source_type": st, "evidence_level_hint": ev,
            "source_url": url or f"https://x/{org}/{d}", "title": None, "structured_hint": hint or {},
            "org_country": "US", "all_sources": [{"url": url or f"https://x/{org}/{d}", "type": st, "title": None}]}


def record(org, d, **over):
    r = {"id": make_id(org, d), "schema_version": "1.1", "org_name": org, "org_type": "other",
         "org_country": "US", "disclosed_date": d, "incident_date": None, "initial_access": "unknown",
         "initial_access_attack_id": None, "veris_action": "unknown", "root_cause": None,
         "technology_involved": [], "impact_type": "unknown", "records_affected": None,
         "threat_actor": None, "evidence_level": "press_report", "confidence": "medium",
         "supporting_quote": None, "summary": None,
         "actor": {"category": "unknown", "variety": "unknown", "motive": "unknown", "name": None, "country": None},
         "third_party": {"involved": None, "archetype": None, "vendor": None}, "control_failure": "unknown",
         "sources": [{"url": f"https://x/{org}/{d}", "type": "press", "title": None, "fetched_at": None}],
         "extracted_by": {"model": "t", "prompt_version": "t", "run_date": d}, "reviewed": False, "notes": None}
    r.update(over)
    return r


# --- identity and merging -------------------------------------------------------------
def test_normalize_org_drops_suffixes_and_dba():
    assert normalize_org("Change Healthcare, Inc.") == "change healthcare"
    assert normalize_org("ACME Corp dba Foo Bar") == "acme"
    assert normalize_org("Federal Bureau of Investigation") == "federal bureau of investigation"


def test_follow_up_within_window_joins_existing_record_across_month_boundary():
    store = [record("Acme Inc", "2026-09-28")]
    merge_into_store(store, record("ACME, Inc.", "2026-10-02", initial_access="phishing",
                                   supporting_quote="q", sources=[{"url": "https://y", "type": "press", "title": None, "fetched_at": None}]))
    assert len(store) == 1
    assert store[0]["id"] == make_id("Acme Inc", "2026-09-28")
    assert store[0]["initial_access"] == "phishing"
    assert len(store[0]["sources"]) == 2
    assert store[0]["disclosed_date"] == "2026-09-28"


def test_same_org_months_apart_is_a_second_record_unless_incident_date_matches():
    store = [record("Acme Inc", "2026-01-10", incident_date="2026-01-01")]
    merge_into_store(store, record("Acme Inc", "2026-06-10"))
    assert len(store) == 2
    merge_into_store(store, record("Acme Inc", "2026-09-10", incident_date="2026-01-03"))
    assert len(store) == 2  # names the January incident, so it joined it
    assert find_record(store, "Acme", "2026-09-10", "2026-01-03")["disclosed_date"] == "2026-01-10"


def test_reviewed_record_only_gains_sources():
    store = [record("Acme Inc", "2026-09-01", initial_access="phishing", reviewed=True)]
    merge_into_store(store, record("Acme Inc", "2026-09-05", initial_access="insider",
                                   sources=[{"url": "https://z", "type": "press", "title": None, "fetched_at": None}]))
    assert store[0]["initial_access"] == "phishing" and len(store[0]["sources"]) == 2


def test_dedupe_groups_candidates_and_prefers_8k_body_over_exhibit():
    c = [cand("Acme Inc", "2026-09-10"),
         cand("ACME, Inc.", "2026-09-20", "sec_8k", "org_confirmed", "https://sec/ex99.htm", {"exhibit": True}),
         cand("ACME, Inc.", "2026-09-20", "sec_8k", "org_confirmed", "https://sec/8k.htm", {"exhibit": False}),
         cand("Acme Inc", "2026-11-20"), cand("", "2026-09-10", url="https://news/1")]
    out = dedupe(c)
    assert len(out) == 3
    primary = next(o for o in out if o.get("org_name") == "ACME, Inc." or o.get("org_name") == "Acme Inc")
    assert primary["source_url"] == "https://sec/8k.htm"
    assert len(primary["all_sources"]) == 3


# --- guards that keep bad values out ---------------------------------------------------
TEXT = "The company said attackers used stolen VPN credentials to get in. About 12,345 people were affected."


def test_post_check_keeps_supported_values():
    inc = post_check({"initial_access": "stolen_or_valid_credentials", "supporting_quote": "attackers used stolen VPN credentials",
                      "records_affected": 12345, "confidence": "high"}, TEXT)
    assert inc["initial_access"] == "stolen_or_valid_credentials" and inc["records_affected"] == 12345 and inc["confidence"] == "high"


def test_post_check_downgrades_fabricated_quote_and_count():
    inc = post_check({"initial_access": "phishing", "supporting_quote": "a phishing email was opened",
                      "records_affected": 999, "confidence": "high"}, TEXT)
    assert inc["confidence"] == "low" and inc["records_affected"] is None


def test_post_check_resets_initial_access_without_quote():
    assert post_check({"initial_access": "phishing", "supporting_quote": None, "confidence": "high"}, TEXT)["initial_access"] == "unknown"


def test_8k_prefilter():
    assert not looks_like_incident_8k("Item 1.01 Entry into agreement. Reps about any cybersecurity incident" + " x" * 2000 + " Item 9.01")
    assert looks_like_incident_8k("Item 1.05 Material Cybersecurity Incidents. The Company identified unauthorized access to its network.")
    assert looks_like_incident_8k("Item 8.01 Other Events. ... a ransomware attack encrypted certain systems.")


def test_language_guard():
    assert mostly_english(TEXT)
    assert not mostly_english("هجوم الفدية على Rackspace Hosted Exchange الجهة المستهدفة شركة Rackspace Technology وعملاء خدمة")
    assert mostly_english("")


def test_llm_schema_hides_pipeline_fields_and_is_valid():
    import jsonschema
    s = llm_schema()
    jsonschema.Draft202012Validator.check_schema(s)
    assert "id" not in s["properties"]["incident"]["properties"]
    jsonschema.validate({"skip": True, "reason": "trend piece"}, s)


# --- deterministic regulator records -------------------------------------------------
def test_hhs_record_maps_checkboxes_and_validates():
    c = cand("Woodlawn Hospital", "2026-09-21", "hhs_portal", "regulator_filing",
             hint={"covered_entity_type": "Healthcare Provider", "individuals_affected": "742",
                   "breach_type": "Hacking/IT Incident", "location": "Email"})
    r = deterministic_record(c, "2026-10-09")
    assert r and not validate(r)
    assert (r["initial_access"], r["veris_action"], r["records_affected"], r["org_type"]) == ("unknown", "hacking", 742, "healthcare")
    c["structured_hint"] = {"breach_type": "Theft", "covered_entity_type": "Health Plan", "individuals_affected": "n/a", "location": "Laptop"}
    r = deterministic_record(c, "2026-10-09")
    assert r["initial_access"] == "lost_or_stolen_device" and r["records_affected"] is None


def test_hhs_csv_export_recovers_jsf_named_columns():
    csv_text = ("javax.faces.component.UIPanel@1,State,Covered Entity Type,Individuals Affected,Breach Submission Date,"
                "Type of Breach,Location of Breached Information,javax.faces.component.UIPanel@2,Web Description\n"
                "Woodlawn Hospital,IN,Healthcare Provider,742,09/21/2026,Hacking/IT Incident,Email,No,\n")
    rows = _hhs_csv_rows(csv_text)
    assert rows[0]["Name of Covered Entity"] == "Woodlawn Hospital" and rows[0]["Business Associate Present"] == "No"
    assert _iso(rows[0]["Breach Submission Date"]) == "2026-09-21"


def test_claim_only_records_are_withheld_from_publication():
    claim = record("Victim Co", "2026-10-01", sources=[{"url": "https://www.ransomware.live/id/x", "type": "ransomware_leak_site", "title": None, "fetched_at": None}])
    assert claim_only(claim)
    claim["sources"].append({"url": "https://news/x", "type": "press", "title": None, "fetched_at": None})
    assert not claim_only(claim)


# --- 1.1: root cause and actor ---------------------------------------------------------
CVE_TEXT = "Attackers exploited CVE-2025-12345 in the company's Citrix NetScaler; a patch had been available since June. ShinyHunters claimed the theft."


def test_post_check_keeps_only_cves_present_in_text():
    inc = post_check({"initial_access": "exploit_public_facing_app", "supporting_quote": "Attackers exploited CVE-2025-12345",
                      "cve": ["cve-2025-12345", "CVE-2024-99999"], "confidence": "high"}, CVE_TEXT)
    assert inc["cve"] == ["CVE-2025-12345"] and "CVE-2024-99999" in inc["notes"]


def test_post_check_clears_actor_name_absent_from_text_and_enriches_known_groups():
    inc = post_check({"initial_access": "unknown", "actor": {"name": "LockBit"}, "confidence": "low"}, CVE_TEXT)
    assert inc["actor"]["name"] is None
    inc = post_check({"initial_access": "unknown", "actor": {"name": "ShinyHunters"}, "confidence": "low"}, CVE_TEXT)
    assert inc["actor"] == {"category": "external", "variety": "organized_crime", "motive": "financial", "name": "ShinyHunters", "country": None}


def test_post_check_resets_control_failure_without_quote_and_credential_source_without_cred_access():
    inc = post_check({"initial_access": "unknown", "control_failure": "missing_mfa", "credential_source": "infostealer", "confidence": "high"}, CVE_TEXT)
    assert inc["control_failure"] == "unknown" and inc["credential_source"] is None


def test_enrich_actor_never_overrides_a_stated_value():
    a = enrich_actor({"name": "Salt Typhoon", "motive": "financial"})
    assert (a["variety"], a["motive"], a["country"]) == ("state_affiliated", "financial", "CN")
    assert enrich_actor({"name": "Nobody Special"})["variety"] == "unknown"


def test_migration_to_1_1_is_idempotent_and_valid():
    old = record("Acme", "2026-01-01"); old["schema_version"] = "1.0"
    for k in ("actor", "third_party", "control_failure"):
        old.pop(k)
    old["threat_actor"] = "Qilin"; old["initial_access"] = "supply_chain_or_third_party"
    new = to_1_1(dict(old))
    assert not validate(new)
    assert new["actor"]["name"] == "Qilin" and new["actor"]["variety"] == "organized_crime"
    assert new["third_party"]["involved"] is True and "threat_actor" not in new
    assert to_1_1(dict(new)) == new


def test_hhs_and_leak_site_records_fill_1_1_fields():
    c = cand("Woodlawn Hospital", "2026-09-21", "hhs_portal", "regulator_filing",
             hint={"covered_entity_type": "Healthcare Provider", "individuals_affected": "742",
                   "breach_type": "Hacking/IT Incident", "location": "Email", "business_associate_present": "Yes"})
    r = deterministic_record(c, "2026-10-09")
    assert r["data_types"] == ["medical"] and r["entry_asset"] == "email_account" and r["third_party"]["involved"] is True
    c = cand("Victim Co", "2026-10-01", "ransomware_leak_site", "actor_claimed", hint={"group": "qilin"})
    r = deterministic_record(c, "2026-10-09")
    assert r["ransomware"] is True and r["actor"]["variety"] == "organized_crime" and r["actor"]["name"] == "qilin" and not validate(r)


def test_vcdb_actor_vector_and_data_mapping():
    rec = {"actor": {"external": {"variety": ["Organized crime"], "motive": ["Financial"], "name": ["LockBit"], "country": ["RU"]}},
           "action": {"hacking": {"variety": ["Exploit vuln"], "vector": ["VPN"], "cve": "CVE-2023-4966"}, "malware": {"variety": ["Ransomware"]}},
           "attribute": {"confidentiality": {"data": [{"variety": "Personal"}, {"variety": "Medical"}], "data_disclosure": "Yes"}},
           "victim": {"victim_id": "Acme Hospital", "industry": "622", "country": ["US"]},
           "timeline": {"incident": {"year": 2024, "month": 3}}, "reference": "https://example.org/a", "confidence": "High", "summary": "x"}
    out = import_vcdb.map_record(rec, "2026-10-09")
    assert out and not validate(out)
    assert out["actor"]["variety"] == "organized_crime" and out["actor"]["name"] == "LockBit" and out["actor"]["country"] == "RU"
    assert out["entry_asset"] == "vpn_or_edge_device" and out["cve"] == ["CVE-2023-4966"] and out["ransomware"] is True
    assert out["data_types"] == ["medical", "personal"] and out["initial_access"] == "exploit_public_facing_app"


# --- Maine notice parsing (pages fetched from a US address) ----------------------------
MAINE_HTML = """<html><body><h1>Data Breach Notices</h1><h2>Entity Information</h2>
<p>Type of Organization:</p><p>Healthcare</p><p>Entity Name:</p><p>Acme Medical Group, P.C.</p>
<p>State, or Country if outside the US:</p><p>United States</p>
<h2>Breach Information</h2>
<p>Total number of persons affected (including residents):</p><p>105387</p>
<p>Total number of Maine residents affected:</p><p>370</p>
<p>Date(s) Breach Occured:</p><p>05/28/2026</p><p>Date Breach Discovered:</p><p>06/01/2026</p>
<p>Description of the Breach:</p><p>External system breach (hacking)</p>
<p>Information Acquired -  Name or other personal identifier in combination with:</p>
<p>Social Security Number; Medical information</p>
<p>Type of Notification:</p><p>Written</p><p>Date(s) of consumer notification:</p><p>09/04/2026</p>
</body></html>"""


def test_maine_notice_parses_fields_and_builds_a_regulator_record():
    from sources import parse_maine_notice
    c = parse_maine_notice(MAINE_HTML, "https://www.maine.gov/agviewer/content/ag/x/abc.shtml")
    assert c["org_name"] == "Acme Medical Group, P.C." and c["disclosed_date"] == "2026-09-04"
    h = c["structured_hint"]
    assert h["breach_description"] == "External system breach (hacking)" and h["persons_affected"] == "105387"
    assert h["information_acquired"].startswith("Social Security")
    c["all_sources"] = [{"url": c["source_url"], "type": "state_ag", "title": None}]
    r = deterministic_record(c, "2026-10-09")
    assert r and not validate(r)
    assert (r["org_type"], r["veris_action"], r["records_affected"], r["discovered_date"]) == ("healthcare", "hacking", 105387, "2026-06-01")
    assert r["data_types"] == ["medical", "personal"]
    assert parse_maine_notice("<html><body>nothing here</body></html>", "u") is None


# --- leak-site claims stay private until confirmed -------------------------------------
def test_claim_attaches_to_confirmed_record_and_settles_later():
    from run import attach_claim, settle_claims
    store = [record("Acme Hospital", "2026-09-10")]
    claim = cand("ACME Hospital Inc", "2026-09-20", "ransomware_leak_site", "actor_claimed",
                 url="https://www.ransomware.live/id/x", hint={"group": "qilin"})
    attach_claim(store[0], claim)
    assert store[0]["ransomware"] is True and store[0]["actor"]["name"] == "qilin" and store[0]["actor"]["variety"] == "organized_crime"
    assert any(s["type"] == "ransomware_leak_site" for s in store[0]["sources"])
    pending = [cand("Nobody Corp", "2026-09-01", "ransomware_leak_site", "actor_claimed", url="https://www.ransomware.live/id/y", hint={"group": "akira"}),
               cand("Old Co", "2024-01-01", "ransomware_leak_site", "actor_claimed", url="https://www.ransomware.live/id/z", hint={"group": "akira"})]
    left = settle_claims(store, pending)
    assert [c["org_name"] for c in left] == ["Nobody Corp"]  # unmatched stays; year-old dropped
    store.append(record("Nobody Corp", "2026-09-05"))
    assert settle_claims(store, left) == [] and store[1]["ransomware"] is True
