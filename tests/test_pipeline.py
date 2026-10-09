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


def cand(org, d, st="press", ev="press_report", url=None, hint=None):
    return {"org_name": org, "disclosed_date": d, "source_type": st, "evidence_level_hint": ev,
            "source_url": url or f"https://x/{org}/{d}", "title": None, "structured_hint": hint or {},
            "org_country": "US", "all_sources": [{"url": url or f"https://x/{org}/{d}", "type": st, "title": None}]}


def record(org, d, **over):
    r = {"id": make_id(org, d), "schema_version": "1.0", "org_name": org, "org_type": "other",
         "org_country": "US", "disclosed_date": d, "incident_date": None, "initial_access": "unknown",
         "initial_access_attack_id": None, "veris_action": "unknown", "root_cause": None,
         "technology_involved": [], "impact_type": "unknown", "records_affected": None,
         "threat_actor": None, "evidence_level": "press_report", "confidence": "medium",
         "supporting_quote": None, "summary": None,
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
