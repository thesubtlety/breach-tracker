"""Correctness tests for the parts that silently produce bad data if they regress.
Run: .venv/bin/python -m pytest -q"""
import json
from datetime import date
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


def test_merge_keeps_first_seen_and_stamps_updated_at_only_on_change():
    store = []
    merge_into_store(store, record("Acme Inc", "2026-09-01"))
    assert store[0]["first_seen"] == "2026-09-01" and "updated_at" not in store[0]
    # a richer follow-up replaces the record but keeps the original first_seen
    merge_into_store(store, record("Acme Inc", "2026-09-10", initial_access="phishing", supporting_quote="q",
                                   extracted_by={"model": "t", "prompt_version": "t", "run_date": "2026-09-10"},
                                   sources=[{"url": "https://y", "type": "press", "title": None, "fetched_at": None}]))
    assert len(store) == 1 and store[0]["first_seen"] == "2026-09-01" and store[0]["updated_at"] == "2026-09-10"
    # the same source again changes nothing
    merge_into_store(store, record("Acme Inc", "2026-09-10", initial_access="phishing", supporting_quote="q",
                                   extracted_by={"model": "t", "prompt_version": "t", "run_date": "2026-09-20"},
                                   sources=[{"url": "https://y", "type": "press", "title": None, "fetched_at": None}]))
    assert store[0]["updated_at"] == "2026-09-10"


def test_find_record_with_index_matches_linear_scan():
    from run import org_index
    store = [record("Acme Inc", "2026-01-10"), record("Beta LLC", "2026-01-12"), record("Acme Inc", "2026-06-10")]
    idx = org_index(store)
    for org, d in [("ACME, Inc.", "2026-01-20"), ("Beta", "2026-02-01"), ("Acme", "2026-06-15"), ("Nobody", "2026-01-10")]:
        assert find_record(store, org, d) is find_record(store, org, d, index=idx)


def test_records_affected_accepts_scaled_figures():
    from extract import number_in_text
    assert number_in_text(14640000, "affecting approximately 14.64 million customer records")
    assert number_in_text(1200000, "about 1.2M people")
    assert number_in_text(12345, "About 12,345 people were affected.")
    assert not number_in_text(14640000, "affecting 14 million customer records")
    assert not number_in_text(5000, "no figure was given")


def test_feed_lists_new_and_updated_but_not_imported():
    import xml.etree.ElementTree as ET
    from build_site import feed
    rows = [record("Acme Inc", "2026-10-01", first_seen="2026-10-01"),
            record("Beta LLC", "2026-08-01", first_seen="2026-08-01", updated_at="2026-10-05"),
            record("Old Co", "2026-01-01", first_seen="2026-01-01"),
            record("Imported Co", "2026-10-02", first_seen="2026-10-02", imported_from={"dataset": "vcdb", "record_id": "x"})]
    root = ET.fromstring(feed(rows, "2026-09-28", "2026-10-10"))
    ns = {"a": "http://www.w3.org/2005/Atom"}
    entries = root.findall("a:entry", ns)
    titles = [e.find("a:title", ns).text for e in entries]
    assert [t.split(":")[0] for t in titles] == ["Beta LLC", "Acme Inc"]
    assert [e.find("a:category", ns).get("term") for e in entries] == ["updated", "new"]


def test_texas_rows_become_state_ag_candidates():
    from sources import texas_candidates
    rows = [{"Name": "BR-0005405", "Business_Name__c": "JM Bozeman Enterprises, including affiliates", "Type_of_Entity__c": "Healthcare \u2013 Medical Provider",
             "Published_at_AG_website_Date__c": 1791763200000, "Breach_Discovered_Date__c": 1783296000000, "Start_Breach_Date__c": None,
             "Types_of_Personal_Information_Involved__c": "Name of individual;Social Security Number Information;Medical Information",
             "Number_of_Texans_affected_by_the_breach__c": 602, "Total_Number_of_Individuals_Affected__c": 3211, "State_withTer__c": "Arkansas"},
            {"Name": "BR-0000001", "Business_Name__c": "Old Co", "Published_at_AG_website_Date__c": 1700000000000}]
    out = texas_candidates(rows, date(2026, 1, 1))
    assert [c["org_name"] for c in out] == ["JM Bozeman Enterprises"]
    assert out[0]["disclosed_date"] == "2026-10-12" and out[0]["source_url"].endswith("#BR-0005405")
    rec = deterministic_record(dict(out[0], all_sources=[{"url": out[0]["source_url"], "type": "state_ag", "title": None}]), "2026-10-12")
    assert rec["org_type"] == "healthcare" and rec["records_affected"] == 3211
    assert rec["discovered_date"] == "2026-07-06" and rec["data_types"] == ["medical", "personal"]


def test_california_list_rows_become_state_ag_candidates():
    from sources import parse_ca_list
    html = """<table><thead><tr><th>Org</th><th>Date</th><th>Reported</th></tr></thead><tbody>
    <tr><td><a href="/ecrime/databreach/reports/sb24-1">iRhythm Technologies Inc.</a></td><td>06/03/2026 , 06/08/2026</td><td>10/06/2026</td></tr>
    <tr><td><a href="/ecrime/databreach/reports/sb24-2">Harman Fitness</a></td><td>n/a</td><td>10/06/2026</td></tr>
    </tbody></table>"""
    rows = parse_ca_list(html)
    assert [r["org_name"] for r in rows] == ["iRhythm Technologies Inc.", "Harman Fitness"]
    assert rows[0]["disclosed_date"] == "2026-10-06" and rows[0]["source_type"] == "state_ag"
    assert rows[0]["source_url"] == "https://oag.ca.gov/ecrime/databreach/reports/sb24-1"
    assert rows[0]["structured_hint"]["date_occurred"] == "06/03/2026"
    rec = deterministic_record(dict(rows[0], all_sources=[{"url": rows[0]["source_url"], "type": "state_ag", "title": None}]), "2026-10-10")
    assert rec["incident_date"] == "2026-06-03" and rec["evidence_level"] == "regulator_filing"


def test_hibp_row_becomes_record_with_count_and_data_types():
    from sources import hibp_data_types
    assert hibp_data_types(["Email addresses", "Passwords", "Credit cards", "Health insurance information", "Avatars"]) == ["credentials", "financial", "medical", "other", "personal"]
    c = {"org_name": "Example Forum", "disclosed_date": "2026-10-01", "source_type": "hibp", "source_url": "https://haveibeenpwned.com/Breach/Example",
         "title": "HIBP", "text": "short", "org_country": "unknown", "evidence_level_hint": "press_report",
         "structured_hint": {"breach_date": "2026-08-15", "pwn_count": 12345, "data_classes": ["Email addresses", "Passwords"], "verified": True, "description": "short"},
         "all_sources": [{"url": "https://haveibeenpwned.com/Breach/Example", "type": "hibp", "title": None}]}
    rec = deterministic_record(c, "2026-10-10")
    assert rec and rec["records_affected"] == 12345 and rec["incident_date"] == "2026-08-15"
    assert rec["data_types"] == ["credentials", "personal"] and rec["evidence_level"] == "press_report"


def test_merge_fills_gaps_without_overriding():
    store = [record("Acme Inc", "2026-09-01", initial_access="phishing", supporting_quote="q", org_type="unknown")]
    merge_into_store(store, record("Acme Inc", "2026-09-03", records_affected=500, incident_date="2026-08-20", org_type="healthcare",
                                   sources=[{"url": "https://hibp/x", "type": "hibp", "title": None, "fetched_at": None}]))
    r = store[0]
    assert r["initial_access"] == "phishing" and r["records_affected"] == 500 and r["incident_date"] == "2026-08-20" and r["org_type"] == "healthcare"
    assert r["updated_at"] == "2026-09-03"


def test_short_org_keeps_first_entity():
    from sources import short_org
    assert short_org("Premera Blue Cross, including Academe, Inc. (formerly LifeWise)") == "Premera Blue Cross"
    assert short_org("TMX Finance Corporate Services, Inc., on behalf of itself") == "TMX Finance Corporate Services, Inc."
    assert short_org("Bankers Life (BL) - BL is the marketing brand of X") == "Bankers Life (BL)"
    assert short_org("Acme Corp") == "Acme Corp"
    assert len(short_org("A" * 300)) == 200


def test_hibp_facts_fill_only_keeps_stated_count():
    from run import apply_hibp_facts
    rec = {"records_affected": 500, "incident_date": None, "data_types": [], "impact_type": "unknown"}
    apply_hibp_facts(rec, {"pwn_count": 9000, "breach_date": "2024-01-02", "data_classes": ["Email addresses"]}, fill_only=True)
    assert rec["records_affected"] == 500 and rec["incident_date"] == "2024-01-02"
    apply_hibp_facts(rec, {"pwn_count": 9000}, fill_only=False)
    assert rec["records_affected"] == 9000


def test_price_reaction_bases_on_filing_day_close():
    from build_site import price_reaction
    closes = {"2025-03-03": 10.0, "2025-03-04": 10.0, "2025-03-05": 9.0, "2025-03-06": 8.0}
    out = price_reaction({"ticker": "X", "filed": "2025-03-04", "closes": closes}, {})
    assert out["base_day"] == "2025-03-04" and out["returns"]["1"]["raw"] == -0.1


def test_letter_sections_slices_narrative():
    from letters import letter_sections
    t = ("Dear Customer,\nWe write to inform you.\nWhat Happened?\nOn May 1, 2024 an unauthorized actor "
         "accessed our network. <<Variable Text 2>>\nWhat Information Was Involved?\nYour name and SSN.\n"
         "What We Are Doing\nWe reset passwords.\nFor More Information\nCall us.")
    out = letter_sections(t)
    assert out.startswith("What Happened?") and "Your name and SSN." in out
    assert "reset passwords" not in out and "<<" not in out
    assert letter_sections("Dear Member, something happened. No headings here.").startswith("Dear Member")


def test_org_id_is_stable_across_spellings(tmp_path, monkeypatch):
    import orgs
    monkeypatch.setattr(orgs, "_aliases", {"american express travel related services": "american express"})
    assert orgs.org_id("Google Inc.") == orgs.org_id("google") == orgs.org_id("Google, Inc")
    assert orgs.org_id("Acme Corp on behalf of itself and its affiliates") == orgs.org_id("Acme Corp")
    assert orgs.org_id("American Express Travel Related Services") == orgs.org_id("American Express")
    assert orgs.org_id("Acme Corp") != orgs.org_id("Acme Hospital")


def test_registry_folds_spellings_and_counts():
    from orgs import registry
    mk = lambda name, d, n=None: {"id": name + d, "org_name": name, "disclosed_date": d, "org_type": "technology",
                                   "org_country": "US", "records_affected": n, "sources": [{"type": "press", "url": "u"}]}
    out = registry([mk("Google Inc.", "2024-01-01", 10), mk("Google", "2025-01-01", 500), mk("Acme", "2023-01-01")])
    g = next(o for o in out if o["name"] == "Google")
    assert g["incidents"] == 2 and g["largest"] == 500 and g["aliases"] == ["Google Inc."] and g["first"] == "2024-01-01"
    assert out[0]["name"] == "Google"


def test_wants_letter_only_unread_unknown_california():
    from letters import wants_letter
    base = {"reviewed": False, "initial_access": "unknown", "sources": [{"type": "state_ag", "url": "https://oag.ca.gov/ecrime/databreach/reports/sb24-1"}]}
    assert wants_letter(dict(base))
    assert not wants_letter(dict(base, initial_access="phishing"))
    assert not wants_letter(dict(base, letter={"url": None, "date": "2026-10-10", "outcome": "no_letter"}))
    assert not wants_letter(dict(base, sources=[{"type": "state_ag", "url": "https://www.maine.gov/x.html"}]))


def test_technique_guard_needs_words_in_text():
    from extract import guard_techniques
    text = "A phishing email led to ransomware that encrypted files; data was exfiltrated."
    assert guard_techniques(["T1566", "T1486", "T1041", "T1491"], text, {}) == ["T1041", "T1486", "T1566"]
    assert guard_techniques(["T1190"], "unauthorized access to our network", {"ransomware": True}) == ["T1486"]
    assert guard_techniques(["t1566.001"], text, {"initial_access_attack_id": "T1078"}) == ["T1078", "T1566.001"]


def test_cpe_product_reads_first_cpe():
    from external import cpe_product
    v = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:progress:moveit_transfer:2023.0.0:*:*:*:*:*:*:*"}]}]}]}
    assert cpe_product(v) == ("progress", "moveit transfer")
    assert cpe_product({}) == (None, None)


def test_vendor_names_split_lists_and_drop_descriptions():
    from orgs import vendor_names
    assert vendor_names("Snowflake, Mixpanel, and Salesforce") == ["Snowflake", "Mixpanel", "Salesforce"]
    assert vendor_names("Citrix and Fortra") == ["Citrix", "Fortra"]
    assert vendor_names("Google, Meta, TikTok, and other third parties") == ["Google", "Meta", "TikTok"]
    assert vendor_names("DanubeNet, Inc. aka Driving School Solutions") == ["DanubeNet, Inc"]
    assert vendor_names("Invisalign (AlignTech)") == ["Invisalign"]
    assert vendor_names("Evolve Bank & Trust") == ["Evolve Bank & Trust"]
    for junk in ("third-party contractor", "customer support provider", "new janitorial service", "Meta contractor", None, ""):
        assert vendor_names(junk) == [], junk


def test_vendor_id_joins_products_and_spellings_to_the_company():
    from orgs import org_id, vendor_id
    assert vendor_id("MOVEit") == vendor_id("Progress Software Corporation") == vendor_id("Progress") == org_id("Progress Software")
    assert vendor_id("GoAnywhere") == vendor_id("Fortra, LLC")
    assert vendor_id("PBI") == vendor_id("Pension Benefits Information, LLC") == vendor_id("PBI Research Services")
    assert vendor_id("Snowflake") != vendor_id("Salesforce")


def test_post_check_clears_vendor_descriptions(monkeypatch):
    import extract
    inc = {"org_name": "X", "disclosed_date": "2026-01-01", "initial_access": "unknown", "summary": "s", "cve": [],
           "third_party": {"involved": True, "archetype": "vendor_hosted_data", "vendor": "a third-party contractor"}}
    out = extract.post_check(inc, "text of the source") if hasattr(extract, "post_check") else None
    assert out is not None, "post_check entry point moved"
    assert out["third_party"]["vendor"] is None and any("description" in n for n in (out.get("notes") or "").split(";"))


def test_vendor_alias_generator_sends_only_unseen_names_and_fails_closed():
    import vendor_aliases as va
    rows = [{"third_party": {"involved": True, "vendor": v}} for v in ("MOVEit", "Progress Software Corp.", "Cencora", "Cencora", "Nobody Inc")]
    assert va.unresolved(rows, {"cencora": "cencora"}) == ["MOVEit", "Nobody Inc", "Progress Software Corp"]
    calls = []

    def fake(system, user, schema, task=None):
        calls.append(json.loads(user)["names"])
        return {"vendors": [{"name": "MOVEit", "company": "Progress Software", "sure": True},
                            {"name": "Nobody Inc", "company": "Somebody", "sure": False},
                            {"name": "Progress Software Corp", "company": "a vendor", "sure": True},
                            {"name": "Not Asked", "company": "Mallory", "sure": True}]}
    out = va.resolve(["MOVEit", "Nobody Inc", "Progress Software Corp"], {"cencora": "cencora"}, call=fake)
    assert calls == [["MOVEit", "Nobody Inc", "Progress Software Corp"]]
    assert out == {"moveit": "progress software", "nobody": "nobody", "progress software": "progress software"}


def test_vendor_registry_shares_org_ids():
    from orgs import org_id, vendor_registry
    mk = lambda org, vendor, d: {"id": org + d, "org_name": org, "org_id": org_id(org), "disclosed_date": d, "org_type": "healthcare",
                                 "third_party": {"involved": True, "vendor": vendor, "archetype": "service_provider"}, "sources": []}
    out = vendor_registry([mk("Hospital A", "AMCA", "2019-06-01"), mk("Hospital B", "AMCA Inc.", "2019-06-03"), mk("AMCA", None, "2019-06-05"),
                           mk("Hospital C", "AMCA and MOVEit", "2023-06-05"), mk("Hospital D", "third-party vendor", "2023-06-06")])
    by = {o["name"]: o for o in out}
    assert set(by) == {"AMCA", "MOVEit"} and by["AMCA"]["incidents"] == 3 and by["AMCA"]["is_org"] is True and by["AMCA"]["id"] == org_id("AMCA")
    assert by["MOVEit"]["id"] == org_id("Progress Software")


def test_claim_stats_counts_pending_and_confirmed():
    from claim_stats import compute
    claims = [{"org_name": f"V{i}", "disclosed_date": "2026-09-20", "org_country": "US", "structured_hint": {"group": "Qilin"}} for i in range(6)]
    rec = {"org_name": "Hosp", "org_type": "healthcare", "disclosed_date": "2026-09-01", "first_seen": "2026-09-10", "actor": {"name": "qilin"},
           "sources": [{"type": "sec_8k", "url": "u"}, {"type": "ransomware_leak_site", "url": "c", "title": "Leak-site claim by qilin", "date": "2026-09-02"}]}
    out = compute(claims, [rec], asof="2026-10-10")
    g = out["groups"][0]
    assert g["group"] == "qilin" and g["claims"] == 7 and g["confirmed"] == 1 and g["last_90_days"] == 7
    assert g["median_days_to_confirmation"] == 8 and g["sectors"] == [("healthcare", 1)]


# --- QA review 2026-10-10 ----------------------------------------------------------------
def test_merge_keeps_org_id_and_derived_techniques_whichever_side_wins():
    from run import attach_claim
    store = [record("Acme Inc", "2026-09-28", records_affected=10)]
    merge_into_store(store, record("Acme Inc", "2026-09-29", initial_access="phishing", initial_access_attack_id="T1566",
                                   supporting_quote="q", sources=[{"url": "https://y", "type": "press", "title": None, "fetched_at": None}]))
    assert len(store) == 1 and store[0]["org_id"] and store[0]["attack_techniques"] == ["T1566"]
    attach_claim(store[0], {"source_url": "https://leak/x", "disclosed_date": "2026-10-01", "title": "Leak-site claim by qilin",
                            "structured_hint": {"group": "qilin"}})
    assert store[0]["ransomware"] is True and store[0]["attack_techniques"] == ["T1486", "T1566"]
    assert store[0]["sources"][-1]["date"] == "2026-10-01"


def test_feed_title_is_the_feed_title_not_the_last_entry():
    from build_site import feed
    rows = [dict(record("Acme Inc", "2026-10-01"), first_seen="2026-10-01")]
    xml = feed(rows, "2026-09-25", "2026-10-10", title="Breach Tracker: incidents behind X")
    assert "<title>Breach Tracker: incidents behind X</title>" in xml and "<title>Acme Inc: unknown (press report)</title>" in xml


def test_letter_record_wins_the_merge_and_is_org_confirmed(monkeypatch):
    import letters
    old = record("Acme Inc", "2026-09-01", evidence_level="regulator_filing", records_affected=5000, technology_involved=["Email"],
                 notes=letters.CHECKBOX_NOTE, extracted_by={"model": "deterministic", "prompt_version": "v4", "run_date": "2026-09-01"},
                 sources=[{"url": "https://oag.ca.gov/ecrime/databreach/reports/sb24-1", "type": "state_ag", "title": None, "fetched_at": None}])
    store = [old]
    monkeypatch.setattr(letters, "fetch_letter", lambda u: ("https://oag.ca.gov/system/files/x.pdf", "What happened. " * 30))
    monkeypatch.setattr(letters, "extract_one", lambda c, text, run_date, model=None: dict(
        record("Acme Inc", "2026-09-01", summary="A letter.", incident_date="2026-08-01", evidence_level="org_confirmed",
               extracted_by={"model": "openai:m", "prompt_version": "v4", "run_date": run_date}), sources=c["all_sources"]))
    monkeypatch.setattr(letters.time, "sleep", lambda s: None)
    counts = letters.read_letters(store, 5, None, "2026-10-10")
    r = store[0]
    assert counts["extracted"] == 1 and r["letter"]["outcome"] == "extracted"
    assert r["evidence_level"] == "org_confirmed" and r["extracted_by"]["model"] == "openai:m"
    assert r["records_affected"] == 5000 and r["summary"] == "A letter." and r["notes"] is None and r["org_id"]
    assert [s["url"] for s in r["sources"]][-1].endswith(".pdf")


def test_empty_actions_vars_fall_back_to_defaults(monkeypatch):
    import importlib
    import common, extract
    monkeypatch.setenv("LLM_PROVIDER", "")
    monkeypatch.setenv("EDGAR_USER_AGENT", "")
    monkeypatch.delenv("LLM_MODEL", raising=False)
    try:
        assert importlib.reload(extract).PROVIDER == "anthropic"
        assert importlib.reload(common).USER_AGENT.startswith("breach-tracker")
    finally:
        monkeypatch.undo(); importlib.reload(extract); importlib.reload(common)


def test_entity_pages_titles_links_and_sitemap(tmp_path):
    from pages import org_page, robots, sitemap, vendor_page, write_pages
    org = {"id": "ab12", "name": "Acme <Health>", "aliases": ["Acme Health Inc"], "sector": "healthcare", "country": "US",
           "incidents": 2, "first": "2025-01-01", "last": "2026-02-02", "largest": 1200, "ticker": None, "ransomware": 1}
    vendor = {"id": "cd34", "name": "Progress Software", "aliases": ["MOVEit"], "incidents": 1, "first": "2026-02-02", "last": "2026-02-02",
              "archetypes": [["vendor_product", 1]], "is_org": False, "feed": False}
    base = {"org_id": "ab12", "org_name": "Acme <Health>", "initial_access": "unknown", "evidence_level": "regulator_filing", "confidence": "high",
            "impact_type": "data_theft", "sources": [{"url": "https://example.org/a", "type": "state_ag", "title": "Notice <1>"}], "first_seen": "2026-02-03"}
    r1 = dict(base, id="r1", disclosed_date="2025-01-01", records_affected=1200)
    r2 = dict(base, id="r2", disclosed_date="2026-02-02", initial_access="exploit_public_facing_app", summary="Via MOVEit.",
              supporting_quote="exploited a vulnerability in MOVEit", cve=["CVE-2023-34362"], attack_techniques=["T1190"],
              third_party={"involved": True, "vendor": "MOVEit", "archetype": "vendor_product"}, derived={"vendors": [{"id": "cd34", "name": "Progress Software"}]},
              updated_at="2026-03-01")
    html = org_page(org, [r1, r2], "https://x.test/")
    assert "<title>Acme &lt;Health&gt; data breaches: how they got in | Breach Vectors</title>" in html
    assert '<link rel="canonical" href="https://x.test/org/ab12/">' in html
    assert html.index("<h2>2026-02-02") < html.index("<h2>2025-01-01"), "newest first"
    assert 'href="../../vendor/cd34/"' in html and "exploited a vulnerability" in html and "Notice &lt;1&gt;" in html and "<Health>" not in html
    vh = vendor_page(vendor, [r2], "https://x.test/")
    assert "<title>Progress Software: 1 breach at its customers | Breach Vectors</title>" in vh and 'href="../../org/ab12/"' in vh
    urls = write_pages([r1, r2], [org], [vendor], tmp_path, "https://x.test/")
    assert (tmp_path / "org/ab12/index.html").exists() and (tmp_path / "vendor/cd34/index.html").exists()
    assert urls == [("org/ab12/", "2026-03-01"), ("vendor/cd34/", "2026-03-01")]
    sm = sitemap(urls, "https://x.test/", "2026-10-11")
    assert "<loc>https://x.test/org/ab12/</loc><lastmod>2026-03-01</lastmod>" in sm and "<loc>https://x.test/</loc>" in sm
    assert robots("https://x.test/").endswith("Sitemap: https://x.test/sitemap.xml\n")
    write_pages([r1], [org], [], tmp_path, "https://x.test/")
    assert not (tmp_path / "vendor").exists() and (tmp_path / "org/ab12/index.html").exists(), "rebuilt from scratch"
