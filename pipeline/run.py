"""Weekly run: collect -> dedupe -> (deterministic or LLM) extract -> merge -> write.

    python pipeline/run.py --since-days 8
    python pipeline/run.py --since-days 8 --only sec_edgar,rss --limit 20 --dry-run
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (CANDIDATES_PATH, INCIDENTS_PATH, PROMPT_VERSION, make_id,  # noqa: E402
                    normalize_org, read_jsonl, today, validate, write_jsonl)
from dedupe import dedupe  # noqa: E402
from fetch_text import fetch_text  # noqa: E402
from sources import collect  # noqa: E402

log = logging.getLogger("run")

# Regulator checkbox -> our enum. Only mappings that are unambiguous; everything
# else stays "unknown" rather than guessing.
HHS_BREACH_TYPE = {
    "Hacking/IT Incident": ("unknown", "hacking"),
    "Theft": ("lost_or_stolen_device", "physical"),
    "Loss": ("lost_or_stolen_device", "error"),
    "Improper Disposal": ("physical_or_paper", "error"),
    "Unauthorized Access/Disclosure": ("unknown", "unknown"),
}
MAINE_DESC = {
    "External system breach (hacking)": ("unknown", "hacking"),
    "Insider wrongdoing": ("insider", "misuse"),
    "Loss or theft of device or media": ("lost_or_stolen_device", "physical"),
    "Inadvertent disclosure": ("unknown", "error"),
    "Internal system breach": ("unknown", "unknown"),
}
MAINE_ORG_TYPE = {
    "Financial Services": "financial", "Education": "education", "Healthcare": "healthcare",
    "Government Entity in Maine": "government", "Other Commercial": "other",
    "Federal Government": "government",
}
HHS_ENTITY_TYPE = {
    "Healthcare Provider": "healthcare", "Health Plan": "healthcare",
    "Business Associate": "professional_services", "Healthcare Clearing House": "healthcare",
}


_ITEM_RE = re.compile(r"item\s*(1\.05|8\.01|7\.01)", re.I)
_INCIDENT_RE = re.compile(r"unauthori[sz]ed (access|activity|party)|cybersecurity incident|ransomware|"
                          r"threat actor|intrusion|encrypted|exfiltrat", re.I)


def looks_like_incident_8k(text: str) -> bool:
    """Cheap prefilter so we don't pay a model to skip merger agreements that mention
    'cybersecurity incident' in reps and warranties. Requires an incident-bearing Item
    and incident language within ~3k characters of it."""
    for m in _ITEM_RE.finditer(text):
        window = text[m.start(): m.start() + 3000]
        if _INCIDENT_RE.search(window):
            return True
    return False


def mostly_english(text: str) -> bool:
    """Non-English sources are out of scope (README); every model we tried extracts
    them anyway, so refuse before paying for the call."""
    letters = [ch for ch in text if ch.isalpha()]
    return not letters or sum(ch.isascii() for ch in letters) / len(letters) >= 0.8


def _int(s) -> int | None:
    try:
        return int(str(s).replace(",", "").strip())
    except (TypeError, ValueError):
        return None


def deterministic_record(c: dict, run_date: str) -> dict | None:
    """Regulator rows with no narrative: build the record from checkboxes, no LLM."""
    hints = c.get("structured_hint") or {}
    h = hints.get(c["source_type"], hints) if c["source_type"] in hints else hints
    if c["source_type"] == "hhs_portal":
        ia, veris = HHS_BREACH_TYPE.get((h.get("breach_type") or "").split(",")[0].strip(), ("unknown", "unknown"))
        org_type = HHS_ENTITY_TYPE.get(h.get("covered_entity_type") or "", "healthcare")
        records = _int(h.get("individuals_affected"))
        tech = [t.strip() for t in (h.get("location") or "").split(",") if t.strip()][:4]
    elif c["source_type"] == "state_ag":
        ia, veris = ("unknown", "unknown")
        for k, v in MAINE_DESC.items():
            if k.lower() in (h.get("breach_description") or "").lower():
                ia, veris = v
                break
        org_type = MAINE_ORG_TYPE.get(h.get("org_type_raw") or "", "unknown")
        records = _int(h.get("persons_affected"))
        tech = []
    elif c["source_type"] == "ransomware_leak_site":
        # An actor claim tells you the group and that extortion is under way. It does not
        # tell you how they got in. Record exactly that much.
        ia, veris = ("unknown", "hacking")
        org_type, records, tech = "unknown", None, []
    else:
        return None
    is_claim = c["source_type"] == "ransomware_leak_site"
    rec = {
        "id": make_id(c["org_name"], c["disclosed_date"]),
        "schema_version": "1.0",
        "org_name": c["org_name"],
        "org_type": org_type,
        "org_country": c.get("org_country", "US"),
        "disclosed_date": c["disclosed_date"],
        "incident_date": None,
        "initial_access": ia,
        "initial_access_attack_id": None,
        "veris_action": veris,
        "root_cause": None,
        "technology_involved": tech,
        "impact_type": "disruption_or_ransomware" if is_claim else "unknown",
        "records_affected": records,
        "threat_actor": (h.get("group") if is_claim else None) or None,
        "evidence_level": "actor_claimed" if is_claim else "regulator_filing",
        "confidence": "medium",
        "supporting_quote": None,
        "summary": None,
        "sources": [{"url": s["url"], "type": s["type"], "title": s.get("title"), "fetched_at": None}
                    for s in c.get("all_sources", [])],
        "extracted_by": {"model": "deterministic", "prompt_version": PROMPT_VERSION, "run_date": run_date},
        "reviewed": False,
        "notes": ("leak-site claim via Ransomware.live (Source: Ransomware.live); unverified"
                  if is_claim else "built from regulator checkboxes; no narrative available"),
    }
    errs = validate(rec)
    if errs:
        log.warning("deterministic record invalid for %s: %s", c["org_name"], errs[:2])
        return None
    return rec


def merge_into_store(store: list[dict], new: dict) -> None:
    """Upsert by id; keep the richer record; union sources; never overwrite reviewed=True."""
    by_id = {r["id"]: r for r in store}
    old = by_id.get(new["id"])
    if not old:
        store.append(new)
        return
    if old.get("reviewed"):
        urls = {s["url"] for s in old["sources"]}
        old["sources"] += [s for s in new["sources"] if s["url"] not in urls]
        return
    richness = lambda r: (r["initial_access"] != "unknown", bool(r.get("root_cause")),  # noqa: E731
                          r.get("records_affected") is not None, len(r.get("technology_involved") or []))
    keep, drop = (new, old) if richness(new) >= richness(old) else (old, new)
    urls = {s["url"] for s in keep["sources"]}
    keep["sources"] += [s for s in drop["sources"] if s["url"] not in urls]
    if keep is new:
        store[store.index(old)] = new


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-days", type=int, default=8)
    ap.add_argument("--only", help="comma-separated source names")
    ap.add_argument("--limit", type=int, default=0, help="max LLM extractions this run")
    ap.add_argument("--dry-run", action="store_true", help="collect+dedupe only; no LLM, no writes")
    ap.add_argument("--collect-only", action="store_true",
                    help="fetch sources and append new candidates to the queue; no LLM. Run daily.")
    ap.add_argument("--no-collect", action="store_true",
                    help="process the existing queue only (e.g. after backfill)")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    run_date = today()

    # The queue: data/candidates.jsonl holds raw, unprocessed candidates keyed by URL.
    # Daily collects append; the weekly run drains. This is how we beat shallow RSS feeds.
    queue = read_jsonl(CANDIDATES_PATH)
    queued_urls = {c["source_url"] for c in queue}
    if not args.no_collect:
        fresh = collect(args.since_days, args.only.split(",") if args.only else None)
        added = [c for c in fresh if c["source_url"] not in queued_urls]
        queue.extend(added)
        log.info("queue: %d existing + %d new = %d", len(queued_urls), len(added), len(queue))
    if args.collect_only:
        write_jsonl(CANDIDATES_PATH, queue)
        return 0

    cands = dedupe(queue)
    log.info("%d candidates after dedupe", len(cands))
    if args.dry_run:
        for c in cands[:50]:
            print(f"{c['disclosed_date']} {c['source_type']:<22} {c['org_name'] or '(unnamed)'!s:<40} {c['source_url']}")
        return 0

    from extract import extract_one, usage_totals  # imported late so --dry-run needs no API key

    store = read_jsonl(INCIDENTS_PATH)
    known_urls = {s["url"] for r in store for s in r["sources"]}
    known_ids = {r["id"] for r in store}
    llm_calls = 0
    processed_urls: set[str] = set()

    def done(c: dict) -> None:
        for s in c.get("all_sources", [{"url": c["source_url"]}]):
            processed_urls.add(s["url"])

    for c in cands:
        if c["source_url"] in known_urls:
            done(c)
            continue
        if c.get("org_name") and make_id(c["org_name"], c["disclosed_date"]) in known_ids \
                and c["source_type"] in ("hhs_portal", "state_ag", "ransomware_leak_site"):
            # Already have this incident from a richer source; just attach the link.
            rec = next(r for r in store if r["id"] == make_id(c["org_name"], c["disclosed_date"]))
            rec["sources"].append({"url": c["source_url"], "type": c["source_type"],
                                   "title": c.get("title"), "fetched_at": None})
            done(c)
            continue

        # Regulator rows and leak-site claims carry no narrative worth an LLM call;
        # build them from their checkboxes. Only 8-Ks, press and posts go to the model.
        if c["source_type"] in ("hhs_portal", "state_ag", "ransomware_leak_site"):
            rec = deterministic_record(c, run_date)
            if rec:
                merge_into_store(store, rec)
            done(c)
            continue

        if args.limit and llm_calls >= args.limit:
            log.info("limit reached; remaining candidates stay queued for next run")
            break

        text = c.get("text") or fetch_text(c["source_url"])
        if not text or len(text) < 200:
            log.info("no usable text for %s; dropped", c["source_url"])
            done(c)  # don't retry forever; verify_sources tracks fetch failure rate
            continue
        if not mostly_english(text):
            log.info("non-English text; dropped without LLM: %s", c["source_url"])
            done(c)
            continue
        if c["source_type"] == "sec_8k" and not looks_like_incident_8k(text):
            log.info("8-K without an incident item; dropped without LLM: %s", c["source_url"])
            done(c)
            continue

        llm_calls += 1
        try:
            rec = extract_one(c, text, run_date)
        except Exception as e:  # noqa: BLE001
            log.exception("extract failed for %s; kept in queue", c["source_url"])
            continue
        if rec:
            merge_into_store(store, rec)
        done(c)

    store.sort(key=lambda r: (r["disclosed_date"], normalize_org(r["org_name"])), reverse=True)
    write_jsonl(INCIDENTS_PATH, store)
    remaining = [c for c in queue if c["source_url"] not in processed_urls]
    write_jsonl(CANDIDATES_PATH, remaining)
    log.info("store: %d incidents; queue: %d left. LLM calls=%d input_tokens=%d output_tokens=%d",
             len(store), len(remaining), usage_totals["calls"], usage_totals["input"], usage_totals["output"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
