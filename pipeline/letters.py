"""Read the consumer notification letters behind California AG notices.

A state list row says who and when. The letter the organization sent says how:
"an unauthorized actor", "our vendor X", "encrypted our systems". Letters follow a
fixed template, so only the "What happened" and "What information was involved"
sections go to the model, about a tenth of the letter.

One letter per record. A record already merged from several states or with a known
initial access is not read again. The outcome is stored on the record (`letter`)
so a run never fetches the same letter twice.

Usage:
  python pipeline/letters.py --limit 40 [--model gpt-5.4-mini] [--dry-run] [--ids ID,...]
"""
from __future__ import annotations

import argparse
import io
import logging
import re
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from common import INCIDENTS_PATH, read_jsonl, today, write_jsonl  # noqa: E402
from extract import extract_one  # noqa: E402
from run import CHECKBOX_NOTE, merge_into_store  # noqa: E402
from sources import BROWSER_UA, _get  # noqa: E402

log = logging.getLogger("letters")
logging.getLogger("pypdf").setLevel(logging.ERROR)  # font-encoding chatter on every letter

CA_HOST = "oag.ca.gov"
LETTER_HOSTS = {"agportal-s3bucket.s3.amazonaws.com": "WA", "consumer.sc.gov": "SC"}  # lists that link the PDF directly
PDF_LINK = re.compile(r'href="(https://oag\.ca\.gov/system/files/[^"]+\.pdf)"', re.I)
HEADING = re.compile(r"(?im)^[\s\W]*(what happened|what information was involved|what we are doing|"
                     r"what are we doing|what you can do|what can you do|for more information|"
                     r"other important information)\b")
STOP_AT = ("what we are", "what are we", "what you can", "what can you", "for more", "other important")
MAX_CHARS = 3500
MIN_CHARS = 200
PACE_SECONDS = 1.5
SAVE_EVERY = 50  # a backlog run takes hours; keep progress

LETTER_PREAMBLE = (
    "Consumer notification letter that the organization named below sent to affected people, "
    "filed with a state attorney general. Only the sections describing what happened and "
    "what information was involved are included. The letter is the incident; do not skip it as a "
    "retrospective. Letters rarely state how many people were affected, so leave records_affected "
    "null unless a total is written. incident_date is when the intrusion began or the data was "
    "accessed; discovered_date is when the organization learned of it. A letter that gives one "
    "date gives one of these, not both: leave the other null.\n\n"
)


def letter_sections(text: str) -> str:
    """The narrative part of a letter: from 'What happened' to the next boilerplate heading."""
    heads = list(HEADING.finditer(text))
    if heads:
        start = heads[0].start()
        stop = next((h.start() for h in heads if h.group(1).lower().startswith(STOP_AT)), len(text))
        seg = text[start:stop]
    else:
        m = re.search(r"(?i)\bdear\b", text)
        seg = text[m.start() if m else 0:]
    seg = re.sub(r"<<[^>]*>>|<[A-Z_0-9]+>", " ", seg)  # mail-merge placeholders
    return re.sub(r"[ \t]+", " ", seg).strip()[:MAX_CHARS]


def pdf_text(data: bytes) -> str:
    import pypdf
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        return "\n".join((p.extract_text() or "") for p in reader.pages[:8])
    except Exception as e:  # noqa: BLE001
        log.warning("pdf unreadable: %s", type(e).__name__)
        return ""


def letter_source(rec: dict) -> tuple[str, str] | None:
    """(url, state): a California report page, or a letter PDF linked from another state's list."""
    for s in rec["sources"]:
        if s["type"] != "state_ag":
            continue
        host = requests.utils.urlparse(s["url"]).hostname or ""
        if CA_HOST in host and "/reports/" in s["url"]:
            return s["url"], "CA"
        if host in LETTER_HOSTS and s["url"].lower().endswith(".pdf"):
            return s["url"], LETTER_HOSTS[host]
    return None


def ca_source(rec: dict) -> str | None:
    src = letter_source(rec)
    return src[0] if src else None


def wants_letter(rec: dict) -> bool:
    return (not rec.get("reviewed") and not rec.get("letter") and letter_source(rec) is not None
            and rec.get("initial_access", "unknown") == "unknown")


def fetch_letter(url: str) -> tuple[str | None, str]:
    """(pdf url, narrative text). Empty text means nothing usable."""
    if not url.lower().endswith(".pdf"):
        page = _get(url, headers={"User-Agent": BROWSER_UA})
        m = page and PDF_LINK.search(page.text)
        if not m:
            return None, ""
        url = m.group(1)
        time.sleep(PACE_SECONDS)
    pdf = _get(url, headers={"User-Agent": BROWSER_UA}, timeout=60)
    if not pdf:
        return url, ""
    return url, letter_sections(pdf_text(pdf.content))


def candidate_from(rec: dict, pdf_url: str) -> dict:
    src = letter_source(rec)
    hint = {"state": src[1] if src else "CA", "letter": True}
    for k in ("incident_date", "discovered_date", "records_affected"):
        if rec.get(k) is not None:
            hint[k] = rec[k]
    return {
        "org_name": rec["org_name"], "disclosed_date": rec["disclosed_date"],
        "source_type": "state_ag", "source_url": pdf_url,
        "title": "Notification letter", "structured_hint": hint,
        "evidence_level_hint": "org_confirmed", "org_country": rec.get("org_country"),
        "all_sources": rec["sources"] + [{"url": pdf_url, "type": "state_ag", "title": "Notification letter"}],
    }


def read_letters(store: list[dict], limit: int, model: str | None, run_date: str,
                 ids: set[str] | None = None, dry_run: bool = False, save=None, state: str | None = None) -> dict:
    todo = [r for r in store if wants_letter(r) and (not ids or r["id"] in ids) and (not state or letter_source(r)[1] == state)]
    todo.sort(key=lambda r: r["disclosed_date"], reverse=True)
    counts = {"eligible": len(todo), "read": 0, "extracted": 0, "skipped": 0, "no_text": 0, "no_letter": 0}
    for rec in todo[:limit]:
        pdf_url, text = fetch_letter(ca_source(rec))
        time.sleep(PACE_SECONDS)
        counts["read"] += 1
        if save and counts["read"] % SAVE_EVERY == 0:
            save()
            log.info("letters: %s", counts)
        if not pdf_url:
            rec["letter"] = {"url": None, "date": run_date, "outcome": "no_letter"}
            counts["no_letter"] += 1
            continue
        if len(text) < MIN_CHARS:
            rec["letter"] = {"url": pdf_url, "date": run_date, "outcome": "no_text"}
            counts["no_text"] += 1
            continue
        if dry_run:
            print(f"--- {rec['org_name']} ({rec['disclosed_date']}) {pdf_url}\n{text[:600]}\n")
            continue
        c = candidate_from(rec, pdf_url)
        try:
            new = extract_one(c, LETTER_PREAMBLE + text, run_date, model=model)
        except Exception:  # noqa: BLE001
            log.exception("extract failed for %s", rec["org_name"])
            continue
        if not new:
            rec["letter"] = {"url": pdf_url, "date": run_date, "outcome": "skipped"}
            counts["skipped"] += 1
            continue
        new["evidence_level"] = "org_confirmed"
        new["id"] = rec["id"]
        for k in ("records_affected", "technology_involved"):  # the list row's facts ride along, so the letter wins the merge
            if not new.get(k) and rec.get(k):
                new[k] = rec[k]
        merge_into_store(store, new)
        kept = next(r for r in store if r["id"] == rec["id"])
        kept["evidence_level"] = "org_confirmed"
        if kept is not new and kept.get("notes") == CHECKBOX_NOTE:
            kept["notes"] = None
        kept["letter"] = {"url": pdf_url, "date": run_date, "outcome": "extracted"}
        counts["extracted"] += 1
    return counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--model", default=None, help="override LLM_MODEL for this pass")
    ap.add_argument("--ids", default="", help="comma-separated record ids")
    ap.add_argument("--dry-run", action="store_true", help="print the text that would be sent")
    ap.add_argument("--state", default=None, help="only letters filed in this state (CA, WA, SC); some sites are US-only")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    store = read_jsonl(INCIDENTS_PATH)
    counts = read_letters(store, args.limit, args.model, today(),
                          {i for i in args.ids.split(",") if i} or None, args.dry_run,
                          save=lambda: write_jsonl(INCIDENTS_PATH, store), state=args.state)
    if not args.dry_run:
        write_jsonl(INCIDENTS_PATH, store)
    log.info("letters: %s", counts)


if __name__ == "__main__":
    main()
