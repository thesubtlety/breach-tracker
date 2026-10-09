"""Shared helpers: paths, IDs, normalization, schema validation."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
SITE_DIR = ROOT / "site"
SCHEMA_PATH = ROOT / "schema" / "incident.schema.json"
PROMPT_PATH = ROOT / "prompts" / "extract.md"
INCIDENTS_PATH = DATA_DIR / "incidents.jsonl"
CANDIDATES_PATH = DATA_DIR / "candidates.jsonl"   # the queue: collected, not yet processed
PROCESSED_PATH = DATA_DIR / "processed.jsonl"     # every URL the run has handled, with its outcome
CLAIMS_PATH = DATA_DIR / "claims.jsonl"           # leak-site claims with no confirming source; gitignored, never published
PROMPT_VERSION = "v3"
# A new source for the same org within this many days of a record's disclosed_date joins
# that record instead of creating a new one. See run.find_record for the rule.
MERGE_WINDOW_DAYS = 45

# SEC and most public sites want a descriptive User-Agent with a contact.
USER_AGENT = os.environ.get("EDGAR_USER_AGENT", "breach-tracker research contact@example.com")

_SUFFIXES = re.compile(
    r"\b(inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|plc|pllc|"
    r"lp|llp|gmbh|ag|sa|s\.a|nv|pty|pc|p\.c|dba|group|holdings)\b\.?",
    re.I,
)


def normalize_org(name: str) -> str:
    """Lowercase, strip punctuation and corporate suffixes, collapse whitespace.
    Good enough for same-week dedupe; not an entity resolver."""
    s = name.lower()
    s = s.split(" dba ")[0].split(" d/b/a ")[0]
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    s = _SUFFIXES.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def make_id(org_name: str, disclosed_date: str) -> str:
    """ID for a *new* record: normalized org + the date it was first disclosed. Later
    sources for the same incident keep this id (run.find_record), so the id is a
    permanent handle for corrections and never depends on a calendar boundary."""
    key = f"{normalize_org(org_name)}|{disclosed_date[:10]}"
    return hashlib.sha1(key.encode()).hexdigest()


def url_key(url: str) -> str:
    """Processed-log key. A hash, not the URL: the log is committed, and leak-site
    permalinks encode the victim name."""
    return hashlib.sha1(url.encode()).hexdigest()[:20]


def today() -> str:
    return date.today().isoformat()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def validate(record: dict, schema: dict | None = None) -> list[str]:
    """Return a list of validation error messages (empty if valid)."""
    import jsonschema

    schema = schema or load_schema()
    v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(record)]
