"""Generate data/vendor_aliases.json: the company behind every third-party name in the
store ("MOVEit" -> "Progress Software"). Names already in the file are not sent again,
so a day with nothing new makes no model call. Runs after letters.py, before build_site.

    python pipeline/vendor_aliases.py [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import INCIDENTS_PATH, read_jsonl  # noqa: E402
from extract import KEY_ENV, PROVIDER, call_llm  # noqa: E402
from orgs import VENDOR_ALIASES_PATH, canonical_key, vendor_names  # noqa: E402

log = logging.getLogger("vendor_aliases")
BATCH = 200
SYSTEM = (
    "You resolve third-party names taken from data breach notifications so that one company "
    "has one name. For each name give the company's common name, without legal suffixes. "
    "A product that is not itself the name people use for the vendor becomes its maker "
    "(MOVEit -> Progress Software, GoAnywhere -> Fortra, Drift -> Salesloft). A product or "
    "service that is its own well-known name stays as it is (Mailchimp, SendGrid, Firebase, "
    "vBulletin), and a company is never resolved to its parent or acquirer, since that would "
    "join unrelated incidents. An abbreviation or spelling variant becomes the full name it "
    "stands for, which may be in the same list or among the known companies (CV3 -> "
    "CommerceV3, PBI -> PBI Research Services). Set sure=false when you do not recognize a "
    "name; it is then kept as given."
)
TASK = {"name": "resolve_vendors", "description": "The company behind each third-party name.",
        "instruction": "Return a JSON object matching this JSON Schema:"}
SCHEMA = {"type": "object", "required": ["vendors"], "additionalProperties": False,
          "properties": {"vendors": {"type": "array", "items": {
              "type": "object", "required": ["name", "company", "sure"], "additionalProperties": False,
              "properties": {"name": {"type": "string"}, "company": {"type": "string"}, "sure": {"type": "boolean"}}}}}}


def load() -> dict[str, str]:
    return json.loads(VENDOR_ALIASES_PATH.read_text()) if VENDOR_ALIASES_PATH.exists() else {}


def unresolved(rows: list[dict], known: dict[str, str]) -> list[str]:
    """One spelling per unknown canonical key, the most frequent."""
    spellings: dict[str, Counter] = {}
    for r in rows:
        for n in vendor_names((r.get("third_party") or {}).get("vendor")):
            spellings.setdefault(canonical_key(n), Counter())[n] += 1
    return sorted(c.most_common(1)[0][0] for k, c in spellings.items() if k not in known)


def resolve(names: list[str], known: dict[str, str] | None = None, call=call_llm) -> dict[str, str]:
    """canonical key of each name -> canonical key of its company. Anything the model
    did not answer, answered unsurely, or answered with a description keeps its own key."""
    out = {canonical_key(n): canonical_key(n) for n in names}
    companies = sorted(set((known or {}).values()))
    for i in range(0, len(names), BATCH):
        batch = names[i:i + BATCH]
        user = json.dumps({"names": batch, "known_companies": companies})
        got = call(SYSTEM, user, SCHEMA, task=TASK).get("vendors") or []
        for item in got:
            name, company = item.get("name"), (item.get("company") or "").strip()
            if name in batch and item.get("sure") and vendor_names(company):
                out[canonical_key(name)] = canonical_key(company)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="list unresolved names; no model call")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    known = load()
    new = unresolved(read_jsonl(INCIDENTS_PATH), known)
    log.info("%d vendor names, %d not yet resolved", len(known) + len(new), len(new))
    if not new or args.dry_run:
        print("\n".join(new))
        return 0
    if not os.environ.get(KEY_ENV[PROVIDER]):
        log.warning("no %s; vendor aliases not updated", KEY_ENV[PROVIDER])
        return 0
    resolved = resolve(new, known)
    changed = {k: v for k, v in resolved.items() if k != v}
    log.info("resolved %d names, %d to another company: %s", len(resolved), len(changed), changed)
    VENDOR_ALIASES_PATH.write_text(json.dumps(dict(sorted({**known, **resolved}.items())), indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
