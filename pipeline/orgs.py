"""Stable organization identity.

`org_id` is a hash of the canonical key for an organization's name: the normalized
name (common.normalize_org) with "on behalf of ..." style tails cut, then mapped
through data/org_aliases.json for the spellings that normalization cannot join
("american express travel related services" -> "american express"). The id depends
only on the name and the alias map, so it is the same across runs and machines.
After editing the alias map, run `python pipeline/migrate.py` to restamp the store.

`registry(rows, prices)` folds a store into one entry per organization for the site.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from common import DATA_DIR, normalize_org

ALIASES_PATH = DATA_DIR / "org_aliases.json"
_TAIL = re.compile(r"\s+(on behalf of|and or its affiliates|and its affiliates|and affiliates|and subsidiaries|"
                   r"including)\b.*$")
_aliases: dict[str, str] | None = None


def aliases() -> dict[str, str]:
    global _aliases
    if _aliases is None:
        _aliases = json.loads(ALIASES_PATH.read_text()) if ALIASES_PATH.exists() else {}
    return _aliases


def canonical_key(name: str) -> str:
    key = _TAIL.sub("", normalize_org(name)).strip() or normalize_org(name)
    return aliases().get(key, key)


def org_id(name: str) -> str:
    return hashlib.sha1(("org|" + canonical_key(name)).encode()).hexdigest()[:12]


def display_name(names: Counter) -> str:
    """Most frequent spelling; among ties the shortest, so 'Google' beats 'Google Inc.'."""
    top = max(names.values())
    return min((n for n, c in names.items() if c == top), key=len)


def registry(rows: list[dict], prices: dict | None = None) -> list[dict]:
    prices = prices or {}
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[r.get("org_id") or org_id(r["org_name"])].append(r)
    out = []
    for oid, recs in groups.items():
        names = Counter(r["org_name"] for r in recs)
        sectors = Counter(r["org_type"] for r in recs if r.get("org_type") not in (None, "unknown"))
        countries = Counter(r["org_country"] for r in recs if r.get("org_country"))
        counts = [r["records_affected"] for r in recs if r.get("records_affected")]
        px = next((prices[r["id"]] for r in recs if r["id"] in prices and prices[r["id"]].get("ticker")), None)
        dates = sorted(r["disclosed_date"] for r in recs)
        out.append({
            "id": oid, "name": display_name(names), "aliases": sorted(n for n in names if n != display_name(names)),
            "sector": sectors.most_common(1)[0][0] if sectors else "unknown",
            "country": countries.most_common(1)[0][0] if countries else None,
            "incidents": len(recs), "first": dates[0], "last": dates[-1],
            "largest": max(counts) if counts else None, "total_records": sum(counts) if counts else None,
            "ticker": (px or {}).get("ticker"), "cik": (px or {}).get("cik"),
            "sec_filer": any(s["type"] == "sec_8k" for r in recs for s in r["sources"]),
            "ransomware": sum(1 for r in recs if r.get("ransomware") is True),
        })
    out.sort(key=lambda o: (-o["incidents"], o["name"]))
    return out
