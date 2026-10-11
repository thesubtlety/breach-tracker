"""Stable organization identity.

`org_id` is a hash of the canonical key for an organization's name: the normalized
name (common.normalize_org) with "on behalf of ..." style tails cut, then mapped
through data/org_aliases.json for the spellings that normalization cannot join
("american express travel related services" -> "american express"). The id depends
only on the name and the alias map, so it is the same across runs and machines.
After editing the alias map, run `python pipeline/migrate.py` to restamp the store.

Vendors named in `third_party.vendor` are free text from the model: a product name
("MOVEit"), a list ("Citrix and Fortra"), or a description ("third-party contractor").
`vendor_names` turns that into company names and `vendor_id` keys each one like an
organization, via data/vendor_aliases.json (product or short name -> company) and then
the org alias map, so a vendor that is also a victim shares its id. Vendor ids are not
stored; the site derives them at build time.

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
VENDOR_ALIASES_PATH = DATA_DIR / "vendor_aliases.json"
_TAIL = re.compile(r"\s+(on behalf of|and or its affiliates|and its affiliates|and affiliates|and subsidiaries|"
                   r"including)\b.*$")
_VENDOR_TAIL = re.compile(r"\s+(aka|a k a|formerly|now part of)\b.*$")
_VENDOR_SPLIT = re.compile(r"\s*,(?!\s*(?:inc|llc|ltd|corp|co|plc|llp|lp|pc|p\.c|cpas|sa|ag|gmbh)\b)\s*(?:and\s+)?|\s*/\s*", re.I)
_PAIR = re.compile(r"(\S+)\s+and\s+(\S+)")  # "Citrix and Fortra", but not "Financial Business and Consumer Solutions"
_GENERIC = re.compile(r"\b(third.party|contractor|vendor|supplier|unnamed|undisclosed|unknown|other third parties)\b|\bprovider$")
_aliases: dict[str, str] | None = None
_vendor_aliases: dict[str, str] | None = None


def aliases() -> dict[str, str]:
    global _aliases
    if _aliases is None:
        _aliases = json.loads(ALIASES_PATH.read_text()) if ALIASES_PATH.exists() else {}
    return _aliases


def vendor_aliases() -> dict[str, str]:
    global _vendor_aliases
    if _vendor_aliases is None:
        _vendor_aliases = json.loads(VENDOR_ALIASES_PATH.read_text()) if VENDOR_ALIASES_PATH.exists() else {}
    return _vendor_aliases


def canonical_key(name: str) -> str:
    key = _TAIL.sub("", normalize_org(name)).strip() or normalize_org(name)
    return aliases().get(key, key)


def _hash(key: str) -> str:
    return hashlib.sha1(("org|" + key).encode()).hexdigest()[:12]


def org_id(name: str) -> str:
    return _hash(canonical_key(name))


def vendor_names(raw: str | None) -> list[str]:
    """Company names in a free-text vendor field: lists split, parentheticals and
    'aka' tails cut, descriptions dropped (all-lowercase, or words like 'contractor')."""
    out: list[str] = []
    parts = _VENDOR_SPLIT.split(re.sub(r"\s*\([^)]*\)", "", raw or ""))
    for part in [p for x in parts for p in (_PAIR.fullmatch(x).groups() if _PAIR.fullmatch(x) else [x])]:
        part = _VENDOR_TAIL.sub("", part).strip(" .")
        if part and part != part.lower() and not _GENERIC.search(part.lower()) and part not in out:
            out.append(part)
    return out


def vendor_key(name: str) -> str:
    key = canonical_key(name)
    return canonical_key(vendor_aliases().get(key, key))


def vendor_id(name: str) -> str:
    return _hash(vendor_key(name))


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


def vendor_registry(rows: list[dict]) -> list[dict]:
    """One entry per named third party, keyed like organizations so a vendor that is
    also a victim in the store shares its id."""
    org_ids = {r.get("org_id") for r in rows}
    groups: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for r in rows:
        for name in vendor_names((r.get("third_party") or {}).get("vendor")):
            groups[vendor_id(name)].append((name, r))
    out = []
    for vid, pairs in groups.items():
        names = Counter(name for name, _ in pairs)
        recs = [r for _, r in pairs]
        sectors = Counter(r["org_type"] for r in recs if r.get("org_type") not in (None, "unknown"))
        dates = sorted(r["disclosed_date"] for r in recs)
        out.append({"id": vid, "name": display_name(names), "aliases": sorted(n for n in names if n != display_name(names)),
                    "incidents": len(recs), "first": dates[0], "last": dates[-1],
                    "sectors": sectors.most_common(3), "is_org": vid in org_ids,
                    "archetypes": Counter(r["third_party"].get("archetype") or "unknown" for r in recs).most_common(2)})
    out.sort(key=lambda o: (-o["incidents"], o["name"]))
    return out
