"""Per-group statistics on ransomware leak-site claims: how many claims each group
posts, how many a filing or article later confirmed, and how long that took.

Reads the private claims queue (data/claims.jsonl, never published) and the store, and
writes aggregates only to data/external/claim_stats.json, which is committed. No claim
and no unconfirmed victim name leaves this script. Run by hand after a long collection
window; the Actions runner holds only a few days of claims.

Usage: python pipeline/claim_stats.py
"""
from __future__ import annotations

import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from actors import _CLAIM_TITLE as _TITLE, actor_key, claim_group as attached_group  # noqa: E402
from common import CLAIMS_PATH, DATA_DIR, INCIDENTS_PATH, read_jsonl, today  # noqa: E402

OUT_PATH = DATA_DIR / "external" / "claim_stats.json"
MIN_CLAIMS = 5


def claim_group(c: dict) -> str | None:
    hint = c.get("structured_hint") or {}
    g = (hint.get("ransomware_leak_site") or hint).get("group")
    return actor_key(g) or None


def record_group(r: dict) -> str | None:
    return attached_group(r) or None


def source_group(s: dict) -> str | None:
    m = s.get("title") and _TITLE.search(s["title"])
    return actor_key(m.group(1)) or None if m else None


def compute(claims: list[dict], store: list[dict], asof: str | None = None) -> dict:
    asof = asof or today()
    recent = (date.fromisoformat(asof) - timedelta(days=90)).isoformat()
    pending = defaultdict(list)
    for c in claims:
        g = claim_group(c)
        if g:
            pending[g].append(c)
    confirmed, seen = defaultdict(list), set()
    for r in store:
        for s in r["sources"]:
            if s["type"] == "ransomware_leak_site":
                g = source_group(s) or record_group(r)
                if g and (g, id(r)) not in seen:
                    seen.add((g, id(r)))
                    confirmed[g].append((r, s))
    groups = []
    for g in set(pending) | set(confirmed):
        n_pending, conf = len(pending[g]), confirmed[g]
        total = n_pending + len(conf)
        if total < MIN_CLAIMS:
            continue
        lags = []
        for r, s in conf:
            if s.get("date") and r.get("first_seen") and r["first_seen"] > s["date"]:
                lags.append((date.fromisoformat(r["first_seen"]) - date.fromisoformat(s["date"])).days)
        months = Counter(c["disclosed_date"][:7] for c in pending[g])
        months.update((s.get("date") or r["disclosed_date"])[:7] for r, s in conf)
        groups.append({
            "group": g, "claims": total, "confirmed": len(conf), "rate": round(len(conf) / total, 3),
            "by_month": sorted(months.items()),
            "last_90_days": sum(1 for c in pending[g] if c["disclosed_date"] >= recent)
            + sum(1 for r, s in conf if (s.get("date") or r["disclosed_date"]) >= recent),
            "sectors": Counter(r["org_type"] for r, _ in conf if r.get("org_type") != "unknown").most_common(3),
            "countries": Counter(c.get("org_country") for c in pending[g] if c.get("org_country") not in (None, "unknown")).most_common(3),
            "median_days_to_confirmation": statistics.median(lags) if lags else None, "n_lag": len(lags),
        })
    groups.sort(key=lambda x: (-x["claims"], x["group"]))
    return {"generated": asof, "pending": sum(len(v) for v in pending.values()),
            "confirmed": sum(len(v) for v in confirmed.values()), "min_claims": MIN_CLAIMS, "groups": groups}


def main() -> None:
    claims = read_jsonl(CLAIMS_PATH) if CLAIMS_PATH.exists() else []
    out = compute(claims, read_jsonl(INCIDENTS_PATH))
    OUT_PATH.parent.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1))
    print(f"claim stats: {out['pending']} pending, {out['confirmed']} confirmed, {len(out['groups'])} groups -> {OUT_PATH}")


if __name__ == "__main__":
    main()
