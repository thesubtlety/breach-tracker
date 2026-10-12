"""Collapse candidates that describe the same incident.

Rule: same normalized org name within a 30-day window is one incident. Sources are
merged, and the candidate with the strongest evidence becomes the primary (its text
is what the LLM reads). News items with org_name "" are left alone here; they get
merged after extraction, once the LLM has named the victim (see run.merge_into_store).
"""
from __future__ import annotations

from datetime import date

from common import normalize_org

EVIDENCE_RANK = {"org_confirmed": 0, "regulator_filing": 1, "press_report": 2, "actor_claimed": 3}
WINDOW_DAYS = 30


def dedupe(cands: list[dict]) -> list[dict]:
    named = [c for c in cands if c.get("org_name")]
    unnamed = [c for c in cands if not c.get("org_name")]
    named.sort(key=lambda c: (normalize_org(c["org_name"]), c["disclosed_date"]))

    groups: list[list[dict]] = []
    for c in named:
        key = normalize_org(c["org_name"])
        d = date.fromisoformat(c["disclosed_date"])
        if groups:
            g = groups[-1]
            gkey = normalize_org(g[0]["org_name"])
            gdate = date.fromisoformat(g[0]["disclosed_date"])
            if key == gkey and abs((d - gdate).days) <= WINDOW_DAYS:
                g.append(c)
                continue
        groups.append([c])

    merged: list[dict] = []
    for g in groups:
        # Strongest evidence first; within SEC hits, the 8-K body before its exhibits.
        g.sort(key=lambda c: (EVIDENCE_RANK.get(c.get("evidence_level_hint", "press_report"), 9),
                              bool((c.get("structured_hint") or {}).get("exhibit"))))
        primary = dict(g[0])
        primary["all_sources"] = [
            {"url": c["source_url"], "type": c["source_type"], "title": c.get("title")}
            for c in g
        ]
        # Carry structured hints from every source so the LLM sees e.g. HHS breach_type
        # even when the primary is an 8-K.
        primary["structured_hint"] = {
            c["source_type"]: c.get("structured_hint") or {} for c in g
        }
        merged.append(primary)
    for c in unnamed:
        c = dict(c)
        c["all_sources"] = [{"url": c["source_url"], "type": c["source_type"], "title": c.get("title")}]
        merged.append(c)
    return merged
