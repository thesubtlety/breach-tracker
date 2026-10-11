"""LLM extraction with a small provider switch.

Providers (env LLM_PROVIDER):
  anthropic   -> Messages API, forced tool call = guaranteed JSON shape, prompt caching on the system prompt
  openai      -> Chat Completions, response_format json_object (works on GPT-5.4 mini/nano)
  gemini      -> Google's OpenAI-compatible endpoint
  deepseek    -> OpenAI-compatible
  openrouter  -> OpenAI-compatible; any open-weight model
  groq        -> OpenAI-compatible

All OpenAI-compatible providers share one code path. We ask for JSON, then validate
against the schema ourselves; that is the part that actually guarantees shape.

The model returns a wrapper:
  {"skip": true, "reason": "..."}                      # not an incident about one org
  {"skip": false, "incident": {...schema subset...}}   # normal case
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import time

import requests

from actors import default_actor, default_third_party, enrich_actor
from orgs import vendor_names
from common import PROMPT_PATH, PROMPT_VERSION, load_schema

log = logging.getLogger("extract")

PROVIDER = os.environ.get("LLM_PROVIDER") or "anthropic"  # an unset Actions var arrives as ""
MODEL = os.environ.get("LLM_MODEL") or {
    "anthropic": "claude-haiku-5-5",
    "openai": "gpt-5.4-nano",
    "gemini": "gemini-2.5-flash-lite",
    "deepseek": "deepseek-v4-flash",
    "openrouter": "google/gemma-4-31b-it",
    "groq": "llama-3.3-70b-versatile",
}[PROVIDER]

BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "deepseek": "https://api.deepseek.com",
    "openrouter": "https://openrouter.ai/api/v1",
    "groq": "https://api.groq.com/openai/v1",
}
KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
}

# Fields the pipeline fills itself; the model never sees or sets them.
PIPELINE_FIELDS = {"id", "sources", "extracted_by", "reviewed", "notes"}

usage_totals = {"input": 0, "output": 0, "calls": 0}


def _load_prompt() -> tuple[str, str]:
    """Split prompts/extract.md on marker lines (a line that is exactly the marker,
    so the explanatory header can mention the markers without breaking the split)."""
    raw = PROMPT_PATH.read_text()
    parts = re.split(r"^---(SYSTEM|USER)---$", raw, flags=re.M)
    # parts = [header, "SYSTEM", system_text, "USER", user_text]
    sections = dict(zip(parts[1::2], parts[2::2]))
    return sections["SYSTEM"].strip(), sections["USER"].strip()


def llm_schema() -> dict:
    """Schema subset the model fills, wrapped with skip/reason."""
    s = copy.deepcopy(load_schema())
    for f in PIPELINE_FIELDS:
        s["properties"].pop(f, None)
    s["required"] = [r for r in s["required"] if r not in PIPELINE_FIELDS]
    s.pop("$id", None)
    s.pop("$schema", None)
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "skip": {"type": "boolean"},
            "reason": {"type": ["string", "null"]},
            "incident": s,
        },
        "required": ["skip"],
    }


def _user_message(c: dict, text: str) -> str:
    _, tmpl = _load_prompt()
    hint = json.dumps(c.get("structured_hint") or {}, ensure_ascii=False)
    return (tmpl.replace("{{org_name}}", c.get("org_name") or "(not known; identify from text)")
                .replace("{{disclosed_date}}", c["disclosed_date"])
                .replace("{{source_type}}", c["source_type"])
                .replace("{{source_url}}", c["source_url"])
                .replace("{{structured_hint}}", hint)
                .replace("{{text}}", text))


# ---------------------------------------------------------------------------
# Provider calls
# ---------------------------------------------------------------------------
def _call_anthropic(system: str, user: str, schema: dict, model: str) -> dict:
    r = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": os.environ[KEY_ENV["anthropic"]],
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1200,
            # Cache the fixed system prompt; it's identical across every call in a run.
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "tools": [{"name": "record_incident",
                       "description": "Record the extracted incident or skip.",
                       "input_schema": schema}],
            "tool_choice": {"type": "tool", "name": "record_incident"},
            "messages": [{"role": "user", "content": user}],
        },
        timeout=120,
    )
    r.raise_for_status()
    body = r.json()
    u = body.get("usage", {})
    usage_totals["input"] += u.get("input_tokens", 0) + u.get("cache_read_input_tokens", 0) \
        + u.get("cache_creation_input_tokens", 0)
    usage_totals["output"] += u.get("output_tokens", 0)
    for block in body.get("content", []):
        if block.get("type") == "tool_use":
            return block["input"]
    raise ValueError("no tool_use block in response")


def _call_openai_compat(system: str, user: str, schema: dict, provider: str, model: str) -> dict:
    base = os.environ.get("LLM_BASE_URL", BASE_URLS[provider])
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system + "\n\nReturn a JSON object with keys skip, reason, incident "
                                                   "matching this JSON Schema:\n" + json.dumps(schema)},
            {"role": "user", "content": user},
        ],
    }
    if os.environ.get("LLM_TEMPERATURE"):  # newer OpenAI models reject anything but the default
        payload["temperature"] = float(os.environ["LLM_TEMPERATURE"])
    if os.environ.get("LLM_JSON_SCHEMA_MODE") == "1":
        payload["response_format"] = {"type": "json_schema",
                                      "json_schema": {"name": "incident_wrapper", "schema": schema}}
    else:
        payload["response_format"] = {"type": "json_object"}
    r = requests.post(f"{base}/chat/completions",
                      headers={"Authorization": f"Bearer {os.environ[KEY_ENV[provider]]}",
                               "Content-Type": "application/json"},
                      json=payload, timeout=120)
    r.raise_for_status()
    body = r.json()
    u = body.get("usage", {})
    usage_totals["input"] += u.get("prompt_tokens", 0)
    usage_totals["output"] += u.get("completion_tokens", 0)
    content = body["choices"][0]["message"]["content"]
    content = re.sub(r"^```(json)?|```$", "", content.strip(), flags=re.M).strip()
    return json.loads(content)


def call_llm(system: str, user: str, schema: dict, provider: str | None = None,
             model: str | None = None) -> dict:
    """Provider/model default to the env-configured ones; the eval harness passes
    them explicitly so one process can score several models."""
    provider, model = provider or PROVIDER, model or MODEL
    usage_totals["calls"] += 1
    for attempt in range(3):
        try:
            if provider == "anthropic":
                return _call_anthropic(system, user, schema, model)
            return _call_openai_compat(system, user, schema, provider, model)
        except (requests.HTTPError, requests.ConnectionError, json.JSONDecodeError, ValueError) as e:
            resp = getattr(e, "response", None)
            if resp is not None and 400 <= resp.status_code < 500 and resp.status_code != 429:
                log.error("llm call rejected: %s %s", e, resp.text[:300])
                raise  # a bad request won't fix itself; don't burn 35s on retries
            wait = 2 ** attempt * 5
            log.warning("llm call failed (%s); retry in %ss", e, wait)
            time.sleep(wait)
    raise RuntimeError("llm call failed after retries")


# ---------------------------------------------------------------------------
# Post-checks that cheap models need
# ---------------------------------------------------------------------------
def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


_SCALE = {"thousand": 1e3, "k": 1e3, "million": 1e6, "m": 1e6, "mn": 1e6, "billion": 1e9, "b": 1e9, "bn": 1e9}
_SCALED = re.compile(r"(\d+(?:\.\d+)?)\s*(thousand|million|billion|k|mn|bn|m|b)\b", re.I)


def number_in_text(n: int, text: str) -> bool:
    """The count appears in the text, either as digits (commas and spaces ignored) or as a
    scaled figure such as "14.64 million" or "1.2M"."""
    if str(n) in re.sub(r"[,\s]", "", text):
        return True
    for num, unit in _SCALED.findall(text):
        v = float(num) * _SCALE[unit.lower()]
        if abs(v - n) <= max(1, 0.005 * n):
            return True
    return False


TECHNIQUE_TRIGGERS = {
    "T1566": r"phish", "T1598": r"phish|pretext|social.engineer|impersonat",
    "T1078": r"credential|password|log-?in|logged in|account|vpn|token",
    "T1190": r"vulnerab|exploit|unpatched|flaw|zero.day|cve-",
    "T1133": r"vpn|remote.access|citrix|external remote|gateway",
    "T1021": r"rdp|remote desktop", "T1195": r"supply.chain|software update|vendor|supplier|third.party",
    "T1199": r"vendor|contractor|partner|third.party|trusted", "T1110": r"brute|password.spray|credential.stuffing",
    "T1621": r"mfa|multi.?factor|push notification|authentication request",
    "T1114": r"e-?mail|mailbox|inbox", "T1213": r"file.share|sharepoint|confluence|repositor|network share|document management",
    "T1530": r"cloud storage|bucket|\bs3\b|blob|onedrive|google drive|dropbox|snowflake",
    "T1041": r"exfiltrat|copied|download|removed|stole|stolen|acquired|obtained|taken|transferred",
    "T1567": r"exfiltrat|upload|mega|cloud|transferred",
    "T1486": r"encrypt|ransomware", "T1485": r"destroy|wiped|deleted|destruction",
    "T1489": r"disrupt|shut.?down|outage|unavailable|offline|took .* offline",
    "T1491": r"deface", "T1657": r"wire|fraud|payment|invoice|diverted|transfer of funds|financial theft",
    "T1552": r"token|api key|secret|credential|hard.?coded",
}


def derived_techniques(inc: dict) -> set[str]:
    """Techniques other fields already establish."""
    out = set()
    if inc.get("initial_access_attack_id"):
        out.add(inc["initial_access_attack_id"])
    if inc.get("ransomware") is True:
        out.add("T1486")
    return out


def guard_techniques(ids: list[str] | None, text: str, inc: dict) -> list[str]:
    """Keep a model-stated technique only when the text carries the behaviour's words."""
    low = text.lower()
    kept = set()
    for t in ids or []:
        t = t.upper()
        pat = TECHNIQUE_TRIGGERS.get(t.split(".")[0])
        if pat and re.search(pat, low):
            kept.add(t)
    return sorted(kept | derived_techniques(inc))[:12]


def post_check(inc: dict, text: str) -> dict:
    """Enforce the honesty rules mechanically; the prompt alone isn't enough."""
    notes = []
    q = inc.get("supporting_quote")
    if q and _ws(q) not in _ws(text):
        notes.append("supporting_quote not found verbatim in source; confidence lowered")
        inc["confidence"] = "low"
    if inc.get("initial_access", "unknown") != "unknown" and not q:
        notes.append("initial_access set without supporting_quote; reset to unknown")
        inc["initial_access"] = "unknown"
        inc["initial_access_attack_id"] = None
        inc["confidence"] = "low"
    if inc.get("records_affected") is not None and not number_in_text(inc["records_affected"], text):
        notes.append("records_affected not found in source; cleared")
        inc["records_affected"] = None
    if inc.get("control_failure", "unknown") != "unknown" and not inc.get("supporting_quote"):
        notes.append("control_failure set without supporting_quote; reset to unknown")
        inc["control_failure"] = "unknown"
    low = text.lower()
    cves = [c.upper() for c in (inc.get("cve") or [])]
    kept = [c for c in cves if c.lower() in low]
    if len(kept) != len(cves):
        notes.append("cve not found in source; dropped " + ", ".join(sorted(set(cves) - set(kept))))
    inc["cve"] = kept
    actor = dict(default_actor(), **(inc.get("actor") or {}))
    if actor.get("name") and _ws(actor["name"]) not in _ws(text):
        notes.append(f"actor name {actor['name']!r} not in source; cleared")
        actor["name"] = None
    inc["actor"] = enrich_actor(actor)
    inc["third_party"] = dict(default_third_party(), **(inc.get("third_party") or {}))
    if inc["third_party"].get("vendor") and not vendor_names(inc["third_party"]["vendor"]):
        notes.append(f"vendor {inc['third_party']['vendor']!r} is a description, not a name; cleared")
        inc["third_party"]["vendor"] = None
    if inc.get("initial_access") != "stolen_or_valid_credentials":
        inc["credential_source"] = None
    inc.setdefault("control_failure", "unknown")
    inc.setdefault("entry_asset", "unknown")
    inc.setdefault("data_types", [])
    inc.setdefault("ransomware", None)
    inc.setdefault("discovered_date", None)
    stated = inc.get("attack_techniques") or []
    inc["attack_techniques"] = guard_techniques(stated, text, inc)
    dropped = sorted(set(t.upper() for t in stated) - set(inc["attack_techniques"]))
    if dropped:
        notes.append("attack_techniques without supporting words dropped: " + ", ".join(dropped))
    inc["notes"] = "; ".join(notes) or None
    return inc


def extract_one(c: dict, text: str, run_date: str, provider: str | None = None,
                model: str | None = None, stats: dict | None = None) -> dict | None:
    """Return a full record (pipeline fields filled) or None if skipped/invalid.
    `stats`, if given, receives repair/skip counters (used by the eval harness)."""
    from common import make_id, validate

    provider, model = provider or PROVIDER, model or MODEL
    stats = stats if stats is not None else {}
    system, _ = _load_prompt()
    schema = llm_schema()
    user = _user_message(c, text)
    out = call_llm(system, user, schema, provider, model)
    stats["raw"] = out

    if out.get("skip"):
        log.info("skip %s: %s", c["source_url"], out.get("reason"))
        stats["skipped"] = True
        return None
    inc = out.get("incident") or {}
    inc = post_check(inc, text)
    inc.setdefault("org_name", c.get("org_name") or "")
    # "Federal Bureau of Investigation (FBI)" and "Federal Bureau of Investigation" must
    # collapse to one id; the prompt asks for no parentheticals but models add them anyway.
    inc["org_name"] = re.sub(r"\s*\([^)]*\)\s*$", "", inc["org_name"]).strip() or inc["org_name"]
    inc["disclosed_date"] = c["disclosed_date"]
    # Evidence can only be as strong as the source we actually read.
    if c.get("evidence_level_hint") == "actor_claimed":
        inc["evidence_level"] = "actor_claimed"
    inc["id"] = make_id(inc["org_name"], inc["disclosed_date"])
    inc["schema_version"] = "1.2"
    inc["sources"] = [{"url": s["url"], "type": s["type"], "title": s.get("title"), "fetched_at": None}
                      for s in c.get("all_sources", [{"url": c["source_url"], "type": c["source_type"]}])]
    inc["extracted_by"] = {"model": f"{provider}:{model}", "prompt_version": PROMPT_VERSION,
                           "run_date": run_date}
    inc["reviewed"] = False

    errs = validate(inc)
    if errs:
        # One repair round: show the model its own errors.
        log.info("schema errors for %s: %s; retrying once", inc.get("org_name"), errs[:3])
        stats["repaired"] = True
        repair = user + "\n\nYour previous answer failed validation:\n- " + "\n- ".join(errs) \
            + "\nPrevious answer:\n" + json.dumps(out) + "\nReturn a corrected JSON object."
        out = call_llm(system, repair, schema, provider, model)
        if out.get("skip"):
            stats["skipped"] = True
            return None
        inc2 = post_check(out.get("incident") or {}, text)
        for k in ("id", "sources", "extracted_by", "reviewed", "disclosed_date", "schema_version"):
            inc2[k] = inc[k]
        inc2.setdefault("org_name", inc["org_name"])
        if validate(inc2):
            log.warning("dropping %s: still invalid", inc.get("org_name"))
            stats["invalid"] = True
            return None
        inc = inc2
    return inc
