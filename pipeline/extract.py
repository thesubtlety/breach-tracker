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

from common import PROMPT_PATH, PROMPT_VERSION, load_schema

log = logging.getLogger("extract")

PROVIDER = os.environ.get("LLM_PROVIDER", "anthropic")
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
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system + "\n\nReturn a JSON object with keys skip, reason, incident "
                                                   "matching this JSON Schema:\n" + json.dumps(schema)},
            {"role": "user", "content": user},
        ],
    }
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
            wait = 2 ** attempt * 5
            log.warning("llm call failed (%s); retry in %ss", e, wait)
            time.sleep(wait)
    raise RuntimeError("llm call failed after retries")


# ---------------------------------------------------------------------------
# Post-checks that cheap models need
# ---------------------------------------------------------------------------
def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


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
    if inc.get("records_affected") is not None:
        n = str(inc["records_affected"])
        if n not in re.sub(r"[,\s]", "", text):
            notes.append("records_affected not found in source; cleared")
            inc["records_affected"] = None
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
    inc["disclosed_date"] = c["disclosed_date"]
    # Evidence can only be as strong as the source we actually read.
    if c.get("evidence_level_hint") == "actor_claimed":
        inc["evidence_level"] = "actor_claimed"
    inc["id"] = make_id(inc["org_name"], inc["disclosed_date"])
    inc["schema_version"] = "1.0"
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
