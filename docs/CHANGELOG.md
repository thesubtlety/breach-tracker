# Changelog

Schema and taxonomy changes, dataset releases, and corrections to published records.
Every entry that changes how a field is populated gets a `schema_version` bump.

## Unreleased

### 2026-10-09 — schema 1.1

Additive. Existing records migrated with `pipeline/migrate.py` (new fields unknown/null).

- `actor` object (category, variety, motive, name, country) replaces `threat_actor`.
  Variety and motive are filled deterministically for known groups (`pipeline/actors.py`);
  the model may only name a group the text attributes.
- `third_party` object (involved, archetype, vendor) following the DBIR's three archetypes.
  `initial_access` stays the mechanism; `supply_chain_or_third_party` is kept for texts
  that say only "through a vendor".
- `control_failure` enum: why the attack worked, only when stated, quote required.
- `cve` (checked verbatim against the text), `entry_asset` (VERIS hacking vector,
  collapsed), `credential_source`, `data_types`, `discovered_date`, `ransomware`.
- VCDB import mapping v2 fills actor, entry asset, CVE, data types and ransomware from
  the VERIS coding. Maine notices fill data_types and discovered_date; HHS rows fill
  data_types=medical and third_party from "Business Associate Present".
- Prompt v3 adds the rules for these fields.
- See docs/VERIS-MAPPING.md for the crosswalk.

### 2026-10-09

- Prompt v2: org_name must be the plain common name (no "(FBI)"-style suffix);
  skip retrospectives and non-English text. Records from today's first runs that
  carry `prompt_version: v1` were produced before these rules.
- Record identity: `id` is now sha1(org + first disclosed date) and later sources
  join a record within a 45-day window or on a matching incident_date (was: same
  calendar month, which split a late-September breach from its October coverage).
  Existing ids are unchanged.
- Publication rule: records whose only source is a ransomware leak-site post are
  kept in the store but withheld from the site, JSON and CSV (Ransomware.live terms).
- Pipeline memory: `data/processed.jsonl` records every handled URL and outcome so
  skipped or unfetchable articles are not re-sent to the model.
- Language guard: non-English text is dropped before the model call.
- Sources: HHS via the portal's CSV export; Maine index moved to list.html (US-only);
  ransomware.live PRO API (key required); Mastodon on mastodon.social; browser
  User-Agent for feeds and news pages; feed summary used when an article page is
  behind a bot challenge.
- First eval (20 docs, human gold): see eval/README.md.
- License: data CC BY-SA 4.0, code MIT.

- schema 1.0: initial schema. `initial_access` has 10 values + `unknown`; `veris_action`
  mirrors VERIS action categories; `evidence_level` ordered org_confirmed >
  regulator_filing > press_report > actor_claimed.
- Added `schema_version` and `imported_from` fields.

## Corrections

Format: date · record id · what changed · why · who asked (if anyone).

(none yet)
