# Changelog

Schema and taxonomy changes, dataset releases, and corrections to published records.
Every entry that changes how a field is populated gets a `schema_version` bump.

## Unreleased

### 2026-10-10 — schema 1.2

Additive. `pipeline/migrate.py` restamps the store.

- `attack_techniques`: every ATT&CK technique the text states (prompt v4, rule 6h), kept
  only when the text carries the behaviour's words (`extract.TECHNIQUE_TRIGGERS`); the
  initial-access id and ransomware encryption (T1486) are added from the record's own
  fields, so regulator and imported rows carry them too. Technique filter and chart.
- `sources[].date`: when a leak-site claim was posted. `pipeline/claim_stats.py` writes
  per-group aggregates (claims, confirmed, rate, 90-day activity, sectors, days to
  confirmation) to `data/external/claim_stats.json`; the claims themselves stay private.
  The page shows the table; "confirmed" means a source this tracker reads joined the record.
- Vendor names normalized (2026-10-11): `orgs.vendor_names` splits lists ("Citrix and Fortra"),
  cuts "aka" tails and parentheticals, and drops descriptions ("third-party contractor");
  `data/vendor_aliases.json` maps products and short names to the company (MOVEit ->
  Progress Software); `pipeline/vendor_aliases.py` generates it, asking the model only
  about names it has not seen, and the daily run commits it. Site rows carry
  `derived.vendors` [{id, name}] instead of `vendor_id`.
  The extractor clears a vendor that is only a description. Stored strings are unchanged.
- Vendors as entities: `orgs.vendor_registry` keys third parties like organizations, so a
  vendor that is also a victim shares its id. `#vendor=` view, `site/vendors.json`, and an
  Atom feed per vendor named on 3+ records (`site/feeds/vendor-<id>.xml`).
- CVE view (`#cve=`): product from the NVD CPE, KEV date, days from listing to the earliest
  incident citing it, and the list of CVEs cited in breaches but absent from KEV.
- Charts: technology named, dwell (intrusion to discovery) and time to notify (discovery
  to disclosure) by sector; full-text search over supporting quotes with a quotes-only
  toggle. "About the data" block with the method, the guard rules and the eval numbers.
- `pipeline/letters.py` reads the notification letter behind a California AG notice
  (only the "what happened" and "what information was involved" sections, about a
  tenth of the letter) and merges the result; outcome kept on the record as `letter`.
  One letter per record, never re-read. Daily run reads 30 new ones.
- QA pass before the first daily run: `org_id` and derived techniques are stamped on every
  merge (merges that replaced the record had dropped `org_id`; a claim attached later did
  not add T1486); a notification letter now outranks the list row it explains (evidence
  `org_confirmed`, the row's count carried over); the Atom feed title was the last entry's;
  an Actions variable left unset arrives as "" and no longer selects a provider named "";
  the quote check reads the letter PDF for letter-sourced quotes; the price fetch stops
  after three empty answers so a blocked API cannot eat the job's 30 minutes;
  `attack_techniques` in both CSVs. Page: a malformed `#id=` no longer aborts the full
  load, a failed fetch is said in the count line, country deep links survive the two-stage
  load, an organization link replaces an open vendor or CVE view, free-text fields escaped,
  source links limited to http(s).
- `org_id` on every record: hash of the normalized name after `data/org_aliases.json`
  (pipeline/orgs.py). The page gets an organization view (`#org=`), name links, and a
  repeat-organizations chart; `site/orgs.json` lists organizations with more than one
  incident or a listing. Rerun `migrate.py` after editing the alias map.
- New sources: California AG breach list (deterministic rows, incident date carried) and
  the Have I Been Pwned breach list (`hibp` source type; description extracted by the
  model, count and dates taken from HIBP; a model skip falls back to a plain row).
  State AG rows now carry `incident_date` from the notice. California: 4,953 rows
  from 2012 onward; filer names that list every affiliate are cut to the first entity.
  HIBP: 1,009 rows (14 aggregate dumps skipped). Store 8,275 -> 13,716.
- Merges fill empty fields (count, incident and discovery dates, summary, sector,
  country, data types) from the record being folded in; stated values are never replaced.
- `pipeline/external.py`: CISA KEV listing dates per CVE and 8-K filer share prices;
  `build_site` joins them as a `derived` block on site rows only. Page gets four charts:
  incident-to-disclosure lag by source, named third parties, share price after an 8-K,
  known-exploited CVEs.
- `first_seen` and `updated_at` on every record (optional in the schema; migrated with
  `pipeline/migrate.py`, first_seen = the original run date). `merge_into_store` stamps
  `updated_at` only when a merge actually changed the record. The site gets a "This week"
  panel and a `new or updated this week` filter; imported dataset rows and records
  disclosed more than 90 days ago (backfills) are excluded there.
- VCDB imported from 2010 onward (was 2022), MOVEit 2023 campaign excluded as before:
  7,432 records, incident-year dated. Store 961 -> 8,275.
- One daily workflow (`daily.yml`) replaces daily-collect + weekly: collect, extract with
  `--limit`, verify, build, commit, deploy. Actions pinned to commit SHAs, pip locked,
  Dependabot added, dispatch input passed through an env var, permissions scoped per job.
- Page loads `recent.json` (last two years plus this week's additions, ~1.2 MB) first and
  swaps in the full `incidents.json` when it arrives. `feed.xml` is an Atom feed of records
  new or changed in the last 30 days.
- `records_affected` guard accepts scaled figures ("14.64 million"); `pipeline/reextract.py`
  re-reads selected records. Counts restored for Adventure Inc, Zoomcar, loanDepot, VF Corp.
- `find_record` takes an optional org index; `settle_claims` uses it, so a weekly run with
  10k pending claims against an 8k store no longer takes minutes.

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
- Publication rule: a ransomware leak-site claim with no confirming source never
  enters the committed store; it waits in a private `data/claims.jsonl` and attaches
  to the record once a filing or article confirms the incident (Ransomware.live terms).
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
