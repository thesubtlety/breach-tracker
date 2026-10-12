# Breach Vectors

A dataset and site of publicly reported data breaches, classified by how the attacker
got in. Each record names the organization, the breach mechanism, the reported security
weakness, the technology involved, the actor, the impact, and the source that said so,
with the supporting sentence quoted. Where no source says how a breach happened, the
record says `unknown`.

Site: https://www.thesubtlety.com/breach-tracker/

The site has a searchable table, pages for every organization, third party, ransomware
group, ATT&CK technique and sector, and charts over the records in view.

## The data

Downloads, rebuilt daily:

- `incidents.json` and `incidents.csv`: every record.
- `feed.xml`: Atom feed of records new or changed in the last 30 days.
- `orgs.json`, `vendors.json`, `actors.json`: the entity registries behind the pages.

The committed store is `data/incidents.jsonl`, one JSON record per line, validated
against `schema/incident.schema.json`. The fields that carry the point:

| Field | Meaning |
|---|---|
| `initial_access` | Breach mechanism: ATT&CK Initial Access collapsed to ten values plus `unknown`. `initial_access_attack_id` holds the T-number when clear. |
| `control_failure` | The reported security weakness, when a source states one: missing MFA, unpatched known vulnerability, exposed storage, and so on. |
| `supporting_quote` | A verbatim sentence from the source. Every stated mechanism needs one, and the pipeline checks it against the fetched text. |
| `evidence_level` | Source type, ranked: `org_confirmed`, `regulator_filing`, `press_report`, `actor_claimed`. |
| `confidence` | How directly the quote supports the classification: high, medium, or low. |
| `cve`, `entry_asset`, `credential_source` | Technical detail around the entry point, when stated. |
| `technology_involved` | Named vendors, products and system types at the entry point. |
| `third_party` | Whether a vendor or supplier was involved, and in which role. |
| `actor` | Category, variety, motive, name and country. Name only when a source attributes. |
| `impact_type`, `ransomware`, `data_types`, `records_affected` | What happened and to how much. |
| `incident_date`, `discovered_date`, `disclosed_date` | Timing. Imported records carry the incident date as the disclosure date. |
| `sources`, `extracted_by`, `imported_from` | Where the record came from and what produced it. |
| `reviewed` | Set by a person. Reviewed records are not overwritten by later runs. |

`id` is a hash of the normalized organization name and the first disclosure date. A
later source for the same organization joins the record if it lands within 45 days or
names the same incident date; otherwise it becomes a second record.

`docs/METHODOLOGY.md` explains how records are made and what the checks establish.
`docs/VERIS-MAPPING.md` is the crosswalk to VERIS and the DBIR.

## Sources

| Source | What it gives | Terms |
|---|---|---|
| SEC EDGAR full-text search | 8-K filings with a narrative paragraph; timing and confirmation more than mechanism | Public record; descriptive `User-Agent` required |
| HHS OCR breach portal | Every US healthcare breach of 500 or more people, with breach type and count | Public domain |
| California, Texas and Maine attorney general lists | Organization, dates, counts, data types; California notices include the consumer letter, which the pipeline reads | Public record. Maine's database has been offline since October 2026 |
| Have I Been Pwned breach catalog | Breach date, record count, data classes, and a description | Attribution, given in the site footer |
| Security news feeds and Mastodon `#databreach` | The place mechanism and technology usually appear | One quoted sentence and a link are stored, not the article |
| VERIS Community Database | Historical incidents coded in VERIS, mapped into this schema and marked `imported_from` | CC BY-SA 4.0 |
| Ransomware.live | Leak-site claims by group | Claims are never published on their own. A claim appears only as a tag on a record another source reported, with attribution and a link. The data is not re-served as an API or feed |

Regulator rows are built from their form fields with no model. 8-Ks, articles and
notification letters are read by a language model into the schema, and a stated
mechanism is kept only if its quote is found in the source text.

## Running it

```
python3 -m venv .venv && .venv/bin/pip install -r pipeline/requirements.txt
cp .env.example .env            # EDGAR_USER_AGENT, one LLM key, RANSOMWARE_LIVE_API_KEY
set -a; . ./.env; set +a
.venv/bin/python pipeline/verify_sources.py --checks health --since-days 30
.venv/bin/python pipeline/run.py --since-days 14 --dry-run
.venv/bin/python pipeline/run.py --since-days 14 --limit 20
.venv/bin/python pipeline/build_site.py && python3 -m http.server -d site
.venv/bin/python -m pytest -q tests
```

`run.py` collects candidates, dedupes them, builds or extracts records, and merges them
into the store. `--limit` caps model calls per run; leftovers stay queued. `--only`
restricts the sources. `pipeline/backfill.py` queues history, `pipeline/import_vcdb.py`
imports VCDB, `pipeline/letters.py` reads notification letters, `pipeline/external.py`
refreshes the CISA KEV catalog and share prices, and `pipeline/review.py` is the manual
review loop.

The daily GitHub Actions workflow (`.github/workflows/daily.yml`) runs the same steps,
checks the sources, commits the data and deploys the site to GitHub Pages. It needs
repository variables `LLM_PROVIDER` and optionally `LLM_MODEL` and `SITE_URL`, and
secrets `EDGAR_USER_AGENT` (it carries a contact address, and secrets are masked in
the public logs), the LLM key, `RANSOMWARE_LIVE_API_KEY` and optionally
`ALPHAVANTAGE_API_KEY`. Pages must be set to deploy from GitHub Actions.

## Limits

- Coverage is uneven. US healthcare and the states with public breach lists are
  overrepresented; most sources omit the mechanism.
- Organization matching is name normalization plus an alias file, not entity
  resolution. A parent and its subsidiary can be two organizations.
- The quote check proves the sentence exists in the source, not that the model read
  it correctly. Records are machine-classified unless marked reviewed.
- Imported records have no disclosure date of their own, so time series on the site
  exclude them.

`docs/RISKS.md` lists known risks and their status. Corrections are welcome as issues
with the record id.

## License

Data: CC BY-SA 4.0. Code: MIT. See `LICENSE`.
