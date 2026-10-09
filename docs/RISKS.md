# Risk register

This is a best-effort experiment. The goal is good-enough data at near-zero cost, not
completeness. Each risk below has a status:

- **mitigated** — handled in code or process already
- **planned** — a concrete step exists but isn't built yet
- **accepted** — we know, we're not fixing it, and here's why

Review this file when something breaks, and once a quarter regardless.

## Now (first weeks)

| # | Risk | Why it matters | Mitigation | Status |
|---|---|---|---|---|
| N1 | No ground truth for model comparison | A 98% vs 99% number is noise without labels; humans disagree on `initial_access` for press articles ~10–20% of the time | `eval/`: frontier models produce silver labels; disagreements between two frontier models go to a human; cheap models are scored against that | planned |
| N2 | Recall-style metric rewards guessing | The harmful failure is a confident wrong `initial_access`, not a missed one | Score per field: enum exact-match, precision on non-`unknown`, quote validity, `skip` precision/recall | planned (eval/compare.py) |
| N3 | Fetch failures dominate "misses" | Paywalls, bot challenges, JS-rendered pages, 8-K exhibits as PDFs, 12k-char truncation cutting off Item 8.01 | `verify_sources.py` reports fetch success rate per source; 8-K parser should locate the Item 1.05/8.01 section before truncating | partly mitigated; Item-locating is planned |
| N4 | EDGAR query is noisy | "cybersecurity incident" appears in merger reps and warranties; large skip fraction costs tokens | Regex prefilter for `Item 1.05`/`Item 8.01` near incident language before the LLM call | planned |
| N5 | "Ambiguous document" has no definition | Self-reported `confidence` is poorly calibrated | Mechanical triggers: two cheap models disagree, quote check failed, schema repair needed, press source with no company quote | planned |
| N6 | RSS lookback is shallow | Feeds expose the last N items; busy feeds overflow a week | Daily collect (no LLM) + weekly extract | mitigated (`--collect-only` + daily workflow) |
| N7 | Provider JSON modes differ | `json_object` is not a schema guarantee; enum casing drifts on weaker models | Schema validation + one repair round; repair rate logged per model | mitigated |
| N8 | Regulator feeds change HTML/columns | HHS column names, Maine page structure, ransomware.live field names | First run expects selector fixes; `verify_sources.py` checks required fields present | mitigated (checks); fixes are manual |
| N9 | Dedupe is string matching, not entity resolution | "Change Healthcare" vs "UnitedHealth Group" become two records | Accept. Note in README. Review loop merges obvious cases | accepted |
| N10 | Legal/ToS: ransomware.live data | Attribution required, non-commercial, no re-serving as a feed | Only tag incidents as claims and link to their permalink; never publish their victim list; attribution string stored on every claim record | mitigated |

## Soon (weeks to months)

| # | Risk | Why it matters | Mitigation | Status |
|---|---|---|---|---|
| S1 | Model deprecation and renames | Haiku 5.5 and GPT-6 Luna are days/weeks old; vendors retire models in 6–12 months (GPT-5 mini/nano delisted; `deepseek-chat` retired July 2026) | Pin model IDs; `extracted_by.model` on every record; re-baseline on the eval set when switching | mitigated (recorded); re-baseline is a habit |
| S2 | Silent quality drift behind an alias | Same model name, different behavior | Weekly regression on a fixed 20-document set with a threshold; alert on drop | planned |
| S3 | Source breakage looks like a quiet week | Zero candidates is indistinguishable from no news | `verify_sources.py` fails the workflow if a source returns zero two runs in a row | mitigated |
| S4 | Stale `unknown` records | Day-1 article says "under investigation"; day-10 vendor writeup names the cause; record never updates | Re-extract when a new source attaches to an `unknown` record; widen org-name matching for late root-cause reports | planned |
| S5 | Cascade costs more than it saves | Above ~30% escalation, two calls cost more than one strong call | Log escalation rate; at this volume the cascade is justified by the disagreement signal, not savings | planned |
| S6 | Review backlog | ⚠ records accumulate faster than one person reviews | Sampling rule: review all non-`unknown` extractions + 5% of `unknown`; everything else stays flagged | accepted with rule |
| S7 | Link rot | Article text isn't stored (copyright); re-extraction needs re-fetch | Keep raw fetched text in private storage outside the public repo, or accept best-effort re-extraction | accepted; private cache optional |
| S8 | GitHub auto-disables the schedule | Public repos: 60 days without activity | Weekly data commit counts as activity; `verify_sources` commit too | mitigated |
| S9 | Rate limits and timeouts | SEC 10 req/s; ransomware.live v2 1 req/min/endpoint; Actions 45-min job timeout | Sleeps in fetchers; `--limit` caps LLM calls; leftover candidates roll to next run | mitigated |
| S10 | Backfill volume and cost | Years of EDGAR hits × LLM calls is the one place cost shows up | Backfill is deterministic where possible; LLM only on 8-Ks with Item 1.05/8.01 and a date range you choose; `--limit` per run | mitigated |

## A year from now

| # | Risk | Why it matters | Mitigation | Status |
|---|---|---|---|---|
| Y1 | Taxonomy drift | ATT&CK ships twice a year; "AI integration / agent credential / MCP token" is already a real initial-access pattern with no bucket | `schema_version` on records; enum changes are additive only; migration note per change in `docs/CHANGELOG.md` | mitigated (field exists); discipline required |
| Y2 | Data volume | ~15k records/year; multi-MB `incidents.json` makes the client table slow on phones | Split `incidents.json` by year, or move to SQLite + Datasette-lite. JSONL in git stays fine | planned when >10k records |
| Y3 | Disputes and takedowns | `actor_claimed` records name organizations from leak sites that misattribute; someone will dispute | Visible corrections process; "claim, not confirmed" labeling; `reviewed` + `notes` on corrected records; CHANGELOG entry per correction | planned |
| Y4 | Source landscape moves | SEC cyber rule under political pressure; NIS2 feeds may appear; more state AG feeds | Fetchers are isolated per source; yearly review of the source table in README | accepted; annual review |
| Y5 | Model question inverts | Next year's cheap model beats this year's strong one | Provider switch is one env var; eval harness re-runs in minutes | mitigated |
| Y6 | Maintainer fatigue | Pipelines survive, review loops die (see Hackmageddon, VCDB) | Zero-review output is still honest (`unknown` default, ⚠ flags); only the regression check pages a human | mitigated by design |
| Y7 | Output becomes a source and errors propagate | Once scraped and cited, wrong records spread | Monthly tagged releases; corrections CHANGELOG; version in every download | planned |
| Y8 | Imported datasets carry their own licenses | EuRepoC is CC-BY-NC; VCDB is CC BY-SA (share-alike applies to derived data) | Record `imported_from` on each record; publish under a compatible license or exclude NC sources from the public dataset | planned; decide before importing EuRepoC |
| Y9 | Frontier "silver" labels were wrong | Silver labels inherit the reference model's biases; a cheap model that matches them inherits the same errors | Human adjudication of frontier disagreements; periodic 30-record human audit of agreed labels | planned |

## Things we are explicitly not doing

- Entity resolution across names and subsidiaries.
- Non-English sources.
- Any attempt to confirm leak-site claims with the named organization.
- Guaranteed completeness for any source. Regulator feeds are the floor; everything above is sampling.
