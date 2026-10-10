# Risk register

This is a best-effort experiment. The goal is good-enough data at near-zero cost, not
completeness. Each risk below has a status:

- **mitigated** — handled in code or process already
- **planned** — a concrete step exists but isn't built yet
- **accepted** — we know, we're not fixing it, and here's why

Review this file when something breaks, and once a quarter regardless. Last reviewed 2026-10-09.

## Now (first weeks)

| # | Risk | Why it matters | Mitigation | Status |
|---|---|---|---|---|
| N1 | No ground truth for model comparison | A 98% vs 99% number is noise without labels; humans disagree on `initial_access` for press articles ~10–20% of the time | `eval/`: frontier silver labels plus human gold. First run 2026-10-09: 20 docs, one reference family (OpenAI only), reviewer labeled every doc | partly mitigated; second family needs another key |
| N2 | Recall-style metric rewards guessing | The harmful failure is a confident wrong `initial_access`, not a missed one | Score per field: enum exact-match, precision on non-`unknown`, quote validity, `skip` precision/recall. `prec_known` decided against gpt-5.4-nano (0.4) | mitigated (eval/compare.py) |
| N3 | Fetch failures dominate "misses" | databreaches.net is behind a Cloudflare challenge; www.sec.gov 403s without an email in the User-Agent; 12k-char truncation can cut off Item 8.01 | Browser User-Agent fallback; feed summary used when the page is blocked; `processed.jsonl` records `no_text` so the failure rate is countable; 8-K Item-locating before truncation still to do | partly mitigated |
| N4 | EDGAR query is noisy | "cybersecurity incident" appears in merger reps and warranties; 7 of 10 hits in a 30-day sample were exhibits with no incident | Regex prefilter for `Item 1.05`/`8.01`/`7.01` near incident language; exhibits ranked below the 8-K body in dedupe | mitigated |
| N5 | "Ambiguous document" has no definition | Self-reported `confidence` is poorly calibrated | Mechanical triggers: two cheap models disagree, quote check failed, schema repair needed, press source with no company quote | planned |
| N16 | ATT&CK techniques beyond initial access rest on a keyword guard, so a technique the model states for the wrong reason survives when the words happen to appear ("account" appears in most letters, so T1078 is the one to doubt) | guard limited to a fixed list; the initial-access id still needs a quote | accepted |
| N17 | Claim confirmation rate is a floor: only filings and articles this tracker reads can confirm a claim | said on the chart; rate shown with the count | accepted |
| N14 | Letters: scanned or image-only PDFs yield no text (1 of 8 sampled); mail-merge templates carry placeholders; a letter saying only "unauthorized access" leaves initial access unknown, which is correct | outcome stored per record; placeholders stripped; no retry | accepted |
| N15 | Organization identity is a name hash plus a hand alias map; subsidiaries, renames and "X on behalf of Y" filers can split or merge wrongly | alias map reviewed as cases appear; ids restamped by migrate | accepted |
| N11 | Texas AG portal untested | Geofenced like Maine; the Salesforce app's structure is unknown from here | Test from a US network (Actions runner) before writing the source | open |
| N12 | Nasdaq price API keeps ~18 months | 41 of 86 8-K filers predate it | Alpha Vantage fallback (free key, 25/day) in `external.py`; set `ALPHAVANTAGE_API_KEY` | mitigated once the key is set |
| N13 | HIBP "added" date is not a disclosure date | Breaches surface on HIBP months or years late; `disclosed_date` is the add date | Shown as `hibp` source; incident_date carries the breach date; lag chart uses incident date | accepted |
| N6 | RSS lookback is shallow | Feeds expose the last N items; busy feeds overflow a week | Daily run; the processed log keeps re-fetched items from costing a second extraction | mitigated (daily workflow) |
| N7 | Provider JSON modes differ | `json_object` is not a schema guarantee; enum casing drifts on weaker models | Schema validation + one repair round; repair rate logged per model | mitigated |
| N8 | Regulator feeds change HTML/columns | Happened on day one: HHS is a JSF form (CSV export driven by form POSTs, two columns named after JSF components), Maine moved to list.html and serves US addresses only, ransomware.live v2 was removed, infosec.exchange tag timelines need login | `verify_sources.py` health check; `sources.py` comments record each site's current shape and date verified | mitigated (checks); fixes are manual |
| N9 | Dedupe is string matching, not entity resolution | "Change Healthcare" vs "UnitedHealth Group" become two records | Accept. Note in README. Review loop merges obvious cases | accepted |
| N10 | Legal/ToS: ransomware.live data | Their policy (README "Monetizing"): no raw data publishing, no re-serving, no relaying queries, fair polling, one key | Claim-only candidates go to a private, gitignored `data/claims.jsonl` and attach to a record only when another source confirms the incident (`run.settle_claims`); the committed store never holds them; `build_site.claim_only` is a second guard; one request per run; attribution on every claim | mitigated |

## Soon (weeks to months)

| # | Risk | Why it matters | Mitigation | Status |
|---|---|---|---|---|
| S0 | Same org, two incidents vs one incident with late coverage | Nothing in the data distinguishes them; a second record with the same name is either a real second breach or a duplicate | Rule: a new source joins an existing record within 45 days of its disclosed_date or on a matching incident_date; otherwise a new record. Review loop merges duplicates by hand (`review.py`) | accepted with rule |
| S11 | HHS rows appear 2–4 weeks after their submission date | An 8-day window misses most of them | HHS fetched with a 45-day window; the URL-keyed queue drops repeats | mitigated |
| S12 | Geofenced sources | maine.gov serves the notice list to US addresses only; works from GitHub runners, not from a European host | Fetcher logs and skips; health check counts it as a problem only after two zero runs | accepted |
| S13 | Processed-URL memory grows and can hide a real retry | `processed.jsonl` stops re-queuing skipped articles, so a transient fetch failure is never retried either | Entries pruned after 120 days; `no_text` outcomes are countable so a spike shows up in review | accepted |
| S1 | Model deprecation and renames | Haiku 5.5 and GPT-6 Luna are days/weeks old; vendors retire models in 6–12 months (GPT-5 mini/nano delisted; `deepseek-chat` retired July 2026) | Pin model IDs; `extracted_by.model` on every record; re-baseline on the eval set when switching | mitigated (recorded); re-baseline is a habit |
| S2 | Silent quality drift behind an alias | Same model name, different behavior | Weekly regression on a fixed 20-document set with a threshold; alert on drop | planned |
| S3 | Source breakage looks like a quiet week | Zero candidates is indistinguishable from no news | `verify_sources.py` fails the workflow if a source returns zero two runs in a row | mitigated |
| S4 | Stale `unknown` records | Day-1 article says "under investigation"; day-10 writeup names the cause (seen with the FBI/ShinyHunters story) | A later article is extracted on its own and merged into the existing record within the 45-day window, richer record wins; follow-ups that name the incident date join across any gap. Gap: regulator rows that attach to an `unknown` record carry no narrative, so nothing to re-extract | mostly mitigated |
| S5 | Cascade costs more than it saves | Above ~30% escalation, two calls cost more than one strong call | Log escalation rate; at this volume the cascade is justified by the disagreement signal, not savings | planned |
| S6 | Review backlog | ⚠ records accumulate faster than one person reviews | Sampling rule: review all non-`unknown` extractions + 5% of `unknown`; everything else stays flagged | accepted with rule |
| S7 | Link rot | Article text isn't stored (copyright); re-extraction needs re-fetch | Keep raw fetched text in private storage outside the public repo, or accept best-effort re-extraction | accepted; private cache optional |
| S8 | GitHub auto-disables the schedule | Public repos: 60 days without activity | Weekly data commit counts as activity; `verify_sources` commit too | mitigated |
| S9 | Rate limits, timeouts, and silent API parameter changes | SEC 10 req/s; ransomware.live 500k/month and 30-min cache; Actions 45-min job timeout; gpt-6-luna rejected `temperature: 0` and every call failed | `--limit` caps LLM calls; leftovers roll over; 4xx responses are logged with their body and not retried; no non-default sampling parameters sent | mitigated |
| S10 | Backfill volume and cost | Years of EDGAR hits × LLM calls is the one place cost shows up | Backfill is deterministic where possible; LLM only on 8-Ks with Item 1.05/8.01 and a date range you choose; `--limit` per run | mitigated |

## A year from now

| # | Risk | Why it matters | Mitigation | Status |
|---|---|---|---|---|
| Y1 | Taxonomy drift | ATT&CK ships twice a year; the DBIR split Pretexting from Phishing in 2026; "agent credential / MCP token" is a real pattern with no bucket yet (`api_or_integration_token` + `unrotated_secret_or_token` is the closest) | `schema_version` on records; enum changes are additive only; `pipeline/migrate.py` for each bump; migration note per change in `docs/CHANGELOG.md`; `docs/VERIS-MAPPING.md` kept current | mitigated; 1.1 done this way |
| Y2 | Data volume | ~15k records/year; multi-MB `incidents.json` makes the client table slow on phones | Split `incidents.json` by year, or move to SQLite + Datasette-lite. JSONL in git stays fine | planned when >10k records |
| Y3 | Disputes and takedowns | `actor_claimed` records name organizations from leak sites that misattribute; someone will dispute | Visible corrections process; "claim, not confirmed" labeling; `reviewed` + `notes` on corrected records; CHANGELOG entry per correction | planned |
| Y4 | Source landscape moves | SEC cyber rule under political pressure; NIS2 feeds may appear; more state AG feeds | Fetchers are isolated per source; yearly review of the source table in README | accepted; annual review |
| Y5 | Model question inverts | Next year's cheap model beats this year's strong one | Provider switch is one env var; eval harness re-runs in minutes | mitigated |
| Y6 | Maintainer fatigue | Pipelines survive, review loops die (see Hackmageddon, VCDB) | Zero-review output is still honest (`unknown` default, ⚠ flags); only the regression check pages a human | mitigated by design |
| Y7 | Output becomes a source and errors propagate | Once scraped and cited, wrong records spread | Monthly tagged releases; corrections CHANGELOG; version in every download | planned |
| Y8 | Imported datasets carry their own licenses | EuRepoC is CC-BY-NC; VCDB is CC BY-SA (share-alike applies to derived data) | Dataset published under CC BY-SA 4.0 (LICENSE); `imported_from` on each record; EuRepoC excluded unless a separate NC-only download is added | mitigated for VCDB; EuRepoC excluded |
| Y9 | Frontier "silver" labels were wrong | Silver labels inherit the reference model's biases; a cheap model that matches them inherits the same errors | Human adjudication of frontier disagreements; periodic 30-record human audit of agreed labels | planned |

## Things we are explicitly not doing

- Entity resolution across names and subsidiaries.
- Non-English sources.
- Any attempt to confirm leak-site claims with the named organization.
- Guaranteed completeness for any source. Regulator feeds are the floor; everything above is sampling.
