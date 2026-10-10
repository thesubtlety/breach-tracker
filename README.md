# breach-tracker

A daily, mostly-automatic list of publicly reported organizational breaches with a small
set of classifications: organization type, how the attacker got in, root cause when stated,
technology involved, impact, and how strong the evidence is. Good-enough data, cheap to run.

This is a best-effort experiment. 100% is not the goal; "better than nothing, honest
about what it doesn't know, and cheap enough to keep running" is.

Status: fetchers verified against the live sites (October 2026): SEC EDGAR, HHS (via
the portal's CSV export), RSS and Mastodon return candidates; ransomware.live needs a
free PRO key; Maine AG serves its notice list only to US addresses, so it works from
GitHub's runners but not from every laptop. First model run and a 20-document eval done 2026-10-09 with the OpenAI key:
see `eval/results.md`. gpt-6-luna is the configured extractor; gpt-5.4-mini is the
fallback if cost matters; gpt-5.4-nano guesses too often. See "First run".

Three phases, in order:

1. **Backfill** (`pipeline/backfill.py`): historical EDGAR 8-Ks, HHS, Maine, and
   ransomware.live into the queue; drained by the normal run with `--limit` so LLM
   spend is paced.
2. **Import existing coded datasets** (`pipeline/import_vcdb.py`, `import_cedb.py`):
   VCDB and UMD CEDB mapped into our schema with `imported_from` provenance, never
   re-extracted. Gives years of org-type/impact/actor history for free.
3. **Monitoring** (`.github/workflows/daily.yml`): one job a day fetches sources, extracts
   what is new (capped by `--limit`), verifies sources, rebuilds the site and commits the
   data. Actions are pinned to commit SHAs and pip is locked; Dependabot proposes bumps.

See `docs/RISKS.md` for what will go wrong now, soon, and in a year, and `eval/README.md`
for how models get compared before one is trusted.

## What is free, and what it gives you

| Source | Cost | Access | What you get | What it won't give you | Terms to respect |
|---|---|---|---|---|---|
| SEC EDGAR full-text search | Free | JSON endpoint `efts.sec.gov/LATEST/search-index`, no key. 10 req/s cap, descriptive `User-Agent` with a contact or you get 403 | Public-company incidents with a narrative paragraph. Search `"cybersecurity incident"` across all 8-K items; filtering on Item 1.05 misses most of them (one Mar–Aug 2026 sample: 13 under 1.05, 16 under 8.01, 2 under 7.01) | Root cause in most cases; filings are deliberately thin | Public record. Fair-access policy only |
| HHS OCR breach portal | Free | JSF web app; `sources.hhs_rows` drives the form and its CSV export (last 24 months of open cases, ~750 rows, posted 2–4 weeks after submission) | Every US healthcare breach ≥500 people, with covered-entity type, breach type (Hacking/IT, Theft, Loss, Improper Disposal, Unauthorized Access), location of data, count | How the hack happened. "Hacking/IT Incident" is as specific as it gets | Public domain |
| Maine AG breach notices | Free | HTML pages, label: value fields; list served to US IPs only (403/redirect elsewhere) | Entity, org type, dates occurred/discovered, breach description checkbox, persons affected, PDF of the consumer letter | Narrative, unless you also parse the PDF letter | Public record |
| Ransomware.live | Free PRO key required (ransomware.live/my; 500k req/month). The unauthenticated v2 API was removed | JSON API, `X-API-KEY` header | Leak-site claims within hours: victim, group, country, AI-assigned sector | Confirmation. These are attacker claims | Attribution required ("Source: Ransomware.live"); non-commercial without approval; do **not** re-serve their data as your own API/feed. This pipeline only tags incidents as claims and links to their permalink |
| News RSS (BleepingComputer, The Record, SecurityWeek, DataBreaches.net, Hackmageddon) | Free | RSS; article text fetched for extraction | The only place root cause and technology usually appear | Coverage of small orgs | Copyright: store one supporting sentence and the link, not the article |
| Mastodon `#databreach` | Free | Public tag timeline on mastodon.social (infosec.exchange now requires login) | Early pointers, often to the same news | Signal-to-noise | Instance ToS |
| VCDB (Verizon) | Free | GitHub, one JSON zip, CC BY-SA 4.0 | 10,047 incidents coded in VERIS (July 2026 file; has 2025 and 2026 entries). `import_vcdb.py` maps it | Representative sampling. 747 of the 749 VCDB records for 2023 are MOVEit victims coded by one analyst; use `--exclude-summary-regex MOVEit` or treat 2023 as one campaign | CC BY-SA (share-alike applies to the derived dataset) |
| California AG | Free | `oag.ca.gov/privacy/databreach/list`, HTML table, 50 rows a page back to 2012 | Organization, breach date(s), report date for every notice sent to a Californian; ~5,300 so far. Reachable from outside the US | No description, so no mechanism; the sample notice PDF has one and is not read yet | Public record |
| Have I Been Pwned breach list | Free, no key | `haveibeenpwned.com/api/v3/breaches` | 1,000+ loaded breaches: breach date, date added, record count, data classes, a description that often says how. Spam lists, stealer logs and fabricated sets skipped; the description goes through the model, the count and dates come from HIBP | Account-data breaches only; many are small forums; HIBP dates "added" can lag the breach by years | Attribution asked, given in the footer |
| Texas AG | Free | `oag.my.site.com` Salesforce app | Entity, Texans affected, data types, since 2021 | Not reachable from this host (geofenced like Maine); untested | Public record |
| UMD Cyber Events Database 2.0 | Free | cybereventsdatabase.org, CSV and JSON download | 16.7k events 2014–Mar 2026 coded by actor, motive, industry, effect | Root cause; weekly cadence | Academic citation requested |
| EuRepoC | Free, but license is now CC-BY-NC 4.0 | Zenodo CSV/XLSX/JSON; daily email tracker | 60 variables, expert-coded, state-conflict focus | Commodity breaches; stable release lags (v1.3 covers through 2024) | Non-commercial |
| UK ICO incident trends | Free | Quarterly CSV/XLSX | Sector, incident type (cyber vs non-cyber), data types, counts | Org names, narrative | Open Government Licence |
| Privacy Rights Clearinghouse Chronology | Stats free; full DB paid | Web | ~104k notifications → ~39k deduplicated events, 86 org subtypes, vendor tracking | Bulk access without paying | Paid license |
| board-cybersecurity.com tracker | Free to browse | Web only | SEC 8-K + Maine/California AG + HHS + HIBP in one table (~20k rows) | No API, no license stated; treat as a cross-check, not a source | Unknown |
| HIBP | Breach catalog free; account lookups paid | `/api/v3/breaches` no key | Breach name, date, data classes, counts | Root cause | API terms |
| Hackmageddon | Free to read | Blog + RSS | Twice-monthly timelines with motive, ATT&CK initial access, sector, country | Bulk data; no stated reuse license | Link and credit; don't bulk-copy |

Bottom line: the free regulator feeds give you *who* and *how many*; news and 8-Ks give
you *how*, for the minority of incidents where anyone said. Ransomware.live gives you
*early* and *claimed*. Nothing free gives you root cause at scale, which is why the
pipeline treats "unknown" as a normal value and tracks the share that is known.

## Hosting and compute

Checked against current plan pages:

- **GitHub Actions**: free with no minute cap on standard runners for public repos;
  2,000 min/month for private repos on the Free plan. One daily run is 3–5 minutes.
  One gotcha: in a public repo, scheduled workflows are disabled automatically after 60
  days with no repository activity. The daily data commit counts as activity, so a
  healthy run keeps itself alive; if it ever stalls, re-enable it from the Actions tab.
- **GitHub Pages**: 1 GB site, soft 100 GB/month bandwidth, soft 10 builds/hour (the
  build cap doesn't apply when deploying via Actions, which this workflow does).
- **Cloudflare Pages**: 500 builds/month, 1 concurrent build, 20,000 files, unmetered
  bandwidth for static assets. Equally free for this. Point it at the repo with no build
  command and `site/` as the output directory if you want unmetered bandwidth or
  Cloudflare's DNS.
- **Cloudflare Workers cron on the free plan is not an option for the pipeline**:
  cron triggers get 10 ms CPU and 100k requests/day; fine for a ping, not for fetching
  and parsing a few hundred pages.

Decision: GitHub Actions for compute, GitHub Pages for hosting, data committed to the
repo as JSONL so the history is the audit log. Move the static output to Cloudflare Pages
only if bandwidth becomes a thing. Total hosting cost: $0.

## Model choice

Token volumes are small. Assume ~150 LLM extractions/week (8-Ks + news; regulator rows
and leak-site claims are built deterministically without a model), ~3,500 input tokens
and ~400 output tokens each, so ~0.5M input and ~0.06M output tokens per week. Prices are
list prices checked October 2026; verify before relying on them, these move monthly.

| Provider / model | $/M in | $/M out | Est. weekly | Notes |
|---|---|---|---|---|
| Anthropic Claude Haiku 5.5 | 0.10 | 0.50 | ~$0.08 (batch ~$0.04) | Released Oct 7 2026. Tiered: $0.50/$2.50 for prompts >100k tokens, which never happens here. Newer tokenizer produces ~30% more tokens than older Claude models, so budget +30%. Forced tool-call gives guaranteed JSON shape; system prompt cacheable at $0.01/M on reads. Batch API 50% off |
| OpenAI GPT-5.4 nano | 0.20 | 1.25 | ~$0.18 | Cached input ~$0.02. Structured outputs supported |
| OpenAI GPT-5.4 mini | 0.75 | 4.50 | ~$0.65 | Overkill for this |
| Google Gemini 2.5 Flash-Lite | 0.10 | 0.40 | ~$0.07 | Flat pricing, 1M context. Older generation but adequate for extraction |
| Google Gemini 3.5 Flash-Lite | 0.30 | 2.50 | ~$0.30 | |
| DeepSeek V4-Flash | 0.14 | 0.28 | ~$0.09 | OpenAI-compatible; cache hits nearly free. Data residency is China if that matters |
| Groq Llama 3.1 8B | 0.05 | 0.08 | ~$0.03 | Cheapest, weakest. Fine if it holds the schema; test first |
| OpenRouter (Gemma 4 31B, Qwen 3.5, etc.) | ~0.10–0.30 | ~0.30–0.80 | ~$0.10 | One key, many models, ~0–5% markup. Some models have free tiers with rate limits |

Every option is under a dollar a week. Cost is not the deciding factor; schema discipline
is. The things that go wrong with cheap models are (a) inventing a root cause because the
article mentions a group known for phishing, (b) fabricating the supporting quote, and
(c) extracting a trend article as if it were an incident. The pipeline guards all three
mechanically (`extract.post_check`, the `skip` wrapper, and schema validation with one
repair round), so a weaker model mostly costs you retries, not bad data.

Recommended path: start with Haiku 5.5 or GPT-5.4 nano via `LLM_PROVIDER`. Hand-label
~50 extractions once, compare, and switch if a cheaper one matches. The provider switch
is one environment variable; nothing else changes.

## Schema

`schema/incident.schema.json` (1.1). The fields that carry the point:

- `initial_access` — ATT&CK Initial Access (TA0001) collapsed to 10 values plus
  `unknown`. `initial_access_attack_id` holds the T-number when clear.
- `veris_action` — VERIS action category so counts can sit next to DBIR numbers.
- `root_cause` — one sentence, only if stated. Null otherwise.
- `technology_involved` — named vendors/products/system types at the entry point.
- `evidence_level` — `org_confirmed` > `regulator_filing` > `press_report` > `actor_claimed`.
  Leak-site claims can never be promoted above `actor_claimed` by the model.
- `supporting_quote` — verbatim sentence; checked as a substring of the source. If it
  isn't there, confidence drops to `low`; if `initial_access` was set without one, it is
  reset to `unknown`.
- `control_failure` — why it worked, when a source says: missing MFA, unpatched known
  vuln, exposed storage, unrotated token, and so on. Distinct from `initial_access`
  (how they got in). Quote required. Expect `unknown` for most records.
- `cve`, `entry_asset`, `credential_source` — the technical detail around initial access
  when stated: which CVE, through what kind of asset, where the credentials came from.
- `third_party` — DBIR's three archetypes (vendor product, vendor-hosted data, vendor
  connection) as a flag separate from the mechanism.
- `actor` — category, variety, motive, name, country. Name only if attributed; variety
  and motive filled deterministically for known groups (`pipeline/actors.py`).
- `data_types`, `ransomware`, `discovered_date` — cheap VERIS attributes; regulators and
  VCDB supply most of them.
- `reviewed` — human flag. Reviewed records are never overwritten by later runs.
- Build-time context, not in the schema: for every CVE on a record, the date CISA listed it
  as exploited (`data/external/kev.json`, via the KEV feed or NVD); for every 8-K filer with
  a ticker, daily closes from a month before the filing to a year after
  (`data/external/prices.json`, Nasdaq data API, Alpha Vantage for filings older than the
  ~18 months Nasdaq keeps). `pipeline/external.py` refreshes both; the page shows the
  market-adjusted return at six horizons and the KEV lead time.
- `first_seen`, `updated_at` — the run that first stored the record, and the last run in
  which a later source changed it (new source, richer fields, attached claim). The site's
  "This week" panel and the `new or updated this week` filter are built from these.

`docs/VERIS-MAPPING.md` is the crosswalk to VERIS and the DBIR.

`id` is `sha1(normalized org + first disclosed date)`. A later source for the same
org joins that record if it lands within 45 days, or names the same incident date;
otherwise it becomes a second record. The data cannot tell a second breach from late
coverage, so two records with the same name is the honest default and the review loop
merges by hand.

## Pipeline

```
sources.collect   -> candidates (one per source hit)  --> data/candidates.jsonl (queue, keyed by URL)
                     daily: run.py (collect + extract)   backfill.py also writes here
dedupe.dedupe     -> one candidate per org per 30 days, strongest evidence first
run.main          -> regulator/leak rows: deterministic record from checkboxes (no LLM)
                     8-K: prefilter for Item 1.05/8.01 + incident language, else dropped
                     8-K / press / posts: fetch text -> extract.extract_one -> validate
                  -> merge into data/incidents.jsonl (upsert by id, union sources)
                  -> processed candidates leave the queue; --limit leftovers stay
verify_sources    -> data/source_health.json (zero-twice canary, link rot, quote re-check)
build_site        -> site/index.html + incidents.json + incidents.csv
```

Deterministic path matters: HHS "Theft" → `lost_or_stolen_device`, Maine "Insider
wrongdoing" → `insider`, and "Hacking/IT Incident" → `unknown` with `veris_action=hacking`.
That is more honest than asking a model to guess, and it is free.

## First run

1. Create a public repo, push this, enable Pages (Settings → Pages → Source: GitHub Actions).
2. Add secrets: one of `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` /
   `DEEPSEEK_API_KEY` / `OPENROUTER_API_KEY` / `GROQ_API_KEY`.
   Add repo variables: `LLM_PROVIDER`, optionally `LLM_MODEL`, and
   `EDGAR_USER_AGENT` = `"your-project your@email"` (SEC requires it).
3. Locally, before trusting the schedule:
   ```
   python3 -m venv .venv && .venv/bin/pip install -r pipeline/requirements.txt
   cp .env.example .env   # fill in EDGAR_USER_AGENT, one LLM key, RANSOMWARE_LIVE_API_KEY
   set -a; . ./.env; set +a
   .venv/bin/python pipeline/verify_sources.py --checks health --since-days 30   # do the fetchers work at all?
   .venv/bin/python pipeline/run.py --since-days 14 --dry-run                     # queue + dedupe, no model
   .venv/bin/python pipeline/run.py --since-days 14 --only sec_edgar,rss --limit 10
   .venv/bin/python pipeline/build_site.py && python3 -m http.server -d site
   ```
   `www.sec.gov` returns 403 unless `EDGAR_USER_AGENT` contains an email address.
4. Import history, then backfill:
   ```
   python pipeline/import_vcdb.py --since-year 2010 --exclude-summary-regex MOVEit   # ~6 min, no model calls
   python pipeline/backfill.py --start 2023-12-18 --sources sec_edgar,hhs,maine_ag
   python pipeline/run.py --no-collect --limit 200     # repeat until the queue drains
   ```
5. Pick the model with `eval/` (see `eval/README.md`) before turning the schedule on.
6. Run both workflows manually once (Actions → Run workflow), then leave them on.

## Review loop

Unreviewed records are counted on the site and marked in the table until
`reviewed: true`. The monthly habit is `python pipeline/review.py`: it walks the
model's extractions with a stated mechanism first, shows the quote and sources, and
one keypress confirms, corrects `initial_access`, adds a note, or deletes. `--merge
ID1 ID2` folds a duplicate into its original. Reviewed records survive later runs
untouched except for new source links.

## Source verification

`pipeline/verify_sources.py` runs in the daily workflow and writes
`data/source_health.json`:

- **health**: every fetcher is called for the last 30 days; required fields checked; a
  source returning zero candidates two runs in a row fails the run (a quiet week and a
  broken selector look identical otherwise).
- **links**: 20 random stored source URLs are fetched; dead rate reported, warning above 30%.
- **quotes**: 20 random extracted records are re-fetched and their `supporting_quote`
  re-checked verbatim. This is the ongoing check on the extractor, independent of the
  eval set.

Verifying *content* beyond that (is the claim true?) is out of scope. `evidence_level`
tells the reader what kind of source said it; the site never says more than that.

## Docs

- `docs/RISKS.md` — risk register with status (mitigated / planned / accepted).
- `docs/CHANGELOG.md` — schema changes, releases, corrections.
- `eval/README.md` — model comparison method.

## Known limits

- US-heavy. The regulator feeds are US; news is global; EuRepoC/UMD cover state activity.
- Org-name dedupe is string normalization, not entity resolution. "Change Healthcare"
  and "UnitedHealth Group" are two records.
- 8-K narratives rarely say how. Expect `unknown` on most of them; the value of 8-Ks is
  timing and confirmation, not mechanism.
- Supporting-quote checking catches fabricated quotes, not fabricated interpretation of
  real quotes. That is what the review loop is for.

# Monetizing
Future.

The proven model in exactly this domain is Troy Hunt’s: the site and data stay free, the API key costs money. HIBP’s lowest tier is a few dollars a month and funds the whole thing. ransomware.live is moving the same direction (free tier, free PRO key, “PRO+ coming soon”), and PRC gives stats away and charges for the full database. So charge for convenience and commercial use, not for the data:

API / feed tier: $10/month or $99/year for an API key, filtered CSV, or sector alerts. Running cost is near zero (ransomware.live PRO is free, model spend is cents a week, Actions and Pages are free), so one subscriber or one GitHub Sponsor is break-even. The proven buyer for a compiled, cited list of public filings is Privacy Rights Clearinghouse's customer: researchers, small law firms, vendor content teams, at $450–4,500/year for their product. Expect low hundreds of subscribers at most, not thousands. Interest is collected with the `api-interest` issue template linked from the site footer; build the API when the replies justify it, not before.
Commercial-use license: $500–1,500/year, paid by invoice. This is the one that works with companies. A security team can expense an invoice easily; they cannot donate $5. Make the public dataset CC BY-NC-SA and sell the commercial license, the same split EuRepoC and ransomware.live use.

Mechanics: Stripe Payment Links plus Stripe Invoicing is the lowest-friction path if you’re US-based and fine handling tax yourself (standard card fees, no monthly cost). If you want a merchant of record that handles international tax and can gate a GitHub repo or issue license keys, Polar’s Starter plan is free monthly at 5% + 50¢ per transaction, with cheaper rates on paid plans; Lemon Squeezy and Paddle are the same 5% + 50¢ shape.

Two constraints before taking any money: the paid product has to exclude ransomware.live-derived fields unless they approve commercial use, and EuRepoC can’t be in it at all (NC). VCDB’s share-alike is fine for charging but the derivative stays CC BY-SA. And put “best effort, no uptime or accuracy guarantee” in the terms; once money changes hands, people expect both.

Ransomware.live's API policy, which applies now and not just to a paid tier:

- Query fairly. Their data is cached for 30 minutes; polling more often returns nothing
  fresher and counts as abuse. The daily run makes one request.
- Do not relay other people's queries to them. Users of anything built on this data query
  this system, never Ransomware.live directly.
- No redistribution as an API or feed, and no publishing of their raw data in any form
  (API, file, or otherwise). The committed store is itself a published file, so a claim
  with no confirming source never enters it. Claims wait in `data/claims.jsonl`
  (gitignored, local only) and attach to a record only once a filing or article
  confirms the incident; `build_site.claim_only` is a second guard on the site. What
  is published is the claim tag (group, date, permalink) on confirmed records.
- No quota circumvention: one account, one key.
- No website or dashboard that mimics their look, layout, or branding.
