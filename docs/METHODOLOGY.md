# Methodology

What a record is, what the checks establish, and where the data is thin.

## Records come from four kinds of source, mapped three ways

- **Regulator rows**: the HHS breach portal, the California, Texas and Maine attorney general lists, and the Have I Been Pwned catalogue, mapped by fixed rules with no model. They give who, when, how many and which data types, and rarely the mechanism. A row that lists data types gets the impact "Data exposed; theft not confirmed", because a regulator form shows that data was involved, not that it left.
- **Extracted rows**: an SEC 8-K, a news article, a breach notification letter or a catalogue description, read by a language model into `schema/incident.schema.json` using `prompts/extract.md`.
- **Imported rows**: the VERIS Community Database, recoded from VERIS fields (`docs/VERIS-MAPPING.md`). Their date is the incident date, not a disclosure date.

Every record lists its sources, the model and prompt version that produced it, and the run date.

## Each record carries one source type, ranked

The source type is the highest-ranked kind of source attached to the record: organization statement, then regulator filing, then news report, then actor claim. A regulator row moves to organization statement when its notification letter is read.

## The model records only what it can quote

A breach mechanism is recorded only with a verbatim quote, and a mechanism without one is reset to unknown. A count, CVE, actor name or ATT&CK technique is kept only if the text contains it. Leak-site claims never become records on their own. They are counted privately and matched when a filing or article reports a breach at the claimed victim; a match does not verify the claim or the group's responsibility.

Unknown means the available sources do not establish the value. It is never inferred.

## The quote check proves presence, not interpretation

The pipeline checks that the quote occurs in the source text. That shows the quote exists. It does not show the quote supports the classification, which is what human review is for. A quote that is not found lowers the classification confidence to low.

## The evaluation is twenty documents, so read gaps, not decimals

Human-checked labels, October 2026. Each cell is how many of the 20 documents the model got right.

| model | extract-or-skip decision | mechanism | sector | source type | count | quote found in text |
|---|---|---|---|---|---|---|
| gpt-6-luna (used) | 18 | 19 | 20 | 20 | 20 | 20 |
| gpt-5.4-mini | 17 | 18 | 19 | 19 | 19 | 15 |
| gpt-5.4-nano | 15 | 15 | 17 | 16 | 19 | 20 |

The extract-or-skip decision is whether the model correctly extracted an incident or skipped a document that was not one, such as a trend piece or a merger exhibit. The model returned unknown for the mechanism on 33% of the set against 15% for the human labels. On eight California notification letters, gpt-5.4-mini needed repair rounds on five and once named a forensic firm as the breached vendor; gpt-6-luna needed none and matched the human dates on every letter. Labelled documents and full tables are in `eval/`.

## Terms with a precise meaning here

- **Zero-day exploitation**: no vendor fix was available when the vulnerability was exploited. An unpatched known vulnerability is one where a fix existed and was not applied.
- **Records affected**: the figure the source gives. Regulator counts are what the filer reported, often one state's residents. Imported counts can be row counts from exposed databases rather than people.
- **Classification confidence**: how directly the quoted text supports the mechanism and weakness. High, directly stated; medium, stated with some interpretation; low, a check failed.
- **Match rate**: matched claims divided by all claims for a group. Most victims never file anything this tracker reads, so the rate reflects coverage more than accuracy.

## Coverage follows the sources, so it is uneven

US healthcare and the California, Texas and Maine reporting systems are over-represented; most of the world is missing. Regulator rows carry no mechanism until their letter is read, and scanned letters yield no text. Organization identity is a name match plus a short alias list, so a subsidiary can appear apart from its parent, and two records with one name may be separate breaches or later reporting on the same one. Share-price and KEV context is computed at build time from public APIs; it is context, not causation.

## The daily run checks its own sources

`data/source_health.json` records candidate counts per source, link rot on a sample, and whether sampled quotes are still present in their sources. Accepted risks are in `docs/RISKS.md`.
