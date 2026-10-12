# Known limitations and open work

What the data cannot tell you, and what is still to build. `docs/METHODOLOGY.md` covers
how records are made.

## Limitations in the data

- **Mechanism is known for a minority of records.** Regulator rows carry no narrative, so
  the mechanism comes only from a notification letter or another source covering the same
  breach. `unknown` is the honest default and the share that is known is shown.
- **The quote check proves presence, not reading.** A verbatim quote must exist in the
  source for a mechanism to stand. Whether the model read that quote correctly is checked
  only by the twenty-document evaluation and by review.
- **ATT&CK techniques beyond initial access rest on a keyword guard.** A technique the
  model states for the wrong reason survives when the words happen to appear; T1078 is
  the one to doubt, since "account" is in most letters.
- **Organization identity is a name hash plus a short alias map.** Subsidiaries, renames
  and "X on behalf of Y" filers can split or merge wrongly. A second record with the same
  name is either a second breach or late coverage of the first; the rule is that a new
  source joins a record within 45 days of its disclosure or on a matching incident date.
- **Leak-site claims are not confirmation.** A claim attaches to a record only when a
  filing or article reports a breach at the claimed victim, and the match rate is a floor:
  most victims never file anything this tracker reads. Unmatched claims are held
  privately, per Ransomware.live's terms.
- **Dates mean different things by source.** Imported VCDB rows carry the incident date
  as the disclosure date. Have I Been Pwned's date is when the breach was added, often
  years after the fact. Regulator counts are usually one state's residents.
- **Coverage follows the sources.** US healthcare and the states with public breach lists
  dominate. VCDB's 2023 is mostly one MOVEit campaign coded by one analyst. Non-English
  sources are out of scope.
- **Some sources are fragile.** Maine's breach database is offline (October 2026). Oregon
  and South Carolina serve US addresses only, so they run on the GitHub runner. Scanned
  letters yield no text. Article text is not stored, so re-extraction needs a live page.
- **Share-price context is thin.** Nasdaq's API keeps about 18 months; older filings need
  an Alpha Vantage key. Filers have other news, so the reaction is context, not cause.
- **Models change under you.** The model and prompt version are stamped on every record.
  Re-run the evaluation before trusting a new model.

## Open work

- A second reference model family in the evaluation, and a periodic human audit of the
  labels the models agree on.
- A regression run on a fixed document set, with a threshold, so quality drift behind a
  model alias is caught.
- A corrections process with tagged dataset releases and a version in every download.
- Splitting `incidents.json` by year once the full file is slow on phones.
- A review sampling rule: every non-`unknown` extraction plus a sample of the rest.

## Not planned

- Entity resolution across names and subsidiaries.
- Non-English sources.
- Confirming leak-site claims with the named organization.
- Completeness for any source. Regulator lists are the floor; everything above is sampling.
