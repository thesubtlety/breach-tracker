# State breach lists: what is checked and what is not

Most US states require breach notices to go to the attorney general or a consumer agency,
but only some publish what they receive. This is the status of each public list as of
October 2026. "Checked daily" means the pipeline reads it every run.

| State | Publisher | What the list gives | Status |
|---|---|---|---|
| California | Attorney General | Organization, breach dates, report date, consumer letter | Checked daily; letters read |
| Texas | Attorney General | Organization, entity type, individuals affected, data types, breach and discovery dates (about 18 months kept) | Checked daily |
| Washington | Attorney General | Organization, report date, breach date, residents affected, information compromised, consumer letter | Checked daily; letters read |
| Oregon | Department of Justice | Organization, report date, breach and discovery dates, number affected (full history since 2015) | Checked daily from the US runner; the site refuses non-US addresses |
| South Carolina | Department of Consumer Affairs | Organization, report date, residents affected, consumer letter (full history since 2015) | Checked daily from the US runner; US addresses only; most letters are scans |
| Vermont | Attorney General | Organization, organization type, residents affected, categories of data (reports since April 2026) | Checked daily |
| Maine | Attorney General | Organization, entity type, dates, breach description, persons affected, consumer letter | Checked daily, but the database has been offline since October 2026 after abuse of the reporting system |
| Maryland | Attorney General | Organization, dates, number affected, how the breach occurred, information exposed, PDF notice | Not yet. The site blocks automated fetches from this machine and from GitHub's runners |
| Massachusetts | Office of Consumer Affairs and Business Regulation | Annual spreadsheets: organization, date, residents affected, data types | Not yet. Blocked for automated fetches |
| Montana | Department of Justice | Business name, breach dates, Montanans affected, notification document | Not yet. Blocked for automated fetches |
| New Hampshire | Department of Justice | Notification letters by company and year | Not yet. Blocked for automated fetches |
| Rhode Island | Attorney General | Notifications received, by year | Not yet. Blocked for automated fetches |
| Wisconsin | Department of Agriculture, Trade and Consumer Protection | Searchable breach database and an archive to 2012 | Not yet. The site does not answer automated fetches |
| New Jersey | NJCCIC | Data breach notifications page | Not yet. Blocked for automated fetches |
| Iowa | Attorney General | Breach notifications, rendered by script in the browser | Not yet. The page has no list to parse without running its script |
| Hawaii | Office of Consumer Protection | Organization, breach type, residents affected, letter | Not yet. The public table stops in April 2024 |
| Indiana | Attorney General | Annual PDF summaries only | Not planned; no per-breach list |
| Delaware | Department of Justice | Reporting forms only | Not planned; no public list |
| North Dakota | Attorney General | No list found on the current site | Not planned |

States not in this table either have no public list or publish only aggregate counts.
Federal sources are separate: the HHS breach portal (healthcare, 500 or more people) and
SEC 8-K filings are both checked daily.

To test a site from a US address, dispatch the manual `probe` workflow with the URLs and
download its `pages` artifact.
