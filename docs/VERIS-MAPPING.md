# How our fields line up with VERIS and the DBIR

Our schema is deliberately small; VERIS is not. This is the crosswalk, so that counts
from this dataset can be put next to DBIR figures with the right caveats. VERIS paths
refer to verisc.json; DBIR terms to the 2026 report.

| Ours | VERIS / DBIR | Caveat |
|---|---|---|
| `initial_access` | DBIR "initial access vector", derived from the first action (`action.hacking.variety/vector`, `action.social.variety`) | DBIR computes its shares over non-Error, non-Misuse breaches; our enum includes `insider`, `lost_or_stolen_device`, `physical_or_paper`, `misconfiguration_or_exposure`. Filter those out before comparing. |
| `phishing` | `action.social.variety = Phishing` (asynchronous: email, SMS) | |
| `vishing_or_social_engineering` | `action.social.variety = Pretexting` (synchronous: phone, help desk, MFA fatigue) | Same concept; we kept our name to avoid breaking consumers. |
| `stolen_or_valid_credentials` | `action.hacking.variety = Use of stolen creds` / DBIR "credential abuse" | DBIR counts credential abuse at any point in the chain separately (39% in 2026); ours is initial access only. |
| `exploit_public_facing_app` | `action.hacking.variety = Exploit vuln` / DBIR "exploitation of vulnerabilities" | Ours implies internet-facing; VERIS does not. |
| `supply_chain_or_third_party` | no single VERIS value; DBIR "third-party involvement" is a flag, not a vector | Prefer the mechanism plus `third_party.involved`. This value remains for cases where the text says only "through a vendor". |
| `misconfiguration_or_exposure` | `action.error.variety = Misconfiguration` or `Publishing error`; `action.hacking.variety = Exploit misconfig` | |
| `insider` | `action.misuse.*` with `actor.internal` | |
| `lost_or_stolen_device` | `action.error.variety = Loss`; `action.physical.variety = Theft` | |
| `physical_or_paper` | `action.error.variety = Misdelivery`, `Disposal error`; `action.physical.*` | |
| `malware_other` | `action.malware.*` with no stated vector | |
| `veris_action` | top-level action category | Direct. |
| `entry_asset` | `action.hacking.vector`, collapsed | `vpn_or_edge_device` ⊂ VPN; `remote_desktop` = Desktop sharing + 3rd party desktop; `saas_or_cloud_console` and `api_or_integration_token` have no VERIS vector and come from `asset.cloud`/text. |
| `control_failure` | `control_failure` (free text in VERIS) / DBIR's "exposures beyond CVEs" | Ours is an enum of what public text actually states. Expect `unknown` for most records. |
| `cve` | `action.hacking.cve`, `action.malware.cve` | Direct. |
| `credential_source` | no VERIS field; DBIR's infostealer analysis | |
| `third_party` | DBIR "rule of three": vendor product / vendor-hosted data / vendor connection; VERIS `action.hacking.vector = Partner`, `actor.partner` | A partner as *vector* is not a partner as *actor*; VERIS makes the same distinction. |
| `actor.category` | `actor.external` / `actor.internal` / `actor.partner` | Direct. |
| `actor.variety` | `actor.external.variety` (Organized crime, State-affiliated, Nation-state → `state_affiliated`, Activist, Former employee, Unaffiliated); `actor.internal.variety` (End-user, System admin) | Filled deterministically for known groups by `pipeline/actors.py`. |
| `actor.motive` | `actor.*.motive` (Financial, Espionage, Ideology, Grudge) | |
| `actor.name`, `actor.country` | `actor.external.name`, `actor.external.country` | |
| `impact_type`, `ransomware` | `attribute.confidentiality.data_disclosure`, `attribute.availability`, `action.malware.variety = Ransomware` | DBIR's "ransomware in 48% of breaches" corresponds to our `ransomware = true`. |
| `data_types` | `attribute.confidentiality.data.variety` (Personal, Medical, Payment+Bank → financial, Credentials, Internal, Secrets) | |
| `records_affected` | `attribute.confidentiality.data_total` | |
| `incident_date`, `discovered_date`, `disclosed_date` | `timeline.incident`, `timeline.discovery` (as a duration in VERIS), no VERIS disclosure date | |
| `evidence_level`, `confidence`, `supporting_quote` | no VERIS equivalent (`confidence` is loosely `rec.confidence`) | Ours describe the *source*, which VERIS assumes an analyst has. |
| `org_type` | `victim.industry` (NAICS), collapsed to 14 buckets | |

Not mapped on purpose: `discovery_method`, timeline durations, `value_chain`, asset
varieties beyond the entry asset. Press rarely states them and regulators never do.
