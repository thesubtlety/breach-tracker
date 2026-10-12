# Eval results

Reference models: openai__gpt-6-astra  
Docs with any silver label: 20; fields needing adjudication: 0 (see eval/adjudicate.jsonl); human gold entries: 20  
Silver initial_access unknown rate: 0.15

| model | skip | initial_access | org_type | evidence_level | impact_type | veris_action | records_affected | threat_actor | root_cause_present | technology_involved | prec_known | unknown_rate | skip_f1 | quote_ok | repair | invalid |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| openai__gpt-5.4-mini | 0.85 | 0.9 | 0.95 | 0.95 | 0.9 | 0.85 | 0.95 | 0.95 | 0.9 | 0.883 | 0.75 | 0.429 | 0.897 | 0.75 | 0.0 | 0.0 |
| openai__gpt-5.4-nano | 0.75 | 0.75 | 0.85 | 0.8 | 0.65 | 0.7 | 0.95 | 0.9 | 0.75 | 0.85 | 0.4 | 0.444 | 0.815 | 1.0 | 0.0 | 0.0 |
| openai__gpt-6-luna | 0.9 | 0.95 | 1.0 | 1.0 | 0.95 | 1.0 | 1.0 | 1.0 | 0.9 | 0.912 | 0.75 | 0.333 | 0.933 | 1.0 | 0.05 | 0.0 |
| (ref) openai__gpt-6-astra | 0.9 | 1.0 | 1.0 | 0.95 | 0.95 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.5 | 0.933 | 1.0 | 0.0 | 0.0 |

Usage per model (from .meta.json):

- candidate openai:gpt-5.4-mini — {'input': 79608, 'output': 1982, 'calls': 20}
- candidate openai:gpt-5.4-nano — {'input': 79608, 'output': 2301, 'calls': 20}
- candidate openai:gpt-6-luna — {'input': 83388, 'output': 7517, 'calls': 21}
- reference openai:gpt-6-astra — {'input': 79608, 'output': 2438, 'calls': 20}
