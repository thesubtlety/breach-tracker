# Eval harness

Purpose: decide which cheap model to run, and whether a strong reviewer earns its
cost, using frontier models as a *silver* reference and a human only on disagreements.

Frontier labels are not ground truth. They're a cheap approximation that is wrong in
correlated ways (they also guess mechanism from attacker reputation). The design limits
that: two different frontier families must agree before a label counts, and every
disagreement goes to a person. A cheap model that matches silver inherits silver's
blind spots, so once a quarter also audit 30 *agreed* labels by hand (RISKS.md Y9).

## Steps

```bash
# 1. Freeze a document set (stratified by source type; text fetched once).
python eval/sample_docs.py --n 150

# 2. Reference labels from two frontier families.
python eval/label.py --role reference --provider anthropic --model claude-opus-5-5
python eval/label.py --role reference --provider openai    --model gpt-6-astra

# 3. Candidate labels.
python eval/label.py --provider anthropic  --model claude-haiku-5-5
python eval/label.py --provider openai     --model gpt-6-luna
python eval/label.py --provider openai     --model gpt-5.4-mini
python eval/label.py --provider anthropic  --model claude-sonnet-5-5
python eval/label.py --provider openai     --model gpt-6-sol
python eval/label.py --provider gemini     --model gemini-2.5-flash-lite
python eval/label.py --provider deepseek   --model deepseek-v4-flash

# 4. Score. Writes eval/results.md and eval/adjudicate.jsonl.
python eval/compare.py

# 5. Adjudicate: open eval/adjudicate.jsonl, fill `gold` per line, append
#    {"doc_id": ..., "<field>": <value>} lines to eval/gold.jsonl, re-run step 4.
```

Cost for the whole thing at 150 docs × ~4k input tokens: reference runs are a few
dollars each; candidates are cents. Re-running after a prompt change is the same.

## Reading results.md

- `prec_known` on `initial_access` is the number that decides. A model at 0.95
  prec_known with a 0.6 unknown_rate is better for this dataset than one at 0.85 with
  0.4, because a wrong confident value is the costly error.
- If a cheap model is within ~3 points of the strong one on `prec_known` and `skip_f1`,
  use the cheap one everywhere.
- If not, look at *which* docs differ (join on doc_id). If they cluster on a source
  type (press articles with multiple victims, say), the cascade trigger is that source
  type, not "confidence".

## What this doesn't measure

- Recall of incidents that never entered the pipeline (fetch failures, feeds that
  overflowed). `verify_sources.py` tracks that side.
- Drift over time. Keep 20 of these docs as a fixed regression set and re-run the
  production model on them weekly (RISKS.md S2).
