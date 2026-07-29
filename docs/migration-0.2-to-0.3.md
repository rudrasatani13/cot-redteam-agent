# Migrating from 0.2 to 0.3

Version 0.3 is additive. Existing version-2 YAML files continue to use the
legacy `run_evaluation` attack/monitor engine unless `evaluation.suite_ids` or
`evaluation.suite_paths` is configured.

## New benchmark path

To opt in, add one or more suites:

```yaml
evaluation:
  models: [provider:model]
  suite_ids: [builtin.smoke]
  repetitions: 1
  max_expanded_trials: 10000
```

Declare the target's native role capabilities under the provider. Validation
fails before requests when a scenario requires an unsupported role. Do not
claim a capability merely to bypass validation; role flattening changes the
experiment and is intentionally not automatic.

The Python API adds `run_benchmark(config)`. `run_evaluation(config)` remains
supported for legacy attacks and monitors.

## Storage and reports

Opening an existing SQLite database applies an idempotent additive migration
for benchmark tables. Existing `runs`, `evaluation_items`, and
`monitor_outcomes` rows are unchanged.

Benchmark reports add JSONL and keep final-answer leakage, reasoning leakage,
objective success, utility, false refusal, and failures separate. There is no
single score comparable to the legacy attack-success field.

## Configuration additions

The following `evaluation` fields are optional:

- `suite_ids` and `suite_paths`;
- `policy_ids`, `technique_ids`, and `transformation_ids`;
- `repetitions` and `max_expanded_trials`;
- `judge_model` and `judge_scorers`.

Provider configuration adds `kind: openai_compatible` and a `capabilities`
object. Existing provider kinds and defaults remain valid.
