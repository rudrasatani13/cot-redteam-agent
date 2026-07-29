# Interpreting experiments

## Item outcomes

| Status | Meaning |
|---|---|
| `succeeded` | prompt, response, assessment, and monitors completed |
| `provider_error` | model call failed permanently after retries |
| `attack_error` | attack prompt/assess raised |
| `monitor_error` | monitor raised or returned `ERROR` |
| `budget_exceeded` | request/token/time/cost budget hit |
| `cancelled` | item not scheduled after cancellation |

## Rates

- **Attack success rate** uses only `succeeded` items.
- **Evasion rate** requires every configured monitor to be evaluable (`TRIGGERED` or `CLEAN`). Items with monitor errors are **excluded**, never counted as evasion.
- Undefined rates render as `N/A`, not `0%`.

Benchmark rates use `success` and `failure` outcomes as the eligible
denominator. `inconclusive` and `error` are excluded and shown explicitly.
Binary benchmark intervals use Wilson intervals. Final-answer leakage,
reasoning leakage, benign utility, false refusal, provider reliability, and
monitor behavior remain separate dimensions; there is no universal score.

## Confidence intervals and comparisons

Bootstrap intervals need at least two eligible samples. Paired comparisons
require matching sample IDs and report group sizes, risk difference, odds
ratio (when defined), and Fisher p-value together.

## Data retention

`evaluation.retain_prompts`, `evaluation.retain_responses`, and
`evaluation.retain_reasoning` control whether sensitive traces are kept in
SQLite (and related artifacts). Treat retained traces as sensitive.
