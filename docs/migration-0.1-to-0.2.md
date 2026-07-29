# Migration guide: 0.1.x → 0.2.0

0.2 is intentionally breaking. There is no runtime compatibility mode.

## Configuration

| 0.1 | 0.2 |
|---|---|
| dual `Config` singleton + loose pydantic | single strict `AppConfig` (`version: 2`) |
| `models.*` | `providers.*` with `kind` |
| secrets in YAML / `${ENV}` substitution | `api_key_env` names only |
| `scheduler.model_watcher` | removed (experimental 0.1) |
| dashboard / parquet extras | removed from advertised install paths |

## Monitor names

| 0.1 style | 0.2 stable ID |
|---|---|
| `regex.regex` | `regex` |
| `regex.regex_advanced` | `regex_advanced` |
| `llm_judge.llm_judge` | `llm_judge` |
| `llm_judge.self_monitor` | `self_monitor` |
| `ensemble.ensemble` | `ensemble` |
| `ensemble.cascading` | `cascading` |

## Attacks

Attack IDs remain `category.name` (for example `injection.cot_injection`).
`BaseAttack.run` is removed; the evaluation engine owns execution.
Implement `create_prompt` and `assess` instead of `generate_prompt` /
`evaluate_response`.

## Results

| 0.1 | 0.2 |
|---|---|
| `AttackResult.success` | `EvaluationItem.assessment.success` |
| `MonitorResult.triggered` bool | `MonitorOutcome.status` + `triggered` property |
| free-form summary dicts | `RunSummary` + metrics eligibility rules |
| results store API | `SQLiteRunStore` |

## CLI

| 0.1 (incomplete) | 0.2 |
|---|---|
| ad-hoc scripts | `init`, `config validate/show`, `run`, `list-*`, `report`, `evolve` |

## Python imports

- `cot_redteam.models` → `cot_redteam.providers`
- `cot_redteam.eval.harness` → `cot_redteam.eval.engine` + `api.run_evaluation`
