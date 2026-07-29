# Release checklist — 0.2.0

## Commands

- [ ] `ruff format --check .`
- [ ] `ruff check .`
- [ ] `mypy cot_redteam`
- [ ] `pytest --cov=cot_redteam --cov-report=json`
- [ ] `python scripts/check_critical_coverage.py coverage.json`
- [ ] `python -m build`
- [ ] clean venv wheel install + `cot-redteam --help`

## Design acceptance criteria evidence

| # | Criterion | Evidence |
|---|---|---|
| 1 | Install wheel, init, validate, run sample | `tests/cli/*`, wheel smoke, `config.example.yaml` |
| 2 | Invalid credential → failed/partial, not zero success | `tests/core/test_config.py`, provider permanent errors |
| 3 | Monitor ERROR not counted as evasion | `tests/eval/test_metrics_v2.py` |
| 4 | Deterministic planning/sample pairing | `tests/eval/test_planner.py` |
| 5 | Five providers supported | `providers/*`, `config.example.yaml` |
| 6 | Transactional SQLite idempotency | `tests/storage/test_sqlite_v2.py` |
| 7 | Atomic artifacts + hashes | `tests/storage/test_artifacts.py` |
| 8 | Real MD/CSV/LaTeX | `tests/reporting/*` |
| 9 | CLI exit codes + Python API | `tests/cli/*`, `cot_redteam/api.py` |
| 10 | Bounded generative attacks | `tests/generative/*` |
| 11 | Docs accurate, no dashboard/parquet claims | `tests/docs/test_documented_examples.py` |
