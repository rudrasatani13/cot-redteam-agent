# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest
pytest --cov=cot_redteam --cov-report=term-missing --cov-report=json
python scripts/check_critical_coverage.py coverage.json
```

Tests must never require network access or real provider credentials.

## Style

- Ruff formatting and linting (`ruff format`, `ruff check`)
- mypy on core packages
- Prefer frozen dataclasses and strict Pydantic models for public contracts

## Issues

Open issues with:

1. expected vs actual behavior
2. minimal reproduction (config snippet, dataset lines, command)
3. Python version and package version

## Releases

Follow [docs/release-checklist.md](docs/release-checklist.md).
