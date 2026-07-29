# Release checklist — 0.2.0

## Repository state

- [ ] Release commit is on the intended branch and the worktree is clean.
- [ ] Version is `0.2.0` in package metadata and changelog.
- [ ] No tag or GitHub Release named `v0.2.0` already exists.
- [ ] Diff contains no credentials, private datasets, provider responses,
      databases, reports, artifacts, caches, or build output.
- [ ] `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, and community templates
      match the release behavior.

## Local verification

- [ ] `python -m ruff format --check .`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy cot_redteam`
- [ ] `python -m pytest --cov=cot_redteam --cov-report=term-missing --cov-report=json`
- [ ] `python scripts/check_critical_coverage.py coverage.json`
- [ ] `python -m pip install --require-hashes -r requirements-dev.lock`
- [ ] `python -m build`
- [ ] `python -m pip check`
- [ ] Inspect wheel metadata and archive contents.
- [ ] Install the wheel in a clean environment outside the repository.
- [ ] Run `cot-redteam init --path config.yaml`.
- [ ] Validate with only the credential required by the selected provider.
- [ ] Load all 15 packaged samples.
- [ ] Resolve the repository security-policy chain.

## GitHub verification

- [ ] Push `codex/production-refactor-v0.2`.
- [ ] Open a pull request into `main`.
- [ ] Python 3.10, 3.11, 3.12, and 3.13 jobs pass.
- [ ] Primary formatting, lint, typing, coverage, and build jobs pass.
- [ ] Wheel smoke job passes.
- [ ] Review the final PR diff and merge without force-pushing.
- [ ] Confirm `main` contains the intended merge commit.

## Public release

- [ ] Change repository visibility to public.
- [ ] Enable GitHub private vulnerability reporting.
- [ ] Verify README, issue-template, support, and security links publicly.
- [ ] Create annotated tag `v0.2.0` from the merged `main` commit.
- [ ] Build wheel and sdist from that exact commit.
- [ ] Publish GitHub Release `v0.2.0` with changelog-derived notes.
- [ ] Attach `cot_redteam_agent-0.2.0-py3-none-any.whl`.
- [ ] Attach `cot_redteam_agent-0.2.0.tar.gz`.
- [ ] Verify release-asset checksums and clean installation.
- [ ] Confirm documentation does not claim PyPI publication.

## Acceptance criteria

| # | Criterion | Evidence |
|---|---|---|
| 1 | Wheel install, init, validate, packaged dataset | CLI tests and wheel smoke |
| 2 | Credentials resolved only for referenced providers | Configuration tests |
| 3 | Monitor failures never count as evasion | Metrics tests |
| 4 | Deterministic planning and sample pairing | Planner tests |
| 5 | Five provider kinds supported | Provider modules and example config |
| 6 | Transactional, idempotent SQLite persistence | Storage tests |
| 7 | Atomic artifacts and valid detached checksums | Artifact and manifest tests |
| 8 | Real Markdown, CSV, and LaTeX output | Reporting tests |
| 9 | CLI exit codes and supported Python API | CLI and API tests |
| 10 | Bounded evaluated generative evolution | Generative tests |
| 11 | Accurate public docs and community guidance | Documentation tests and review |
