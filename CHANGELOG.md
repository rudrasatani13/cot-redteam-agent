# Changelog

## Unreleased

## 0.3.0 — 2026-07-29

### Added

- Role-aware message and capability contracts with deterministic scripted
  multi-turn execution
- Repeated benchmark trial matrices across model, suite, policy, technique,
  transformation, and repetition
- Cryptographically random per-trial multi-fragment canaries
- Evidence-bearing deterministic scorers, strict-JSON optional judges, utility
  controls, false-refusal outcomes, and Wilson confidence intervals
- Packaged 12-scenario smoke and 56-scenario core benchmark suites
- Generic explicitly configured OpenAI-compatible provider kind
- Offline CyberSecEval and IH-Challenge JSONL adapters that never execute
  dataset grader code
- Additive benchmark SQLite schema, retention-aware transcripts, versioned
  manifests, JSONL evidence, and benchmark Markdown/CSV/LaTeX reports
- `list-suites`, `suite validate|show`, and `dataset import` CLI commands
- Verifiable `injection.system_canary` attack with an explicit trusted-system
  boundary and exact-disclosure success criteria
- Item-level Markdown evidence for retained prompts, responses, provider
  reasoning, attack assessments, and monitor outcomes

### Changed

- `cot-redteam run` selects the benchmark engine when suites are configured and
  otherwise preserves the legacy `0.2` path
- Attack success, reasoning leakage, utility, refusal, reliability, and monitor
  outcomes are no longer collapsed into one benchmark score
- Regex monitoring without visible reasoning is now non-evaluable instead of
  clean, preventing misleading evasion rates
- The packaged quickstart now uses the system-canary attack

### Compatibility

- Existing version-2 YAML configuration, `run_evaluation`, legacy plugins,
  attacks, monitors, reports, and stored runs remain supported.
- See `docs/migration-0.2-to-0.3.md`.

## 0.2.0 — 2026-07-29

Intentional breaking rewrite for production-grade CoT red-team evaluation.

### Added

- Strict `AppConfig` (version 2) with credential environment variables and redaction
- Stable attack/monitor plugin registries and entry-point discovery
- Shared asynchronous OpenAI-compatible and Anthropic providers
- Dataset digests, paired planner, budgets, async evaluation engine
- Eligibility-aware metrics (errors never count as evasion)
- Transactional SQLite store, atomic artifacts, reproducibility manifests
- Markdown / CSV / LaTeX report renderers
- Supported Python API (`run_evaluation`, `load_run`)
- Bounded generative evolution evaluated through the standard run engine
- Per-provider concurrency limits and pricing-based estimated-cost budgets
- Wheel-safe `init` configuration and packaged 15-sample dataset
- Retention-aware sanitization before SQLite and artifact persistence
- Detached manifest checksums and stored report manifests
- CI for Python 3.10–3.13, coverage floors, wheel smoke tests
- Security policy, responsible-use guidance, and contributor community files

### Removed

- `0.1.x` dual configuration paths and `BaseAttack.run` engine ownership
- Unintegrated model watcher scheduler
- Advertised but unimplemented dashboard / Parquet tracking extras

### Migration

See `docs/migration-0.1-to-0.2.md`.

### Distribution

Release artifacts are distributed through GitHub Releases. Version `0.2.0` is
not published to PyPI.
