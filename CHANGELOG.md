# Changelog

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
