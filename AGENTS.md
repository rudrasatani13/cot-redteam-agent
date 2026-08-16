# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. This
file is the on-boarding contract: read it before making changes, follow the
quality gates, and preserve the project's security invariants.

## What this project is

CoT Red Team Agent (`cot-redteam-agent`) is an open-source CLI and Python API
for evaluating LLM and agent behavior under adversarial inputs. It runs
reproducible model attacks, offline simulated-agent scenarios, records
failure-aware evidence, and generates auditable reports and replayable
security regressions.

Architecture at a glance:

- `cot_redteam/attacks/` — attack families (`injection`, `evasion`,
  `steganography`, `distillation`, `faithfulness`, `manipulation`,
  `sandbagging`, `generative`, `harm`), each a plugin-registered
  `BaseAttack` subclass.
- `cot_redteam/benchmark/` — deterministic prompt-injection benchmark
  suites (schema, planner, engine, judge, scoring, retention).
- `cot_redteam/agent/` — v0.6 proof-of-action lane: simulated worlds,
  deny-by-default `ToolGateway`, deterministic oracles, replay artifacts,
  regression suites. **Model text is evidence; only observed simulated
  actions and state transitions prove impact.**
- `cot_redteam/eval/` — run engine, budgets, events, metrics, manifest.
- `cot_redteam/providers/` — `Provider` protocol: openrouter, openai,
  anthropic, vllm, llamacpp, openai_compatible, mock.
- `cot_redteam/core/` — config, types, serialization, invocation,
  reasoning, network policy.
- `cot_redteam/reporting/` — Markdown/CSV/LaTeX renderers, OWASP GenAI
  LLM Top 10 (2026) tagging, benchmark and agent reports.
- `cot_redteam/tui/` — interactive adaptive dashboard.
- `cot_redteam/plugins/` — attack/monitor plugin bootstrap + registry.
- `tests/` — mirrors the package layout; every module has tests.

## Development setup and quality gates

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff format --check .      # formatting
ruff check .               # lint (E, F, I, B, UP; line length 100)
mypy cot_redteam           # type checks (disallow_untyped_defs in core)
pytest                     # full suite (offline, uses the keyless mock provider)
python scripts/check_critical_coverage.py coverage.json  # coverage gate
```

CI runs all of the above plus a Python 3.10-3.13 matrix on Ubuntu, macOS,
and Windows, a hash-locked dependency install, and a wheel smoke test.
Local coverage must stay at or above the `fail_under` threshold in
`pyproject.toml` (75%), and `scripts/check_critical_coverage.py` guards
critical modules.

## Hard invariants (do not break these)

1. **No secrets in source or artifacts.** Provider keys are read only from
   named environment variables. Never write a key to YAML, logs, SQLite,
   reports, manifests, or test fixtures. Run `tests/core/test_no_direct_provider_generate.py`
   expectations: providers must be invoked through `core/invocation.py`.
2. **Deterministic proof of impact.** LLM judge opinion, assistant prose,
   and model reasoning are never proof of an exploit. Agent-lane outcomes
   must be proven by oracles over observed tool actions and pre/post world
   state snapshots (see `cot_redteam/agent/`).
3. **Budgets bound everything.** Requests, tokens, time, and estimated cost
   budgets must be honored by every new evaluation path.
4. **Retention is enforceable.** `retain_*` settings must redact prompts,
   responses, reasoning, tool arguments, and memory before persistence.
5. **Generated attack specifications are data.** Never evaluate them as
   Python or shell code. Third-party plugins and target adapters are
   trusted code that runs in-process — document that trust boundary.
6. **Reports never overclaim.** Counters use honest eligibility sets;
   refusal re-quotes are never compliant disclosure; errors are excluded,
   not silently counted; OWASP tags always cite the mapping version.
7. **Reproducibility.** New run paths must persist manifests, artifact
   checksums, and (for agent exploits) replay JSON with detached `.sha256`
   sidecars that are verified on load.

## Conventions

- Python 3.10-3.13; `from __future__ import annotations` in every module.
- Core domain types are immutable frozen dataclasses in `core/types.py`.
- Provider calls go through `core/invocation.py` (`InvocationService`),
  never directly from attacks/judges/monitors.
- New attacks register via `register_attack` (entry points for third-party
  packages); new monitors via `register_monitor`. Every registered attack
  family must resolve at least one OWASP tag.
- Attack ids are dot-namespaced (`family.name`); OWASP prefix rules rely on
  this. Add a rule in `reporting/owasp.py` when you add a family.
- Exit codes: 0 completed, 1 findings/exploit reproduced, 2 config/env
  errors, 3 partial/inconclusive, 130 interrupted. CI gates key on `1`.
- Errors are typed (`cot_redteam/core/errors.py`); use the taxonomy at
  boundaries instead of bare `ValueError`s where a taxonomy exists.

## Testing

- Add tests in the mirror directory under `tests/` (e.g. `tests/attacks/`).
- All tests must run offline and without credentials (mock provider).
- Security-critical behavior gets regression tests that pin the exact
  failure mode (see `tests/attacks/test_scoring_regressions.py`,
  `tests/storage/test_artifact_paths.py`, `tests/agent/`).
- Symlink-dependent tests are skipped on Windows (`os.name == "nt"`).
- Do not use `--timeout` without pytest-timeout (it is in dev extras).

## Docs and process

- Major versions get a design spec + implementation plan under
  `docs/superpowers/specs/` and `docs/superpowers/plans/` before coding.
- Breaking changes get a migration guide (`docs/migration-*.md`) and a
  CHANGELOG entry with the breaking boundary.
- The roadmap lives in `docs/roadmap.md`; keep it current.
- Security vulnerabilities are reported privately per `SECURITY.md`, never
  in issues or PRs.
- CI pins actions to full commit SHAs; dependency installs are
  hash-locked (`requirements-dev.lock`). Regenerate the lock with:
  `pip-compile --allow-unsafe --extra=dev --generate-hashes --output-file=requirements-dev.lock pyproject.toml`

## Useful commands

```bash
cot-redteam init --path config.yaml
cot-redteam config validate --config config.yaml
cot-redteam list-attacks && cot-redteam list-monitors
cot-redteam run --config config.yaml
cot-redteam scan --config config.yaml          # exit 1 = findings
cot-redteam agent scan --config cot_redteam/data/agent_security.example.yaml
cot-redteam replay artifacts/<run_id>/replay.json
cot-redteam regress --suite security-regressions/
```
