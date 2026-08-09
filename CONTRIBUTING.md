# Contributing

Thank you for improving CoT Red Team Agent. Contributions should keep the
project reproducible, failure-aware, provider-neutral, and safe to run with
user-supplied credentials.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Usage questions belong in the support channels described in
[SUPPORT.md](SUPPORT.md). Do not disclose vulnerabilities in public issues or
pull requests; follow [SECURITY.md](SECURITY.md).

## Before opening a change

- Search existing issues and pull requests.
- Open an issue before large behavioral or public-API changes.
- Keep changes focused; avoid unrelated refactoring.
- Preserve backward compatibility within `0.3.x` unless the change fixes a
  security or correctness defect that cannot be addressed compatibly.
- Never include real API keys, provider responses, proprietary datasets, or
  generated artifacts.

## Development setup

```bash
git clone https://github.com/rudrasatani13/cot-redteam-agent.git
cd cot-redteam-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Use Python 3.10 through 3.13. Tests must not require network access, real
provider credentials, or paid model calls.

## Quality gates

Run the same primary checks used by CI:

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy cot_redteam
python -m pytest \
  --cov=cot_redteam \
  --cov-report=term-missing \
  --cov-report=json
python scripts/check_critical_coverage.py coverage.json
python -m build
python -m pip check
```

Behavior changes require tests. Critical modules must remain at or above the
repository's enforced coverage threshold.

## Architecture expectations

- Public contracts use explicit typed models.
- Configuration models reject unknown fields.
- Provider failures remain distinct from attack and monitor failures.
- Monitor errors must not count as successful evasion.
- External input is treated as untrusted data.
- Sensitive retention policy is applied before persistence.
- Filesystem writes are atomic where partial output would be misleading.
- Bounded retries, concurrency, request counts, token use, elapsed time, and
  estimated cost are preserved.
- Every built-in logical model call routes through
  `cot_redteam.core.invocation` (enforced by the AST source-guard test
  `tests/core/test_no_direct_provider_generate.py`); do not call
  `Provider.generate` from new production code outside provider
  implementations and `core/invocation.py`.
- Agent impact is proven only by structured observed actions and
  deterministic world state transitions (`cot_redteam.agent`); model text
  and LLM judge opinion are never proof of impact.
- New agent tool handlers must go through the deny-by-default
  `ToolGateway`; no simulated world tool may perform real filesystem,
  shell, network, subprocess, or external database effects.

## Adding an attack or monitor

Built-in attacks and monitors must:

1. declare stable plugin metadata and IDs;
2. validate configuration explicitly;
3. avoid network calls outside the configured provider abstraction;
4. return structured outcomes instead of swallowing exceptions;
5. include deterministic offline tests;
6. document any limitations or required model behavior.

Third-party integrations should use the entry-point contracts documented in
[docs/plugins.md](docs/plugins.md). Installing a Python plugin grants it code
execution in the host process, so users must trust the packages they install.

## Documentation

Update public documentation when changing configuration, CLI behavior, Python
contracts, persistence, reporting, or plugin interfaces. Examples must be
executable or clearly marked when they contact a provider.

Do not claim support for integrations, release channels, or behaviors that are
not implemented and tested.

## Pull requests

Pull requests should include:

- the problem and root cause;
- the chosen solution and relevant tradeoffs;
- tests added or updated;
- commands used for verification;
- migration or compatibility impact;
- security and data-retention impact when applicable.

Keep commits understandable and use concise imperative messages. Maintainers may
request changes when a contribution broadens scope, weakens a safety invariant,
or adds operational burden without a demonstrated use case.

## Releases

Maintainers follow [docs/release-checklist.md](docs/release-checklist.md).
