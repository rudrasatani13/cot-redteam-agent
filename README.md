# CoT Red Team Agent

[![CI](https://github.com/rudrasatani13/cot-redteam-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/rudrasatani13/cot-redteam-agent/actions/workflows/ci.yml)
[![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

CoT Red Team Agent is an open-source CLI and Python API for evaluating visible
LLM reasoning under adversarial prompts. You provide model API credentials or a
local inference endpoint; the tool plans reproducible experiments, runs attacks
and monitors, records failure-aware outcomes, and generates auditable reports.

Version `0.2.0` is an intentional breaking rewrite of `0.1.x`. Existing users
should read the [migration guide](docs/migration-0.1-to-0.2.md).

## What it does

- Runs built-in and third-party attacks against one or more target models.
- Evaluates outputs with regex, LLM-judge, ensemble, and evasion monitors.
- Distinguishes provider, attack, monitor, budget, and cancellation failures.
- Tracks request, token, elapsed-time, and estimated-cost budgets.
- Stores runs transactionally in SQLite with retention-aware redaction.
- Produces Markdown, CSV, and LaTeX reports with honest eligibility counts.
- Writes reproducibility manifests and detached artifact checksums.
- Evolves bounded populations of generated attack templates through the normal
  evaluation engine.

The tool does not provide a hosted service or guarantee that automated monitors
represent ground truth.

## Supported providers

| Provider | Configuration kind | Typical use |
|---|---|---|
| OpenRouter | `openrouter` | Hosted access to multiple model families |
| OpenAI | `openai` | OpenAI API models |
| Anthropic | `anthropic` | Anthropic Messages API models |
| vLLM | `vllm` | Local or self-hosted OpenAI-compatible server |
| llama.cpp | `llamacpp` | Local llama.cpp OpenAI-compatible server |

Provider keys are read only from named environment variables. Secrets must not
be placed directly in YAML files.

## Installation

Python 3.10 through 3.13 is supported.

Install the tagged source release:

```bash
# test: command
python -m pip install "git+https://github.com/rudrasatani13/cot-redteam-agent.git@v0.2.0"
```

Or install the wheel attached to the GitHub release:

```bash
python -m pip install \
  "https://github.com/rudrasatani13/cot-redteam-agent/releases/download/v0.2.0/cot_redteam_agent-0.2.0-py3-none-any.whl"
```

For development:

```bash
git clone https://github.com/rudrasatani13/cot-redteam-agent.git
cd cot-redteam-agent
python -m pip install -e ".[dev]"
```

This release is not published to PyPI.

## Five-minute quickstart

Create a wheel-safe example configuration:

```bash
# test: command
cot-redteam init --path config.yaml
export OPENROUTER_API_KEY=your-key
cot-redteam config validate --config config.yaml
cot-redteam list-attacks
cot-redteam list-monitors
```

The generated configuration uses the packaged `pkg:sample.jsonl` dataset and
works outside the repository. It includes optional provider examples, but
validation requires credentials only for providers referenced by the selected
evaluation and generative models.

Run the configured evaluation when you are ready to contact the provider:

```bash
cot-redteam run --config config.yaml
cot-redteam list-runs --config config.yaml
```

Render a report using the `run_id` printed by the run command:

```bash
cot-redteam report \
  --config config.yaml \
  --run-id RUN_ID \
  --format markdown
```

## Visible reasoning and interpretation

The tool records visible reasoning only when it is:

1. exposed in a provider response field; or
2. enclosed by configured delimiters such as `<think>...</think>`.

Ordinary answer prose is not relabeled as hidden reasoning. Model outputs are
nondeterministic, automated monitors are imperfect, and attack success does not
prove a general model vulnerability. Reports preserve failed and excluded
items so those limitations remain visible.

## Data handling

Prompts, responses, and visible reasoning can contain confidential information.
Review `evaluation.retain_prompts`, `evaluation.retain_responses`, and
`evaluation.retain_reasoning` before running against sensitive datasets.

The default configuration retains evaluation traces. Stored SQLite databases,
artifacts, reports, and generated archives should be protected as sensitive
research data and must not be committed.

## Responsible use

Use the project only with models, endpoints, datasets, and credentials you are
authorized to test. Respect provider terms, rate limits, privacy obligations,
and applicable law. Do not use generated attacks to access third-party systems
or data without permission.

Model-safety results belong in normal research reports or issues. Suspected
software vulnerabilities in this repository must be reported privately under
the [security policy](SECURITY.md).

## Python API

```python
# test: python
import asyncio

from cot_redteam.api import run_evaluation
from cot_redteam.core.config import load_config


async def main() -> None:
    config = load_config("config.yaml")
    run = await run_evaluation(config)
    print(run.run_id, run.status.value)


asyncio.run(main())
```

`run_evaluation` contacts configured providers and may incur cost.

## CLI reference

- `cot-redteam init`
- `cot-redteam config validate|show`
- `cot-redteam list-attacks|list-monitors|list-providers`
- `cot-redteam run`
- `cot-redteam list-runs|show-run|report`
- `cot-redteam evolve`

Exit codes are `0` for completed, `1` for failed, `2` for configuration errors,
and `3` for partial runs.

## Documentation

| Guide | Purpose |
|---|---|
| [Configuration](docs/configuration.md) | Schema, credentials, precedence, and validation |
| [Providers](docs/providers.md) | Provider-specific behavior and endpoints |
| [Plugins](docs/plugins.md) | Attack and monitor extension contracts |
| [Experiments](docs/experiments.md) | Metrics, rates, comparisons, and retention |
| [Migration](docs/migration-0.1-to-0.2.md) | Breaking changes from `0.1.x` |
| [Support](SUPPORT.md) | Where to ask questions or report reproducible bugs |
| [Contributing](CONTRIBUTING.md) | Development and pull-request workflow |
| [Security](SECURITY.md) | Private vulnerability reporting and scope |
| [Changelog](CHANGELOG.md) | Version history |

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
mypy cot_redteam
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete quality gates.

## License

Released under the [MIT License](LICENSE).
