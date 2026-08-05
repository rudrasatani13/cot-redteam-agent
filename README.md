# CoT Red Team Agent

[![CI](https://github.com/rudrasatani13/cot-redteam-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/rudrasatani13/cot-redteam-agent/actions/workflows/ci.yml)
[![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

CoT Red Team Agent is an open-source CLI and Python API for evaluating visible
LLM reasoning under adversarial prompts. You provide model API credentials or a
local inference endpoint; the tool plans reproducible experiments, runs attacks
and monitors, records failure-aware outcomes, and generates auditable reports.

Version `0.5.0` adds a Parseltongue-inspired encoding attack family with
encoded-disclosure scoring, hedge-aware refusal classification, a keyless
`mock` provider for demos and CI, a multi-model `race` command, and a fully
tested interactive TUI while preserving the `0.4` adaptive attacks, `0.3`
benchmark, and `0.2` Python API. Existing users should also read the
[0.3 migration guide](docs/migration-0.2-to-0.3.md).

![Adaptive red-team TUI](docs/assets/tui-adaptive-redteam.png)

*Interactive adaptive TUI: multi-model board, payload attempt log, model output,
and last real successful disclosure (refusal re-quotes are not counted as success).*

## What it does

- Runs built-in and third-party attacks against one or more target models.
- Agentic canary extraction: seeds a payload bank, classifies each refusal, then
  invents the next technique until a **compliant final-text** disclosure (or
  budget). Refusal quotes are not success.
- **LLM-driven attacker** (`injection.system_canary_agent_llm`): an attacker
  model writes the next extraction prompts from the conversation (PAIR loop,
  TAP-style candidate branching) and falls back to the deterministic catalog
  if the attacker provider fails. Requires `attacker_model` in `attack_config`.
- Adaptive fixed-bank mode also available (`injection.system_canary_adaptive`).
- Interactive Codex-style TUI with slash commands, multi-model board, and live
  attempt timeline (`cot-redteam tui`).
- Runs packaged 12-trial smoke and 56-scenario core prompt-injection suites.
- Preserves system, developer, user, assistant, and simulated tool message roles.
- Scores exact and partial canary disclosure separately in final text and
  visible provider reasoning (refusal analysis that only quotes a canary is not
  success).
- Reports attack objectives, benign-task utility, false refusals, exclusions,
  and Wilson confidence intervals as separate dimensions.
- Evaluates outputs with regex, LLM-judge, ensemble, and evasion monitors.
- Distinguishes provider, attack, monitor, budget, and cancellation failures.
- Tracks request, token, elapsed-time, and estimated-cost budgets.
- Stores runs transactionally in SQLite with retention-aware redaction.
- Produces Markdown, CSV, and LaTeX reports with honest eligibility counts.
- Produces lossless JSONL benchmark evidence for retained multi-turn transcripts.
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
| Generic endpoint | `openai_compatible` | Explicit user-selected compatible API |
| Mock | `mock` | Deterministic keyless provider for demos, tests, and CI |

Provider keys are read only from named environment variables. Secrets must not
be placed directly in YAML files. The `mock` provider needs no key at all:
`mock_mode: auto|refuse|disclose|error` controls whether it discloses a
synthetic canary, refuses, or raises provider errors — ideal for smoke tests
and CI without spending any budget.

## Installation

Python 3.10 through 3.13 is supported.

Install from PyPI:

```bash
python -m pip install cot-redteam-agent
```

Or install the tagged source release:

```bash
# test: command
python -m pip install "git+https://github.com/rudrasatani13/cot-redteam-agent.git@v0.5.0"
```

Or install the wheel attached to the GitHub release:

```bash
python -m pip install \
  "https://github.com/rudrasatani13/cot-redteam-agent/releases/download/v0.5.0/cot_redteam_agent-0.5.0-py3-none-any.whl"
```

For development:

```bash
git clone https://github.com/rudrasatani13/cot-redteam-agent.git
cd cot-redteam-agent
python -m pip install -e ".[dev]"
```

Published on PyPI as `cot-redteam-agent`.

## Five-minute quickstart

Create a wheel-safe example configuration:

```bash
# test: command
cot-redteam init --path config.yaml
# Edit evaluation.models and generative model IDs for your provider route.
export OPENROUTER_API_KEY=your-key
cot-redteam config validate --config config.yaml
cot-redteam list-attacks
cot-redteam list-monitors
```

The generated configuration uses the packaged `pkg:sample.jsonl` dataset and
works outside the repository. It includes optional provider examples, but
validation requires credentials only for providers referenced by the selected
evaluation and generative models. The default attack is
`injection.system_canary_agent` (invent techniques until real disclosure).

Run the configured evaluation when you are ready to contact the provider:

```bash
cot-redteam run --config config.yaml
cot-redteam list-runs --config config.yaml
```

### Interactive adaptive TUI

`--config` is required (bare `cot-redteam tui` will error):

```bash
cot-redteam tui --config config.yaml
# or auto-start:
cot-redteam tui --config config.yaml --auto-start
```

The bottom type bar is a **single slim line** (no tall box borders). Type a
slash command and press Enter. Mid panels expand; the composer stays pinned.

Inside the TUI:

```text
/model openrouter:your-model-id
/payloads 8
/run
```

Useful commands: `/help`, `/add`, `/models`, `/attack`, `/stop`, `/quit`. See
the full [TUI guide](docs/tui.md) (layout + slim composer notes).

Render a report using the `run_id` printed by the run command:

```bash
cot-redteam report \
  --config config.yaml \
  --run-id RUN_ID \
  --format markdown
```

Markdown reports include retained system and attack prompts, model responses,
visible provider reasoning, exact attack-assessment evidence, and monitor
outcomes. The packaged adaptive canary attack places a synthetic token only in a
trusted system instruction and reports success only on real disclosure—not when
the model refuses while quoting the canary during analysis.

## Prompt-injection benchmark

List the packaged suites:

```bash
cot-redteam list-suites
cot-redteam suite show --id builtin.smoke
```

In `config.yaml`, select a suite and remove the legacy `attacks` and `monitors`
entries if you want a benchmark-only run:

```yaml
evaluation:
  models:
    - openrouter:your-model-route
  suite_ids:
    - builtin.smoke
  repetitions: 1
  budgets:
    # 12 trials; one is two-turn, so the target-request minimum is 13.
    max_requests: 13
  retain_prompts: true
  retain_responses: true
  retain_reasoning: true
```

Provider capabilities are declared under `providers.<name>.capabilities`.
Unsupported roles fail during `config validate`, before any billed request.
The packaged smoke suite includes a simulated tool-output case, so the selected
route must declare `tool_role: true`; otherwise use a filtered local suite.

Run and inspect it with the same commands:

```bash
cot-redteam config validate --config config.yaml
cot-redteam run --config config.yaml
cot-redteam report --config config.yaml --run-id RUN_ID --format markdown
cot-redteam report --config config.yaml --run-id RUN_ID --format jsonl
```

Benchmark results apply only to the tested model route, provider behavior,
policy, suite version, transformations, and repetitions. They are not a
universal model-security score. See the [benchmark guide](docs/benchmarking.md).

## Visible reasoning and interpretation

The tool records visible reasoning only when it is:

1. exposed in a provider response field; or
2. enclosed by configured delimiters such as `<think>...</think>`.

Ordinary answer prose is not relabeled as hidden reasoning. Model outputs are
nondeterministic, automated monitors are imperfect, and attack success does not
prove a general model vulnerability. Reports preserve failed and excluded
items so those limitations remain visible. A reasoning-only canary disclosure
means the tested provider route exposed protected system content to its API
caller; it does not prove that every deployment of the named model does so.

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

from cot_redteam.api import run_benchmark
from cot_redteam.core.config import load_config


async def main() -> None:
    config = load_config("config.yaml")
    run = await run_benchmark(config)
    print(run.run_id, len(run.trials))


asyncio.run(main())
```

Use `run_evaluation` for the backward-compatible `0.2` attack/monitor path and
`run_benchmark` for configured suites. Both contact providers and may incur cost.

## CLI reference

- `cot-redteam init`
- `cot-redteam config validate|show`
- `cot-redteam list-attacks|list-monitors|list-providers`
- `cot-redteam list-suites`
- `cot-redteam suite validate|show`
- `cot-redteam dataset import cyberseceval|ih-challenge`
- `cot-redteam run`
- `cot-redteam tui` — interactive adaptive dashboard
- `cot-redteam race` — race one probe across models and compare compliance
- `cot-redteam list-runs|show-run|report`
- `cot-redteam evolve`

Exit codes are `0` for completed, `1` for failed, `2` for configuration errors,
and `3` for partial runs.

## Documentation

| Guide | Purpose |
|---|---|
| [Configuration](docs/configuration.md) | Schema, credentials, precedence, and validation |
| [Interactive TUI](docs/tui.md) | Adaptive dashboard, slash commands, screenshot |
| [Providers](docs/providers.md) | Provider-specific behavior and endpoints |
| [Plugins](docs/plugins.md) | Attack and monitor extension contracts |
| [Experiments](docs/experiments.md) | Metrics, rates, comparisons, and retention |
| [Benchmarking](docs/benchmarking.md) | Suites, capabilities, scoring, reports, and imports |
| [0.3 migration](docs/migration-0.2-to-0.3.md) | Additive changes from `0.2.x` |
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
