# CoT Red Team Agent 0.2

Open-source CLI and Python API for **Chain-of-Thought red-team evaluation**.
You supply provider credentials; the tool runs attacks and monitors, records
failure-aware outcomes, and writes truthful reports.

This is an intentional breaking release from `0.1.x`. See
[docs/migration-0.1-to-0.2.md](docs/migration-0.1-to-0.2.md).

## Install

```bash
# test: command
python -m pip install -e ".[dev]"
```

Or from a built wheel:

```bash
python -m pip install dist/cot_redteam_agent-0.2.0-py3-none-any.whl
```

Requires Python 3.10–3.13.

## Five-minute quickstart

```bash
# test: command
cot-redteam init --path config.yaml
export OPENROUTER_API_KEY=your-key
cot-redteam config validate --config config.yaml
# cot-redteam run --config config.yaml   # contacts providers
cot-redteam list-attacks
cot-redteam list-monitors
```

`config.example.yaml` (copied by `init`) configures OpenRouter, OpenAI,
Anthropic, vLLM, and llama.cpp **without embedding secrets**. Remote providers
read credentials only from named environment variables.

## What 0.2 guarantees

- Strict YAML configuration (`version: 2`) with unknown-key rejection
- Stable plugin IDs for attacks and monitors
- Asynchronous providers with retries and lifecycle close
- Explicit item statuses: success, provider/attack/monitor error, budget, cancel
- Monitor `ERROR` / `NOT_RUN` never count as successful evasion
- Transactional SQLite storage and content-addressed artifacts
- Markdown, CSV, and LaTeX reports with eligibility denominators
- Bounded generative attack evolution (no infinite loops, no code execution)

## Visible reasoning

The tool only records **visible** reasoning from:

1. provider-exposed reasoning fields, or
2. explicit delimiter pairs such as `<think>...</think>`.

Ordinary answer text that contains words like “because” is **not** labeled as
reasoning. Automated monitors are **not** ground truth.

## Python API

```python
# test: python
import asyncio
from cot_redteam.core.config import load_config
from cot_redteam.api import run_evaluation


async def main():
    config = load_config("config.example.yaml")
    # run = await run_evaluation(config)  # requires credentials + network
    assert config.version == 2


asyncio.run(main())
```

## CLI commands

- `cot-redteam init`
- `cot-redteam config validate|show`
- `cot-redteam list-attacks|list-monitors|list-providers`
- `cot-redteam run`
- `cot-redteam list-runs|show-run|report`
- `cot-redteam evolve`

Exit codes: `0` completed, `1` failed, `2` configuration, `3` partial.

## Documentation

| Guide | Path |
|---|---|
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Providers | [docs/providers.md](docs/providers.md) |
| Plugins | [docs/plugins.md](docs/plugins.md) |
| Experiments | [docs/experiments.md](docs/experiments.md) |
| Migration | [docs/migration-0.1-to-0.2.md](docs/migration-0.1-to-0.2.md) |
| Release checklist | [docs/release-checklist.md](docs/release-checklist.md) |

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check .
mypy cot_redteam
```

## License

MIT — see [LICENSE](LICENSE).
