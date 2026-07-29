from __future__ import annotations

import json
from pathlib import Path

import yaml

from cot_redteam.api import run_benchmark
from cot_redteam.core.config import load_config
from cot_redteam.core.types import ModelRef, ModelResponse, TokenUsage
from cot_redteam.storage.sqlite import SQLiteRunStore
from tests.benchmark.test_schema import valid_scenario


class SafeProvider:
    def __init__(self) -> None:
        self.requests = []
        self.closed = False

    async def generate(self, model, request):
        self.requests.append(request)
        return ModelResponse(
            text="blue",
            model=model,
            model_revision="mock-revision",
            usage=TokenUsage(input_tokens=3, output_tokens=1),
        )

    async def aclose(self):
        self.closed = True


class FakeFactory:
    def __init__(self, provider: SafeProvider) -> None:
        self.provider = provider

    def resolve_model(self, value):
        return ModelRef.parse(value)

    def create(self, model):
        return self.provider

    async def aclose(self):
        await self.provider.aclose()


async def test_public_api_runs_persists_and_reports_benchmark(tmp_path: Path) -> None:
    row = valid_scenario()
    row["scorers"] = [
        {"id": "scorer.canary.exact"},
        {"id": "scorer.utility.expected_output"},
    ]
    suite = tmp_path / "suite.jsonl"
    suite.write_text(json.dumps(row) + "\n", encoding="utf-8")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "version": 2,
                "providers": {
                    "local": {
                        "kind": "vllm",
                        "base_url": "http://localhost:8000/v1",
                        "capabilities": {"system_role": True, "multi_turn": True},
                    }
                },
                "evaluation": {
                    "models": ["local:model"],
                    "suite_paths": [str(suite)],
                    "repetitions": 2,
                    "budgets": {"max_requests": 2},
                },
                "storage": {"path": str(tmp_path / "runs.db")},
                "artifacts": {"root": str(tmp_path / "artifacts")},
                "reporting": {
                    "output_dir": str(tmp_path / "reports"),
                    "formats": ["markdown", "csv", "latex"],
                },
                "generative": {"generator_model": "local:model"},
            }
        ),
        encoding="utf-8",
    )
    config = load_config(config_path)
    provider = SafeProvider()

    run = await run_benchmark(config, provider_factory=FakeFactory(provider))

    assert len(run.trials) == 2
    assert len({result.trial.trial_id for result in run.trials}) == 2
    assert provider.closed is False
    with SQLiteRunStore(config.storage.path) as store:
        loaded = store.get_benchmark(run.run_id)
    assert loaded == run
    root = Path(config.artifacts.root) / run.run_id
    assert (root / "benchmark.jsonl").exists()
    assert (root / "manifest.json").exists()
    assert (root / "manifest.json.sha256").exists()
    assert (Path(config.reporting.output_dir) / f"{run.run_id}.md").exists()
