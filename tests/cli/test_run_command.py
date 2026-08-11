"""CLI run command with fake provider."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cot_redteam.cli.main import main
from cot_redteam.core.types import ModelRef, ModelResponse, TokenUsage
from cot_redteam.providers.factory import ProviderFactory


class OkProvider:
    async def generate(self, model, request):
        return ModelResponse(
            text="<think>normal reasoning</think>4",
            model=model,
            usage=TokenUsage(2, 2),
            provider_request_id="x",
        )

    async def aclose(self):
        return None


class FailProvider:
    async def generate(self, model, request):
        from cot_redteam.core.errors import PermanentProviderError

        raise PermanentProviderError("nope")

    async def aclose(self):
        return None


def _write_config(tmp_path: Path, dataset: Path) -> Path:
    cfg = {
        "version": 2,
        "global": {"seed": 1, "concurrency": 2, "output_dir": str(tmp_path / "out")},
        "providers": {
            "fake": {
                "kind": "vllm",
                "base_url": "http://localhost:9/v1",
            }
        },
        "evaluation": {
            "models": ["fake:local"],
            "attacks": ["injection.cot_injection"],
            "monitors": ["regex"],
            "dataset_path": str(dataset),
            "sample_count": 1,
            "budgets": {"max_requests": 10},
        },
        "storage": {"path": str(tmp_path / "db.sqlite")},
        "artifacts": {"root": str(tmp_path / "artifacts")},
        "reporting": {"output_dir": str(tmp_path / "reports"), "formats": ["markdown"]},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_run_via_api_with_injected_factory(tmp_path: Path) -> None:
    from cot_redteam.api import run_evaluation
    from cot_redteam.core.config import load_config

    dataset = tmp_path / "d.jsonl"
    dataset.write_text('{"id":"1","question":"2+2?"}\n', encoding="utf-8")
    cfg_path = _write_config(tmp_path, dataset)
    config = load_config(cfg_path)

    class Factory(ProviderFactory):
        def __init__(self):
            # bypass parent init partially
            self._config = config
            self._environ = {}
            self._transport_factory = None
            self._cache = {}
            self.provider = OkProvider()

        def create(self, model: ModelRef):
            return self.provider

        def resolve_model(self, value: str) -> ModelRef:
            return ModelRef.parse(value)

        async def aclose(self):
            await self.provider.aclose()

    run = await run_evaluation(config, provider_factory=Factory())
    assert run.summary.planned == 1


def test_list_attacks() -> None:
    assert main(["list-attacks"]) == 0
    assert main(["list-monitors"]) == 0
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_cli_description_tracks_package_version() -> None:
    """Regression: the help banner hardcoded '0.3' after the 0.4.0 release."""
    from cot_redteam import __version__
    from cot_redteam.cli.main import _build_parser

    parser = _build_parser()
    assert parser.description == f"CoT Red Team Agent {__version__}"
    assert "0.3" not in parser.description


def test_evolve_without_generator_model_errors_cleanly(tmp_path: Path) -> None:
    """evolve must fail with a clear message when no generator model is set.

    Regression: the old generative.generator_model default silently required
    openrouter at config-validate time; with the default removed, evolve must
    tell the user what to configure instead of crashing.
    """
    dataset = tmp_path / "d.jsonl"
    dataset.write_text('{"id":"1","question":"2+2?"}\n', encoding="utf-8")
    cfg = {
        "version": 2,
        "global": {"seed": 1},
        "providers": {"fake": {"kind": "vllm", "base_url": "http://localhost:9/v1"}},
        "evaluation": {
            "models": ["fake:local"],
            "attacks": ["injection.cot_injection"],
            "monitors": ["regex"],
            "dataset_path": str(dataset),
            "sample_count": 1,
        },
        "storage": {"path": str(tmp_path / "db.sqlite")},
    }
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert main(["evolve", "--config", str(cfg_path)]) == 2


def test_run_config_error_trial_exits_config(tmp_path: Path, monkeypatch) -> None:
    """Regression: a benchmark trial typed CONFIG_ERROR (e.g. judge scorer
    missing rubric) must make `run` exit 2 (config error), not 3 (partial)."""
    from datetime import datetime, timezone
    from importlib import import_module
    from types import SimpleNamespace

    cli_main = import_module("cot_redteam.cli.main")
    from cot_redteam.benchmark.conversation import config_error_transcript
    from cot_redteam.benchmark.results import BenchmarkRunResult, BenchmarkTrialResult
    from cot_redteam.benchmark.scoring import TranscriptScoring

    trial = SimpleNamespace(trial_id="cfg-run:trial:1")
    result = BenchmarkTrialResult(
        trial=trial,  # type: ignore[arg-type]
        transcript=config_error_transcript(
            "cfg-run:trial:1", "judge scorer 'evidence_judge' requires a non-empty rubric"
        ),
        scoring=TranscriptScoring(trial_id="cfg-run:trial:1", outcomes=()),
        canary_metadata={},
        transformation_digest="",
        judge_results=(),
    )
    run = BenchmarkRunResult(
        run_id="cfg-run",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        trials=(result,),
    )

    async def fake_run_benchmark(config):
        return run

    monkeypatch.setattr(cli_main, "run_benchmark", fake_run_benchmark)

    cfg = {
        "version": 2,
        "global": {"seed": 1},
        "providers": {"mock": {"kind": "mock", "mock_mode": "refuse"}},
        "evaluation": {
            "models": ["mock:model"],
            "suite_paths": [str(tmp_path / "suite.jsonl")],
            "monitors": ["regex"],
            "judge_model": "mock:judge",
            "judge_scorers": ["evidence_judge"],
        },
    }
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    assert main(["run", "--config", str(cfg_path)]) == 2
