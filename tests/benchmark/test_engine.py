from __future__ import annotations

import json
from pathlib import Path

from cot_redteam.benchmark.engine import BenchmarkEngine
from cot_redteam.benchmark.planner import BenchmarkPlanner
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.config import load_config
from cot_redteam.core.types import (
    ModelRef,
    ModelResponse,
    TargetCapabilities,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker

from .test_schema import valid_scenario


class EchoProvider:
    capabilities = TargetCapabilities(system_role=True, multi_turn=True)

    def __init__(self) -> None:
        self.requests = []

    async def generate(self, model, request):
        self.requests.append(request)
        return ModelResponse(
            text="blue",
            model=model,
            usage=TokenUsage(input_tokens=2, output_tokens=1),
        )

    async def aclose(self) -> None:
        return None


class FakeFactory:
    def __init__(self, provider: EchoProvider) -> None:
        self.provider = provider

    def resolve_model(self, value):
        return ModelRef.parse(value)

    def create(self, model):
        return self.provider


async def test_engine_executes_prepares_and_scores_trial_end_to_end(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    row = valid_scenario()
    row["scorers"] = [
        {"id": "scorer.canary.exact"},
        {"id": "scorer.utility.expected_output"},
    ]
    path = tmp_path / "suite.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    suite = ScenarioSuite.load_jsonl(path, suite_id="suite.test")
    model = ModelRef.parse("openrouter:test/model")
    plan = BenchmarkPlanner(
        models=[model],
        suites=[suite],
        target_capabilities={"openrouter": EchoProvider.capabilities},
        budgets=config.evaluation.budgets,
        run_id="run-engine",
    ).create()
    provider = EchoProvider()
    budget = BudgetTracker(config.evaluation.budgets)

    execution = await BenchmarkEngine(
        config,
        FakeFactory(provider),
        budget,
    ).run(plan)

    assert len(execution.results) == 1
    result = execution.results[0]
    assert result.transcript.status.value == "completed"
    assert result.scoring.outcomes[0].verdict.value == "failure"
    assert result.scoring.outcomes[2].verdict.value == "success"
    assert budget.snapshot().requests == 1
    system = provider.requests[0].messages[0].content
    assert "COTRT3-" in system
    assert result.canary_metadata["digest"]
