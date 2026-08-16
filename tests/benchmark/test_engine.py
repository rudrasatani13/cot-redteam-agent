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


async def test_unexpected_trial_exception_is_isolated_not_fatal(
    tmp_path: Path, monkeypatch
) -> None:
    """An unexpected exception in one trial becomes typed internal-error
    evidence while sibling trials finish; the run never aborts."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    row = valid_scenario()
    path = tmp_path / "suite.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    suite = ScenarioSuite.load_jsonl(path, suite_id="suite.test")
    model = ModelRef.parse("openrouter:test/model")
    plan = BenchmarkPlanner(
        models=[model],
        suites=[suite],
        target_capabilities={"openrouter": EchoProvider.capabilities},
        budgets=config.evaluation.budgets,
        repetitions=2,
        run_id="run-engine-iso",
    ).create()

    class BoomProvider(EchoProvider):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        async def generate(self, model, request):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("unexpected boom")
            return await super().generate(model, request)

    provider = BoomProvider()
    budget = BudgetTracker(config.evaluation.budgets)
    execution = await BenchmarkEngine(
        config,
        FakeFactory(provider),
        budget,
    ).run(plan)

    assert len(execution.results) == 2
    statuses = [result.transcript.status.value for result in execution.results]
    assert "completed" in statuses
    assert "internal_error" in statuses
    errored = next(
        result for result in execution.results if result.transcript.status.value == "internal_error"
    )
    assert errored.transcript.error is not None
    # The internal-error trial carries no success evidence: never clean.
    assert not errored.scoring.outcomes
    assert all(not outcome.eligible for outcome in errored.scoring.outcomes)


async def test_config_error_trial_is_typed_config_error_not_internal() -> None:
    """Regression: a ConfigurationError raised inside trial execution (e.g.
    a judge scorer missing its rubric) must be typed CONFIG_ERROR — not
    swallowed as INTERNAL_ERROR — so the CLI can exit 2 (config error)
    instead of 3 (partial) while completed trials keep their evidence."""
    import types

    from cot_redteam.core.errors import ConfigurationError

    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    engine = BenchmarkEngine(
        config,
        FakeFactory(EchoProvider()),
        BudgetTracker(config.evaluation.budgets),
    )

    async def _bomb(trial):
        raise ConfigurationError("judge scorer 'evidence_judge' requires a non-empty rubric")

    engine._run_trial = _bomb  # type: ignore[method-assign]
    trial = types.SimpleNamespace(trial_id="audit:trial:1")
    result = await engine._run_trial_safe(trial)  # type: ignore[arg-type]
    assert result.transcript.status.value == "config_error"
    assert "non-empty rubric" in (result.transcript.error or "")
