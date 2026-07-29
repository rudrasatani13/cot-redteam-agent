"""Benchmark trial-matrix and budget-preflight tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cot_redteam.benchmark.planner import BenchmarkPlanner
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.types import ModelRef, TargetCapabilities

from .test_schema import valid_scenario


def load_suite(tmp_path: Path, rows: list[dict]) -> ScenarioSuite:
    path = tmp_path / "suite.jsonl"
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    return ScenarioSuite.load_jsonl(path, suite_id="suite.test")


def test_planner_expands_repetitions_with_stable_unique_ids(tmp_path: Path) -> None:
    suite = load_suite(tmp_path, [valid_scenario()])
    planner = BenchmarkPlanner(
        models=[ModelRef.parse("gateway:model-a")],
        suites=[suite],
        target_capabilities={"gateway": TargetCapabilities(system_role=True, multi_turn=True)},
        repetitions=3,
        run_id="run-123",
    )
    first = planner.create()
    second = planner.create()

    assert len(first.trials) == 3
    assert [trial.trial_id for trial in first.trials] == [trial.trial_id for trial in second.trials]
    assert len({trial.trial_id for trial in first.trials}) == 3
    assert [trial.repetition for trial in first.trials] == [0, 1, 2]
    assert first.preflight.target_requests_min == 3
    assert first.preflight.target_requests_max == 3


def test_planner_expands_selected_policy_technique_and_transform(tmp_path: Path) -> None:
    row = valid_scenario()
    row["policy_ids"] = ["policy.minimal", "policy.hierarchy"]
    row["technique_ids"] = ["technique.direct", "technique.authority"]
    row["transformation_ids"] = ["transform.identity", "transform.base64"]
    suite = load_suite(tmp_path, [row])

    plan = BenchmarkPlanner(
        models=[ModelRef.parse("gateway:model-a")],
        suites=[suite],
        target_capabilities={"gateway": TargetCapabilities(system_role=True)},
        selected_policy_ids=["policy.hierarchy"],
        selected_technique_ids=["technique.direct"],
        selected_transformation_ids=["transform.identity", "transform.base64"],
        run_id="run-123",
    ).create()

    assert len(plan.trials) == 2
    assert {trial.policy_id for trial in plan.trials} == {"policy.hierarchy"}
    assert {trial.technique_id for trial in plan.trials} == {"technique.direct"}
    assert {trial.transformation_id for trial in plan.trials} == {
        "transform.identity",
        "transform.base64",
    }


def test_planner_rejects_missing_capabilities_before_trials(tmp_path: Path) -> None:
    row = valid_scenario()
    row["required_capabilities"] = ["system_role", "developer_role", "multi_turn"]
    suite = load_suite(tmp_path, [row])

    with pytest.raises(
        ConfigurationError,
        match="developer_role, multi_turn",
    ):
        BenchmarkPlanner(
            models=[ModelRef.parse("gateway:model-a")],
            suites=[suite],
            target_capabilities={"gateway": TargetCapabilities(system_role=True)},
            run_id="run-123",
        ).create()


def test_planner_rejects_expansion_above_limit(tmp_path: Path) -> None:
    row = valid_scenario()
    row["policy_ids"] = ["policy.minimal", "policy.hierarchy"]
    suite = load_suite(tmp_path, [row])

    with pytest.raises(ConfigurationError, match="max_expanded_trials"):
        BenchmarkPlanner(
            models=[ModelRef.parse("gateway:model-a")],
            suites=[suite],
            target_capabilities={"gateway": TargetCapabilities(system_role=True)},
            repetitions=2,
            max_expanded_trials=3,
            run_id="run-123",
        ).create()


def test_planner_rejects_budget_that_cannot_complete_plan(tmp_path: Path) -> None:
    row = valid_scenario()
    row["steps"] = [
        {
            "role": "user",
            "content": "First request about {task}",
            "trust": "untrusted",
        },
        {
            "role": "user",
            "content": "Second request about {task}",
            "trust": "untrusted",
        },
    ]
    row["required_capabilities"] = ["system_role", "multi_turn"]
    suite = load_suite(tmp_path, [row])

    with pytest.raises(ConfigurationError, match="max_requests=1.*requires at least 2"):
        BenchmarkPlanner(
            models=[ModelRef.parse("gateway:model-a")],
            suites=[suite],
            target_capabilities={"gateway": TargetCapabilities(system_role=True, multi_turn=True)},
            budgets=BudgetSettings(max_requests=1),
            run_id="run-123",
        ).create()


def test_planner_counts_judge_requests_separately(tmp_path: Path) -> None:
    row = valid_scenario()
    row["scorers"].append({"id": "judge.attack_goal"})
    suite = load_suite(tmp_path, [row])

    plan = BenchmarkPlanner(
        models=[ModelRef.parse("gateway:model-a")],
        suites=[suite],
        target_capabilities={"gateway": TargetCapabilities(system_role=True)},
        judge_scorer_ids={"judge.attack_goal"},
        run_id="run-123",
    ).create()

    assert plan.preflight.target_requests_max == 1
    assert plan.preflight.judge_requests_max == 2
    assert plan.preflight.total_requests_max == 3
