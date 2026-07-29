"""Deterministic benchmark trial expansion and request-budget preflight."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from itertools import product

from cot_redteam.benchmark.schema import ScenarioSpec
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.serialization import canonical_json, sha256_text
from cot_redteam.core.types import MessageRole, ModelRef, TargetCapabilities


@dataclass(frozen=True)
class PlannedTrial:
    trial_id: str
    model: ModelRef
    suite_id: str
    scenario: ScenarioSpec
    policy_id: str
    technique_id: str
    transformation_id: str
    repetition: int
    target_request_count: int
    judge_request_count: int


@dataclass(frozen=True)
class RequestPreflight:
    target_requests_min: int
    target_requests_max: int
    judge_requests_max: int

    @property
    def total_requests_min(self) -> int:
        return self.target_requests_min

    @property
    def total_requests_max(self) -> int:
        return self.target_requests_max + self.judge_requests_max


@dataclass(frozen=True)
class BenchmarkPlan:
    run_id: str
    trials: tuple[PlannedTrial, ...]
    preflight: RequestPreflight


def _selected(
    available: Sequence[str],
    requested: tuple[str, ...] | None,
) -> tuple[str, ...]:
    if requested is None:
        return tuple(available)
    requested_set = set(requested)
    return tuple(value for value in available if value in requested_set)


def _target_turn_count(scenario: ScenarioSpec) -> int:
    actionable = sum(
        1 for step in scenario.steps if step.role in (MessageRole.USER, MessageRole.TOOL)
    )
    return max(1, actionable)


class BenchmarkPlanner:
    def __init__(
        self,
        *,
        models: Sequence[ModelRef],
        suites: Sequence[ScenarioSuite],
        target_capabilities: Mapping[str, TargetCapabilities],
        selected_policy_ids: Sequence[str] | None = None,
        selected_technique_ids: Sequence[str] | None = None,
        selected_transformation_ids: Sequence[str] | None = None,
        repetitions: int = 1,
        max_expanded_trials: int = 10_000,
        judge_scorer_ids: Set[str] | None = None,
        budgets: BudgetSettings | None = None,
        run_id: str | None = None,
    ) -> None:
        self.models = tuple(models)
        self.suites = tuple(suites)
        self.target_capabilities = dict(target_capabilities)
        self.selected_policy_ids = (
            tuple(selected_policy_ids) if selected_policy_ids is not None else None
        )
        self.selected_technique_ids = (
            tuple(selected_technique_ids) if selected_technique_ids is not None else None
        )
        self.selected_transformation_ids = (
            tuple(selected_transformation_ids) if selected_transformation_ids is not None else None
        )
        self.repetitions = repetitions
        self.max_expanded_trials = max_expanded_trials
        self.judge_scorer_ids = frozenset(judge_scorer_ids or ())
        self.budgets = budgets or BudgetSettings()
        self.run_id = run_id or str(uuid.uuid4())

    def _validate_inputs(self) -> None:
        if not self.models:
            raise ConfigurationError("benchmark models must not be empty")
        if not self.suites:
            raise ConfigurationError("benchmark suites must not be empty")
        if self.repetitions < 1:
            raise ConfigurationError("repetitions must be at least 1")
        if self.max_expanded_trials < 1:
            raise ConfigurationError("max_expanded_trials must be at least 1")

        failures: list[str] = []
        for model in self.models:
            capabilities = self.target_capabilities.get(model.provider)
            if capabilities is None:
                failures.append(f"{model}: no target capabilities declared")
                continue
            for suite in self.suites:
                for scenario in suite.scenarios:
                    missing = scenario.requirements.missing_from(capabilities)
                    if missing:
                        failures.append(f"{model} / {scenario.id}: {', '.join(missing)}")
        if failures:
            raise ConfigurationError("unsupported target capabilities: " + "; ".join(failures))

    def create(self) -> BenchmarkPlan:
        self._validate_inputs()
        trials: list[PlannedTrial] = []

        for model in self.models:
            for suite in self.suites:
                for scenario in suite.scenarios:
                    policies = _selected(scenario.policy_ids, self.selected_policy_ids)
                    techniques = _selected(
                        scenario.technique_ids,
                        self.selected_technique_ids,
                    )
                    transformations = _selected(
                        scenario.transformation_ids,
                        self.selected_transformation_ids,
                    )
                    if not policies or not techniques or not transformations:
                        continue

                    target_calls = _target_turn_count(scenario)
                    judge_calls = sum(
                        1 for scorer in scenario.scorers if scorer.id in self.judge_scorer_ids
                    )
                    for policy_id, technique_id, transformation_id, repetition in product(
                        policies,
                        techniques,
                        transformations,
                        range(self.repetitions),
                    ):
                        if len(trials) >= self.max_expanded_trials:
                            raise ConfigurationError(
                                "benchmark expansion exceeds "
                                f"max_expanded_trials={self.max_expanded_trials}"
                            )
                        key = {
                            "run_id": self.run_id,
                            "model": str(model),
                            "suite_id": suite.id,
                            "scenario_id": scenario.id,
                            "scenario_digest": scenario.digest,
                            "policy_id": policy_id,
                            "technique_id": technique_id,
                            "transformation_id": transformation_id,
                            "repetition": repetition,
                        }
                        suffix = sha256_text(canonical_json(key))[:24]
                        trials.append(
                            PlannedTrial(
                                trial_id=f"{self.run_id}:trial:{suffix}",
                                model=model,
                                suite_id=suite.id,
                                scenario=scenario,
                                policy_id=policy_id,
                                technique_id=technique_id,
                                transformation_id=transformation_id,
                                repetition=repetition,
                                target_request_count=target_calls,
                                judge_request_count=judge_calls,
                            )
                        )

        if not trials:
            raise ConfigurationError(
                "benchmark selection produced zero eligible trials; "
                "check policy, technique, and transformation filters"
            )
        target_requests = sum(trial.target_request_count for trial in trials)
        judge_requests = sum(trial.judge_request_count for trial in trials)
        total_requests = target_requests + judge_requests
        if self.budgets.max_requests is not None and self.budgets.max_requests < total_requests:
            raise ConfigurationError(
                f"max_requests={self.budgets.max_requests} cannot complete the plan; "
                f"requires at least {total_requests}"
            )
        preflight = RequestPreflight(
            target_requests_min=target_requests,
            target_requests_max=target_requests,
            judge_requests_max=judge_requests,
        )
        return BenchmarkPlan(
            run_id=self.run_id,
            trials=tuple(trials),
            preflight=preflight,
        )
