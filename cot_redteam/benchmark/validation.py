"""Benchmark suite resolution and offline configuration validation."""

from __future__ import annotations

import re
from pathlib import Path

from cot_redteam.benchmark.corpora import load_builtin_suite
from cot_redteam.benchmark.planner import BenchmarkPlanner
from cot_redteam.benchmark.policies import BUILTIN_POLICIES
from cot_redteam.benchmark.scoring import scorer_ids
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.benchmark.techniques import TECHNIQUE_IDS
from cot_redteam.benchmark.transforms import TRANSFORM_IDS
from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.types import ModelRef, TargetCapabilities

_LOCAL_SUITE_ID = re.compile(r"[^a-z0-9._-]+")


def load_configured_suites(config: AppConfig) -> tuple[ScenarioSuite, ...]:
    suites = [load_builtin_suite(suite_id) for suite_id in config.evaluation.suite_ids]
    for index, path in enumerate(config.evaluation.suite_paths, start=1):
        stem = _LOCAL_SUITE_ID.sub("-", Path(path).stem.lower()).strip("-._")
        suites.append(
            ScenarioSuite.load_jsonl(
                path,
                suite_id=f"local.{stem or index}",
            )
        )
    if not suites:
        raise ConfigurationError("benchmark run requires evaluation.suite_ids or suite_paths")
    if len({suite.id for suite in suites}) != len(suites):
        raise ConfigurationError("configured benchmark suite ids must be unique")
    return tuple(suites)


def validate_benchmark_config(config: AppConfig) -> tuple[ScenarioSuite, ...]:
    suites = load_configured_suites(config)
    deterministic = set(scorer_ids())
    judge_ids = set(config.evaluation.judge_scorers)
    if judge_ids and not config.evaluation.judge_model:
        raise ConfigurationError("judge_scorers requires evaluation.judge_model")
    failures: list[str] = []
    for suite in suites:
        for scenario in suite.scenarios:
            for policy_id in scenario.policy_ids:
                if policy_id not in BUILTIN_POLICIES:
                    failures.append(f"{scenario.id}: unknown policy {policy_id}")
            for technique_id in scenario.technique_ids:
                if technique_id not in TECHNIQUE_IDS:
                    failures.append(f"{scenario.id}: unknown technique {technique_id}")
            for transform_id in scenario.transformation_ids:
                if transform_id not in TRANSFORM_IDS:
                    failures.append(f"{scenario.id}: unknown transformation {transform_id}")
            for scorer in scenario.scorers:
                if scorer.id not in deterministic and scorer.id not in judge_ids:
                    failures.append(f"{scenario.id}: unknown scorer {scorer.id}")
    if failures:
        raise ConfigurationError("invalid benchmark references: " + "; ".join(failures))

    models = tuple(ModelRef.parse(value) for value in config.evaluation.models)
    capabilities = {
        name: TargetCapabilities(**settings.capabilities.model_dump())
        for name, settings in config.providers.items()
    }
    BenchmarkPlanner(
        models=models,
        suites=suites,
        target_capabilities=capabilities,
        selected_policy_ids=config.evaluation.policy_ids or None,
        selected_technique_ids=config.evaluation.technique_ids or None,
        selected_transformation_ids=config.evaluation.transformation_ids or None,
        repetitions=config.evaluation.repetitions,
        max_expanded_trials=config.evaluation.max_expanded_trials,
        judge_scorer_ids=judge_ids,
        budgets=config.evaluation.budgets,
        run_id="validation",
    ).create()
    return suites
