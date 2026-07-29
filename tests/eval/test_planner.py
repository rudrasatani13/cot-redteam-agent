"""Planner tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cot_redteam.core.config import load_config
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.eval.planner import RunPlanner
from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests
from cot_redteam.providers.factory import ProviderFactory

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config" / "minimal.yaml"
ROOT = Path(__file__).resolve().parents[2]


def _planner(seed: int = 42, sample_count: int = 2, **empty):
    reset_plugins_for_tests()
    bootstrap_plugins(force=True)
    config = load_config(
        FIXTURES,
        overrides={
            "global.seed": seed,
            "evaluation.sample_count": sample_count,
            "evaluation.dataset_path": str(ROOT / "cot_redteam/eval/datasets/sample.jsonl"),
        },
    )
    if empty.get("models") is not None:
        config = config.model_copy(
            update={"evaluation": config.evaluation.model_copy(update={"models": []})}
        )
    if empty.get("attacks") is not None:
        config = config.model_copy(
            update={"evaluation": config.evaluation.model_copy(update={"attacks": []})}
        )
    if empty.get("monitors") is not None:
        config = config.model_copy(
            update={"evaluation": config.evaluation.model_copy(update={"monitors": []})}
        )
    factory = ProviderFactory(config, environ={"OPENROUTER_API_KEY": "k"})
    return RunPlanner(config, provider_factory=factory)


def test_planner_uses_paired_sample_ids() -> None:
    plan = _planner(seed=42, sample_count=2).create()
    by_attack: dict[str, tuple[str, ...]] = {}
    for item in plan.items:
        by_attack.setdefault(item.attack_id, [])
        by_attack[item.attack_id].append(item.sample.id)  # type: ignore[attr-defined]
    # normalize
    normalized = {k: tuple(sorted(v)) for k, v in by_attack.items()}
    assert len(set(normalized.values())) == 1


@pytest.mark.parametrize("empty_field", ["models", "attacks", "monitors"])
def test_planner_rejects_empty_dimension(empty_field: str) -> None:
    with pytest.raises(ConfigurationError, match=empty_field):
        _planner(**{empty_field: []}).create()
