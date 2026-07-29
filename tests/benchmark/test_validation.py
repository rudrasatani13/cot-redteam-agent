from __future__ import annotations

import json
from pathlib import Path

import pytest

from cot_redteam.benchmark.validation import validate_benchmark_config
from cot_redteam.core.config import load_config
from cot_redteam.core.errors import ConfigurationError

from .test_schema import valid_scenario


def _config(tmp_path: Path, scenario: dict):
    suite = tmp_path / "suite.jsonl"
    suite.write_text(json.dumps(scenario) + "\n", encoding="utf-8")
    path = tmp_path / "config.yaml"
    path.write_text(
        f"""
version: 2
providers:
  local:
    kind: vllm
    capabilities:
      system_role: true
evaluation:
  models: [local:model]
  suite_paths: [{suite}]
generative:
  generator_model: local:model
""",
        encoding="utf-8",
    )
    return load_config(path)


def test_validation_resolves_all_benchmark_references(tmp_path: Path) -> None:
    scenario = valid_scenario()
    scenario["scorers"] = [{"id": "scorer.canary.exact"}]

    suites = validate_benchmark_config(_config(tmp_path, scenario))

    assert suites[0].scenarios[0].id == scenario["id"]


def test_validation_rejects_unknown_scorer_before_provider_call(
    tmp_path: Path,
) -> None:
    scenario = valid_scenario()
    scenario["scorers"] = [{"id": "scorer.nope"}]

    with pytest.raises(ConfigurationError, match="unknown scorer"):
        validate_benchmark_config(_config(tmp_path, scenario))
