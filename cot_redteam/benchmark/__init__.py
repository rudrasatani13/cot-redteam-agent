"""Declarative prompt-injection benchmark contracts."""

from cot_redteam.benchmark.schema import PolicySpec, ScenarioSpec
from cot_redteam.benchmark.scoring import ScorerOutcome, ScorerVerdict
from cot_redteam.benchmark.suite import ScenarioSuite

__all__ = [
    "PolicySpec",
    "ScenarioSpec",
    "ScenarioSuite",
    "ScorerOutcome",
    "ScorerVerdict",
]
