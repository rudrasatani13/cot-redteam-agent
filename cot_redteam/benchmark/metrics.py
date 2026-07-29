"""Eligibility-aware benchmark rate summaries with Wilson intervals."""

from __future__ import annotations

import math
from dataclasses import dataclass

from cot_redteam.benchmark.scoring import ScorerVerdict


@dataclass(frozen=True)
class BenchmarkObservation:
    verdict: ScorerVerdict

    @property
    def eligible(self) -> bool:
        return self.verdict in (ScorerVerdict.SUCCESS, ScorerVerdict.FAILURE)


@dataclass(frozen=True)
class BenchmarkRateSummary:
    eligible: int
    successes: int
    excluded: int
    rate: float | None
    ci_low: float | None
    ci_high: float | None


def wilson_interval(
    successes: int,
    eligible: int,
    *,
    z: float = 1.959963984540054,
) -> tuple[float | None, float | None]:
    if eligible < 0 or successes < 0 or successes > eligible:
        raise ValueError("successes and eligible counts are inconsistent")
    if z <= 0:
        raise ValueError("z must be positive")
    if eligible == 0:
        return None, None
    rate = successes / eligible
    z_squared = z * z
    denominator = 1 + z_squared / eligible
    center = (rate + z_squared / (2 * eligible)) / denominator
    margin = (
        z
        * math.sqrt(rate * (1 - rate) / eligible + z_squared / (4 * eligible * eligible))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def summarize_observations(
    observations: tuple[BenchmarkObservation, ...],
) -> BenchmarkRateSummary:
    eligible = sum(observation.eligible for observation in observations)
    successes = sum(observation.verdict is ScorerVerdict.SUCCESS for observation in observations)
    excluded = len(observations) - eligible
    rate = successes / eligible if eligible else None
    low, high = wilson_interval(successes, eligible)
    return BenchmarkRateSummary(
        eligible=eligible,
        successes=successes,
        excluded=excluded,
        rate=rate,
        ci_low=low,
        ci_high=high,
    )
