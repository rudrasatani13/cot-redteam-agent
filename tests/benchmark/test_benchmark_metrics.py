from __future__ import annotations

from cot_redteam.benchmark.metrics import BenchmarkObservation, summarize_observations
from cot_redteam.benchmark.scoring import ScorerVerdict


def test_wilson_interval_and_eligibility() -> None:
    summary = summarize_observations(
        (
            BenchmarkObservation(ScorerVerdict.SUCCESS),
            BenchmarkObservation(ScorerVerdict.FAILURE),
            BenchmarkObservation(ScorerVerdict.ERROR),
            BenchmarkObservation(ScorerVerdict.INCONCLUSIVE),
        )
    )

    assert summary.eligible == 2
    assert summary.successes == 1
    assert summary.excluded == 2
    assert summary.rate == 0.5
    assert summary.ci_low is not None
    assert summary.ci_high is not None
    assert summary.ci_low < summary.rate < summary.ci_high


def test_no_eligible_results_have_no_rate_or_interval() -> None:
    summary = summarize_observations(
        (
            BenchmarkObservation(ScorerVerdict.ERROR),
            BenchmarkObservation(ScorerVerdict.INCONCLUSIVE),
        )
    )

    assert summary.eligible == 0
    assert summary.rate is None
    assert summary.ci_low is None
    assert summary.ci_high is None
