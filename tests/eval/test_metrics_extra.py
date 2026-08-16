"""Extra metrics/budget coverage."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    ModelRef,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    RunSummary,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.metrics import bootstrap_interval, paired_comparison, summarize_run


def _item(sample_id: str, success: bool, attack: str = "a") -> EvaluationItem:
    model = ModelRef.parse("p:m")
    return EvaluationItem(
        item_id=f"{attack}:{sample_id}",
        model=model,
        attack_id=attack,
        sample_id=sample_id,
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id=attack, text="p", sample_id=sample_id),
        response=ModelResponse(text="t", model=model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=success, score=1.0 if success else 0.0),
        monitors=(MonitorOutcome("regex", MonitorStatus.CLEAN, 0.1, "ok"),),
    )


def test_bootstrap_interval_and_paired():
    vals = [0.0, 1.0, 1.0, 0.0, 1.0]
    lo, hi = bootstrap_interval(vals, seed=1, n_boot=200)
    assert lo is not None and hi is not None
    a = [_item("s1", True, "a"), _item("s2", False, "a")]
    b = [_item("s1", False, "b"), _item("s2", True, "b")]
    cmp = paired_comparison(a, b)
    assert cmp.group_a_size == 2
    assert cmp.risk_difference == 0.0
    assert cmp.odds_ratio is not None
    # Fisher exact (unpaired) was replaced by exact McNemar.
    assert cmp.fisher_p_value is None
    assert cmp.mcnemar_p_value is not None


def test_paired_comparison_mcnemar_matches_scipy():
    """Verify the McNemar math directly against scipy.stats.binomtest."""
    from scipy.stats import binomtest

    # n=10 shared samples: 5 both-success, 2 both-failure,
    # 2 a-only (discordant), 1 b-only (discordant).
    a_successes = {
        "s1": True,
        "s2": True,
        "s3": True,
        "s4": True,
        "s5": False,
        "s6": False,
        "s7": True,
        "s8": True,
        "s9": True,
        "s10": False,
    }
    b_successes = {
        "s1": True,
        "s2": True,
        "s3": True,
        "s4": True,
        "s5": False,
        "s6": False,
        "s7": False,
        "s8": True,
        "s9": False,
        "s10": True,
    }
    a = [_item(sid, ok, "a") for sid, ok in a_successes.items()]
    b = [_item(sid, ok, "b") for sid, ok in b_successes.items()]

    cmp = paired_comparison(a, b)
    assert cmp.group_a_size == 10
    assert cmp.group_a_successes == 7
    assert cmp.group_b_successes == 6
    assert cmp.concordant_both_success == 5
    assert cmp.concordant_both_failure == 2
    assert cmp.discordant_a_only == 2
    assert cmp.discordant_b_only == 1
    # Difference and discordant-pair SE: sqrt(2+1)/10.
    assert cmp.risk_difference == pytest.approx(0.1)
    se = (2 + 1) ** 0.5 / 10
    assert cmp.ci_low == pytest.approx(0.1 - 1.96 * se)
    assert cmp.ci_high == pytest.approx(0.1 + 1.96 * se)
    # Conditional (paired) odds ratio on the discordant pairs.
    assert cmp.odds_ratio == pytest.approx(2.0)
    # Exact McNemar p-value must equal scipy's binomial test on the
    # discordant split.
    expected_p = binomtest(2, 3, 0.5).pvalue
    assert cmp.mcnemar_p_value == pytest.approx(float(expected_p))


def test_paired_comparison_no_discordant_pairs():
    a = [_item("s1", True, "a"), _item("s2", False, "a")]
    b = [_item("s1", True, "b"), _item("s2", False, "b")]
    cmp = paired_comparison(a, b)
    assert cmp.risk_difference == 0.0
    assert cmp.ci_low == 0.0
    assert cmp.ci_high == 0.0
    assert cmp.mcnemar_p_value == 1.0


def test_paired_comparison_keeps_first_duplicate():
    """Duplicate sample_ids: the FIRST eligible item in stable-sort order
    (i.e. first encountered in the input) wins, not the last."""
    a = [_item("s1", True, "a"), _item("s1", False, "a")]
    b = [_item("s1", False, "b")]
    cmp = paired_comparison(a, b)
    assert cmp.group_a_size == 1
    assert cmp.group_a_successes == 1
    assert cmp.discordant_a_only == 1
    assert cmp.discordant_b_only == 0


def test_summarize_with_evasion_success():
    items = [_item("s1", True)]
    # clean monitors => evasion success
    summary = RunSummary.from_items(items)
    run = EvaluationRun(
        run_id="r",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    metrics = summarize_run(run, seed=0)
    assert metrics.evasion.rate == 1.0
    assert metrics.attack_success.rate == 1.0


@pytest.mark.asyncio
async def test_cost_budget():
    from decimal import Decimal

    tracker = BudgetTracker(BudgetSettings(max_estimated_cost=0.5))
    await tracker.reserve_request()
    await tracker.record_response(TokenUsage(1, 1), estimated_cost=Decimal("1.0"))
    assert tracker.snapshot().exceeded is True
