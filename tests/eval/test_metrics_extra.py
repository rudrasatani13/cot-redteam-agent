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
    assert cmp.risk_difference is not None
    assert cmp.fisher_p_value is not None or cmp.odds_ratio is not None


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
