"""Eligibility-aware metrics tests."""

from __future__ import annotations

from datetime import datetime, timezone

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
from cot_redteam.eval.metrics import summarize_run


def _run(items: list[EvaluationItem]) -> EvaluationRun:
    summary = RunSummary.from_items(items)
    return EvaluationRun(
        run_id="r",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def run_with_monitor_error() -> EvaluationRun:
    model = ModelRef.parse("p:m")
    EvaluationItem(
        item_id="i1",
        model=model,
        attack_id="a",
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id="a", text="p", sample_id="s"),
        response=ModelResponse(text="t", model=model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=True, score=1.0),
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.ERROR,
                confidence=None,
                explanation="fail",
            ),
        ),
    )
    # SUCCEEDED with ERROR monitor is inconsistent with engine, but metrics
    # should still exclude from evasion. Use MONITOR_ERROR item path via custom.
    # Plan test: create succeeded-like via direct summarize on custom run with
    # only monitor error item status MONITOR_ERROR.
    err_item = EvaluationItem(
        item_id="i2",
        model=model,
        attack_id="a",
        sample_id="s",
        status=ItemStatus.MONITOR_ERROR,
        prompt=AttackPrompt(attack_id="a", text="p", sample_id="s"),
        response=ModelResponse(text="t", model=model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=True, score=1.0),
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.ERROR,
                confidence=None,
                explanation="fail",
            ),
        ),
        error="monitor error",
    )
    return _run([err_item])


def empty_failed_run() -> EvaluationRun:
    model = ModelRef.parse("p:m")
    item = EvaluationItem(
        item_id="i",
        model=model,
        attack_id="a",
        sample_id="s",
        status=ItemStatus.PROVIDER_ERROR,
        error="x",
    )
    return _run([item])


def test_monitor_error_is_excluded_from_evasion_rate() -> None:
    # succeeded item with non-evaluable monitor should exclude
    model = ModelRef.parse("p:m")
    item = EvaluationItem(
        item_id="i1",
        model=model,
        attack_id="a",
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id="a", text="p", sample_id="s"),
        response=ModelResponse(text="t", model=model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=True, score=1.0),
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.ERROR,
                confidence=None,
                explanation="fail",
            ),
        ),
    )
    summary = summarize_run(_run([item]))
    assert summary.evasion.eligible == 0
    assert summary.evasion.excluded == 1
    assert summary.evasion.rate is None


def test_empty_run_has_no_rate_instead_of_zero_percent() -> None:
    summary = summarize_run(empty_failed_run())
    assert summary.attack_success.rate is None
