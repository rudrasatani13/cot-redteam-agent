"""Domain model tests for v0.2 types."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    EvaluationItem,
    ItemStatus,
    ModelRef,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    ReasoningSource,
    RunStatus,
    RunSummary,
    TokenUsage,
)


def succeeded_item() -> EvaluationItem:
    model = ModelRef.parse("openrouter:test/model")
    prompt = AttackPrompt(
        attack_id="injection.cot_injection",
        text="prompt",
        sample_id="s1",
    )
    response = ModelResponse(
        text="answer",
        model=model,
        reasoning=None,
        reasoning_source=ReasoningSource.ABSENT,
        usage=TokenUsage(1, 1),
    )
    assessment = AttackAssessment(success=True, score=1.0, evidence=("ok",))
    return EvaluationItem(
        item_id="item-1",
        model=model,
        attack_id="injection.cot_injection",
        sample_id="s1",
        status=ItemStatus.SUCCEEDED,
        prompt=prompt,
        response=response,
        assessment=assessment,
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.CLEAN,
                confidence=0.9,
                explanation="clean",
            ),
        ),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def provider_error_item() -> EvaluationItem:
    return EvaluationItem(
        item_id="item-err",
        model=ModelRef.parse("openrouter:test/model"),
        attack_id="injection.cot_injection",
        sample_id="s1",
        status=ItemStatus.PROVIDER_ERROR,
        error="timeout",
    )


def test_model_ref_requires_provider_separator() -> None:
    with pytest.raises(ValueError, match="provider:model-id"):
        ModelRef.parse("gpt-4o")


def test_model_ref_parses() -> None:
    ref = ModelRef.parse("openrouter:anthropic/claude-3.5-sonnet")
    assert ref.provider == "openrouter"
    assert ref.model_id == "anthropic/claude-3.5-sonnet"
    assert str(ref) == "openrouter:anthropic/claude-3.5-sonnet"


def test_monitor_error_is_not_clean() -> None:
    outcome = MonitorOutcome(
        monitor_id="regex",
        status=MonitorStatus.ERROR,
        confidence=None,
        explanation="pattern compilation failed",
    )
    assert outcome.is_evaluable is False
    assert outcome.triggered is None


def test_monitor_triggered_and_clean() -> None:
    triggered = MonitorOutcome("regex", MonitorStatus.TRIGGERED, 0.8, "hit")
    clean = MonitorOutcome("regex", MonitorStatus.CLEAN, 0.1, "ok")
    assert triggered.triggered is True
    assert clean.triggered is False
    assert triggered.is_evaluable and clean.is_evaluable


def test_run_status_is_derived_from_item_counts() -> None:
    assert RunSummary.from_items([succeeded_item()]).status is RunStatus.COMPLETED
    assert (
        RunSummary.from_items([succeeded_item(), provider_error_item()]).status is RunStatus.PARTIAL
    )
    assert RunSummary.from_items([provider_error_item()]).status is RunStatus.FAILED


def test_succeeded_item_requires_prompt_response_assessment() -> None:
    with pytest.raises(ValueError, match="prompt"):
        EvaluationItem(
            item_id="x",
            model=ModelRef.parse("p:m"),
            attack_id="a",
            sample_id="s",
            status=ItemStatus.SUCCEEDED,
            response=ModelResponse(text="t", model=ModelRef.parse("p:m")),
            assessment=AttackAssessment(success=False, score=0.0),
        )


def test_error_item_requires_message() -> None:
    with pytest.raises(ValueError, match="error message"):
        EvaluationItem(
            item_id="x",
            model=ModelRef.parse("p:m"),
            attack_id="a",
            sample_id="s",
            status=ItemStatus.PROVIDER_ERROR,
        )


def test_score_bounds() -> None:
    with pytest.raises(ValueError, match="score"):
        AttackAssessment(success=True, score=1.5)
