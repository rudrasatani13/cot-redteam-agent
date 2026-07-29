"""Retention sanitization tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.core.config import load_config
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
    ReasoningSource,
    RunSummary,
    TokenUsage,
)
from cot_redteam.eval.retention import sanitize_run


def test_sanitize_strips_prompts_and_reasoning(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    config = config.model_copy(
        update={
            "evaluation": config.evaluation.model_copy(
                update={
                    "retain_prompts": False,
                    "retain_responses": True,
                    "retain_reasoning": False,
                }
            )
        }
    )
    model = ModelRef.parse("openrouter:test/model")
    item = EvaluationItem(
        item_id="i",
        model=model,
        attack_id="a",
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id="a", text="SECRET PROMPT", sample_id="s"),
        response=ModelResponse(
            text="visible answer",
            model=model,
            reasoning="SECRET REASONING",
            reasoning_source=ReasoningSource.DELIMITED,
            usage=TokenUsage(1, 1),
        ),
        assessment=AttackAssessment(success=True, score=1.0),
        monitors=(MonitorOutcome("regex", MonitorStatus.CLEAN, 0.1, "ok"),),
    )
    summary = RunSummary.from_items([item])
    run = EvaluationRun(
        run_id="r",
        status=summary.status,
        items=(item,),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    cleaned = sanitize_run(run, config)
    assert cleaned.items[0].prompt is not None
    assert cleaned.items[0].prompt.text == "[redacted]"
    assert cleaned.items[0].response is not None
    assert cleaned.items[0].response.text == "visible answer"
    assert cleaned.items[0].response.reasoning is None
