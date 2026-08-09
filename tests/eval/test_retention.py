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


def _run_with_monitor_details(
    details: dict,
    *,
    retain_responses: bool,
    secrets: tuple[str, ...] = (),
) -> EvaluationRun:
    model = ModelRef.parse("openrouter:test/model")
    monitor = MonitorOutcome(
        monitor_id="llm_judge",
        status=MonitorStatus.CLEAN,
        confidence=0.2,
        explanation="judge said ok",
        details=details,
    )
    item = EvaluationItem(
        item_id="i",
        model=model,
        attack_id="a",
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id="a", text="probe", sample_id="s"),
        response=ModelResponse(
            text="answer",
            model=model,
            usage=TokenUsage(1, 1),
        ),
        assessment=AttackAssessment(success=False, score=0.0),
        monitors=(monitor,),
    )
    summary = RunSummary.from_items([item])
    return EvaluationRun(
        run_id="r",
        status=summary.status,
        items=(item,),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def test_judge_response_removed_when_responses_not_retained(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    config = config.model_copy(
        update={
            "evaluation": config.evaluation.model_copy(
                update={
                    "retain_prompts": True,
                    "retain_responses": False,
                    "retain_reasoning": True,
                }
            )
        }
    )
    run = _run_with_monitor_details(
        {"judge_response": "raw judge text", "raw_keys": ["suspicious"]},
        retain_responses=False,
    )
    cleaned = sanitize_run(run, config)
    details = cleaned.items[0].monitors[0].details
    assert "judge_response" not in details
    assert details["raw_keys"] == ["suspicious"]


def test_monitor_details_sensitive_keys_redacted_recursively(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    config = config.model_copy(
        update={
            "evaluation": config.evaluation.model_copy(
                update={
                    "retain_prompts": True,
                    "retain_responses": True,
                    "retain_reasoning": True,
                }
            )
        }
    )
    run = _run_with_monitor_details(
        {
            "judge_response": "ok",
            "headers": {
                "authorization": "Bearer SECRETTOKEN",
                "x-api-key": "k-123",
                "cookie": "session=abc",
                "safe": {"nested": "value", "access_token": "tok-1"},
            },
        },
        retain_responses=True,
    )
    cleaned = sanitize_run(run, config)
    details = cleaned.items[0].monitors[0].details
    headers = details["headers"]
    assert headers["authorization"] == "[redacted]"
    assert headers["x-api-key"] == "[redacted]"
    assert headers["cookie"] == "[redacted]"
    assert headers["safe"]["access_token"] == "[redacted]"
    assert headers["safe"]["nested"] == "value"


def test_explicit_secret_values_redacted_in_details_and_explanation(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    config = config.model_copy(
        update={
            "evaluation": config.evaluation.model_copy(
                update={
                    "retain_prompts": True,
                    "retain_responses": True,
                    "retain_reasoning": True,
                }
            )
        }
    )
    secret = "CANARY-SECRET-1234"
    run = _run_with_monitor_details(
        {"judge_response": f"mentioning {secret}"},
        retain_responses=True,
    )
    # Explanation must also be scrubbed when it contains a configured secret.
    monitor = run.items[0].monitors[0]
    from dataclasses import replace

    monitor = replace(monitor, explanation=f"leaked {secret} here")
    run = EvaluationRun(
        run_id=run.run_id,
        status=run.status,
        items=(replace(run.items[0], monitors=(monitor,)),),
        summary=run.summary,
        started_at=run.started_at,
        completed_at=run.completed_at,
    )
    cleaned = sanitize_run(run, config, secrets=(secret,))
    details = cleaned.items[0].monitors[0].details
    assert secret not in str(details)
    assert secret not in cleaned.items[0].monitors[0].explanation
