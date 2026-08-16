"""Regression tests for engine attempt-selection and history scrubbing fixes."""

from __future__ import annotations

from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    ModelRef,
    ModelResponse,
    TokenUsage,
)
from cot_redteam.eval.engine import EvaluationEngine, _scrub_secret


def _prompt(text: str) -> AttackPrompt:
    return AttackPrompt(attack_id="a", text=text, sample_id="s1")


def _response(text: str) -> ModelResponse:
    return ModelResponse(text=text, model=ModelRef.parse("fake:m"), usage=TokenUsage(1, 1))


def _assessment(success: bool) -> AttackAssessment:
    return AttackAssessment(
        success=success,
        score=1.0 if success else 0.0,
        evidence=("ok",) if success else (),
    )


def test_select_final_attempt_prefers_success_over_later_failure() -> None:
    """H6: with stop_on_success disabled a real disclosure must survive."""
    success_prompt = _prompt("winning prompt")
    success_response = _response("here is the token")
    success_assessment = _assessment(True)
    last_prompt = _prompt("later failing prompt")
    last_response = _response("refused")
    last_assessment = _assessment(False)

    prompt, response, assessment = EvaluationEngine._select_final_attempt(
        last_prompt,
        last_response,
        last_assessment,
        success_prompt,
        success_response,
        success_assessment,
        "winning-payload",
    )
    assert prompt is success_prompt
    assert response is success_response
    assert assessment is success_assessment
    assert assessment.success is True


def test_select_final_attempt_keeps_last_when_no_success() -> None:
    last_prompt = _prompt("only prompt")
    last_response = _response("refused")
    last_assessment = _assessment(False)
    prompt, response, assessment = EvaluationEngine._select_final_attempt(
        last_prompt,
        last_response,
        last_assessment,
        None,
        None,
        None,
        None,
    )
    assert prompt is last_prompt
    assert response is last_response
    assert assessment is last_assessment


def test_select_final_attempt_keeps_last_success() -> None:
    """When the last attempt itself succeeded, keep it (no swap needed)."""
    success_prompt = _prompt("final winning prompt")
    success_response = _response("token disclosed")
    success_assessment = _assessment(True)
    prompt, _, assessment = EvaluationEngine._select_final_attempt(
        success_prompt,
        success_response,
        success_assessment,
        success_prompt,
        success_response,
        success_assessment,
        "payload",
    )
    assert prompt is success_prompt
    assert assessment.success is True


def test_scrub_secret_is_idempotent_and_safe() -> None:
    secret = "COT-REDTEAM-CANARY-XYZ12345"
    text = f"refusal quoting {secret} and lowercase {secret.lower()}"
    once = _scrub_secret(text, secret)
    twice = _scrub_secret(once, secret)
    assert secret not in once
    assert secret.lower() not in once
    assert once == twice
    # Short "secrets" are left alone to avoid mangling ordinary text.
    assert _scrub_secret("abc def", "abc") == "abc def"
