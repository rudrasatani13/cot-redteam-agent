from __future__ import annotations

from dataclasses import replace

from cot_redteam.benchmark.judge import JudgeResult
from cot_redteam.benchmark.retention import sanitize_trial_result
from cot_redteam.benchmark.scoring import (
    EvidenceChannel,
    ScorerOutcome,
    ScorerVerdict,
)
from cot_redteam.core.config import EvaluationSettings

from .test_results import benchmark_trial_result


def test_benchmark_retention_redacts_every_sensitive_channel(tmp_path) -> None:
    result = benchmark_trial_result(tmp_path)
    settings = EvaluationSettings(
        models=["gateway:model"],
        attacks=[],
        monitors=[],
        retain_prompts=False,
        retain_responses=False,
        retain_reasoning=False,
    )

    cleaned = sanitize_trial_result(result, settings)

    assert all(message.content == "[redacted]" for message in cleaned.transcript.messages)
    response = cleaned.transcript.turns[0].response
    assert response is not None
    assert response.text == "[redacted]"
    assert response.reasoning is None
    assert all(not outcome.evidence for outcome in cleaned.scoring.outcomes)


def test_benchmark_retention_redacts_judge_subject_and_explanation(tmp_path) -> None:
    result = benchmark_trial_result(tmp_path)
    judge = JudgeResult(
        outcome=ScorerOutcome(
            scorer_id="judge.test",
            scorer_version="1.0.0",
            channel=EvidenceChannel.REASONING,
            verdict=ScorerVerdict.SUCCESS,
            score=1.0,
            eligible=True,
            explanation="quoted SECRET REASONING",
            judge_metadata={"model": "judge"},
        ),
        raw_input="subject SECRET REASONING",
        raw_output='{"explanation":"SECRET REASONING"}',
    )
    result = replace(result, judge_results=(judge,))
    settings = EvaluationSettings(
        models=["gateway:model"],
        attacks=[],
        monitors=[],
        retain_prompts=True,
        retain_responses=True,
        retain_reasoning=False,
    )

    cleaned = sanitize_trial_result(result, settings)

    assert cleaned.judge_results[0].raw_input == "[redacted]"
    assert cleaned.judge_results[0].raw_output is None
    assert cleaned.judge_results[0].outcome.explanation == "[redacted]"
