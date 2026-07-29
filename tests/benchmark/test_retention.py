from __future__ import annotations

from cot_redteam.benchmark.retention import sanitize_trial_result
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
