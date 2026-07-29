"""Apply the single evaluation retention policy to benchmark results."""

from __future__ import annotations

from dataclasses import replace

from cot_redteam.benchmark.conversation import ConversationTranscript, ConversationTurn
from cot_redteam.benchmark.judge import JudgeResult
from cot_redteam.benchmark.results import BenchmarkTrialResult
from cot_redteam.benchmark.scoring import EvidenceChannel, ScorerOutcome, TranscriptScoring
from cot_redteam.core.config import EvaluationSettings
from cot_redteam.core.types import Message, ModelResponse, ReasoningSource

_REDACTED = "[redacted]"


def _redact_message(message: Message) -> Message:
    return replace(message, content=_REDACTED, metadata={})


def _sanitize_response(
    response: ModelResponse | None,
    settings: EvaluationSettings,
) -> ModelResponse | None:
    if response is None:
        return None
    reasoning = response.reasoning if settings.retain_reasoning else None
    source = response.reasoning_source if settings.retain_reasoning else ReasoningSource.ABSENT
    return replace(
        response,
        text=response.text if settings.retain_responses else _REDACTED,
        reasoning=reasoning,
        reasoning_source=source,
        metadata=response.metadata if settings.retain_responses else {},
    )


def _sanitize_outcome(
    outcome: ScorerOutcome,
    settings: EvaluationSettings,
) -> ScorerOutcome:
    retain_evidence = (
        settings.retain_responses
        if outcome.channel is EvidenceChannel.FINAL
        else settings.retain_reasoning
    )
    return replace(outcome, evidence=outcome.evidence if retain_evidence else ())


def sanitize_trial_result(
    result: BenchmarkTrialResult,
    settings: EvaluationSettings,
) -> BenchmarkTrialResult:
    messages = tuple(
        message if settings.retain_prompts else _redact_message(message)
        for message in result.transcript.messages
    )
    turns = tuple(
        ConversationTurn(
            turn_index=turn.turn_index,
            request_messages=tuple(
                message if settings.retain_prompts else _redact_message(message)
                for message in turn.request_messages
            ),
            response=_sanitize_response(turn.response, settings),
            error=turn.error,
        )
        for turn in result.transcript.turns
    )
    transcript = ConversationTranscript(
        trial_id=result.transcript.trial_id,
        status=result.transcript.status,
        messages=messages,
        turns=turns,
        error=result.transcript.error,
    )
    scoring = TranscriptScoring(
        trial_id=result.scoring.trial_id,
        outcomes=tuple(
            _sanitize_outcome(outcome, settings) for outcome in result.scoring.outcomes
        ),
    )
    judges = tuple(
        JudgeResult(
            outcome=_sanitize_outcome(judge.outcome, settings),
            raw_input=judge.raw_input if settings.retain_prompts else _REDACTED,
            raw_output=judge.raw_output if settings.retain_responses else None,
        )
        for judge in result.judge_results
    )
    return replace(
        result,
        transcript=transcript,
        scoring=scoring,
        judge_results=judges,
    )
