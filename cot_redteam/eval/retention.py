"""Sanitize evaluation runs according to retention policy before persistence."""

from __future__ import annotations

from cot_redteam.core.config import AppConfig
from cot_redteam.core.types import (
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    ModelResponse,
    ReasoningSource,
)


def sanitize_run(run: EvaluationRun, config: AppConfig) -> EvaluationRun:
    """Strip prompts/responses/reasoning when retention flags are false."""
    retain_prompts = config.evaluation.retain_prompts
    retain_responses = config.evaluation.retain_responses
    retain_reasoning = config.evaluation.retain_reasoning
    items: list[EvaluationItem] = []
    for item in run.items:
        prompt = item.prompt
        response = item.response
        if prompt is not None and not retain_prompts:
            prompt = AttackPrompt(
                attack_id=prompt.attack_id,
                text="[redacted]",
                sample_id=prompt.sample_id,
                system_prompt=None,
                metadata={},
            )
        if response is not None:
            text = response.text if retain_responses else "[redacted]"
            reasoning = response.reasoning
            source = response.reasoning_source
            if not retain_reasoning:
                reasoning = None
                source = ReasoningSource.ABSENT
            if not retain_responses:
                # Without response body, also drop reasoning content.
                reasoning = None if not retain_reasoning else reasoning
            response = ModelResponse(
                text=text,
                model=response.model,
                reasoning=reasoning,
                reasoning_source=source,
                latency_ms=response.latency_ms,
                usage=response.usage,
                provider_request_id=response.provider_request_id,
                finish_reason=response.finish_reason,
                model_revision=response.model_revision,
                metadata=response.metadata if retain_responses else {},
            )
        items.append(
            EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample_id,
                status=item.status,
                prompt=prompt,
                response=response,
                assessment=item.assessment,
                monitors=item.monitors,
                error=item.error,
                started_at=item.started_at,
                completed_at=item.completed_at,
            )
        )
    return EvaluationRun(
        run_id=run.run_id,
        status=run.status,
        items=tuple(items),
        summary=run.summary,
        started_at=run.started_at,
        completed_at=run.completed_at,
        seed=run.seed,
        config_digest=run.config_digest,
        dataset_digest=run.dataset_digest,
        metadata=run.metadata,
    )
