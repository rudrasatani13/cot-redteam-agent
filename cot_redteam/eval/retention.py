"""Sanitize evaluation runs according to retention policy before persistence.

Also provides the shared recursive sensitive-value redactor used by the
agent retention boundary, benchmark retention, and monitor detail
sanitization.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, cast

from cot_redteam.core.config import AppConfig
from cot_redteam.core.types import (
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    ModelResponse,
    MonitorOutcome,
    ReasoningSource,
)

#: Normalized credential-class key names that must never persist raw values.
SENSITIVE_KEY_RE = re.compile(
    r"(authorization|proxy-authorization|api[_-]?key|apikey|access[_-]?token|"
    r"refresh[_-]?token|secret|password|cookie|set-cookie|session|bearer)",
    re.IGNORECASE,
)

_REDACTED = "[redacted]"


def redact_sensitive_values(value: Any, *, secrets: Sequence[str] = ()) -> Any:
    """Recursively replace sensitive values.

    - Mapping keys matching ``SENSITIVE_KEY_RE`` are redacted;
    - string values are scrubbed of any configured ``secrets`` substring, and
      JSON-encoded strings are parsed, redacted recursively, and
      re-serialized deterministically;
    - lists, tuples, and mappings are traversed recursively.
    """
    if isinstance(value, str):
        redacted = value
        for secret in secrets:
            if secret and secret in redacted:
                redacted = redacted.replace(secret, _REDACTED)
        try:
            decoded = json.loads(redacted)
        except (json.JSONDecodeError, TypeError):
            return redacted
        if isinstance(decoded, (dict, list)):
            return json.dumps(
                redact_sensitive_values(decoded, secrets=secrets),
                ensure_ascii=False,
                sort_keys=True,
            )
        return redacted
    if isinstance(value, Mapping):
        return {
            str(key): (
                _REDACTED
                if SENSITIVE_KEY_RE.search(str(key))
                else redact_sensitive_values(item, secrets=secrets)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return type(value)(redact_sensitive_values(item, secrets=secrets) for item in value)
    return value


def _sanitize_monitor(
    outcome: MonitorOutcome,
    *,
    retain_responses: bool,
    secrets: Sequence[str] = (),
) -> MonitorOutcome:
    details = dict(outcome.details)
    if not retain_responses:
        # LLMJudgeMonitor stores a truncated raw judge response; it must not
        # survive when model responses are configured not to be retained.
        details.pop("judge_response", None)
    details = cast("dict[str, Any]", redact_sensitive_values(details, secrets=secrets))
    explanation = cast(str, redact_sensitive_values(outcome.explanation, secrets=secrets))
    return MonitorOutcome(
        monitor_id=outcome.monitor_id,
        status=outcome.status,
        confidence=outcome.confidence,
        explanation=explanation,
        details=details,
    )


def sanitize_run(
    run: EvaluationRun,
    config: AppConfig,
    *,
    secrets: Sequence[str] = (),
) -> EvaluationRun:
    """Strip prompts/responses/reasoning when retention flags are false.

    ``secrets`` is an optional explicit set of values that must never
    survive in monitor details or explanations.
    """
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
            # retain_responses and retain_reasoning are independent toggles:
            # a user may keep reasoning while redacting response text or vice
            # versa. Reasoning is only dropped when retain_reasoning is false.
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
        monitors = tuple(
            _sanitize_monitor(
                outcome,
                retain_responses=retain_responses,
                secrets=secrets,
            )
            for outcome in item.monitors
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
                monitors=monitors,
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
