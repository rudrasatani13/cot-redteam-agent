"""Agent retention: privacy-first sanitization at every storage boundary.

Structural data is always retained because it is needed for proof: event
type, tool/action names, resource identifiers, sanitized authorization
scopes, status/error classes, event relationships, state digests, and
oracle verdicts. Raw tool arguments/results, memory values, world values,
and final-response content are omitted by default.

The same deterministic sanitizer is used by the trajectory recorder's
persistence sink, the SQLite agent store (a final boundary that sanitizes
again even when the caller claims an event is already sanitized), the
replay writer, and the reporters.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast

from cot_redteam.agent.config import AgentRetentionSettings
from cot_redteam.agent.types import (
    AgentEventUnion,
    AgentRun,
    AgentTrajectory,
    FinalResponse,
    Finding,
    MemoryMutation,
    OracleResult,
    ToolCallRequested,
    ToolResultReceived,
)
from cot_redteam.core.types import JsonValue
from cot_redteam.eval.retention import redact_sensitive_values

_ERROR_SECRET_RE = re.compile(
    r"(?P<label>\b(?:authorization|proxy-authorization|api[_-]?key|apikey|"
    r"access[_-]?token|refresh[_-]?token|secret|password|cookie|set-cookie|"
    r"session|bearer)\b)(?P<separator>\s*[:=]\s*|\s+)(?P<value>[^\s,;]+)",
    re.IGNORECASE,
)


def sanitize_error_text(error: str | None, *, secrets: tuple[str, ...] = ()) -> str | None:
    """Redact known secrets and credential-like values from run errors."""
    if error is None:
        return None
    redacted = str(redact_sensitive_values(error, secrets=secrets))
    return _ERROR_SECRET_RE.sub(
        lambda match: f"{match.group('label')}{match.group('separator')}[redacted]",
        redacted,
    )


def world_canary_secrets(*snapshots: object) -> tuple[str, ...]:
    """Extract synthetic world canaries for diagnostic redaction.

    Only values under the explicit ``canaries`` state bucket are treated as
    secrets.  Other world values may be proof-relevant identifiers and must
    not be blanket-redacted.  Snapshots are accepted as generic objects so
    this helper does not couple retention to a concrete world implementation.
    """
    values: list[str] = []
    for snapshot in snapshots:
        state = getattr(snapshot, "state", snapshot)
        if not isinstance(state, Mapping):
            continue
        canaries = state.get("canaries")
        if not isinstance(canaries, Mapping):
            continue
        for value in canaries.values():
            if isinstance(value, str) and value and value not in values:
                values.append(value)
    return tuple(values)


def _sanitize_diagnostic_value(value: JsonValue, *, secrets: tuple[str, ...]) -> JsonValue:
    """Redact credential-like strings and configured canaries recursively."""
    redacted = redact_sensitive_values(value, secrets=secrets)
    if isinstance(redacted, str):
        return sanitize_error_text(redacted, secrets=secrets)
    if isinstance(redacted, Mapping):
        return {
            str(key): _sanitize_diagnostic_value(child, secrets=secrets)
            for key, child in redacted.items()
        }
    if isinstance(redacted, list):
        return [_sanitize_diagnostic_value(child, secrets=secrets) for child in redacted]
    if isinstance(redacted, tuple):
        return tuple(_sanitize_diagnostic_value(child, secrets=secrets) for child in redacted)
    return redacted


class AgentSanitizer:
    def __init__(
        self,
        settings: AgentRetentionSettings,
        *,
        secrets: tuple[str, ...] = (),
    ) -> None:
        self.settings = settings
        self.secrets = secrets

    def sanitize_event(self, data: Mapping[str, object]) -> dict[str, object]:
        """Sanitize one event envelope before persistence/reporting.

        Structural fields (event ids, relationships, tool names, resource
        identifiers, authorization scopes, status/error classes, digests)
        are always retained because they are the proof. Only value-carrying
        payload fields are omitted per retention or redacted for
        credential-class keys. Authorization scopes are contractually free
        of credential material and are never redacted wholesale.
        """
        out = dict(data)
        event_type = out.get("event_type")
        if event_type == "final_response" and not self.settings.retain_final_response:
            out["text"] = None
            out["text_retained"] = False
            out["text_artifact"] = None
        elif event_type == "tool_call_requested" and not self.settings.retain_tool_arguments:
            out["sanitized_arguments"] = None
            out["arguments_artifact"] = None
        elif event_type == "tool_result_received" and not self.settings.retain_tool_results:
            out["sanitized_result"] = None
            out["result_artifact"] = None
        elif event_type == "memory_mutation" and not self.settings.retain_memory_values:
            out["value_present"] = False
            out["value_artifact"] = None
        # Value-carrying fields keep credential-class redaction regardless of
        # retention flags.
        if out.get("payload") is not None:
            out["payload"] = redact_sensitive_values(out["payload"])
        if out.get("sanitized_arguments") is not None:
            out["sanitized_arguments"] = redact_sensitive_values(out["sanitized_arguments"])
        if out.get("sanitized_result") is not None:
            out["sanitized_result"] = redact_sensitive_values(out["sanitized_result"])
        return out

    def sanitize_arguments(self, arguments: Mapping[str, JsonValue]) -> JsonValue:
        if not self.settings.retain_tool_arguments:
            return {"redacted": True}
        return cast(JsonValue, redact_sensitive_values(dict(arguments)))

    def sanitize_result(self, result: JsonValue) -> JsonValue:
        if not self.settings.retain_tool_results:
            return {"redacted": True}
        return cast(JsonValue, redact_sensitive_values(result))

    def sanitize_oracle_result(self, result: OracleResult) -> OracleResult:
        """Sanitize oracle diagnostics before persistence or reporting.

        Verdicts, IDs, digests, and event references are structural proof
        fields. Human-readable diagnostics and evidence details are treated as
        untrusted and redacted for credential-like values and world canaries.
        """
        evidence = tuple(
            item.model_copy(
                update={
                    "kind": sanitize_error_text(item.kind, secrets=self.secrets) or "",
                    "resource": sanitize_error_text(item.resource, secrets=self.secrets),
                    "detail": _sanitize_diagnostic_value(item.detail, secrets=self.secrets),
                }
            )
            for item in result.evidence
        )
        return result.model_copy(
            update={
                "summary": sanitize_error_text(result.summary, secrets=self.secrets) or "",
                "evidence": evidence,
                "error": sanitize_error_text(result.error, secrets=self.secrets),
            }
        )

    def sanitize_oracle_result_collection(
        self, results: tuple[OracleResult, ...]
    ) -> tuple[OracleResult, ...]:
        """Sanitize a complete oracle result collection deterministically."""
        return tuple(self.sanitize_oracle_result(result) for result in results)

    def sanitize_finding(self, finding: Finding) -> Finding:
        """Sanitize finding diagnostics derived from oracle output."""
        return finding.model_copy(
            update={
                "category": sanitize_error_text(finding.category, secrets=self.secrets) or "",
                "summary": sanitize_error_text(finding.summary, secrets=self.secrets) or "",
            }
        )

    def sanitize_world_state(self, state: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        """World values are proof-irrelevant after the oracle has run; the
        digests are the evidence."""
        if not self.settings.retain_world_values:
            return {str(key): "[redacted]" for key in state}
        return cast("dict[str, JsonValue]", redact_sensitive_values(dict(state)))

    def sanitize_trajectory(self, trajectory: AgentTrajectory) -> AgentTrajectory:
        """Sanitize events and RECOMPUTE the digest over the sanitized
        content: a trajectory object must never carry a checksum that does
        not describe its own events. The original digest is preserved by
        ``sanitize_run`` in ``AgentRun.original_trajectory_digest``."""
        events: list[AgentEventUnion] = []
        for event in trajectory.events:
            if isinstance(event, FinalResponse) and not self.settings.retain_final_response:
                event = event.model_copy(update={"text": None, "text_retained": False})
            elif isinstance(event, ToolCallRequested) and not self.settings.retain_tool_arguments:
                event = event.model_copy(update={"sanitized_arguments": None})
            elif isinstance(event, ToolResultReceived) and not self.settings.retain_tool_results:
                event = event.model_copy(update={"sanitized_result": None})
            elif isinstance(event, MemoryMutation) and not self.settings.retain_memory_values:
                event = event.model_copy(update={"value_present": False})
            events.append(event)
        # digest=None -> recomputed over the sanitized events.
        return AgentTrajectory(
            run_id=trajectory.run_id,
            session_id=trajectory.session_id,
            events=tuple(events),
        )

    def sanitize_run(self, run: AgentRun) -> AgentRun:
        """Final boundary enforcement over a complete AgentRun.

        The sanitized trajectory's digest describes the sanitized content;
        ``AgentRun.original_trajectory_digest`` keeps the proof anchor of
        the original (pre-retention) trajectory.
        """
        return run.model_copy(
            update={
                "trajectory": self.sanitize_trajectory(run.trajectory),
                "original_trajectory_digest": run.original_trajectory_digest
                or run.trajectory.digest,
                "error": sanitize_error_text(run.error, secrets=self.secrets),
                "oracle_results": tuple(
                    self.sanitize_oracle_result(result) for result in run.oracle_results
                ),
                "findings": tuple(self.sanitize_finding(finding) for finding in run.findings),
            }
        )


def sanitize_agent_run(run: AgentRun, settings: AgentRetentionSettings) -> AgentRun:
    return AgentSanitizer(settings).sanitize_run(run)
