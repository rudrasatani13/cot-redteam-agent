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

from collections.abc import Mapping
from typing import cast

from cot_redteam.agent.config import AgentRetentionSettings
from cot_redteam.agent.types import (
    AgentEventUnion,
    AgentRun,
    AgentTrajectory,
    FinalResponse,
    MemoryMutation,
    ToolCallRequested,
    ToolResultReceived,
)
from cot_redteam.core.types import JsonValue
from cot_redteam.eval.retention import redact_sensitive_values


class AgentSanitizer:
    def __init__(self, settings: AgentRetentionSettings) -> None:
        self.settings = settings

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

    def sanitize_world_state(self, state: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
        """World values are proof-irrelevant after the oracle has run; the
        digests are the evidence."""
        if not self.settings.retain_world_values:
            return {str(key): "[redacted]" for key in state}
        return cast("dict[str, JsonValue]", redact_sensitive_values(dict(state)))

    def sanitize_trajectory(self, trajectory: AgentTrajectory) -> AgentTrajectory:
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
        return AgentTrajectory(
            run_id=trajectory.run_id,
            session_id=trajectory.session_id,
            events=tuple(events),
            digest=trajectory.digest,
        )

    def sanitize_run(self, run: AgentRun) -> AgentRun:
        """Final boundary enforcement over a complete AgentRun."""
        return run.model_copy(
            update={
                "trajectory": self.sanitize_trajectory(run.trajectory),
            }
        )


def sanitize_agent_run(run: AgentRun, settings: AgentRetentionSettings) -> AgentRun:
    return AgentSanitizer(settings).sanitize_run(run)
