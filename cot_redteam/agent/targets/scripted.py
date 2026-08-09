"""Deterministic scripted target fixtures for the agent engine.

``ScriptedTarget`` runs a declarative script: a fixed sequence of tool
calls and an optional final response. Tool calls go through the runtime's
deny-by-default ``ToolGatewayProtocol``; the gateway decides authorization
and records the gateway-observed events. Vulnerable/patched/clean fixtures
are code-defined built-ins that parameterize the script (PR6 wires them to
the Support Agent World).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from cot_redteam.agent.target import (
    AgentTargetRequest,
    FinalResponseData,
    TargetRuntime,
)
from cot_redteam.agent.types import (
    AgentStep,
    AgentTargetCapabilities,
    AuthorizationScope,
    EventProvenance,
    EventTrust,
    FinalResponse,
)
from cot_redteam.core.types import JsonValue


@dataclass(frozen=True)
class ScriptedToolCall:
    tool_name: str
    arguments: Mapping[str, JsonValue] = field(default_factory=dict)
    requested_authorization: tuple[AuthorizationScope, ...] = ()
    requires_approval: bool = False
    approval_principal: str = "support_agent"
    approval_policy_id: str = "support/1"
    approval_policy_version: str = "1"
    #: Normalized approval subject (e.g. ``crm.update_customer:C-7:note``).
    #: Defaults to the tool name.
    approval_subject: str | None = None


@dataclass(frozen=True)
class ScriptedFinalResponse:
    text: str


ScriptedStep = ScriptedToolCall | ScriptedFinalResponse


class ScriptedTarget:
    """Fixture target that executes a fixed, deterministic script."""

    id = "scripted"
    version = "1"
    capabilities = AgentTargetCapabilities(
        tool_use=True,
        approval_controls=True,
        mutable_state=True,
        parallel_tool_calls=True,
        external_network=False,
        persistent_memory=False,
        delegation=False,
    )

    def __init__(
        self,
        *,
        script: Sequence[ScriptedStep],
        target_id: str = "scripted",
        target_version: str = "1",
        retain_final_response: bool = True,
    ) -> None:
        self.id = target_id
        self.version = target_version
        self.script = tuple(script)
        self.retain_final_response = retain_final_response
        self.closed = False

    def _provenance(self, source_id: str) -> EventProvenance:
        return EventProvenance(
            source_kind="target",
            source_id=source_id,
            source_version=self.version,
            trust=EventTrust.UNTRUSTED,
        )

    async def run(
        self,
        request: AgentTargetRequest,
        runtime: TargetRuntime,
    ) -> FinalResponseData:
        provenance = self._provenance(self.id)
        await runtime.trajectory.record(
            AgentStep(
                run_id=request.run_id,
                session_id=request.session_id,
                event_id=f"{self.id}-step-{request.run_id}",
                agent_id=self.id,
                provenance=provenance,
                step_kind="decision",
                input_source=request.user_input,
            )
        )
        final_text: str | None = None
        for index, step in enumerate(self.script):
            if isinstance(step, ScriptedFinalResponse):
                final_text = step.text
                continue
            call_id = f"call-{index}"
            if step.requires_approval:
                approval_id = f"approval-{index}"
                subject_action = step.approval_subject or step.tool_name
                granted = await runtime.approvals.request(
                    approval_id=approval_id,
                    subject_action=subject_action,
                    principal=step.approval_principal,
                    policy_id=step.approval_policy_id,
                    policy_version=step.approval_policy_version,
                )
                # The ApprovalDecision event is recorded by the approval gate
                # (engine-owned, trusted provenance), never by the target, so
                # a target cannot forge a granted approval.
                if not granted:
                    continue
            await runtime.tool_gateway.execute(
                call_id=call_id,
                tool_name=step.tool_name,
                arguments=step.arguments,
                requested_authorization=step.requested_authorization,
            )
        final_event = FinalResponse(
            run_id=request.run_id,
            session_id=request.session_id,
            event_id=f"{self.id}-final-{request.run_id}",
            parent_event_id=f"{self.id}-step-{request.run_id}",
            agent_id=self.id,
            provenance=provenance,
            text_retained=self.retain_final_response and final_text is not None,
            text=final_text if self.retain_final_response else None,
        )
        await runtime.trajectory.record(final_event)
        return FinalResponseData(
            text_retained=final_event.text_retained,
            text=final_event.text,
        )

    async def aclose(self) -> None:
        self.closed = True
