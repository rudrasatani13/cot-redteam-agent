"""Scripted and provider-adapter target tests."""

from __future__ import annotations

import pytest

from cot_redteam.agent.target import (
    AgentTargetRequest,
    FinalResponseData,
    TargetRuntime,
)
from cot_redteam.agent.targets.provider_adapter import ProviderTargetAdapter
from cot_redteam.agent.targets.scripted import (
    ScriptedFinalResponse,
    ScriptedTarget,
    ScriptedToolCall,
)
from cot_redteam.agent.trajectory import TrajectoryRecorder
from cot_redteam.agent.types import (
    AgentTargetCapabilities,
    AuthorizationScope,
    ToolCallRequested,
)
from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.types import ModelRef, TokenUsage
from cot_redteam.eval.budgets import BudgetTracker


class FakeGateway:
    """Mirrors the real ToolGateway contract: records the gateway-observed
    ToolCallRequested / ToolResultReceived events into the trajectory."""

    def __init__(self, recorder) -> None:
        # The fake gateway models a trusted producer and therefore uses the
        # recorder's private capability-bearing writer.
        self.recorder = recorder._trusted_writer()
        self.calls: list[tuple[str, dict]] = []

    async def execute(self, *, call_id, tool_name, arguments, requested_authorization=()):
        self.calls.append((tool_name, dict(arguments)))
        from cot_redteam.agent.types import (
            EventProvenance,
            ToolCallRequested,
            ToolResultReceived,
        )

        provenance = EventProvenance(
            source_kind="tool_gateway",
            source_id="fake_gateway",
            source_version="1",
        )
        await self.recorder.record(
            ToolCallRequested(
                event_type="tool_call_requested",
                run_id=self.recorder.run_id,
                session_id=self.recorder.session_id,
                event_id=f"gw-{call_id}-req",
                agent_id=self.recorder.agent_id,
                provenance=provenance,
                call_id=call_id,
                tool_name=tool_name,
                tool_version="1",
                requested_authorization_scope=requested_authorization,
            )
        )
        await self.recorder.record(
            ToolResultReceived(
                event_type="tool_result_received",
                run_id=self.recorder.run_id,
                session_id=self.recorder.session_id,
                event_id=f"gw-{call_id}-res",
                parent_event_id=f"gw-{call_id}-req",
                agent_id=self.recorder.agent_id,
                provenance=provenance,
                call_id=call_id,
                tool_name=tool_name,
                sanitized_result={"ok": True},
            )
        )
        return {"ok": True}


class FakeApprovals:
    """Mirrors the engine's PolicyApprovalGate: records the ApprovalDecision
    in the trajectory with SYSTEM (trusted) provenance."""

    def __init__(self, granted: bool = True, recorder=None) -> None:
        self.granted = granted
        self.requests: list[str] = []
        self.recorder = recorder

    async def request(self, *, approval_id, subject_action, principal, policy_id, policy_version):
        self.requests.append(approval_id)
        if self.recorder is not None:
            from cot_redteam.agent.types import (
                ApprovalDecision,
                ApprovalValue,
                EventProvenance,
            )

            await self.recorder.record(
                ApprovalDecision(
                    event_type="approval_decision",
                    run_id=self.recorder.run_id,
                    session_id=self.recorder.session_id,
                    event_id=f"gate-approval-{approval_id}",
                    agent_id=self.recorder.agent_id,
                    provenance=EventProvenance(
                        source_kind="system",
                        source_id="approval_gate",
                        source_version="1",
                    ),
                    approval_id=approval_id,
                    subject_action=subject_action,
                    decision=ApprovalValue.GRANTED if self.granted else ApprovalValue.DENIED,
                    principal=principal,
                    policy_id=policy_id,
                    policy_version=policy_version,
                )
            )
        return self.granted


class FakeInvocationService:
    def __init__(self) -> None:
        self.calls = 0

    async def invoke(self, *, model, request, role, correlation_id=None):
        self.calls += 1
        from cot_redteam.core.types import ModelResponse

        return ModelResponse(
            text="provider answer",
            model=model,
            usage=TokenUsage(1, 1),
            provider_request_id="p",
        )


def _request() -> AgentTargetRequest:
    return AgentTargetRequest(
        scenario_id="support.indirect_prompt_injection.v1",
        scenario_version="1",
        attack_id="injection.indirect.v1",
        attack_version="1",
        run_id="run-1",
        session_id="session-1",
        seed=7,
        user_input="ticket T-42 needs help",
    )


def _runtime(
    *,
    gateway=None,
    approvals=None,
    invocation=None,
    agent_id: str = "scripted",
    with_recorder: bool = False,
    with_gateway: bool = False,
) -> (
    TargetRuntime
    | tuple[TargetRuntime, TrajectoryRecorder]
    | tuple[TargetRuntime, object]
    | tuple[TargetRuntime, TrajectoryRecorder, object]
):
    recorder = TrajectoryRecorder(run_id="run-1", session_id="session-1", agent_id=agent_id)
    gateway_instance = gateway or FakeGateway(recorder)
    runtime = TargetRuntime(
        run_id="run-1",
        session_id="session-1",
        invocation_service=invocation or FakeInvocationService(),
        tool_gateway=gateway_instance,
        trajectory=recorder,
        approvals=approvals or FakeApprovals(),
        budget=BudgetTracker(BudgetSettings()),
    )
    if with_recorder and with_gateway:
        return runtime, recorder, gateway_instance
    if with_recorder:
        return runtime, recorder
    if with_gateway:
        return runtime, gateway_instance
    return runtime


def test_scripted_target_capabilities() -> None:
    target = ScriptedTarget(script=())
    caps = target.capabilities
    assert isinstance(caps, AgentTargetCapabilities)
    assert caps.tool_use is True
    assert caps.external_network is False


@pytest.mark.asyncio
async def test_scripted_target_executes_script_and_closes() -> None:
    target = ScriptedTarget(
        script=(
            ScriptedToolCall(
                tool_name="support.get_ticket",
                arguments={"ticket_id": "T-42"},
            ),
            ScriptedFinalResponse(text="I resolved T-42."),
        )
    )
    runtime, gateway = _runtime(with_gateway=True)
    result = await target.run(_request(), runtime)
    assert isinstance(result, FinalResponseData)
    assert result.text_retained is True
    assert result.text == "I resolved T-42."
    assert gateway.calls == [("support.get_ticket", {"ticket_id": "T-42"})]
    trajectory = runtime.trajectory.build_trajectory()
    assert trajectory.digest is not None
    assert trajectory.events[0].event_type == "agent_step"
    assert trajectory.events[-1].event_type == "final_response"
    await target.aclose()
    assert target.closed is True


@pytest.mark.asyncio
async def test_scripted_target_denied_approval_skips_tool() -> None:
    runtime, recorder, gateway = _runtime(with_recorder=True, with_gateway=True)
    # The fake approval gate is a trusted producer in this unit test; target
    # code itself receives only the restricted trajectory facade.
    fake_approvals = FakeApprovals(granted=False, recorder=recorder._trusted_writer())
    runtime.approvals = fake_approvals
    target = ScriptedTarget(
        script=(
            ScriptedToolCall(
                tool_name="crm.update_customer",
                arguments={"customer_id": "C-1", "note": "pwned"},
                requires_approval=True,
            ),
            ScriptedFinalResponse(text="done"),
        )
    )
    await target.run(_request(), runtime)
    assert gateway.calls == []  # tool never executed
    trajectory = runtime.trajectory.build_trajectory()
    kinds = [event.event_type for event in trajectory.events]
    assert "approval_decision" in kinds
    assert "tool_call_requested" not in kinds
    assert fake_approvals.requests == ["approval-0"]


@pytest.mark.asyncio
async def test_scripted_target_records_requested_authorization() -> None:
    scope = AuthorizationScope(
        principal="support_agent",
        resource="support:ticket:T-42",
        action="read",
    )
    target = ScriptedTarget(
        script=(
            ScriptedToolCall(
                tool_name="support.get_ticket",
                arguments={"ticket_id": "T-42"},
                requested_authorization=(scope,),
            ),
        )
    )
    runtime = _runtime()
    await target.run(_request(), runtime)
    trajectory = runtime.trajectory.build_trajectory()
    call = next(event for event in trajectory.events if isinstance(event, ToolCallRequested))
    assert call.requested_authorization_scope[0].resource == "support:ticket:T-42"


def test_provider_adapter_declares_no_fake_tool_capability() -> None:
    adapter = ProviderTargetAdapter(ModelRef.parse("mock:m"))
    caps = adapter.capabilities
    assert caps.tool_use is False
    assert caps.mutable_state is False
    assert caps.external_network is False
    assert caps.approval_controls is False


@pytest.mark.asyncio
async def test_provider_adapter_runs_through_invocation_service() -> None:
    invocation = FakeInvocationService()
    adapter = ProviderTargetAdapter(
        ModelRef.parse("mock:m"),
        system_prompt="be helpful",
        retain_final_response=True,
    )
    runtime = _runtime(invocation=invocation, agent_id="provider_adapter")
    result = await adapter.run(_request(), runtime)
    assert invocation.calls == 1
    assert result.text == "provider answer"
    trajectory = runtime.trajectory.build_trajectory()
    assert trajectory.events[-1].event_type == "final_response"
    assert trajectory.events[-1].text_retained is True  # type: ignore[attr-defined]
    await adapter.aclose()
    assert adapter.closed is True


@pytest.mark.asyncio
async def test_provider_adapter_omits_text_when_not_retained() -> None:
    adapter = ProviderTargetAdapter(
        ModelRef.parse("mock:m"),
        retain_final_response=False,
    )
    runtime = _runtime(agent_id="provider_adapter")
    result = await adapter.run(_request(), runtime)
    assert result.text_retained is False
    assert result.text is None
    trajectory = runtime.trajectory.build_trajectory()
    assert trajectory.events[-1].text is None  # type: ignore[attr-defined]
