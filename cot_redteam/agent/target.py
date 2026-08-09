"""Agent target protocol and the constrained runtime handed to targets.

``Target`` is the agent-level protocol: something that may make model
calls, use tools, mutate simulated state, request approval, keep memory,
or delegate. It is deliberately NOT a replacement for ``Provider``.

Targets never receive a raw SQLite connection, arbitrary filesystem path,
shell executor, network client, or mutable world object. They receive a
``TargetRuntime`` with typed access to the invocation boundary, the
simulated tool gateway, the trajectory recorder, and the approval
interface.
"""

from __future__ import annotations

import weakref
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from cot_redteam.agent.trajectory import TargetTrajectory, TrajectoryRecorder
from cot_redteam.agent.types import (
    AgentTargetCapabilities,
    AuthorizationScope,
)
from cot_redteam.core.invocation import InvocationService
from cot_redteam.core.types import JsonValue
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import ProgressCallback


@dataclass(frozen=True)
class AgentTargetRequest:
    """Scenario/user inputs for one target run.

    Does not expose world internals. ``metadata`` carries sanitized values
    only.
    """

    scenario_id: str
    scenario_version: str
    attack_id: str
    attack_version: str
    run_id: str
    session_id: str
    seed: int
    user_input: str
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class FinalResponseData:
    """The target's final response; text is retained per retention policy."""

    text_retained: bool = False
    text: str | None = None


class ToolGatewayProtocol(Protocol):
    """Deny-by-default simulated action boundary (implemented in PR6)."""

    async def execute(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, JsonValue],
        requested_authorization: tuple[AuthorizationScope, ...] = (),
    ) -> JsonValue: ...


class ApprovalInterface(Protocol):
    """Approval request/decision boundary."""

    async def request(
        self,
        *,
        approval_id: str,
        subject_action: str,
        principal: str,
        policy_id: str,
        policy_version: str,
    ) -> bool: ...


_TARGET_GATEWAYS: weakref.WeakKeyDictionary[TargetGatewayView, ToolGatewayProtocol] = (
    weakref.WeakKeyDictionary()
)
_TARGET_APPROVALS: weakref.WeakKeyDictionary[TargetApprovalView, ApprovalInterface] = (
    weakref.WeakKeyDictionary()
)


class TargetGatewayView:
    """Capability-free adapter view over the trusted gateway.

    The gateway/world object is held in a private weak-map entry rather than
    on the target-visible object, preventing accidental access to mutable
    world state or the producer recorder. This is defense in depth, not an
    in-process Python sandbox.
    """

    __slots__ = ("__weakref__",)

    def __init__(self, gateway: ToolGatewayProtocol) -> None:
        _TARGET_GATEWAYS[self] = gateway

    async def execute(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, JsonValue],
        requested_authorization: tuple[AuthorizationScope, ...] = (),
    ) -> JsonValue:
        return await _TARGET_GATEWAYS[self].execute(
            call_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
            requested_authorization=requested_authorization,
        )


class TargetApprovalView:
    """Capability-free target view over the trusted approval gate."""

    __slots__ = ("__weakref__",)

    def __init__(self, approvals: ApprovalInterface) -> None:
        _TARGET_APPROVALS[self] = approvals

    async def request(
        self,
        *,
        approval_id: str,
        subject_action: str,
        principal: str,
        policy_id: str,
        policy_version: str,
    ) -> bool:
        return await _TARGET_APPROVALS[self].request(
            approval_id=approval_id,
            subject_action=subject_action,
            principal=principal,
            policy_id=policy_id,
            policy_version=policy_version,
        )


class TargetRuntime:
    """Constrained runtime object passed to targets.

    Trusted target adapters may use the invocation service for model calls, the tool
    gateway for simulated actions, the restricted trajectory facade for
    structured non-tool events, and the approval interface for approval
    decisions.  Privileged gateway/approval/world evidence is producer-owned
    and cannot be appended through the public ``trajectory`` API. Adapter
    implementations execute in-process and are outside the hostile-input
    boundary; model output and tool-result data remain untrusted.
    """

    def __init__(
        self,
        *,
        run_id: str,
        session_id: str,
        invocation_service: InvocationService,
        tool_gateway: ToolGatewayProtocol,
        trajectory: TrajectoryRecorder | TargetTrajectory,
        approvals: ApprovalInterface,
        budget: BudgetTracker,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.run_id = run_id
        self.session_id = session_id
        self.invocation_service = invocation_service
        self.tool_gateway = (
            tool_gateway
            if isinstance(tool_gateway, TargetGatewayView)
            else TargetGatewayView(tool_gateway)
        )
        self.trajectory = (
            trajectory if isinstance(trajectory, TargetTrajectory) else TargetTrajectory(trajectory)
        )
        self.approvals = (
            approvals
            if isinstance(approvals, TargetApprovalView)
            else TargetApprovalView(approvals)
        )
        self.budget = budget
        self.progress = progress


@runtime_checkable
class Target(Protocol):
    """Agent-level execution contract (not a Provider replacement)."""

    id: str
    version: str
    capabilities: AgentTargetCapabilities

    async def run(
        self,
        request: AgentTargetRequest,
        runtime: TargetRuntime,
    ) -> FinalResponseData: ...

    async def aclose(self) -> None: ...
