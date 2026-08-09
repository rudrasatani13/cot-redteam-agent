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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from cot_redteam.agent.trajectory import TrajectoryRecorder
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


class TargetRuntime:
    """Constrained runtime object passed to targets.

    Targets may use the invocation service for model calls, the tool
    gateway for simulated actions, the trajectory recorder for structured
    non-tool events, and the approval interface for approval decisions.
    """

    def __init__(
        self,
        *,
        run_id: str,
        session_id: str,
        invocation_service: InvocationService,
        tool_gateway: ToolGatewayProtocol,
        trajectory: TrajectoryRecorder,
        approvals: ApprovalInterface,
        budget: BudgetTracker,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.run_id = run_id
        self.session_id = session_id
        self.invocation_service = invocation_service
        self.tool_gateway = tool_gateway
        self.trajectory = trajectory
        self.approvals = approvals
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
