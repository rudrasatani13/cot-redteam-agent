"""Deny-by-default simulated tool gateway.

The gateway owns all Support World action execution and the gateway-observed
trajectory events (ToolCallRequested before dispatch, ActionEvent for the
observed attempt/execution with state digests and requested-vs-observed
authorization, ToolResultReceived with the structured result/error).

Enforced before dispatch:

- the tool name must exist in the world's fixed registry;
- the tool must be permitted by the scenario sandbox allowlist;
- argument schema validation;
- serialized argument/result byte limits;
- a maximum action count per run;
- a per-call timeout;
- a maximum concurrent tool-call bound.

The sandbox allowlist is a *safety* boundary, not the security invariant
under test: a scenario may intentionally include an action the agent is not
authorized to take so an exploit can produce an observable simulated side
effect. Authorization (requested vs policy-observed) is recorded for
deterministic oracles, never used to hide a mismatch.

No handler capable of filesystem, shell, network, subprocess, or external
database access exists; generated model text is always plain data.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from typing import Any

from cot_redteam.agent.trajectory import TrajectoryRecorder
from cot_redteam.agent.types import (
    ActionEvent,
    AuthorizationState,
    EventProvenance,
    EventStatus,
    ToolCallRequested,
    ToolResultReceived,
)
from cot_redteam.agent.worlds.base import BaseWorld
from cot_redteam.core.errors import CotRedTeamError
from cot_redteam.core.types import JsonValue

SanitizeArguments = Callable[[Mapping[str, JsonValue]], JsonValue]
SanitizeResult = Callable[[JsonValue], JsonValue]


class ToolError(CotRedTeamError):
    """Base class for structured tool gateway failures."""


class UnknownToolError(ToolError):
    """The tool name is not in the world's fixed registry."""


class ToolDeniedError(ToolError):
    """The tool is not permitted by the scenario sandbox allowlist."""


class ToolArgumentError(ToolError):
    """The arguments failed schema or size validation."""


class ToolLimitExceededError(ToolError):
    """The per-run action count limit was exceeded."""


class ToolTimeoutError(ToolError):
    """The tool call exceeded its per-call timeout."""


class WorldStateError(ToolError):
    """The world handler failed to produce a valid state transition."""


class ToolGateway:
    """Deny-by-default simulated action boundary."""

    def __init__(
        self,
        *,
        world: BaseWorld,
        trajectory: TrajectoryRecorder,
        scenario_id: str,
        tool_allowlist: tuple[str, ...],
        max_actions: int = 100,
        max_serialized_argument_bytes: int = 8192,
        max_serialized_result_bytes: int = 65536,
        tool_timeout_seconds: float = 5.0,
        max_concurrent_tool_calls: int = 4,
        sanitize_arguments: SanitizeArguments | None = None,
        sanitize_result: SanitizeResult | None = None,
        authorization_policy: tuple[Any, ...] = (),
        progress: Any = None,
    ) -> None:
        self.world = world
        self.trajectory = trajectory
        self.scenario_id = scenario_id
        self.tool_allowlist = frozenset(tool_allowlist)
        self.max_actions = max(1, max_actions)
        self.max_serialized_argument_bytes = max(1, max_serialized_argument_bytes)
        self.max_serialized_result_bytes = max(1, max_serialized_result_bytes)
        self.tool_timeout_seconds = tool_timeout_seconds
        self.max_concurrent_tool_calls = max(1, max_concurrent_tool_calls)
        self._sanitize_arguments = sanitize_arguments or (lambda args: dict(args))
        self._sanitize_result = sanitize_result or (lambda result: result)
        self._authorization_policy = tuple(authorization_policy)
        self._progress = progress
        self._semaphore = asyncio.Semaphore(self.max_concurrent_tool_calls)
        self._actions_taken = 0
        self._call_ids: set[str] = set()

    # -- authorization ------------------------------------------------------

    def _observed_authorization(
        self,
        requested: tuple[Any, ...],
    ) -> AuthorizationState:
        """Compare requested scopes against the scenario authorization policy.

        The policy is a tuple of ``AuthorizationScope`` values; a request is
        authorized when every requested scope is covered by a policy scope
        with the same principal/resource/action.
        """
        if not requested:
            return AuthorizationState.UNKNOWN
        for scope in requested:
            covered = False
            for policy_scope in self._authorization_policy:
                if (
                    policy_scope.principal == scope.principal
                    and policy_scope.resource == scope.resource
                    and policy_scope.action == scope.action
                ):
                    covered = True
                    break
            if not covered:
                return AuthorizationState.UNAUTHORIZED
        return AuthorizationState.AUTHORIZED

    def _provenance(self) -> EventProvenance:
        return EventProvenance(
            source_kind="tool_gateway",
            source_id=self.scenario_id,
            source_version="1",
        )

    def _record_call_id(self, call_id: str) -> None:
        if call_id in self._call_ids:
            raise ToolError(f"duplicate call_id {call_id!r}")
        self._call_ids.add(call_id)

    # -- execution ----------------------------------------------------------

    async def execute(
        self,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, JsonValue],
        requested_authorization: tuple[Any, ...] = (),
    ) -> JsonValue:
        provenance = self._provenance()
        self._record_call_id(call_id)
        request_event = ToolCallRequested(
            event_type="tool_call_requested",
            run_id=self.trajectory.run_id,
            session_id=self.trajectory.session_id,
            event_id=f"gw-{call_id}-req",
            agent_id=self.trajectory.agent_id,
            provenance=provenance,
            call_id=call_id,
            tool_name=tool_name,
            tool_version="1",
            sanitized_arguments=self._sanitize_arguments(arguments),
            requested_authorization_scope=requested_authorization,
            status=EventStatus.REQUESTED,
        )
        await self.trajectory.record(request_event)
        parent_event_id = request_event.event_id

        async def fail(
            *,
            error_code: str,
            error_message: str,
            authorization_state: AuthorizationState,
            executed: bool = False,
        ) -> JsonValue:
            await self.trajectory.record(
                ActionEvent(
                    event_type="action_event",
                    run_id=self.trajectory.run_id,
                    session_id=self.trajectory.session_id,
                    event_id=f"gw-{call_id}-action",
                    parent_event_id=parent_event_id,
                    agent_id=self.trajectory.agent_id,
                    provenance=provenance,
                    call_id=call_id,
                    action_kind=tool_name,
                    resource=tool_name,
                    attempted=True,
                    executed=executed,
                    authorization_state=authorization_state,
                    state_before_digest=self.world.snapshot().digest,
                    state_after_digest=self.world.snapshot().digest,
                    status=EventStatus.DENIED if not executed else EventStatus.FAILED,
                    error_code=error_code,
                    error_message=error_message,
                )
            )
            await self.trajectory.record(
                ToolResultReceived(
                    event_type="tool_result_received",
                    run_id=self.trajectory.run_id,
                    session_id=self.trajectory.session_id,
                    event_id=f"gw-{call_id}-res",
                    parent_event_id=parent_event_id,
                    agent_id=self.trajectory.agent_id,
                    provenance=provenance,
                    call_id=call_id,
                    tool_name=tool_name,
                    sanitized_result=None,
                    status=EventStatus.FAILED,
                    error_code=error_code,
                    error_message=error_message,
                )
            )
            return {"error": error_code, "message": error_message}

        spec = self.world.tools.get(tool_name)
        if spec is None:
            await fail(
                error_code="tool_denied",
                error_message=f"unknown tool {tool_name!r}",
                authorization_state=AuthorizationState.UNKNOWN,
            )
            raise UnknownToolError(f"unknown tool {tool_name!r}")
        if tool_name not in self.tool_allowlist:
            await fail(
                error_code="tool_denied",
                error_message=f"tool {tool_name!r} is not in the scenario allowlist",
                authorization_state=AuthorizationState.UNKNOWN,
            )
            raise ToolDeniedError(
                f"tool {tool_name!r} not allowed by scenario {self.scenario_id!r}"
            )

        try:
            spec.validate(arguments)
        except ValueError as exc:
            await fail(
                error_code="tool_argument_error",
                error_message=str(exc),
                authorization_state=AuthorizationState.UNKNOWN,
            )
            raise ToolArgumentError(str(exc)) from exc

        try:
            serialized_arguments = json.dumps(dict(arguments), ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            await fail(
                error_code="tool_argument_error",
                error_message=f"arguments are not JSON-serializable: {exc}",
                authorization_state=AuthorizationState.UNKNOWN,
            )
            raise ToolArgumentError("arguments must be JSON-serializable") from exc
        if len(serialized_arguments.encode("utf-8")) > self.max_serialized_argument_bytes:
            await fail(
                error_code="tool_argument_too_large",
                error_message="serialized arguments exceed the size limit",
                authorization_state=AuthorizationState.UNKNOWN,
            )
            raise ToolArgumentError("serialized arguments exceed the size limit")

        if self._actions_taken >= self.max_actions:
            await fail(
                error_code="tool_limit_exceeded",
                error_message="per-run action count limit exceeded",
                authorization_state=AuthorizationState.UNKNOWN,
            )
            raise ToolLimitExceededError("per-run action count limit exceeded")

        observed = self._observed_authorization(requested_authorization)
        state_before = self.world.snapshot().digest

        async with self._semaphore:
            self._actions_taken += 1
            try:
                raw_result = await asyncio.wait_for(
                    spec.handler(arguments),
                    timeout=self.tool_timeout_seconds,
                )
            except asyncio.TimeoutError as exc:
                await fail(
                    error_code="tool_timeout",
                    error_message=f"tool {tool_name!r} timed out",
                    authorization_state=observed,
                )
                raise ToolTimeoutError(f"tool {tool_name!r} timed out") from exc
            except Exception as exc:
                await fail(
                    error_code="world_state_error",
                    error_message=str(exc)[:500],
                    authorization_state=observed,
                )
                raise WorldStateError(str(exc)[:500]) from exc

        state_after = self.world.snapshot().digest
        try:
            serialized_result = json.dumps(raw_result, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise WorldStateError("tool result is not JSON-serializable") from exc
        if len(serialized_result.encode("utf-8")) > self.max_serialized_result_bytes:
            raise ToolLimitExceededError("serialized result exceeds the size limit")

        await self.trajectory.record(
            ActionEvent(
                event_type="action_event",
                run_id=self.trajectory.run_id,
                session_id=self.trajectory.session_id,
                event_id=f"gw-{call_id}-action",
                parent_event_id=parent_event_id,
                agent_id=self.trajectory.agent_id,
                provenance=provenance,
                call_id=call_id,
                action_kind=tool_name,
                resource=tool_name,
                attempted=True,
                executed=True,
                authorization_state=observed,
                state_before_digest=state_before,
                state_after_digest=state_after,
            )
        )
        await self.trajectory.record(
            ToolResultReceived(
                event_type="tool_result_received",
                run_id=self.trajectory.run_id,
                session_id=self.trajectory.session_id,
                event_id=f"gw-{call_id}-res",
                parent_event_id=parent_event_id,
                agent_id=self.trajectory.agent_id,
                provenance=provenance,
                call_id=call_id,
                tool_name=tool_name,
                sanitized_result=self._sanitize_result(raw_result),
            )
        )
        return self._sanitize_result(raw_result)
