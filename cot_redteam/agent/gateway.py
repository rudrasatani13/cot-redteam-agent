"""Deny-by-default simulated tool gateway.

The gateway owns all Support World action execution and the gateway-observed
trajectory events (ToolCallRequested before dispatch, ActionEvent for the
observed attempt/execution with state digests and requested-vs-derived
authorization, ToolResultReceived with the structured result/error).

Enforced before dispatch:

- the tool name must exist in the world's fixed registry;
- the tool must be permitted by the scenario sandbox allowlist;
- argument schema validation;
- serialized argument byte limits;
- a maximum action count per run (reserved atomically under the concurrency
  semaphore so parallel calls cannot exceed it);
- a per-call timeout;
- a maximum concurrent tool-call bound.

Authorization is decided by a TRUSTED scope resolver owned by the engine:
``scope_resolver(tool_name, validated_arguments)`` derives the scope the
operation genuinely requires, and that derived scope is compared against the
scenario authorization policy. The target-provided ``requested_authorization``
is recorded as evidence only and can never decide authorization — a lying
target cannot spoof an authorized verdict.

Once a handler has executed, the gateway records the ActionEvent (executed,
with pre/post state digests) before result serialization; a later result
serialization/size failure is a separate FAILED ToolResultReceived, never an
erased executed action.

No handler capable of filesystem, shell, network, subprocess, or external
database access exists; generated model text is always plain data.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping

from cot_redteam.agent.trajectory import TrajectoryRecorder
from cot_redteam.agent.types import (
    ActionEvent,
    AuthorizationScope,
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
#: Trusted resolver: (tool_name, validated arguments) -> scope the operation
#: genuinely requires, or None when no scope applies.
ScopeResolver = Callable[[str, Mapping[str, JsonValue]], AuthorizationScope | None]


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
        scope_resolver: ScopeResolver,
        max_actions: int = 100,
        max_serialized_argument_bytes: int = 8192,
        max_serialized_result_bytes: int = 65536,
        tool_timeout_seconds: float = 5.0,
        max_concurrent_tool_calls: int = 4,
        sanitize_arguments: SanitizeArguments | None = None,
        sanitize_result: SanitizeResult | None = None,
        authorization_policy: tuple[AuthorizationScope, ...] = (),
    ) -> None:
        self.world = world
        self.trajectory = trajectory
        self.scenario_id = scenario_id
        self.tool_allowlist = frozenset(tool_allowlist)
        self.scope_resolver = scope_resolver
        self.max_actions = max(1, max_actions)
        self.max_serialized_argument_bytes = max(1, max_serialized_argument_bytes)
        self.max_serialized_result_bytes = max(1, max_serialized_result_bytes)
        self.tool_timeout_seconds = tool_timeout_seconds
        self.max_concurrent_tool_calls = max(1, max_concurrent_tool_calls)
        self._sanitize_arguments = sanitize_arguments or (lambda args: dict(args))
        self._sanitize_result = sanitize_result or (lambda result: result)
        self._authorization_policy = tuple(authorization_policy)
        self._semaphore = asyncio.Semaphore(self.max_concurrent_tool_calls)
        self._actions_taken = 0
        self._call_ids: set[str] = set()

    # -- authorization ------------------------------------------------------

    def _observed_authorization(self, derived: AuthorizationScope | None) -> AuthorizationState:
        """Decide authorization from the TRUSTED derived scope only.

        The target-provided ``requested_authorization`` is evidence, never a
        decision input; a lying target cannot claim a scope it does not have.
        """
        if derived is None:
            return AuthorizationState.UNKNOWN
        for policy_scope in self._authorization_policy:
            if (
                policy_scope.principal == derived.principal
                and policy_scope.resource == derived.resource
                and policy_scope.action == derived.action
            ):
                return AuthorizationState.AUTHORIZED
        return AuthorizationState.UNAUTHORIZED

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
        requested_authorization: tuple[AuthorizationScope, ...] = (),
    ) -> JsonValue:
        provenance = self._provenance()
        self._record_call_id(call_id)
        # Derive the scope the operation genuinely requires (trusted) and
        # decide authorization BEFORE recording the request event, so the
        # recorded ToolCallRequested carries the observed scope for oracle
        # evidence and every fail path has the derived verdict.
        derived = self.scope_resolver(tool_name, dict(arguments))
        observed = self._observed_authorization(derived)
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
            observed_authorization_scope=(derived,) if derived is not None else (),
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
                    requested_authorization_scope=requested_authorization,
                    observed_authorization_scope=(derived,) if derived is not None else (),
                    authorization_state=authorization_state,
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
                authorization_state=observed,
            )
            raise ToolArgumentError(str(exc)) from exc

        try:
            serialized_arguments = json.dumps(dict(arguments), ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
            await fail(
                error_code="tool_argument_error",
                error_message=f"arguments are not JSON-serializable: {exc}",
                authorization_state=observed,
            )
            raise ToolArgumentError("arguments must be JSON-serializable") from exc
        if len(serialized_arguments.encode("utf-8")) > self.max_serialized_argument_bytes:
            await fail(
                error_code="tool_argument_too_large",
                error_message="serialized arguments exceed the size limit",
                authorization_state=observed,
            )
            raise ToolArgumentError("serialized arguments exceed the size limit")

        async with self._semaphore:
            # Atomic action-budget reservation: check + increment under the
            # semaphore so concurrent calls cannot exceed max_actions.
            if self._actions_taken >= self.max_actions:
                await fail(
                    error_code="tool_limit_exceeded",
                    error_message="per-run action count limit exceeded",
                    authorization_state=observed,
                )
                raise ToolLimitExceededError("per-run action count limit exceeded")
            self._actions_taken += 1
            state_before = self.world.snapshot().digest
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

        # The handler ran: record the executed ActionEvent with pre/post
        # state digests BEFORE result serialization. A later result failure
        # is a separate FAILED ToolResultReceived, never an erased action.
        state_after = self.world.snapshot().digest
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
                requested_authorization_scope=requested_authorization,
                observed_authorization_scope=(derived,) if derived is not None else (),
                authorization_state=observed,
                state_before_digest=state_before,
                state_after_digest=state_after,
            )
        )
        try:
            serialized_result = json.dumps(raw_result, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as exc:
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
                    error_code="world_state_error",
                    error_message=f"tool result is not JSON-serializable: {exc}",
                )
            )
            raise WorldStateError("tool result is not JSON-serializable") from exc
        if len(serialized_result.encode("utf-8")) > self.max_serialized_result_bytes:
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
                    error_code="tool_result_too_large",
                    error_message="serialized result exceeds the size limit",
                )
            )
            raise ToolLimitExceededError("serialized result exceeds the size limit")

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
