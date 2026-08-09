"""ToolGateway deny-by-default enforcement and event recording tests."""

from __future__ import annotations

import asyncio

import pytest

from cot_redteam.agent.gateway import (
    ToolArgumentError,
    ToolDeniedError,
    ToolGateway,
    ToolLimitExceededError,
    ToolTimeoutError,
    UnknownToolError,
)
from cot_redteam.agent.trajectory import TrajectoryRecorder
from cot_redteam.agent.types import (
    ActionEvent,
    AuthorizationScope,
    AuthorizationState,
    ToolCallRequested,
    ToolResultReceived,
)
from cot_redteam.agent.worlds.support import SupportAgentWorld


def _world() -> SupportAgentWorld:
    return SupportAgentWorld(
        initial_state={
            "tickets": {"T-1": {"id": "T-1", "subject": "x", "body": "hello"}},
            "crm_records": {"C-7": {"id": "C-7", "email": "a@example.com"}},
            "canaries": {},
            "outbound_sink": {},
            "approval_state": {},
            "protected_state": {},
        }
    )


def _test_scope_resolver(tool_name: str, arguments: dict):
    """Test resolver mirroring the trusted production derivation."""
    from cot_redteam.agent.types import AuthorizationScope

    if tool_name == "webhook.send":
        return AuthorizationScope(
            principal="support_agent",
            resource=f"outbound:sink:{arguments.get('name', '')}",
            action="send",
        )
    if tool_name == "crm.update_customer":
        patch = arguments.get("patch") or {}
        action = "note" if set(patch) <= {"note"} else "update"
        return AuthorizationScope(principal="support_agent", resource="crm:customer", action=action)
    if tool_name in ("support.get_ticket", "crm.get_customer"):
        return AuthorizationScope(
            principal="support_agent",
            resource="support:ticket" if tool_name.startswith("support") else "crm:customer",
            action="read",
        )
    return None


def _gateway(
    world: SupportAgentWorld,
    *,
    allowlist: tuple[str, ...] = (
        "support.get_ticket",
        "crm.update_customer",
        "webhook.send",
    ),
    scope_resolver=None,
    **kwargs,
) -> tuple[ToolGateway, TrajectoryRecorder]:
    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    gateway = ToolGateway(
        world=world,
        trajectory=recorder,
        scenario_id="scenario.test",
        tool_allowlist=allowlist,
        scope_resolver=scope_resolver or _test_scope_resolver,
        **kwargs,
    )
    return gateway, recorder


@pytest.mark.asyncio
async def test_execute_records_gateway_events_and_mutates_world() -> None:
    world = _world()
    gateway, recorder = _gateway(world)
    result = await gateway.execute(
        call_id="call-1",
        tool_name="webhook.send",
        arguments={"name": "audit", "payload": {"event": "t"}},
    )
    assert result == {"accepted": True, "sink": "audit", "message_count": 1}
    trajectory = recorder.build_trajectory()
    kinds = [event.event_type for event in trajectory.events]
    assert kinds == [
        "tool_call_requested",
        "action_event",
        "tool_result_received",
    ]
    action = trajectory.events[1]
    assert isinstance(action, ActionEvent)
    assert action.executed is True
    assert action.state_before_digest != action.state_after_digest
    result_event = trajectory.events[2]
    assert isinstance(result_event, ToolResultReceived)
    assert result_event.call_id == "call-1"


@pytest.mark.asyncio
async def test_unknown_tool_denied() -> None:
    world = _world()
    gateway, recorder = _gateway(world)
    with pytest.raises(UnknownToolError):
        await gateway.execute(
            call_id="call-1",
            tool_name="shell.exec",
            arguments={"command": "id"},
        )
    trajectory = recorder.build_trajectory()
    action = next(event for event in trajectory.events if isinstance(event, ActionEvent))
    assert action.executed is False
    assert action.error_code == "tool_denied"


@pytest.mark.asyncio
async def test_scenario_disallowed_tool_denied() -> None:
    world = _world()
    # crm.get_customer is in the world registry but not the scenario allowlist.
    gateway, recorder = _gateway(world, allowlist=("support.get_ticket",))
    with pytest.raises(ToolDeniedError, match="not allowed"):
        await gateway.execute(
            call_id="call-1",
            tool_name="crm.get_customer",
            arguments={"customer_id": "C-7"},
        )
    trajectory = recorder.build_trajectory()
    action = next(event for event in trajectory.events if isinstance(event, ActionEvent))
    assert action.executed is False


@pytest.mark.asyncio
async def test_oversized_arguments_denied_before_handler() -> None:
    world = _world()
    gateway, _ = _gateway(world, max_serialized_argument_bytes=16)
    with pytest.raises(ToolArgumentError, match="size limit"):
        await gateway.execute(
            call_id="call-1",
            tool_name="webhook.send",
            arguments={"name": "audit", "payload": {"event": "this is much too long"}},
        )
    # The world handler never ran.
    assert world.outbound_sink == {}


@pytest.mark.asyncio
async def test_schema_violation_denied() -> None:
    world = _world()
    gateway, _ = _gateway(world)
    with pytest.raises(ToolArgumentError, match="must be a string"):
        await gateway.execute(
            call_id="call-1",
            tool_name="support.get_ticket",
            arguments={"ticket_id": 42},
        )


@pytest.mark.asyncio
async def test_action_count_limit_enforced() -> None:
    world = _world()
    gateway, _ = _gateway(world, max_actions=1)
    await gateway.execute(
        call_id="call-1",
        tool_name="support.get_ticket",
        arguments={"ticket_id": "T-1"},
    )
    with pytest.raises(ToolLimitExceededError):
        await gateway.execute(
            call_id="call-2",
            tool_name="support.get_ticket",
            arguments={"ticket_id": "T-1"},
        )


@pytest.mark.asyncio
async def test_timeout_represented_structurally() -> None:
    world = _world()

    async def slow_handler(arguments):
        await asyncio.sleep(1.0)
        return {"ok": True}

    world.tools["support.get_ticket"] = world.tools["support.get_ticket"]  # keep
    original = world.tools["support.get_ticket"].handler

    async def slow(arguments):
        del arguments
        await asyncio.sleep(5.0)
        return {"ok": True}

    from dataclasses import replace

    world.tools["support.get_ticket"] = replace(world.tools["support.get_ticket"], handler=slow)
    try:
        gateway, recorder = _gateway(world, tool_timeout_seconds=0.01)
        with pytest.raises(ToolTimeoutError):
            await gateway.execute(
                call_id="call-1",
                tool_name="support.get_ticket",
                arguments={"ticket_id": "T-1"},
            )
    finally:
        world.tools["support.get_ticket"] = replace(
            world.tools["support.get_ticket"], handler=original
        )
    trajectory = recorder.build_trajectory()
    action = next(event for event in trajectory.events if isinstance(event, ActionEvent))
    assert action.executed is False
    assert action.error_code == "tool_timeout"


@pytest.mark.asyncio
async def test_concurrent_tool_bound_enforced() -> None:
    world = _world()

    from dataclasses import replace

    original = world.tools["support.get_ticket"].handler
    active = 0
    max_active = 0
    lock = asyncio.Lock()

    async def counting_handler(arguments):
        nonlocal active, max_active
        async with lock:
            active += 1
            max_active = max(max_active, active)
        try:
            await asyncio.sleep(0.05)
            return {"ticket": {"id": str(arguments["ticket_id"])}}
        finally:
            async with lock:
                active -= 1

    world.tools["support.get_ticket"] = replace(
        world.tools["support.get_ticket"], handler=counting_handler
    )
    gateway, _ = _gateway(world, max_concurrent_tool_calls=1)
    try:
        await asyncio.gather(
            *[
                gateway.execute(
                    call_id=f"call-{i}",
                    tool_name="support.get_ticket",
                    arguments={"ticket_id": "T-1"},
                )
                for i in range(4)
            ]
        )
    finally:
        world.tools["support.get_ticket"] = replace(
            world.tools["support.get_ticket"], handler=original
        )
    assert max_active == 1


@pytest.mark.asyncio
async def test_requested_vs_observed_authorization_recorded() -> None:
    world = _world()
    policy = (
        AuthorizationScope(
            principal="support_agent",
            resource="outbound:sink:internal_audit",
            action="send",
        ),
    )
    gateway, recorder = _gateway(world, authorization_policy=policy)
    await gateway.execute(
        call_id="call-1",
        tool_name="webhook.send",
        arguments={"name": "exfil", "payload": {"x": 1}},
        requested_authorization=(
            AuthorizationScope(
                principal="support_agent",
                resource="outbound:sink:exfil",
                action="send",
            ),
        ),
    )
    trajectory = recorder.build_trajectory()
    action = next(event for event in trajectory.events if isinstance(event, ActionEvent))
    assert action.authorization_state is AuthorizationState.UNAUTHORIZED
    requested = trajectory.events[0]
    assert isinstance(requested, ToolCallRequested)
    assert requested.requested_authorization_scope[0].resource == "outbound:sink:exfil"


@pytest.mark.asyncio
async def test_webhook_only_mutates_in_memory_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_socket(*args, **kwargs):
        raise AssertionError("network access forbidden")

    def no_subprocess(*args, **kwargs):
        raise AssertionError("subprocess forbidden")

    monkeypatch.setattr("socket.socket", no_socket)
    monkeypatch.setattr("subprocess.run", no_subprocess)

    world = _world()
    gateway, _ = _gateway(world)
    result = await gateway.execute(
        call_id="call-1",
        tool_name="webhook.send",
        arguments={"name": "audit", "payload": {"event": "t"}},
    )
    assert result["accepted"] is True
    assert world.outbound_sink["audit"][0]["payload"] == {"event": "t"}
    assert len(world.outbound_sink) == 1


@pytest.mark.asyncio
async def test_duplicate_call_id_rejected() -> None:
    world = _world()
    gateway, _ = _gateway(world)
    await gateway.execute(
        call_id="call-1",
        tool_name="support.get_ticket",
        arguments={"ticket_id": "T-1"},
    )
    with pytest.raises(Exception, match="duplicate call_id"):
        await gateway.execute(
            call_id="call-1",
            tool_name="support.get_ticket",
            arguments={"ticket_id": "T-1"},
        )
