"""Support Agent World determinism and sandbox tests."""

from __future__ import annotations

import asyncio

import pytest

from cot_redteam.agent.scenarios.support import (
    support_fixture,
    support_scenario,
)
from cot_redteam.agent.worlds.support import SupportAgentWorld


def _world() -> SupportAgentWorld:
    fixture = support_fixture("support.indirect_prompt_injection.v1", "vulnerable")
    return SupportAgentWorld(initial_state=fixture.initial_state)


def test_snapshot_digest_is_deterministic() -> None:
    world = _world()
    first = world.snapshot()
    second = world.snapshot()
    assert first.digest == second.digest
    assert first.state == second.state


def test_reset_returns_byte_equivalent_snapshot() -> None:
    world = _world()
    baseline = world.snapshot()
    # Mutate the world.
    world.tickets["T-100"]["body"] = "mutated"
    world.outbound_sink.setdefault("audit", []).append({"payload": {"x": 1}})
    assert world.snapshot().digest != baseline.digest
    world.reset()
    after = world.snapshot()
    assert after.digest == baseline.digest
    assert after.state == baseline.state


def test_no_state_carries_between_trials() -> None:
    world = _world()
    baseline = world.snapshot()
    # The mutation must actually happen (awaited), then reset must restore
    # the byte-equivalent initial state.
    asyncio.run(world._webhook_send({"name": "audit", "payload": {"x": 1}}))
    assert world.outbound_sink  # mutation took effect
    world.reset()
    assert world.snapshot().state == baseline.state


def test_webhook_send_appends_to_in_memory_sink_only() -> None:
    world = _world()
    result = asyncio.run(world._webhook_send({"name": "exfil", "payload": {"code": "CANARY"}}))
    assert result["accepted"] is True
    assert world.outbound_sink["exfil"][0]["payload"] == {"code": "CANARY"}
    # No other state mutated.
    assert world.tickets == world._initial_state["tickets"]


def test_ticket_lookup_and_missing() -> None:
    world = _world()
    found = asyncio.run(world._get_ticket({"ticket_id": "T-100"}))
    assert found["ticket"]["id"] == "T-100"
    with pytest.raises(Exception, match="not found"):
        asyncio.run(world._get_ticket({"ticket_id": "NOPE"}))


def test_crm_update_mutates_record() -> None:
    world = _world()
    asyncio.run(world._update_customer({"customer_id": "C-7", "patch": {"note": "hi"}}))
    assert world.crm_records["C-7"]["note"] == "hi"


def test_tool_registry_has_no_escape_handlers() -> None:
    """No generic shell/python/filesystem/http/sql/browser tool exists."""
    world = _world()
    names = set(world.tools.keys())
    assert "shell.exec" not in names
    assert "python" not in names
    assert "filesystem.write" not in names
    assert "http.request" not in names
    assert "sql.query" not in names
    assert "browser.open" not in names
    assert all(not name.startswith(("shell", "exec", "subprocess")) for name in names)


def test_all_scenarios_have_vulnerable_patched_clean_fixtures() -> None:
    for scenario_id in (
        "support.indirect_prompt_injection.v1",
        "support.tool_result_injection.v1",
        "support.approval_bypass.v1",
    ):
        scenario = support_scenario(scenario_id)
        assert scenario.required_oracles
        for fixture in ("vulnerable", "patched", "clean"):
            spec = support_fixture(scenario_id, fixture)
            assert spec.scenario_id == scenario_id
            assert spec.script
            assert spec.digest
            # The world constructed from the fixture must reset byte-identically.
            world = SupportAgentWorld(initial_state=spec.initial_state)
            baseline = world.snapshot()
            world.reset()
            assert world.snapshot().digest == baseline.digest


def test_fixture_action_traces_are_deterministic() -> None:
    """The same fixture produces the same scripted trace every time."""
    scenario_id = "support.tool_result_injection.v1"
    first = support_fixture(scenario_id, "vulnerable")
    second = support_fixture(scenario_id, "vulnerable")
    from cot_redteam.agent.targets.scripted import ScriptedToolCall

    def tool_names(script):
        return [step.tool_name for step in script if isinstance(step, ScriptedToolCall)]

    assert tool_names(first.script) == tool_names(second.script)
    assert first.digest == second.digest


# -- declarative argument validation ----------------------------------------


def test_validate_args_rejects_bool_for_integer() -> None:
    """bool is an int subclass in Python but is not a valid integer arg."""
    from cot_redteam.agent.worlds.base import validate_args

    validator = validate_args(("count",), {"count": "integer"})
    with pytest.raises(ValueError, match="must be an integer"):
        validator({"count": True})
    validator({"count": 3})  # a real integer passes


def test_validate_args_rejects_unknown_argument_names() -> None:
    from cot_redteam.agent.worlds.base import validate_args

    validator = validate_args(("ticket_id",), {"ticket_id": "string"})
    validator({"ticket_id": "T-1"})
    with pytest.raises(ValueError, match="unknown argument"):
        validator({"ticket_id": "T-1", "extra": "smuggled"})


def test_validate_args_still_enforces_required_and_types() -> None:
    from cot_redteam.agent.worlds.base import validate_args

    validator = validate_args(
        ("customer_id", "patch"), {"customer_id": "string", "patch": "object"}
    )
    with pytest.raises(ValueError, match="missing required argument"):
        validator({"customer_id": "C-7"})
    with pytest.raises(ValueError, match="must be an object"):
        validator({"customer_id": "C-7", "patch": "not-an-object"})
