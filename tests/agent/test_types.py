"""Agent event schema, trajectory, and capability type tests."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from cot_redteam.agent.types import (
    AgentEventUnion,
    AgentStep,
    AgentTargetCapabilities,
    AgentTrajectory,
    ApprovalDecision,
    ApprovalValue,
    EventProvenance,
    FinalResponse,
    ToolCallRequested,
    ToolResultReceived,
    ensure_supported_event_schema,
    trajectory_digest,
    validate_agent_event,
)
from cot_redteam.core.types import TargetCapabilities


def _provenance() -> EventProvenance:
    return EventProvenance(
        source_kind="target",
        source_id="scripted",
        source_version="1",
        trust="untrusted",
    )


def _events(extra: str = "base") -> tuple[AgentEventUnion, ...]:
    prov = _provenance()
    step = AgentStep(
        event_type="agent_step",
        run_id=f"r-{extra}",
        session_id=f"s-{extra}",
        event_id="e1",
        agent_id="scripted",
        provenance=prov,
        step_kind="decision",
        input_source="user",
        sequence_no=1,
    )
    call = ToolCallRequested(
        event_type="tool_call_requested",
        run_id=f"r-{extra}",
        session_id=f"s-{extra}",
        event_id="e2",
        parent_event_id="e1",
        agent_id="scripted",
        provenance=prov,
        call_id="call-1",
        tool_name="support.get_ticket",
        tool_version="1",
        sequence_no=2,
    )
    result = ToolResultReceived(
        event_type="tool_result_received",
        run_id=f"r-{extra}",
        session_id=f"s-{extra}",
        event_id="e3",
        parent_event_id="e2",
        agent_id="scripted",
        provenance=prov,
        call_id="call-1",
        tool_name="support.get_ticket",
        sanitized_result={"id": "T-1"},
        sequence_no=3,
    )
    final = FinalResponse(
        event_type="final_response",
        run_id=f"r-{extra}",
        session_id=f"s-{extra}",
        event_id="e4",
        parent_event_id="e3",
        agent_id="scripted",
        provenance=prov,
        text_retained=True,
        text="resolved",
        sequence_no=4,
    )
    return (step, call, result, final)


def test_event_json_round_trip_strict() -> None:
    events = _events()
    for event in events:
        data = json.loads(json.dumps(event.model_dump(mode="json")))
        restored = validate_agent_event(data)
        assert restored == event
        assert restored.event_type == event.event_type


def test_unknown_event_field_rejected() -> None:
    data = dict(_events()[1].model_dump(mode="python"))
    data["surprise"] = True
    with pytest.raises(ValidationError, match="surprise"):
        validate_agent_event(data)


def test_incompatible_schema_version_rejected() -> None:
    data = dict(_events()[0].model_dump(mode="python"))
    data["schema_version"] = 2
    with pytest.raises(ValueError, match="schema version"):
        ensure_supported_event_schema(data)


def test_unknown_event_type_rejected() -> None:
    data = dict(_events()[0].model_dump(mode="python"))
    data["event_type"] = "not_a_real_event"
    with pytest.raises(ValidationError):
        validate_agent_event(data)


def test_capabilities_do_not_alter_old_target_capabilities() -> None:
    agent_caps = AgentTargetCapabilities(tool_use=True)
    legacy = TargetCapabilities()
    assert agent_caps.tool_use is True
    assert legacy.tool_role is False
    assert not hasattr(legacy, "tool_use")
    # Serialization stays independent.
    assert "tool_use" in agent_caps.model_dump()
    assert "tool_use" not in legacy.__dict__


def test_trajectory_validation_sequence_contiguous() -> None:
    events = _events()
    bad = (events[0].model_copy(update={"sequence_no": 2}), *events[1:])
    with pytest.raises(ValueError, match="contiguous"):
        AgentTrajectory(run_id="r", session_id="s", events=bad)


def test_trajectory_duplicate_event_id_rejected() -> None:
    events = _events()
    dup = (
        events[0],
        events[1].model_copy(update={"sequence_no": 2, "event_id": "e1"}),
        *events[2:],
    )
    with pytest.raises(ValueError, match="duplicate event id"):
        AgentTrajectory(run_id="r", session_id="s", events=dup)


def test_trajectory_parent_must_precede() -> None:
    events = _events()
    # Swap step and call so the parent references a later event.
    swapped = (
        events[1].model_copy(update={"sequence_no": 1}),
        events[0].model_copy(update={"sequence_no": 2, "parent_event_id": None}),
        *events[2:],
    )
    with pytest.raises(ValueError, match="precede|not in this trajectory"):
        AgentTrajectory(run_id="r", session_id="s", events=swapped)


def test_trajectory_unknown_parent_rejected() -> None:
    events = _events()
    bad = (
        events[0],
        events[1].model_copy(update={"parent_event_id": "missing"}),
        *events[2:],
    )
    with pytest.raises(ValueError, match="not in this trajectory"):
        AgentTrajectory(run_id="r", session_id="s", events=bad)


def test_trajectory_external_parent_run_allowed() -> None:
    events = _events()
    external = (
        events[0],
        events[1].model_copy(
            update={"parent_event_id": "other-run-event", "parent_run_id": "run-0"}
        ),
        *events[2:],
    )
    trajectory = AgentTrajectory(run_id="r", session_id="s", events=external)
    assert trajectory.digest is not None


def test_trajectory_tool_result_must_reference_known_call() -> None:
    events = _events()
    bad = (
        events[0],
        events[1],
        events[2].model_copy(update={"call_id": "call-unknown"}),
        events[3],
    )
    with pytest.raises(ValueError, match="unknown call_id"):
        AgentTrajectory(run_id="r", session_id="s", events=bad)


def test_parallel_call_correlation_survives_serialization() -> None:
    prov = _provenance()
    step = AgentStep(
        event_type="agent_step",
        run_id="r",
        session_id="s",
        event_id="e1",
        agent_id="scripted",
        provenance=prov,
        step_kind="parallel",
        input_source="user",
        sequence_no=1,
    )
    call_a = ToolCallRequested(
        event_type="tool_call_requested",
        run_id="r",
        session_id="s",
        event_id="e2",
        parent_event_id="e1",
        agent_id="scripted",
        provenance=prov,
        call_id="call-a",
        tool_name="a",
        tool_version="1",
        sequence_no=2,
    )
    call_b = ToolCallRequested(
        event_type="tool_call_requested",
        run_id="r",
        session_id="s",
        event_id="e3",
        parent_event_id="e1",
        agent_id="scripted",
        provenance=prov,
        call_id="call-b",
        tool_name="b",
        tool_version="1",
        sequence_no=3,
    )
    result_a = ToolResultReceived(
        event_type="tool_result_received",
        run_id="r",
        session_id="s",
        event_id="e4",
        parent_event_id="e2",
        agent_id="scripted",
        provenance=prov,
        call_id="call-a",
        tool_name="a",
        sequence_no=4,
    )
    result_b = ToolResultReceived(
        event_type="tool_result_received",
        run_id="r",
        session_id="s",
        event_id="e5",
        parent_event_id="e3",
        agent_id="scripted",
        provenance=prov,
        call_id="call-b",
        tool_name="b",
        sequence_no=5,
    )
    trajectory = AgentTrajectory(
        run_id="r",
        session_id="s",
        events=(step, call_a, call_b, result_a, result_b),
    )
    restored = AgentTrajectory.model_validate(
        json.loads(json.dumps(trajectory.model_dump(mode="json")))
    )
    assert restored.events[3].call_id == "call-a"  # type: ignore[attr-defined]
    assert restored.events[4].call_id == "call-b"  # type: ignore[attr-defined]
    assert restored.events[2].parent_event_id == "e1"  # type: ignore[attr-defined]


def test_timestamps_do_not_alter_digest_or_order() -> None:
    from datetime import datetime, timezone

    events_a = _events("a")
    events_b = _events("b")
    stamped = tuple(
        event.model_copy(update={"occurred_at": datetime(2026, 1, 1, tzinfo=timezone.utc)})
        for event in events_a
    )
    plain = events_b
    ta = AgentTrajectory(run_id="r-a", session_id="s-a", events=stamped)
    tb = AgentTrajectory(run_id="r-b", session_id="s-b", events=plain)
    # Different run/session/event ids and timestamps, same semantics.
    assert ta.digest == tb.digest
    assert trajectory_digest(ta) == trajectory_digest(tb)


def test_digest_is_deterministic() -> None:
    events = _events()
    first = AgentTrajectory(run_id="r", session_id="s", events=events)
    second = AgentTrajectory(
        run_id="r",
        session_id="s",
        events=tuple(event.model_dump() for event in events),  # re-parsed
    )
    assert first.digest == second.digest


def test_approval_decision_event_round_trip() -> None:
    prov = _provenance()
    decision = ApprovalDecision(
        event_type="approval_decision",
        run_id="r",
        session_id="s",
        event_id="e1",
        agent_id="scripted",
        provenance=prov,
        approval_id="approval-1",
        subject_action="crm.update_customer:scenario",
        decision=ApprovalValue.GRANTED,
        principal="support_agent",
        policy_id="support/1",
        policy_version="1",
        sequence_no=1,
    )
    data = json.loads(json.dumps(decision.model_dump(mode="json")))
    restored = validate_agent_event(data)
    assert isinstance(restored, ApprovalDecision)
    assert restored.decision is ApprovalValue.GRANTED
