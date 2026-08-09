"""TrajectoryRecorder sequence allocation and validation tests."""

from __future__ import annotations

import asyncio

import pytest

from cot_redteam.agent.trajectory import TrajectoryRecorder
from cot_redteam.agent.types import (
    AgentStep,
    EventProvenance,
    FinalResponse,
)


def _step(run_id: str, event_id: str) -> AgentStep:
    return AgentStep(
        event_type="agent_step",
        run_id=run_id,
        session_id="s",
        event_id=event_id,
        agent_id="scripted",
        provenance=EventProvenance(source_kind="target", source_id="scripted", trust="untrusted"),
        step_kind="decision",
        input_source="user",
    )


async def test_sequence_allocated_monotonically() -> None:
    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    first = await recorder.record(_step("r", "e1"))
    second = await recorder.record(_step("r", "e2"))
    assert first.sequence_no == 1
    assert second.sequence_no == 2
    trajectory = recorder.build_trajectory()
    assert trajectory.digest is not None
    assert [event.sequence_no for event in trajectory.events] == [1, 2]


async def test_duplicate_event_id_rejected() -> None:
    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    await recorder.record(_step("r", "e1"))
    with pytest.raises(ValueError, match="duplicate event id"):
        await recorder.record(_step("r", "e1"))
    assert recorder.event_count == 1


async def test_run_session_agent_mismatch_rejected() -> None:
    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    with pytest.raises(ValueError, match="run_id"):
        await recorder.record(_step("other", "e1"))
    with pytest.raises(ValueError, match="session_id"):
        await recorder.record(_step("r", "e1").model_copy(update={"session_id": "other"}))
    with pytest.raises(ValueError, match="agent_id"):
        await recorder.record(_step("r", "e1").model_copy(update={"agent_id": "other"}))


async def test_recorder_assigns_sequence_under_concurrency() -> None:
    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    events = await asyncio.gather(*[recorder.record(_step("r", f"e{i}")) for i in range(20)])
    sequences = sorted(event.sequence_no for event in events)
    assert sequences == list(range(1, 21))


async def test_timestamps_do_not_change_order() -> None:
    from datetime import datetime, timezone

    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    await recorder.record(
        _step("r", "e1").model_copy(
            update={"occurred_at": datetime(2026, 1, 2, tzinfo=timezone.utc)}
        )
    )
    await recorder.record(
        _step("r", "e2").model_copy(
            update={"occurred_at": datetime(2026, 1, 1, tzinfo=timezone.utc)}
        )
    )
    trajectory = recorder.build_trajectory()
    assert trajectory.events[0].event_id == "e1"
    assert trajectory.events[1].event_id == "e2"


async def test_parent_relationships_preserved() -> None:
    recorder = TrajectoryRecorder(run_id="r", session_id="s", agent_id="scripted")
    step = await recorder.record(_step("r", "e1"))
    final = await recorder.record(
        FinalResponse(
            event_type="final_response",
            run_id="r",
            session_id="s",
            event_id="e2",
            parent_event_id=step.event_id,
            agent_id="scripted",
            provenance=EventProvenance(
                source_kind="target", source_id="scripted", trust="untrusted"
            ),
            text_retained=False,
            text=None,
        )
    )
    trajectory = recorder.build_trajectory()
    assert trajectory.events[1].parent_event_id == "e1"
    assert final.sequence_no == 2
