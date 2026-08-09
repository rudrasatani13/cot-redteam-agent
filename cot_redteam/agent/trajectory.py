"""Canonical trajectory recorder: the only allocator of sequence numbers.

The recorder appends immutable events, allocates ``sequence_no`` under an
async lock, validates run/session/agent identity and event-ID uniqueness,
emits progress updates, and builds validated ``AgentTrajectory`` objects
with canonical digests. Timestamps are optional diagnostics and never
define trajectory order.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping

from cot_redteam.agent.types import (
    AGENT_EVENT_SCHEMA_VERSION,
    AgentEventUnion,
    AgentTrajectory,
    ensure_supported_event_schema,
)
from cot_redteam.core.types import JsonValue
from cot_redteam.eval.events import ProgressCallback, RunEvent, RunEventKind, emit

#: Optional hook receiving sanitized event envelopes for persistence (PR8).
EventSink = Callable[[Mapping[str, JsonValue]], None]


class TrajectoryRecorder:
    def __init__(
        self,
        *,
        run_id: str,
        session_id: str,
        agent_id: str,
        progress: ProgressCallback | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        if not run_id or not session_id or not agent_id:
            raise ValueError("run_id, session_id, and agent_id are required")
        self.run_id = run_id
        self.session_id = session_id
        self.agent_id = agent_id
        self.progress = progress
        self.event_sink = event_sink
        self._lock = asyncio.Lock()
        self._events: dict[int, AgentEventUnion] = {}
        self._event_ids: set[str] = set()

    @property
    def event_count(self) -> int:
        return len(self._events)

    async def record(self, event: AgentEventUnion) -> AgentEventUnion:
        """Validate and append one immutable event with a fresh sequence number."""
        ensure_supported_event_schema(event.model_dump(mode="python"))
        if event.run_id != self.run_id:
            raise ValueError(
                f"event run_id {event.run_id!r} does not match recorder run {self.run_id!r}"
            )
        if event.session_id != self.session_id:
            raise ValueError(
                f"event session_id {event.session_id!r} does not match recorder "
                f"session {self.session_id!r}"
            )
        if event.agent_id != self.agent_id:
            raise ValueError(
                f"event agent_id {event.agent_id!r} does not match recorder agent {self.agent_id!r}"
            )
        async with self._lock:
            if event.event_id in self._event_ids:
                raise ValueError(f"duplicate event id {event.event_id!r}")
            sequence_no = len(self._events) + 1
            recorded = event.model_copy(
                update={
                    "sequence_no": sequence_no,
                    "schema_version": AGENT_EVENT_SCHEMA_VERSION,
                }
            )
            self._events[sequence_no] = recorded
            self._event_ids.add(recorded.event_id)
        await emit(
            self.progress,
            RunEvent(
                kind=RunEventKind.ACTIVITY,
                run_id=self.run_id,
                message=(
                    f"agent event {recorded.event_type} seq={sequence_no} id={recorded.event_id}"
                ),
                detail={
                    "event_type": recorded.event_type,
                    "sequence_no": sequence_no,
                    "event_id": recorded.event_id,
                },
            ),
        )
        if self.event_sink is not None:
            self.event_sink(recorded.model_dump(mode="python"))
        return recorded

    def build_trajectory(self) -> AgentTrajectory:
        """Build and validate the immutable trajectory for this run."""
        events = tuple(self._events[index] for index in sorted(self._events))
        return AgentTrajectory(
            run_id=self.run_id,
            session_id=self.session_id,
            events=events,
        )
