"""Canonical trajectory recorder: the only allocator of sequence numbers.

The recorder appends immutable events, allocates ``sequence_no`` under an
async lock, validates run/session/agent identity and event-ID uniqueness,
emits progress updates, and builds validated ``AgentTrajectory`` objects
with canonical digests. Timestamps are optional diagnostics and never
define trajectory order.
"""

from __future__ import annotations

import asyncio
import weakref
from collections.abc import Callable, Mapping

from cot_redteam.agent.types import (
    AGENT_EVENT_SCHEMA_VERSION,
    ActionEvent,
    AgentEventUnion,
    AgentStep,
    AgentTrajectory,
    ApprovalDecision,
    FinalResponse,
    MemoryMutation,
    SideEffect,
    ToolCallRequested,
    ToolResultReceived,
    ensure_supported_event_schema,
)
from cot_redteam.core.types import JsonValue
from cot_redteam.eval.events import ProgressCallback, RunEvent, RunEventKind, emit

#: Optional hook receiving sanitized event envelopes for persistence (PR8).
EventSink = Callable[[Mapping[str, JsonValue]], None]


_PRIVILEGED_EVENT_TYPES = (
    ToolCallRequested,
    ToolResultReceived,
    ActionEvent,
    ApprovalDecision,
    SideEffect,
    MemoryMutation,
)


class _TrajectoryCapability:
    """Opaque per-recorder capability for trusted event producers."""

    __slots__ = ()


class _TrustedTrajectoryWriter:
    """Private producer view that carries a recorder's capability."""

    __slots__ = ("_capability", "_recorder")

    def __init__(self, recorder: TrajectoryRecorder) -> None:
        self._recorder = recorder
        self._capability = recorder._capability

    @property
    def run_id(self) -> str:
        return self._recorder.run_id

    @property
    def session_id(self) -> str:
        return self._recorder.session_id

    @property
    def agent_id(self) -> str:
        return self._recorder.agent_id

    async def record(self, event: AgentEventUnion) -> AgentEventUnion:
        return await self._recorder._record(event, capability=self._capability)


class TrajectoryPersistenceError(RuntimeError):
    """The append-only event sink rejected an event.

    Once an event cannot be persisted, the recorder is permanently marked
    failed.  Continuing to allocate events would allow an in-memory
    trajectory to diverge from its durable prefix and could make oracle
    evidence point at events that are absent from storage.
    """


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
        self._capability = _TrajectoryCapability()
        self._lock = asyncio.Lock()
        self._events: dict[int, AgentEventUnion] = {}
        self._event_ids: set[str] = set()
        self._persistence_error: Exception | None = None

    @property
    def event_count(self) -> int:
        return len(self._events)

    @property
    def persistence_error(self) -> Exception | None:
        """The first event-sink failure, if any.

        This is intentionally exposed to the execution engine so a failed
        append can force an ``ERROR`` outcome even when an oracle still sees
        a state mutation from the attempted action.
        """

        return self._persistence_error

    async def record(self, event: AgentEventUnion) -> AgentEventUnion:
        """Validate and append target-owned events with a fresh sequence number.

        Privileged evidence events require the private capability held by
        gateway/approval/world producer views.  A raw recorder reference
        therefore cannot be used to forge action evidence.
        """
        return await self._record(event, capability=None)

    async def _record(
        self,
        event: AgentEventUnion,
        *,
        capability: _TrajectoryCapability | None,
    ) -> AgentEventUnion:
        """Validate and append one event, optionally under producer authority."""
        if isinstance(event, _PRIVILEGED_EVENT_TYPES) and capability is not self._capability:
            raise PermissionError(
                f"privileged {event.event_type} events require a trusted producer"
            )
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
            if self._persistence_error is not None:
                raise TrajectoryPersistenceError(
                    "trajectory event persistence failed; recorder is closed"
                ) from self._persistence_error
            if event.event_id in self._event_ids:
                raise ValueError(f"duplicate event id {event.event_id!r}")
            sequence_no = len(self._events) + 1
            recorded = event.model_copy(
                update={
                    "sequence_no": sequence_no,
                    "schema_version": AGENT_EVENT_SCHEMA_VERSION,
                }
            )
            # Persist while holding the allocation lock.  This serializes
            # sink calls in sequence order and, on failure, prevents a later
            # event from being persisted after a missing prefix event.
            if self.event_sink is not None:
                try:
                    self.event_sink(recorded.model_dump(mode="python"))
                except Exception as exc:
                    self._persistence_error = exc
                    raise TrajectoryPersistenceError(
                        f"failed to persist trajectory event {recorded.event_id!r}"
                    ) from exc
            self._events[sequence_no] = recorded
            self._event_ids.add(recorded.event_id)
        # Persist BEFORE progress: durable evidence wins over UI decoration.
        # A crash while emitting progress must never leave a later event
        # persisted while an earlier one is missing.
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
        return recorded

    def _trusted_writer(self) -> _TrustedTrajectoryWriter:
        """Return the private producer view used by gateway/approval code."""
        return _TrustedTrajectoryWriter(self)

    def build_trajectory(self) -> AgentTrajectory:
        """Build and validate the immutable trajectory for this run."""
        events = tuple(self._events[index] for index in sorted(self._events))
        return AgentTrajectory(
            run_id=self.run_id,
            session_id=self.session_id,
            events=events,
        )


_TARGET_TRAJECTORIES: weakref.WeakKeyDictionary[TargetTrajectory, TrajectoryRecorder] = (
    weakref.WeakKeyDictionary()
)


class TargetTrajectory:
    """Restricted trajectory writer exposed to trusted target adapters.

    Adapters may contribute agent-processing and final-response events, but
    gateway/approval/world evidence is producer-owned. This facade prevents
    accidental privileged writes; it is not a sandbox against malicious
    in-process Python code.
    """

    __slots__ = ("__weakref__",)

    def __init__(self, recorder: TrajectoryRecorder) -> None:
        _TARGET_TRAJECTORIES[self] = recorder

    @property
    def run_id(self) -> str:
        return _TARGET_TRAJECTORIES[self].run_id

    @property
    def session_id(self) -> str:
        return _TARGET_TRAJECTORIES[self].session_id

    @property
    def agent_id(self) -> str:
        return _TARGET_TRAJECTORIES[self].agent_id

    @property
    def event_count(self) -> int:
        return _TARGET_TRAJECTORIES[self].event_count

    @property
    def persistence_error(self) -> Exception | None:
        return _TARGET_TRAJECTORIES[self].persistence_error

    async def record(self, event: AgentEventUnion) -> AgentEventUnion:
        """Record only target-owned event types.

        The allowlist is intentionally explicit and fail-closed: adding a
        new event type cannot accidentally make it target-writable.
        """
        if isinstance(event, _PRIVILEGED_EVENT_TYPES):
            raise PermissionError(f"targets cannot record privileged {event.event_type} events")
        # AgentStep and FinalResponse are currently the only target-owned
        # events.  Keep unknown/future event types denied by default.
        if not isinstance(event, (AgentStep, FinalResponse)):
            raise PermissionError(f"targets cannot record {event.event_type} events")
        return await _TARGET_TRAJECTORIES[self].record(event)

    def build_trajectory(self) -> AgentTrajectory:
        """Build a read-only snapshot for compatibility with target tests."""
        return _TARGET_TRAJECTORIES[self].build_trajectory()
