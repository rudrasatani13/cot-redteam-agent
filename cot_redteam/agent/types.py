"""Immutable agent-domain types: events, trajectories, runs, oracles.

The agent event and replay schemas use frozen strict Pydantic models with
``extra="forbid"`` so JSON unions are tagged/discriminated, validation is
deterministic, and incompatible replay data is rejected rather than
coerced. Values are JSON-compatible only; no event payload may carry an
executable object type.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from cot_redteam.core.types import JsonValue

AGENT_EVENT_SCHEMA_VERSION = 1
REPLAY_SCHEMA_VERSION = 1
SUPPORT_WORLD_VERSION = "support-world/1"


class AgentRunStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class AgentOutcome(str, Enum):
    INVARIANT_HELD = "invariant_held"
    VERIFIED_EXPLOIT = "verified_exploit"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class EventTrust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    DERIVED = "derived"


class EventStatus(str, Enum):
    REQUESTED = "requested"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"


class AuthorizationState(str, Enum):
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN = "unknown"


class ApprovalValue(str, Enum):
    GRANTED = "granted"
    DENIED = "denied"


class OracleVerdict(str, Enum):
    INVARIANT_HELD = "invariant_held"
    VERIFIED_EXPLOIT = "verified_exploit"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class AgentTargetCapabilities(BaseModel):
    """Agent-level capabilities.

    Capabilities describe behavior the target can perform, never
    authorization to perform it. This type is deliberately separate from
    ``core.types.TargetCapabilities`` (provider/model message capabilities).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_use: bool = False
    persistent_memory: bool = False
    approval_controls: bool = False
    external_network: bool = False
    delegation: bool = False
    mutable_state: bool = False
    parallel_tool_calls: bool = False


class AuthorizationScope(BaseModel):
    """Structured authorization scope; never carries credential material."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal: str
    resource: str
    action: str
    constraints: dict[str, JsonValue] = Field(default_factory=dict)


class ArtifactReference(BaseModel):
    """Reference to a stored artifact; never serializes an absolute path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    media_type: str
    relative_path: str
    sha256: str
    byte_length: int
    sensitivity: Literal["public", "internal", "sensitive"] = "internal"


class EventProvenance(BaseModel):
    """Provenance of a trajectory event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_kind: Literal["scenario", "target", "tool_gateway", "world", "oracle", "system"]
    source_id: str
    source_version: str | None = None
    trust: EventTrust = EventTrust.TRUSTED
    artifact_reference: ArtifactReference | None = None


class _AgentEventBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = AGENT_EVENT_SCHEMA_VERSION
    run_id: str
    session_id: str
    event_id: str
    parent_event_id: str | None = None
    #: Monotonic sequence allocated by the TrajectoryRecorder; never by
    #: wall-clock time. 0 means "unassigned".
    sequence_no: int = 0
    agent_id: str
    parent_run_id: str | None = None
    event_type: str
    provenance: EventProvenance
    requested_authorization_scope: tuple[AuthorizationScope, ...] = ()
    observed_authorization_scope: tuple[AuthorizationScope, ...] = ()
    status: EventStatus = EventStatus.SUCCEEDED
    error_code: str | None = None
    error_message: str | None = None
    payload: JsonValue | None = None
    artifact_reference: ArtifactReference | None = None
    #: Diagnostic only; never defines trajectory order or digest.
    occurred_at: datetime | None = None


class AgentStep(_AgentEventBase):
    """One target decision/processing step."""

    event_type: Literal["agent_step"] = "agent_step"
    step_kind: str
    input_source: str


class ToolCallRequested(_AgentEventBase):
    """A tool invocation request recorded before authorization/dispatch."""

    event_type: Literal["tool_call_requested"] = "tool_call_requested"
    call_id: str
    tool_name: str
    tool_version: str
    sanitized_arguments: JsonValue | None = None
    arguments_artifact: ArtifactReference | None = None


class ToolResultReceived(_AgentEventBase):
    """The structured result or error of an executed tool call."""

    event_type: Literal["tool_result_received"] = "tool_result_received"
    call_id: str
    tool_name: str
    sanitized_result: JsonValue | None = None
    result_artifact: ArtifactReference | None = None


class ActionEvent(_AgentEventBase):
    """Gateway/world observation of an attempted or executed action."""

    event_type: Literal["action_event"] = "action_event"
    call_id: str
    action_kind: str
    resource: str
    attempted: bool
    executed: bool
    authorization_state: AuthorizationState = AuthorizationState.UNKNOWN
    state_before_digest: str | None = None
    state_after_digest: str | None = None


class ApprovalDecision(_AgentEventBase):
    """A recorded approval request decision."""

    event_type: Literal["approval_decision"] = "approval_decision"
    approval_id: str
    subject_action: str
    decision: ApprovalValue
    principal: str
    policy_id: str
    policy_version: str


class MemoryMutation(_AgentEventBase):
    """A structured memory mutation; raw values default to omitted."""

    event_type: Literal["memory_mutation"] = "memory_mutation"
    memory_namespace: str
    operation: Literal["set", "delete", "append"]
    key: str
    value_present: bool = False
    value_artifact: ArtifactReference | None = None


class SideEffect(_AgentEventBase):
    """Normalized world-observed effect derived from an executed action."""

    event_type: Literal["side_effect"] = "side_effect"
    effect_kind: str
    resource: str
    before_digest: str | None = None
    after_digest: str | None = None
    source_action_event_id: str


class FinalResponse(_AgentEventBase):
    """The target's final response text (retained per retention policy).

    A FinalResponse never proves impact without a matching action/state
    observation.
    """

    event_type: Literal["final_response"] = "final_response"
    text_retained: bool = False
    text: str | None = None
    text_artifact: ArtifactReference | None = None


AgentEvent = Annotated[
    AgentStep
    | ToolCallRequested
    | ToolResultReceived
    | ActionEvent
    | ApprovalDecision
    | MemoryMutation
    | SideEffect
    | FinalResponse,
    Field(discriminator="event_type"),
]

AgentEventUnion = (
    AgentStep
    | ToolCallRequested
    | ToolResultReceived
    | ActionEvent
    | ApprovalDecision
    | MemoryMutation
    | SideEffect
    | FinalResponse
)

_EVENT_ADAPTER: TypeAdapter[AgentEventUnion] = TypeAdapter(AgentEventUnion)


def validate_agent_event(data: Mapping[str, object]) -> AgentEventUnion:
    """Strictly validate one agent event from JSON-compatible data."""
    return _EVENT_ADAPTER.validate_python(dict(data))


def ensure_supported_event_schema(data: Mapping[str, object]) -> None:
    """Reject unknown major event schema versions before any coercion."""
    version = data.get("schema_version", AGENT_EVENT_SCHEMA_VERSION)
    if not isinstance(version, int) or version != AGENT_EVENT_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported agent event schema version {version!r}; "
            f"expected {AGENT_EVENT_SCHEMA_VERSION}"
        )


class VersionedRef(BaseModel):
    """Versioned identifier for scenarios, targets, worlds, and attacks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    version: str


class OracleEvidenceItem(BaseModel):
    """One structured oracle evidence entry."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    resource: str | None = None
    detail: JsonValue | None = None


class OracleResult(BaseModel):
    """Outcome of one deterministic oracle evaluation.

    ``ERROR`` and ``INCONCLUSIVE`` are never mapped to secure/clean.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    oracle_id: str
    oracle_version: str
    verdict: OracleVerdict
    summary: str
    evidence_event_ids: tuple[str, ...] = ()
    pre_snapshot_digest: str | None = None
    post_snapshot_digest: str | None = None
    evidence: tuple[OracleEvidenceItem, ...] = ()
    error: str | None = None


class Finding(BaseModel):
    """A security finding derived from oracle evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str
    oracle_id: str
    category: str
    severity: str
    summary: str
    evidence_event_ids: tuple[str, ...] = ()


class AgentTrajectory(BaseModel):
    """Immutable ordered event sequence with a canonical digest.

    Validation rules:
    - sequence starts at 1 and strictly increases by 1;
    - event IDs are unique;
    - parent references point to an earlier event in the same trajectory or
      declare a parent run/session relationship;
    - tool result/action events reference a known call_id;
    - ordering is never derived from timestamps.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = AGENT_EVENT_SCHEMA_VERSION
    run_id: str
    session_id: str
    events: tuple[AgentEventUnion, ...] = ()
    digest: str | None = None

    def model_post_init(self, __context: object) -> None:
        self._validate_trajectory()

    def _validate_trajectory(self) -> None:
        seen_ids: set[str] = set()
        call_ids: set[str] = set()
        call_sequence: dict[str, int] = {}
        event_by_id: dict[str, int] = {}
        for index, event in enumerate(self.events, start=1):
            if event.sequence_no != index:
                raise ValueError(
                    f"trajectory sequence must be contiguous starting at 1; "
                    f"expected {index}, got {event.sequence_no} (event {event.event_id!r})"
                )
            if event.event_id in seen_ids:
                raise ValueError(f"duplicate event id {event.event_id!r}")
            seen_ids.add(event.event_id)
            event_by_id[event.event_id] = event.sequence_no
            if isinstance(event, (ToolResultReceived, ActionEvent)):
                if event.call_id not in call_ids:
                    raise ValueError(
                        f"{event.event_type} references unknown call_id {event.call_id!r}"
                    )
            if isinstance(event, ToolCallRequested):
                call_ids.add(event.call_id)
                call_sequence[event.call_id] = event.sequence_no
            parent = event.parent_event_id
            if parent is not None and event.parent_run_id is None:
                if parent not in event_by_id:
                    raise ValueError(
                        f"parent event {parent!r} of {event.event_id!r} is not in this trajectory"
                    )
                if event_by_id[parent] >= event.sequence_no:
                    raise ValueError(f"parent event {parent!r} must precede {event.event_id!r}")
        # Tool results/actions must reference a call declared earlier.
        for event in self.events:
            if isinstance(event, (ToolResultReceived, ActionEvent)):
                declared = call_sequence.get(event.call_id)
                if declared is None or declared >= event.sequence_no:
                    raise ValueError(
                        f"{event.event_type} call_id {event.call_id!r} must be "
                        "declared by an earlier tool_call_requested"
                    )
        if self.digest is None:
            object.__setattr__(self, "digest", trajectory_digest(self))


def trajectory_digest(trajectory: AgentTrajectory) -> str:
    """Canonical digest over the semantic projection of the trajectory.

    Excludes non-deterministic diagnostic timestamps, run/session/event
    identifiers, and normalizes parent references to sequence numbers so
    scripted replays stay stable across runs.
    """
    from cot_redteam.core.serialization import canonical_json, sha256_text

    event_by_id = {event.event_id: event.sequence_no for event in trajectory.events}
    projection: list[dict[str, object]] = []
    for event in trajectory.events:
        data = event.model_dump(
            mode="python",
            exclude={
                "run_id",
                "session_id",
                "event_id",
                "agent_id",
                "occurred_at",
                "sequence_no",
                "parent_event_id",
                "parent_run_id",
            },
        )
        parent = event.parent_event_id
        if parent is not None:
            if parent in event_by_id:
                data["parent_sequence_no"] = event_by_id[parent]
            else:
                data["parent_external"] = {
                    "run_id": event.parent_run_id,
                    "event_id": parent,
                }
        data["sequence_position"] = event.sequence_no
        projection.append(data)
    return sha256_text(canonical_json(projection))


class AgentRun(BaseModel):
    """A complete agent run: context, trajectory, oracles, findings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = AGENT_EVENT_SCHEMA_VERSION
    run_id: str
    session_id: str
    scenario_ref: VersionedRef
    target_ref: VersionedRef
    world_ref: VersionedRef
    attack_ref: VersionedRef
    status: AgentRunStatus
    outcome: AgentOutcome | None = None
    trajectory: AgentTrajectory
    pre_snapshot_digest: str | None = None
    post_snapshot_digest: str | None = None
    oracle_results: tuple[OracleResult, ...] = ()
    findings: tuple[Finding, ...] = ()
    budget_snapshot: dict[str, JsonValue] = Field(default_factory=dict)
    started_at: datetime
    completed_at: datetime | None = None
    error: str | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


def aggregate_outcome(results: tuple[OracleResult, ...]) -> AgentOutcome:
    """Aggregate oracle verdicts into a run outcome.

    1. any VERIFIED_EXPLOIT -> VERIFIED_EXPLOIT;
    2. else any ERROR -> ERROR;
    3. else any INCONCLUSIVE -> INCONCLUSIVE;
    4. else all required oracles INVARIANT_HELD -> INVARIANT_HELD.
    """
    if not results:
        return AgentOutcome.INCONCLUSIVE
    if any(result.verdict is OracleVerdict.VERIFIED_EXPLOIT for result in results):
        return AgentOutcome.VERIFIED_EXPLOIT
    if any(result.verdict is OracleVerdict.ERROR for result in results):
        return AgentOutcome.ERROR
    if any(result.verdict is OracleVerdict.INCONCLUSIVE for result in results):
        return AgentOutcome.INCONCLUSIVE
    return AgentOutcome.INVARIANT_HELD
