"""Immutable runtime domain types and outcome enums for v0.2."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

JsonPrimitive = None | bool | int | float | str
# Any keeps recursive JSON containers simple for mypy/pydantic.
JsonValue = Any
JsonDataclass = Any


class ItemStatus(str, Enum):
    SUCCEEDED = "succeeded"
    ATTACK_ERROR = "attack_error"
    PROVIDER_ERROR = "provider_error"
    MONITOR_ERROR = "monitor_error"
    BUDGET_EXCEEDED = "budget_exceeded"
    CANCELLED = "cancelled"


class MonitorStatus(str, Enum):
    TRIGGERED = "triggered"
    CLEAN = "clean"
    ERROR = "error"
    NOT_RUN = "not_run"


class RunStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class ReasoningSource(str, Enum):
    PROVIDER = "provider"
    DELIMITED = "delimited"
    ABSENT = "absent"


class MessageRole(str, Enum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class MessageTrust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class AttackCategory(str, Enum):
    INJECTION = "injection"
    FAITHFULNESS = "faithfulness"
    STEGANOGRAPHY = "steganography"
    DISTILLATION = "distillation"
    MANIPULATION = "manipulation"
    SANDBAGGING = "sandbagging"
    EVASION = "evasion"
    GENERATIVE = "generative"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_unit_interval(name: str, value: float | None) -> None:
    if value is None:
        return
    if not 0.0 <= float(value) <= 1.0:
        raise ValueError(f"{name} must be between 0.0 and 1.0 inclusive, got {value!r}")


@dataclass(frozen=True)
class ModelRef:
    provider: str
    model_id: str

    def __post_init__(self) -> None:
        if not self.provider or not self.provider.strip():
            raise ValueError("provider must be non-empty")
        if not self.model_id or not self.model_id.strip():
            raise ValueError("model_id must be non-empty")
        object.__setattr__(self, "provider", self.provider.strip())
        object.__setattr__(self, "model_id", self.model_id.strip())

    @classmethod
    def parse(cls, value: str) -> ModelRef:
        if ":" not in value:
            raise ValueError("provider:model-id")
        provider, model_id = value.split(":", 1)
        if not provider or not model_id:
            raise ValueError("provider:model-id")
        return cls(provider=provider, model_id=model_id)

    def __str__(self) -> str:
        return f"{self.provider}:{self.model_id}"


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int | None = None

    def __post_init__(self) -> None:
        if self.input_tokens < 0 or self.output_tokens < 0:
            raise ValueError("token counts must be non-negative")
        if self.total_tokens is None:
            object.__setattr__(
                self,
                "total_tokens",
                self.input_tokens + self.output_tokens,
            )


@dataclass(frozen=True)
class DatasetSample:
    id: str
    question: str
    answer: str | None = None
    category: str | None = None
    difficulty: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("sample id is required")
        if not self.question:
            raise ValueError("sample question is required")
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class Message:
    role: MessageRole
    content: str
    name: str | None = None
    trust: MessageTrust = MessageTrust.TRUSTED
    source: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        content = self.content.strip()
        if not content:
            raise ValueError("message content must be non-empty")
        object.__setattr__(self, "content", content)
        if self.name is not None:
            name = self.name.strip()
            if not name:
                raise ValueError("message name must be non-empty when provided")
            object.__setattr__(self, "name", name)
        if self.source is not None:
            source = self.source.strip()
            if not source:
                raise ValueError("message source must be non-empty when provided")
            object.__setattr__(self, "source", source)
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class TargetCapabilities:
    system_role: bool = False
    developer_role: bool = False
    multi_turn: bool = False
    tool_role: bool = False
    visible_reasoning: bool = False
    native_seed: bool = False
    input_modalities: tuple[str, ...] = ("text",)
    output_modalities: tuple[str, ...] = ("text",)

    def __post_init__(self) -> None:
        object.__setattr__(self, "input_modalities", tuple(self.input_modalities))
        object.__setattr__(self, "output_modalities", tuple(self.output_modalities))
        if not self.input_modalities or not self.output_modalities:
            raise ValueError("target modalities must not be empty")


@dataclass(frozen=True)
class TargetRequirements:
    system_role: bool = False
    developer_role: bool = False
    multi_turn: bool = False
    tool_role: bool = False
    visible_reasoning: bool = False
    native_seed: bool = False

    def missing_from(self, capabilities: TargetCapabilities) -> tuple[str, ...]:
        names = (
            "system_role",
            "developer_role",
            "multi_turn",
            "tool_role",
            "visible_reasoning",
            "native_seed",
        )
        return tuple(
            name for name in names if getattr(self, name) and not getattr(capabilities, name)
        )

    def validate(self, capabilities: TargetCapabilities) -> None:
        missing = self.missing_from(capabilities)
        if missing:
            raise ValueError(f"target is missing required capabilities: {', '.join(missing)}")


@dataclass(frozen=True)
class GenerationRequest:
    prompt: str | None = None
    system_prompt: str | None = None
    messages: tuple[Message, ...] = ()
    temperature: float = 0.7
    max_tokens: int = 4096
    stop: tuple[str, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        has_prompt = self.prompt is not None and bool(self.prompt.strip())
        has_messages = bool(self.messages)
        if has_prompt == has_messages:
            raise ValueError("exactly one of prompt or messages is required")
        if self.prompt is not None and not self.prompt.strip():
            raise ValueError("prompt must be non-empty when provided")
        if has_messages and self.system_prompt is not None:
            raise ValueError("system_prompt is only valid with the legacy prompt form")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be between 0.0 and 2.0")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if self.prompt is not None:
            object.__setattr__(self, "prompt", self.prompt.strip())
        object.__setattr__(self, "messages", tuple(self.messages))
        object.__setattr__(self, "stop", tuple(self.stop))
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model: ModelRef
    reasoning: str | None = None
    reasoning_source: ReasoningSource = ReasoningSource.ABSENT
    latency_ms: float = 0.0
    usage: TokenUsage = field(default_factory=TokenUsage)
    provider_request_id: str | None = None
    finish_reason: str | None = None
    model_revision: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.latency_ms < 0:
            raise ValueError("latency_ms must be non-negative")
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class AttackPrompt:
    attack_id: str
    text: str
    sample_id: str
    system_prompt: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.attack_id:
            raise ValueError("attack_id is required")
        if not self.text:
            raise ValueError("prompt text is required")
        if not self.sample_id:
            raise ValueError("sample_id is required")
        object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class AttackAssessment:
    success: bool
    score: float
    evidence: tuple[str, ...] = ()
    metrics: Mapping[str, float] = field(default_factory=dict)
    explanation: str = ""

    def __post_init__(self) -> None:
        _validate_unit_interval("score", self.score)
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "metrics", dict(self.metrics))
        for key, value in self.metrics.items():
            if not isinstance(value, (int, float)):
                raise ValueError(f"metric {key!r} must be numeric")


@dataclass(frozen=True)
class MonitorOutcome:
    monitor_id: str
    status: MonitorStatus
    confidence: float | None
    explanation: str
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.monitor_id:
            raise ValueError("monitor_id is required")
        _validate_unit_interval("confidence", self.confidence)
        object.__setattr__(self, "details", dict(self.details))

    @property
    def is_evaluable(self) -> bool:
        return self.status in (MonitorStatus.TRIGGERED, MonitorStatus.CLEAN)

    @property
    def triggered(self) -> bool | None:
        if self.status is MonitorStatus.TRIGGERED:
            return True
        if self.status is MonitorStatus.CLEAN:
            return False
        return None


@dataclass(frozen=True)
class EvaluationItem:
    item_id: str
    model: ModelRef
    attack_id: str
    sample_id: str
    status: ItemStatus
    prompt: AttackPrompt | None = None
    response: ModelResponse | None = None
    assessment: AttackAssessment | None = None
    monitors: tuple[MonitorOutcome, ...] = ()
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "monitors", tuple(self.monitors))
        if self.status is ItemStatus.SUCCEEDED:
            if self.prompt is None:
                raise ValueError("succeeded items require a prompt")
            if self.response is None:
                raise ValueError("succeeded items require a response")
            if self.assessment is None:
                raise ValueError("succeeded items require an assessment")
            if self.error is not None:
                raise ValueError("succeeded items must not set error")
        elif self.status in (
            ItemStatus.ATTACK_ERROR,
            ItemStatus.PROVIDER_ERROR,
            ItemStatus.MONITOR_ERROR,
            ItemStatus.BUDGET_EXCEEDED,
        ):
            if not self.error:
                raise ValueError(f"{self.status.value} items require an error message")


@dataclass(frozen=True)
class RunSummary:
    status: RunStatus
    planned: int
    succeeded: int
    failed: int
    cancelled: int
    monitor_excluded: int

    @classmethod
    def from_items(cls, items: Sequence[EvaluationItem]) -> RunSummary:
        planned = len(items)
        succeeded = sum(1 for item in items if item.status is ItemStatus.SUCCEEDED)
        cancelled = sum(1 for item in items if item.status is ItemStatus.CANCELLED)
        failed = planned - succeeded - cancelled
        monitor_excluded = 0
        for item in items:
            if item.status is not ItemStatus.SUCCEEDED:
                continue
            if not item.monitors:
                monitor_excluded += 1
                continue
            if any(not outcome.is_evaluable for outcome in item.monitors):
                monitor_excluded += 1

        if planned == 0 or succeeded == 0:
            status = RunStatus.FAILED
        elif failed == 0 and cancelled == 0:
            status = RunStatus.COMPLETED
        else:
            status = RunStatus.PARTIAL

        return cls(
            status=status,
            planned=planned,
            succeeded=succeeded,
            failed=failed,
            cancelled=cancelled,
            monitor_excluded=monitor_excluded,
        )


@dataclass(frozen=True)
class EvaluationRun:
    run_id: str
    status: RunStatus
    items: tuple[EvaluationItem, ...]
    summary: RunSummary
    started_at: datetime
    completed_at: datetime
    seed: int | None = None
    config_digest: str | None = None
    dataset_digest: str | None = None
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.summary.status is not self.status:
            raise ValueError("run status must match summary status")
