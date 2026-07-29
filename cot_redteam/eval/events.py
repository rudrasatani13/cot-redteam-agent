"""Progress events for live CLI / TUI consumers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from cot_redteam.core.types import JsonValue


class RunEventKind(str, Enum):
    RUN_STARTED = "run_started"
    ITEM_STARTED = "item_started"
    ATTEMPT_STARTED = "attempt_started"
    ATTEMPT_FINISHED = "attempt_finished"
    ITEM_FINISHED = "item_finished"
    RUN_FINISHED = "run_finished"
    ACTIVITY = "activity"


@dataclass(frozen=True)
class RunEvent:
    kind: RunEventKind
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    run_id: str | None = None
    item_id: str | None = None
    model: str | None = None
    attack_id: str | None = None
    sample_id: str | None = None
    payload_id: str | None = None
    attempt: int | None = None
    attempts_total: int | None = None
    success: bool | None = None
    status: str | None = None
    message: str = ""
    tokens_input: int | None = None
    tokens_output: int | None = None
    evidence: tuple[str, ...] = ()
    detail: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "detail", dict(self.detail))


ProgressCallback = Callable[[RunEvent], Awaitable[None] | None]


async def emit(callback: ProgressCallback | None, event: RunEvent) -> None:
    if callback is None:
        return
    result = callback(event)
    if result is not None and hasattr(result, "__await__"):
        await result  # type: ignore[misc]
