"""Provider protocol, retry policy, and lifecycle helpers."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from cot_redteam.core.errors import PermanentProviderError, TransientProviderError
from cot_redteam.core.types import (
    GenerationRequest,
    Message,
    MessageRole,
    ModelRef,
    ModelResponse,
    TargetCapabilities,
)

SleepFn = Callable[[float], Awaitable[None]]


class Provider(Protocol):
    capabilities: TargetCapabilities

    async def generate(
        self,
        model: ModelRef,
        request: GenerationRequest,
    ) -> ModelResponse: ...

    async def aclose(self) -> None: ...


def validate_message_capabilities(
    messages: tuple[Message, ...],
    capabilities: TargetCapabilities,
) -> None:
    """Reject message histories that exceed declared provider capabilities."""
    missing: list[str] = []
    roles = {message.role for message in messages}
    if MessageRole.SYSTEM in roles and not capabilities.system_role:
        missing.append("system_role")
    if MessageRole.DEVELOPER in roles and not capabilities.developer_role:
        missing.append("developer_role")
    if MessageRole.TOOL in roles and not capabilities.tool_role:
        missing.append("tool_role")
    user_count = sum(1 for message in messages if message.role is MessageRole.USER)
    if (MessageRole.ASSISTANT in roles or user_count > 1) and not capabilities.multi_turn:
        missing.append("multi_turn")
    if missing:
        raise PermanentProviderError(
            "request requires unsupported target capabilities: " + ", ".join(missing)
        )


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 8.0
    jitter: float = 0.1

    def delay_for_attempt(self, attempt: int) -> float:
        delay = min(self.max_delay_seconds, self.base_delay_seconds * (2**attempt))
        if self.jitter:
            delay *= 1.0 + random.uniform(-self.jitter, self.jitter)
        return float(max(0.0, delay))


async def default_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def classify_http_status(status_code: int) -> type[Exception]:
    if status_code == 429 or status_code >= 500:
        return TransientProviderError
    if 400 <= status_code < 500:
        return PermanentProviderError
    return TransientProviderError
