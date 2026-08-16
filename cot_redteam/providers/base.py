"""Provider protocol, retry policy, and lifecycle helpers.

Wire-attempt convention: providers retry transient transport failures
internally, so one logical ``generate`` call may issue several HTTP
requests (up to ``1 + max_retries``). Every request sent is counted in
the cumulative ``request_count`` attribute, and the per-call count for
the most recent ``generate`` call is exposed as ``last_wire_attempts``
(and as ``wire_attempts`` in the success response metadata) so the
invocation boundary can account for actual wire traffic.
"""

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

# Server-supplied Retry-After delays are untrusted; never sleep longer
# than this regardless of what the header claims.
MAX_RETRY_AFTER_SECONDS = 60.0


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
        # Jitter applies inside the cap so delays never exceed
        # max_delay_seconds (previously the cap was applied before jitter,
        # letting backoff overshoot by up to jitter%).
        delay = self.base_delay_seconds * (2**attempt)
        if self.jitter:
            delay *= 1.0 + random.uniform(-self.jitter, self.jitter)
        return float(min(self.max_delay_seconds, max(0.0, delay)))


async def default_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def parse_retry_after(value: str | None) -> float | None:
    """Parse a ``Retry-After`` header value (delta-seconds form).

    Returns ``None`` when the header is absent or unusable (empty,
    non-numeric, the HTTP-date form, NaN, or infinite) so callers fall
    back to their policy backoff. Otherwise the delay is clamped to
    ``[0.0, MAX_RETRY_AFTER_SECONDS]`` so a hostile or misbehaving server
    cannot stall the run.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        return None
    if seconds != seconds or seconds in (float("inf"), float("-inf")):
        return None
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)


def classify_http_status(status_code: int) -> type[Exception]:
    if status_code == 429 or status_code >= 500:
        return TransientProviderError
    if 300 <= status_code < 500:
        # Redirects (3xx) are permanent configuration problems such as a
        # wrong base URL; retrying them can never succeed.
        return PermanentProviderError
    return TransientProviderError
