"""Provider protocol, retry policy, and lifecycle helpers."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from cot_redteam.core.errors import PermanentProviderError, TransientProviderError
from cot_redteam.core.types import GenerationRequest, ModelRef, ModelResponse

SleepFn = Callable[[float], Awaitable[None]]


class Provider(Protocol):
    async def generate(
        self,
        model: ModelRef,
        request: GenerationRequest,
    ) -> ModelResponse: ...

    async def aclose(self) -> None: ...


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
