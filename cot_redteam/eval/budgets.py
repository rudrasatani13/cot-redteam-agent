"""Request, token, elapsed-time, and cost accounting."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal

from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import BudgetExceededError
from cot_redteam.core.types import TokenUsage

Monotonic = Callable[[], float]


@dataclass(frozen=True)
class BudgetSnapshot:
    requests: int
    input_tokens: int
    output_tokens: int
    estimated_cost: Decimal
    elapsed_seconds: float
    exceeded: bool


class BudgetTracker:
    def __init__(
        self,
        settings: BudgetSettings,
        *,
        clock: Monotonic | None = None,
    ) -> None:
        self.settings = settings
        self._clock = clock or time.monotonic
        self._started = self._clock()
        self._lock = asyncio.Lock()
        self._requests = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._estimated_cost = Decimal("0")
        self._exceeded = False

    def _elapsed(self) -> float:
        return self._clock() - self._started

    def _check_limits_unlocked(self) -> None:
        s = self.settings
        if s.max_elapsed_seconds is not None and self._elapsed() >= s.max_elapsed_seconds:
            self._exceeded = True
            raise BudgetExceededError("max_elapsed_seconds exceeded")
        if s.max_requests is not None and self._requests >= s.max_requests:
            self._exceeded = True
            raise BudgetExceededError("max_requests exceeded")
        if s.max_input_tokens is not None and self._input_tokens >= s.max_input_tokens:
            self._exceeded = True
            raise BudgetExceededError("max_input_tokens exceeded")
        if s.max_output_tokens is not None and self._output_tokens >= s.max_output_tokens:
            self._exceeded = True
            raise BudgetExceededError("max_output_tokens exceeded")
        if s.max_estimated_cost is not None and self._estimated_cost >= Decimal(
            str(s.max_estimated_cost)
        ):
            self._exceeded = True
            raise BudgetExceededError("max_estimated_cost exceeded")

    async def reserve_request(self) -> None:
        async with self._lock:
            if self._exceeded:
                raise BudgetExceededError("budget already exceeded")
            # _check_limits_unlocked already rejects when the request count
            # is at (or above) max_requests, so reserving one more here can
            # never exceed the limit.
            self._check_limits_unlocked()
            # Reserve by incrementing request count before the call.
            self._requests += 1

    async def record_response(
        self,
        usage: TokenUsage,
        estimated_cost: Decimal | None = None,
    ) -> None:
        async with self._lock:
            self._input_tokens += usage.input_tokens
            self._output_tokens += usage.output_tokens
            if estimated_cost is not None:
                self._estimated_cost += estimated_cost
            try:
                self._check_limits_unlocked()
            except BudgetExceededError:
                # Commit accounting even when limits are now exceeded.
                self._exceeded = True

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            requests=self._requests,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            estimated_cost=self._estimated_cost,
            elapsed_seconds=self._elapsed(),
            exceeded=self._exceeded,
        )
