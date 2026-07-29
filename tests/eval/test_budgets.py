"""Budget tracker tests."""

from __future__ import annotations

import pytest

from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import BudgetExceededError
from cot_redteam.core.types import TokenUsage
from cot_redteam.eval.budgets import BudgetTracker


@pytest.mark.asyncio
async def test_request_reservation_and_exceed() -> None:
    tracker = BudgetTracker(BudgetSettings(max_requests=1))
    await tracker.reserve_request()
    with pytest.raises(BudgetExceededError):
        await tracker.reserve_request()
    snap = tracker.snapshot()
    assert snap.requests == 1
    assert snap.exceeded is True


@pytest.mark.asyncio
async def test_token_accounting_persists_after_exceed() -> None:
    clock = {"t": 0.0}

    def mono() -> float:
        return clock["t"]

    tracker = BudgetTracker(
        BudgetSettings(max_output_tokens=5),
        clock=mono,
    )
    await tracker.reserve_request()
    await tracker.record_response(TokenUsage(1, 10))
    snap = tracker.snapshot()
    assert snap.output_tokens == 10
    assert snap.exceeded is True


@pytest.mark.asyncio
async def test_elapsed_budget() -> None:
    clock = {"t": 0.0}

    def mono() -> float:
        return clock["t"]

    tracker = BudgetTracker(BudgetSettings(max_elapsed_seconds=1.0), clock=mono)
    clock["t"] = 2.0
    with pytest.raises(BudgetExceededError, match="elapsed"):
        await tracker.reserve_request()
