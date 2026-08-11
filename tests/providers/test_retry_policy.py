"""Retry backoff delay cap tests."""

from __future__ import annotations

import random

from cot_redteam.providers.base import RetryPolicy


def test_delay_never_exceeds_max_delay_with_jitter() -> None:
    """Jitter applies inside the cap: delays must stay <= max_delay_seconds."""
    random.seed(1)
    policy = RetryPolicy(max_retries=10, base_delay_seconds=0.25, max_delay_seconds=8.0, jitter=0.1)
    for attempt in range(0, 12):
        delay = policy.delay_for_attempt(attempt)
        assert 0.0 <= delay <= policy.max_delay_seconds, (attempt, delay)


def test_delay_scales_exponentially_before_cap() -> None:
    random.seed(2)
    policy = RetryPolicy(max_retries=10, base_delay_seconds=0.5, max_delay_seconds=8.0, jitter=0.0)
    assert policy.delay_for_attempt(0) == 0.5
    assert policy.delay_for_attempt(1) == 1.0
    assert policy.delay_for_attempt(4) == 8.0  # 0.5 * 16 capped
    assert policy.delay_for_attempt(10) == 8.0
