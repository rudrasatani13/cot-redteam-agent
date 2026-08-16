"""Regression tests for provider retry caps, status classification, cost."""

from __future__ import annotations

from decimal import Decimal

import pytest

from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import PermanentProviderError, TransientProviderError
from cot_redteam.core.invocation import InvocationService
from cot_redteam.core.types import ModelRef, TokenUsage
from cot_redteam.providers.base import (
    MAX_RETRY_AFTER_SECONDS,
    classify_http_status,
    parse_retry_after,
)
from cot_redteam.providers.factory import ProviderFactory


def test_parse_retry_after_caps_hostile_values() -> None:
    assert parse_retry_after(None) is None
    assert parse_retry_after("not-a-number") is None
    assert parse_retry_after("30") == 30.0
    # A hostile Retry-After of ~11.5 days must clamp to the cap.
    assert parse_retry_after("999999") == MAX_RETRY_AFTER_SECONDS
    assert parse_retry_after("-5") == 0.0


def test_parse_retry_after_handles_http_date_as_unknown() -> None:
    # The HTTP-date form is not silently slept on; it reads as None so the
    # normal jittered backoff applies.
    assert parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT") is None


def test_redirects_are_permanent_not_transient() -> None:
    assert classify_http_status(301) is PermanentProviderError
    assert classify_http_status(307) is PermanentProviderError
    assert classify_http_status(429) is TransientProviderError
    assert classify_http_status(503) is TransientProviderError
    assert classify_http_status(401) is PermanentProviderError


def _pricing_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "providers": {
                "anthropic": {
                    "kind": "anthropic",
                    "api_key_env": "ANTHROPIC_API_KEY",
                    "input_price_per_million": 4.0,
                    "output_price_per_million": 16.0,
                }
            },
            "evaluation": {
                "models": ["anthropic:m"],
                "dataset_path": "pkg:sample.jsonl",
            },
        }
    )


def test_cache_tokens_are_billed_in_cost_estimate() -> None:
    factory = ProviderFactory(_pricing_config())
    service = InvocationService(_pricing_config(), provider_factory=factory)
    model = ModelRef.parse("anthropic:m")
    usage = TokenUsage(
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        cache_read_input_tokens=1_000_000,
        cache_creation_input_tokens=1_000_000,
    )
    cost = service.estimate_cost(model, usage)
    assert cost is not None
    # input 4 + output 16 + cache read 0.4 + cache write 5 = 25.40 USD
    assert cost == Decimal("25.4")


def test_token_usage_total_is_recomputed_when_inconsistent() -> None:
    usage = TokenUsage(input_tokens=30, output_tokens=60, total_tokens=5)
    assert usage.total_tokens == 90
    consistent = TokenUsage(input_tokens=30, output_tokens=60, total_tokens=90)
    assert consistent.total_tokens == 90


def test_confidence_interval_rejects_bools() -> None:
    from cot_redteam.core.types import AttackAssessment

    with pytest.raises(ValueError):
        AttackAssessment(success=True, score=True)  # type: ignore[arg-type]
