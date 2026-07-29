"""Anthropic provider tests."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from cot_redteam.core.config import ResolvedProviderSettings
from cot_redteam.core.errors import PermanentProviderError, TransientProviderError
from cot_redteam.core.types import GenerationRequest, ModelRef
from cot_redteam.providers.anthropic import AnthropicProvider


def settings() -> ResolvedProviderSettings:
    return ResolvedProviderSettings(
        name="anthropic",
        kind="anthropic",
        base_url="https://api.anthropic.com",
        api_key=SecretStr("sk-test"),
        api_key_env="ANTHROPIC_API_KEY",
        timeout=30.0,
        max_retries=1,
        concurrency=1,
    )


@pytest.mark.asyncio
async def test_anthropic_content_and_usage() -> None:
    payload = {
        "id": "msg_1",
        "model": "claude-3",
        "content": [
            {"type": "thinking", "thinking": "plan"},
            {"type": "text", "text": "hello"},
            {"type": "text", "text": " world"},
        ],
        "usage": {"input_tokens": 3, "output_tokens": 2},
        "stop_reason": "end_turn",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=payload,
            headers={"request-id": "req-a"},
            request=request,
        )

    provider = AnthropicProvider(settings(), transport=httpx.MockTransport(handler))
    response = await provider.generate(
        ModelRef.parse("anthropic:claude-3"),
        GenerationRequest(prompt="hi"),
    )
    assert response.text == "hello world"
    assert response.reasoning == "plan"
    assert response.usage.input_tokens == 3
    assert response.provider_request_id == "req-a"
    await provider.aclose()


@pytest.mark.asyncio
async def test_malformed_success_is_permanent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": []}, request=request)

    provider = AnthropicProvider(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(PermanentProviderError):
        await provider.generate(
            ModelRef.parse("anthropic:claude-3"),
            GenerationRequest(prompt="hi"),
        )
    await provider.aclose()


@pytest.mark.asyncio
async def test_rate_limit_retries_then_fails() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(429, json={"error": "rate"}, request=request)

    async def no_sleep(_s: float) -> None:
        return None

    provider = AnthropicProvider(
        settings(),
        transport=httpx.MockTransport(handler),
        sleep=no_sleep,
    )
    with pytest.raises(TransientProviderError):
        await provider.generate(
            ModelRef.parse("anthropic:claude-3"),
            GenerationRequest(prompt="hi"),
        )
    assert calls["n"] == 2  # initial + 1 retry
    await provider.aclose()
