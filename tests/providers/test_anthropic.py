"""Anthropic provider tests."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from cot_redteam.core.config import ResolvedProviderSettings
from cot_redteam.core.errors import PermanentProviderError, TransientProviderError
from cot_redteam.core.types import GenerationRequest, Message, MessageRole, ModelRef
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
    # Text blocks are joined with a paragraph separator so adjacent tokens
    # from separate blocks cannot fuse.
    assert response.text == "hello\n\n world"
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


@pytest.mark.asyncio
async def test_anthropic_serializes_supported_conversation_roles() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(__import__("json").loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "msg_1",
                "model": "claude-3",
                "content": [{"type": "text", "text": "ok"}],
                "usage": {},
            },
            request=request,
        )

    provider = AnthropicProvider(settings(), transport=httpx.MockTransport(handler))
    await provider.generate(
        ModelRef.parse("anthropic:claude-3"),
        GenerationRequest(
            messages=(
                Message(role=MessageRole.SYSTEM, content="policy"),
                Message(role=MessageRole.USER, content="question"),
                Message(role=MessageRole.ASSISTANT, content="answer"),
                Message(role=MessageRole.USER, content="follow-up"),
            )
        ),
    )

    assert captured["system"] == "policy"
    assert captured["messages"] == [
        {"role": "user", "content": "question"},
        {"role": "assistant", "content": "answer"},
        {"role": "user", "content": "follow-up"},
    ]
    await provider.aclose()


@pytest.mark.asyncio
async def test_anthropic_rejects_unsupported_developer_role_before_request() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(500, request=request)

    provider = AnthropicProvider(settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(PermanentProviderError, match="developer"):
        await provider.generate(
            ModelRef.parse("anthropic:claude-3"),
            GenerationRequest(
                messages=(
                    Message(role=MessageRole.DEVELOPER, content="unsupported"),
                    Message(role=MessageRole.USER, content="question"),
                )
            ),
        )
    assert calls["count"] == 0
    await provider.aclose()
