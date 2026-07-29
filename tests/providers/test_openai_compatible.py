"""OpenAI-compatible provider tests."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr

from cot_redteam.core.config import ResolvedProviderSettings, TargetCapabilitySettings
from cot_redteam.core.errors import PermanentProviderError
from cot_redteam.core.types import GenerationRequest, Message, MessageRole, ModelRef
from cot_redteam.providers.openai_compatible import OpenAICompatibleProvider

MODEL = ModelRef.parse("openrouter:model/x")


def settings() -> ResolvedProviderSettings:
    return ResolvedProviderSettings(
        name="openrouter",
        kind="openrouter",
        base_url="https://openrouter.ai/api/v1",
        api_key=SecretStr("test-key"),
        api_key_env="OPENROUTER_API_KEY",
        timeout=30.0,
        max_retries=2,
        concurrency=2,
        capabilities=TargetCapabilitySettings(
            system_role=True,
            developer_role=True,
            multi_turn=True,
        ),
    )


def request() -> GenerationRequest:
    return GenerationRequest(prompt="hi", temperature=0.0, max_tokens=16)


def mock_transport(payload: dict, status: int = 200, headers: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            json=payload,
            headers=headers or {"x-request-id": "req-123"},
            request=request,
        )

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_openai_compatible_provider_preserves_usage_and_request_id() -> None:
    response_payload = {
        "id": "chatcmpl-1",
        "model": "model/x",
        "choices": [
            {
                "message": {"role": "assistant", "content": "answer"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 12, "completion_tokens": 7},
    }
    provider = OpenAICompatibleProvider(
        settings(),
        transport=mock_transport(response_payload),
        sleep=lambda _s: __import__("asyncio").sleep(0),
    )
    response = await provider.generate(MODEL, request())
    assert response.text == "answer"
    assert response.usage.input_tokens == 12
    assert response.usage.output_tokens == 7
    assert response.provider_request_id == "req-123"
    await provider.aclose()


@pytest.mark.asyncio
async def test_permanent_401_is_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, json={"error": "nope"}, request=request)

    provider = OpenAICompatibleProvider(
        settings(),
        transport=httpx.MockTransport(handler),
        sleep=lambda _s: __import__("asyncio").sleep(0),
    )
    with pytest.raises(PermanentProviderError):
        await provider.generate(MODEL, request())
    assert calls["n"] == 1
    assert provider.request_count == 1
    await provider.aclose()


@pytest.mark.asyncio
async def test_openai_compatible_serializes_ordered_message_roles() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(__import__("json").loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "model/x",
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "usage": {},
            },
            request=request,
        )

    provider = OpenAICompatibleProvider(
        settings(),
        transport=httpx.MockTransport(handler),
    )
    await provider.generate(
        MODEL,
        GenerationRequest(
            messages=(
                Message(role=MessageRole.SYSTEM, content="policy"),
                Message(role=MessageRole.DEVELOPER, content="developer rule"),
                Message(role=MessageRole.USER, content="question"),
                Message(role=MessageRole.ASSISTANT, content="first answer"),
                Message(role=MessageRole.USER, content="follow-up"),
            ),
            temperature=0.0,
            max_tokens=16,
        ),
    )

    assert captured["messages"] == [
        {"role": "system", "content": "policy"},
        {"role": "developer", "content": "developer rule"},
        {"role": "user", "content": "question"},
        {"role": "assistant", "content": "first answer"},
        {"role": "user", "content": "follow-up"},
    ]
    await provider.aclose()


@pytest.mark.asyncio
async def test_openai_compatible_rejects_role_missing_from_declared_capabilities() -> None:
    restricted = settings().model_copy(
        update={
            "capabilities": TargetCapabilitySettings(
                system_role=True,
                developer_role=False,
                multi_turn=True,
            )
        }
    )
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(500, request=request)

    provider = OpenAICompatibleProvider(
        restricted,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PermanentProviderError, match="developer_role"):
        await provider.generate(
            MODEL,
            GenerationRequest(
                messages=(
                    Message(role=MessageRole.DEVELOPER, content="rule"),
                    Message(role=MessageRole.USER, content="question"),
                )
            ),
        )
    assert calls["count"] == 0
    await provider.aclose()
