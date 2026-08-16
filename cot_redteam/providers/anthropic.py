"""Anthropic Messages API transport."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

import httpx

from cot_redteam.core.config import ResolvedProviderSettings
from cot_redteam.core.errors import PermanentProviderError, TransientProviderError
from cot_redteam.core.types import (
    GenerationRequest,
    MessageRole,
    ModelRef,
    ModelResponse,
    ReasoningSource,
    TargetCapabilities,
    TokenUsage,
)
from cot_redteam.providers.base import (
    RetryPolicy,
    SleepFn,
    classify_http_status,
    default_sleep,
    parse_retry_after,
    validate_message_capabilities,
)


def _usage_int(usage: Mapping[str, Any], key: str) -> int:
    """Read an integer usage field, treating only ``None`` as missing.

    An explicit ``or 0`` chain would also skip a legitimate ``0``; use an
    explicit ``None`` check instead.
    """
    value = usage.get(key)
    return int(value) if value is not None else 0


class AnthropicProvider:
    def __init__(
        self,
        settings: ResolvedProviderSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: SleepFn | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.capabilities = TargetCapabilities(**settings.capabilities.model_dump())
        self.request_count = 0
        self.last_wire_attempts = 0
        self._sleep = sleep or default_sleep
        self._retry = RetryPolicy(max_retries=settings.max_retries)
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            **settings.headers,
        }
        if settings.api_key is not None:
            headers["x-api-key"] = settings.api_key.get_secret_value()
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=settings.base_url.rstrip("/"),
            headers=headers,
            timeout=settings.timeout,
            transport=transport,
        )

    async def generate(
        self,
        model: ModelRef,
        request: GenerationRequest,
    ) -> ModelResponse:
        system_parts: list[str] = []
        messages: list[dict[str, str]] = []
        if request.messages:
            validate_message_capabilities(request.messages, self.capabilities)
            conversation_started = False
            for message in request.messages:
                if message.name is not None:
                    raise PermanentProviderError(
                        "anthropic text conversations do not support message names"
                    )
                if message.role is MessageRole.SYSTEM:
                    if conversation_started:
                        raise PermanentProviderError(
                            "anthropic system messages must precede conversation messages"
                        )
                    system_parts.append(message.content)
                elif message.role in (MessageRole.USER, MessageRole.ASSISTANT):
                    conversation_started = True
                    messages.append(
                        {
                            "role": message.role.value,
                            "content": message.content,
                        }
                    )
                else:
                    raise PermanentProviderError(
                        f"anthropic text conversations do not support {message.role.value} role"
                    )
        else:
            if request.prompt is None:
                raise PermanentProviderError("legacy prompt is missing")
            messages.append({"role": "user", "content": request.prompt})
            if request.system_prompt:
                system_parts.append(request.system_prompt)

        payload: dict[str, Any] = {
            "model": model.model_id,
            "max_tokens": request.max_tokens,
            # Anthropic rejects temperature > 1.0 while the shared
            # GenerationRequest contract allows 0-2 for other providers;
            # clamp for this transport only.
            "temperature": min(max(request.temperature, 0.0), 1.0),
            "messages": messages,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if request.stop:
            payload["stop_sequences"] = list(request.stop)

        attempt = 0
        wire_attempts = 0
        try:
            while True:
                self.request_count += 1
                wire_attempts += 1
                started = time.perf_counter()
                try:
                    response = await self._client.post("/v1/messages", json=payload)
                except httpx.TimeoutException as exc:
                    if attempt >= self._retry.max_retries:
                        raise TransientProviderError(f"timeout after retries: {exc}") from exc
                    await self._sleep(self._retry.delay_for_attempt(attempt))
                    attempt += 1
                    continue
                except httpx.TransportError as exc:
                    if attempt >= self._retry.max_retries:
                        raise TransientProviderError(f"connection error: {exc}") from exc
                    await self._sleep(self._retry.delay_for_attempt(attempt))
                    attempt += 1
                    continue

                if response.status_code >= 300:
                    err_cls = classify_http_status(response.status_code)
                    if err_cls is TransientProviderError and attempt < self._retry.max_retries:
                        retry_after = parse_retry_after(response.headers.get("Retry-After"))
                        if retry_after is not None:
                            await self._sleep(retry_after)
                        else:
                            await self._sleep(self._retry.delay_for_attempt(attempt))
                        attempt += 1
                        continue
                    raise err_cls(f"anthropic HTTP {response.status_code} for {model}")

                try:
                    data = response.json()
                except ValueError as exc:
                    raise PermanentProviderError("invalid JSON response body") from exc

                try:
                    return self._parse_success(model, data, response, started, wire_attempts)
                except PermanentProviderError:
                    raise
                except Exception as exc:
                    raise PermanentProviderError(f"schema-invalid success payload: {exc}") from exc
        finally:
            self.last_wire_attempts = wire_attempts

    def _parse_success(
        self,
        model: ModelRef,
        data: Mapping[str, Any],
        response: httpx.Response,
        started: float,
        wire_attempts: int,
    ) -> ModelResponse:
        content = data.get("content")
        if not isinstance(content, list) or not content:
            raise PermanentProviderError("missing content blocks")
        text_parts: list[str] = []
        reasoning_parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                text_parts.append(str(block.get("text", "")))
            elif btype in ("thinking", "reasoning"):
                reasoning_parts.append(str(block.get("thinking") or block.get("text") or ""))
        text = "\n\n".join(text_parts)
        if not text and not reasoning_parts:
            raise PermanentProviderError("empty anthropic content")
        reasoning = "\n".join(p for p in reasoning_parts if p) or None
        reasoning_source = ReasoningSource.PROVIDER if reasoning else ReasoningSource.ABSENT
        usage_raw = data.get("usage")
        if not isinstance(usage_raw, Mapping):
            usage_raw = {}
        usage = TokenUsage(
            input_tokens=_usage_int(usage_raw, "input_tokens"),
            output_tokens=_usage_int(usage_raw, "output_tokens"),
            cache_read_input_tokens=_usage_int(usage_raw, "cache_read_input_tokens"),
            cache_creation_input_tokens=_usage_int(usage_raw, "cache_creation_input_tokens"),
        )
        request_id = response.headers.get("request-id") or data.get("id")
        return ModelResponse(
            text=text,
            model=model,
            reasoning=reasoning,
            reasoning_source=reasoning_source,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            usage=usage,
            provider_request_id=str(request_id) if request_id else None,
            finish_reason=str(data.get("stop_reason")) if data.get("stop_reason") else None,
            model_revision=str(data.get("model")) if data.get("model") else None,
            metadata={"provider_kind": "anthropic", "wire_attempts": wire_attempts},
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
