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
    ModelRef,
    ModelResponse,
    ReasoningSource,
    TokenUsage,
)
from cot_redteam.providers.base import RetryPolicy, SleepFn, classify_http_status, default_sleep


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
        self.request_count = 0
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
        payload: dict[str, Any] = {
            "model": model.model_id,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [{"role": "user", "content": request.prompt}],
        }
        if request.system_prompt:
            payload["system"] = request.system_prompt
        if request.stop:
            payload["stop_sequences"] = list(request.stop)

        attempt = 0
        while True:
            self.request_count += 1
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

            if response.status_code >= 400:
                err_cls = classify_http_status(response.status_code)
                if err_cls is TransientProviderError and attempt < self._retry.max_retries:
                    await self._sleep(self._retry.delay_for_attempt(attempt))
                    attempt += 1
                    continue
                raise err_cls(f"anthropic HTTP {response.status_code} for {model}")

            try:
                data = response.json()
            except ValueError as exc:
                raise PermanentProviderError("invalid JSON response body") from exc

            try:
                return self._parse_success(model, data, response, started)
            except PermanentProviderError:
                raise
            except Exception as exc:
                raise PermanentProviderError(f"schema-invalid success payload: {exc}") from exc

    def _parse_success(
        self,
        model: ModelRef,
        data: Mapping[str, Any],
        response: httpx.Response,
        started: float,
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
        text = "".join(text_parts)
        if not text and not reasoning_parts:
            raise PermanentProviderError("empty anthropic content")
        reasoning = "\n".join(p for p in reasoning_parts if p) or None
        reasoning_source = ReasoningSource.PROVIDER if reasoning else ReasoningSource.ABSENT
        usage_raw = data.get("usage") or {}
        usage = TokenUsage(
            input_tokens=int(usage_raw.get("input_tokens") or 0),
            output_tokens=int(usage_raw.get("output_tokens") or 0),
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
            metadata={"provider_kind": "anthropic"},
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
