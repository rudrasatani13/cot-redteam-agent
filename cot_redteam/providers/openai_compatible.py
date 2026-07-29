"""Shared OpenAI-compatible transport for OpenRouter/OpenAI/vLLM/llama.cpp."""

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


class OpenAICompatibleProvider:
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
        headers = {"Content-Type": "application/json", **settings.headers}
        if settings.api_key is not None:
            headers["Authorization"] = f"Bearer {settings.api_key.get_secret_value()}"
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
            "messages": [],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.system_prompt:
            payload["messages"].append({"role": "system", "content": request.system_prompt})
        payload["messages"].append({"role": "user", "content": request.prompt})
        if request.stop:
            payload["stop"] = list(request.stop)

        attempt = 0
        while True:
            self.request_count += 1
            started = time.perf_counter()
            try:
                response = await self._client.post("/chat/completions", json=payload)
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
                    retry_after = response.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        await self._sleep(float(retry_after))
                    else:
                        await self._sleep(self._retry.delay_for_attempt(attempt))
                    attempt += 1
                    continue
                raise err_cls(f"provider HTTP {response.status_code} for {model}")

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
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise PermanentProviderError("missing choices")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if content is None:
            raise PermanentProviderError("missing message content")
        if isinstance(content, list):
            text_parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_parts.append(str(block.get("text", "")))
            text = "".join(text_parts)
        else:
            text = str(content)

        reasoning = None
        reasoning_source = ReasoningSource.ABSENT
        for key in ("reasoning", "reasoning_content", "thinking"):
            if message.get(key):
                reasoning = str(message[key])
                reasoning_source = ReasoningSource.PROVIDER
                break

        usage_raw = data.get("usage") or {}
        usage = TokenUsage(
            input_tokens=int(usage_raw.get("prompt_tokens") or usage_raw.get("input_tokens") or 0),
            output_tokens=int(
                usage_raw.get("completion_tokens") or usage_raw.get("output_tokens") or 0
            ),
        )
        latency_ms = (time.perf_counter() - started) * 1000.0
        request_id = response.headers.get("x-request-id") or response.headers.get("request-id")
        finish_reason = choices[0].get("finish_reason")
        model_revision = data.get("model")
        metadata: dict[str, Any] = {
            "provider_kind": self.settings.kind,
        }
        if isinstance(model_revision, str) and model_revision != model.model_id:
            metadata["returned_model"] = model_revision

        return ModelResponse(
            text=text,
            model=model,
            reasoning=reasoning,
            reasoning_source=reasoning_source,
            latency_ms=latency_ms,
            usage=usage,
            provider_request_id=request_id,
            finish_reason=str(finish_reason) if finish_reason else None,
            model_revision=str(model_revision) if model_revision else None,
            metadata=metadata,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
