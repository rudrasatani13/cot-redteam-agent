"""Validated provider construction and model-alias resolution."""

from __future__ import annotations

from collections.abc import Callable, Mapping

import httpx

from cot_redteam.core.config import AppConfig, ResolvedProviderSettings, resolve_provider
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.types import ModelRef
from cot_redteam.providers.anthropic import AnthropicProvider
from cot_redteam.providers.base import Provider
from cot_redteam.providers.openai_compatible import OpenAICompatibleProvider

TransportFactory = Callable[[ResolvedProviderSettings], httpx.AsyncBaseTransport | None]


class ProviderFactory:
    def __init__(
        self,
        config: AppConfig,
        *,
        environ: Mapping[str, str] | None = None,
        transport_factory: TransportFactory | None = None,
    ) -> None:
        self._config = config
        self._environ = environ
        self._transport_factory = transport_factory
        self._cache: dict[str, Provider] = {}

    def resolve_model(self, value: str) -> ModelRef:
        ref = ModelRef.parse(value)
        if ref.provider not in self._config.providers:
            available = ", ".join(sorted(self._config.providers))
            raise ConfigurationError(f"unknown provider {ref.provider!r}. Available: {available}")
        settings = self._config.providers[ref.provider]
        alias = settings.aliases.get(ref.model_id)
        if alias:
            return ModelRef(provider=ref.provider, model_id=alias)
        return ref

    def create(self, model: ModelRef) -> Provider:
        if model.provider in self._cache:
            return self._cache[model.provider]
        resolved = resolve_provider(
            self._config,
            model.provider,
            environ=self._environ,
        )
        transport = None
        if self._transport_factory is not None:
            transport = self._transport_factory(resolved)
        if resolved.kind == "anthropic":
            provider: Provider = AnthropicProvider(resolved, transport=transport)
        else:
            provider = OpenAICompatibleProvider(resolved, transport=transport)
        self._cache[model.provider] = provider
        return provider

    async def aclose(self) -> None:
        for provider in self._cache.values():
            await provider.aclose()
        self._cache.clear()
