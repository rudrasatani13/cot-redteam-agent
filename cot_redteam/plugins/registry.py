"""Generic duplicate-safe plugin registry."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Generic, TypeVar

from cot_redteam.core.errors import PluginError
from cot_redteam.core.types import JsonValue

T = TypeVar("T")

ProviderResolver = Callable[[str], object]


@dataclass(frozen=True)
class PluginMetadata:
    id: str
    version: str
    description: str
    category: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginContext:
    provider_resolver: ProviderResolver | None = None


class Registry(Generic[T]):
    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._factories: dict[str, Callable[[Mapping[str, JsonValue], PluginContext], T]] = {}
        self._metadata: dict[str, PluginMetadata] = {}

    def register(
        self,
        metadata: PluginMetadata,
        factory: Callable[[Mapping[str, JsonValue], PluginContext], T],
    ) -> None:
        if metadata.id in self._factories:
            raise PluginError(f"duplicate {self._kind} plugin: {metadata.id}")
        self._factories[metadata.id] = factory
        self._metadata[metadata.id] = metadata

    def create(
        self,
        plugin_id: str,
        config: Mapping[str, JsonValue] | None = None,
        context: PluginContext | None = None,
    ) -> T:
        if plugin_id not in self._factories:
            available = ", ".join(sorted(self._factories)) or "(none)"
            raise PluginError(f"unknown {self._kind} plugin {plugin_id!r}. Available: {available}")
        return self._factories[plugin_id](dict(config or {}), context or PluginContext())

    def metadata(self) -> tuple[PluginMetadata, ...]:
        return tuple(self._metadata[k] for k in sorted(self._metadata))

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))

    def clear(self) -> None:
        self._factories.clear()
        self._metadata.clear()

    def __contains__(self, plugin_id: str) -> bool:
        return plugin_id in self._factories
