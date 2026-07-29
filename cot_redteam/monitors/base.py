"""Public monitor contract and monitor registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import ClassVar

from cot_redteam.core.types import AttackPrompt, JsonValue, ModelResponse, MonitorOutcome
from cot_redteam.plugins.registry import PluginContext, PluginMetadata, Registry


class BaseMonitor(ABC):
    """Engine-facing monitor contract."""

    metadata: ClassVar[PluginMetadata]

    def __init__(
        self,
        config: Mapping[str, JsonValue] | None = None,
        *,
        context: PluginContext | None = None,
    ) -> None:
        self.config: dict[str, JsonValue] = dict(config or {})
        self.context = context or PluginContext()

    @abstractmethod
    async def evaluate(
        self,
        prompt: AttackPrompt,
        response: ModelResponse,
    ) -> MonitorOutcome:
        """Evaluate an attack prompt and model response."""


MonitorRegistry: Registry[BaseMonitor] = Registry("monitor")


def register_monitor(monitor_cls: type[BaseMonitor]) -> type[BaseMonitor]:
    """Class decorator that registers a monitor factory."""

    def factory(
        config: Mapping[str, JsonValue],
        context: PluginContext,
    ) -> BaseMonitor:
        return monitor_cls(config, context=context)

    if monitor_cls.metadata.id not in MonitorRegistry:
        MonitorRegistry.register(monitor_cls.metadata, factory)
    else:
        MonitorRegistry._factories[monitor_cls.metadata.id] = factory  # type: ignore[attr-defined]
        MonitorRegistry._metadata[monitor_cls.metadata.id] = monitor_cls.metadata  # type: ignore[attr-defined]
    return monitor_cls
