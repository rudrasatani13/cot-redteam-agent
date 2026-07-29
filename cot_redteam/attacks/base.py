"""Public attack contract and attack registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import ClassVar

from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    DatasetSample,
    JsonValue,
    ModelResponse,
)
from cot_redteam.plugins.registry import PluginContext, PluginMetadata, Registry


class BaseAttack(ABC):
    """Engine-facing attack contract."""

    metadata: ClassVar[PluginMetadata]

    def __init__(self, config: Mapping[str, JsonValue] | None = None) -> None:
        self.config: dict[str, JsonValue] = dict(config or {})

    @abstractmethod
    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        """Create the attack prompt for a dataset sample."""

    @abstractmethod
    def assess(
        self,
        sample: DatasetSample,
        prompt: AttackPrompt,
        response: ModelResponse,
    ) -> AttackAssessment:
        """Assess whether the attack succeeded against the model response."""


AttackRegistry: Registry[BaseAttack] = Registry("attack")


def register_attack(attack_cls: type[BaseAttack]) -> type[BaseAttack]:
    """Class decorator that registers an attack factory."""

    def factory(
        config: Mapping[str, JsonValue],
        context: PluginContext,
    ) -> BaseAttack:
        return attack_cls(config)

    # Idempotent under importlib.reload used by tests.
    if attack_cls.metadata.id not in AttackRegistry:
        AttackRegistry.register(attack_cls.metadata, factory)
    else:
        AttackRegistry._factories[attack_cls.metadata.id] = factory  # type: ignore[attr-defined]
        AttackRegistry._metadata[attack_cls.metadata.id] = attack_cls.metadata  # type: ignore[attr-defined]
    return attack_cls
