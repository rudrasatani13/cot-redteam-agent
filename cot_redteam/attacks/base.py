"""Public attack contract and attack registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
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

    def create_prompts(self, sample: DatasetSample) -> Sequence[AttackPrompt]:
        """Return ordered payload variants for adaptive multi-attempt evaluation.

        Default: a single prompt. Adaptive attacks override this to expose a
        full payload bank so the engine can try the next prompt when one fails.
        """
        return (self.create_prompt(sample),)

    @property
    def stop_on_success(self) -> bool:
        """If True, the engine stops trying further payloads after a success."""
        raw = self.config.get("stop_on_success", True)
        return bool(raw)

    @property
    def is_agentic(self) -> bool:
        """If True, the engine invents further prompts after bank exhaustion."""
        return False

    @property
    def max_attempts(self) -> int | None:
        """Optional hard cap for agentic / adaptive multi-attempt loops."""
        raw = self.config.get("max_attempts")
        if raw is None:
            return None
        return int(raw)

    def next_prompt_after_failure(
        self,
        sample: DatasetSample,
        history: Sequence[Mapping[str, JsonValue]],
        *,
        max_attempts: int | None = None,
    ) -> AttackPrompt | None:
        """Return the next invented prompt after a failed attempt, or None.

        Non-agentic attacks leave this as a no-op. Agentic attacks use the
        failure history (defense class, prior payload ids) to pick a new technique.
        """
        del sample, history, max_attempts
        return None

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
