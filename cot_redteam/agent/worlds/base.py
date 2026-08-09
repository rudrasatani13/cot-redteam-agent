"""World snapshot contract and tool specification for the agent engine.

A ``WorldSnapshot`` is the immutable pre/post state a deterministic oracle
evaluates. The digest is computed over the full state so any observable
mutation changes it.

``ToolSpec`` describes one simulated tool: its name/version, an argument
validator, an async handler, and the effect classification oracles use.
"""

from __future__ import annotations

import copy
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cot_redteam.core.serialization import canonical_json, sha256_text
from cot_redteam.core.types import JsonValue

ArgumentValidator = Callable[[Mapping[str, JsonValue]], None]
ToolHandler = Callable[[Mapping[str, JsonValue]], Awaitable[JsonValue]]


def state_digest(world_id: str, world_version: str, state: Mapping[str, Any]) -> str:
    """Deterministic digest over the complete world state."""
    return sha256_text(
        canonical_json({"world_id": world_id, "world_version": world_version, "state": state})
    )


class WorldSnapshot(BaseModel):
    """Immutable world state at a point in time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    world_id: str
    world_version: str
    state: dict[str, JsonValue] = Field(default_factory=dict)
    digest: str = ""

    def model_post_init(self, __context: object) -> None:
        if not self.digest:
            object.__setattr__(
                self,
                "digest",
                state_digest(self.world_id, self.world_version, self.state),
            )


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    description: str
    validate: ArgumentValidator
    handler: ToolHandler
    #: Effects classification used by oracles.
    effect_kind: str = "read"
    resource: str = ""


def validate_args(
    required: tuple[str, ...],
    types: dict[str, str] | None = None,
) -> ArgumentValidator:
    """Build a minimal declarative argument validator (string/integer/
    object/array/boolean with required checks)."""
    expected_types = types or {}

    def validate(arguments: Mapping[str, JsonValue]) -> None:
        for name in required:
            if name not in arguments:
                raise ValueError(f"missing required argument {name!r}")
        for name, expected in expected_types.items():
            if name not in arguments:
                continue
            value = arguments[name]
            if expected == "string" and not isinstance(value, str):
                raise ValueError(f"argument {name!r} must be a string")
            if expected == "integer" and not isinstance(value, int):
                raise ValueError(f"argument {name!r} must be an integer")
            if expected == "object" and not isinstance(value, dict):
                raise ValueError(f"argument {name!r} must be an object")
            if expected == "array" and not isinstance(value, list):
                raise ValueError(f"argument {name!r} must be an array")
            if expected == "boolean" and not isinstance(value, bool):
                raise ValueError(f"argument {name!r} must be a boolean")

    return validate


class BaseWorld(ABC):
    """Contract every simulated v0.6 world satisfies."""

    world_id: str
    world_version: str
    #: Fixed tool registry: tool name -> ToolSpec. Deny-by-default gateways
    #: only ever dispatch through here.
    tools: dict[str, ToolSpec] = {}

    def snapshot(self) -> WorldSnapshot:
        """Return the current immutable world state (default: full deep copy)."""
        return WorldSnapshot(
            world_id=self.world_id,
            world_version=self.world_version,
            state=copy.deepcopy(self.snapshot_state()),
        )

    def reset(self) -> None:
        """Restore the initial fixture state; no state carries between trials."""
        self._restore_initial()

    @abstractmethod
    def snapshot_state(self) -> dict[str, JsonValue]:
        """Return the current state as JSON-compatible data."""

    @abstractmethod
    def _restore_initial(self) -> None:
        """Restore the initial state captured at construction."""
