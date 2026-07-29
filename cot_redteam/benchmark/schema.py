"""Strict declarative schema for benchmark scenarios and policy profiles."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cot_redteam.benchmark.templates import validate_template
from cot_redteam.core.serialization import canonical_json, sha256_text
from cot_redteam.core.types import MessageRole, MessageTrust, TargetRequirements

StableId = str
CapabilityName = Literal[
    "system_role",
    "developer_role",
    "multi_turn",
    "tool_role",
    "visible_reasoning",
    "native_seed",
]
ObjectiveType = Literal[
    "disclose_canary",
    "disclose_protected_text",
    "emit_rogue_string",
    "violate_output_constraint",
    "follow_lower_trust_instruction",
    "complete_benign_task",
    "avoid_false_refusal",
]

_STABLE_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_ATTACK_VARIABLES = frozenset({"task", "rogue_string", "untrusted_content", "label"})
_POLICY_VARIABLES = frozenset({"canary", "task", "untrusted_content_label"})
_MAX_TEMPLATE_LENGTH = 32_000


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _validate_stable_id(value: str) -> str:
    value = value.strip()
    if not _STABLE_ID.fullmatch(value):
        raise ValueError("must be a lowercase stable identifier")
    return value


class SourceSpec(StrictModel):
    citation: str | None = Field(default=None, max_length=1000)
    url: str | None = Field(default=None, max_length=2000)
    license: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def _require_attribution(self) -> SourceSpec:
        if not (self.citation and self.citation.strip()) and not (self.url and self.url.strip()):
            raise ValueError("source requires a citation or url")
        return self


class TaskSpec(StrictModel):
    prompt: str = Field(min_length=1, max_length=_MAX_TEMPLATE_LENGTH)
    expected_output: str | None = Field(default=None, max_length=_MAX_TEMPLATE_LENGTH)


class ObjectiveSpec(StrictModel):
    type: ObjectiveType
    target: str | None = Field(default=None, max_length=4000)
    parameters: dict[str, Any] = Field(default_factory=dict)


class MessageTemplateSpec(StrictModel):
    role: MessageRole
    content: str = Field(min_length=1, max_length=_MAX_TEMPLATE_LENGTH)
    trust: MessageTrust
    name: str | None = Field(default=None, min_length=1, max_length=100)
    source: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("content")
    @classmethod
    def _safe_content_template(cls, value: str) -> str:
        try:
            validate_template(value, allowed_variables=_ATTACK_VARIABLES)
        except ValueError as exc:
            raise ValueError(f"invalid message template: {exc}") from exc
        return value


class ScorerSpec(StrictModel):
    id: StableId
    config: dict[str, Any] = Field(default_factory=dict)

    _valid_id = field_validator("id")(_validate_stable_id)


class ScenarioSpec(StrictModel):
    version: Literal[1] = 1
    id: StableId
    title: str = Field(min_length=1, max_length=200)
    family: StableId
    channel: StableId
    task: TaskSpec
    objective: ObjectiveSpec
    steps: tuple[MessageTemplateSpec, ...] = Field(min_length=1, max_length=20)
    required_capabilities: tuple[CapabilityName, ...] = ()
    policy_ids: tuple[StableId, ...] = ()
    technique_ids: tuple[StableId, ...] = ()
    transformation_ids: tuple[StableId, ...] = ()
    scorers: tuple[ScorerSpec, ...] = Field(min_length=1, max_length=20)
    source: SourceSpec
    tags: tuple[str, ...] = Field(default=(), max_length=30)
    difficulty: Literal["basic", "intermediate", "advanced"] = "basic"

    _valid_id = field_validator("id")(_validate_stable_id)
    _valid_family = field_validator("family")(_validate_stable_id)
    _valid_channel = field_validator("channel")(_validate_stable_id)

    @field_validator("policy_ids", "technique_ids", "transformation_ids")
    @classmethod
    def _valid_reference_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_validate_stable_id(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("references must not contain duplicates")
        return normalized

    @field_validator("required_capabilities")
    @classmethod
    def _unique_capabilities(cls, values: tuple[CapabilityName, ...]) -> tuple[CapabilityName, ...]:
        if len(values) != len(set(values)):
            raise ValueError("required capabilities must not contain duplicates")
        return values

    @field_validator("tags")
    @classmethod
    def _valid_tags(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            tag = value.strip()
            if not tag or len(tag) > 60:
                raise ValueError("tags must be non-empty and at most 60 characters")
            normalized.append(tag)
        if len(normalized) != len(set(normalized)):
            raise ValueError("tags must not contain duplicates")
        return tuple(normalized)

    @property
    def requirements(self) -> TargetRequirements:
        selected = set(self.required_capabilities)
        return TargetRequirements(
            system_role="system_role" in selected,
            developer_role="developer_role" in selected,
            multi_turn="multi_turn" in selected,
            tool_role="tool_role" in selected,
            visible_reasoning="visible_reasoning" in selected,
            native_seed="native_seed" in selected,
        )

    @property
    def digest(self) -> str:
        return sha256_text(canonical_json(self.model_dump(mode="python")))

    @property
    def content_digest(self) -> str:
        return sha256_text(canonical_json(self.model_dump(mode="python", exclude={"id"})))


class PolicySpec(StrictModel):
    id: StableId
    version: str
    instructions: str = Field(min_length=1, max_length=_MAX_TEMPLATE_LENGTH)
    allowed_variables: tuple[str, ...] = ()
    description: str = Field(default="", max_length=1000)

    _valid_id = field_validator("id")(_validate_stable_id)

    @field_validator("version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("version must use MAJOR.MINOR.PATCH")
        return value

    @field_validator("allowed_variables")
    @classmethod
    def _valid_variables(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        unknown = set(values) - _POLICY_VARIABLES
        if unknown:
            raise ValueError(f"unsupported policy variables: {sorted(unknown)}")
        if len(values) != len(set(values)):
            raise ValueError("allowed variables must not contain duplicates")
        return values

    @model_validator(mode="after")
    def _safe_instructions(self) -> PolicySpec:
        try:
            validate_template(
                self.instructions,
                allowed_variables=frozenset(self.allowed_variables),
            )
        except ValueError as exc:
            raise ValueError(f"invalid policy template: {exc}") from exc
        return self
