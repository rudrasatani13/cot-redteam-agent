"""Strict Pydantic configuration, YAML loading, secret resolution, and redaction."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.serialization import canonical_json
from cot_redteam.core.types import ModelRef


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class GlobalSettings(StrictModel):
    seed: int = 42
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    output_dir: str = "./results"
    concurrency: int = Field(default=4, ge=1)


class ProviderSettings(StrictModel):
    kind: Literal["openrouter", "openai", "anthropic", "vllm", "llamacpp"]
    base_url: str | None = None
    api_key_env: str | None = None
    timeout: float = Field(default=120.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    concurrency: int = Field(default=4, ge=1)
    aliases: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    input_price_per_million: float | None = Field(default=None, ge=0)
    output_price_per_million: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _remote_requires_api_key_env(self) -> ProviderSettings:
        if self.kind in ("vllm", "llamacpp"):
            return self
        if not self.api_key_env:
            raise ValueError(f"remote provider kind {self.kind!r} requires api_key_env")
        return self


class BudgetSettings(StrictModel):
    max_requests: int | None = Field(default=None, ge=1)
    max_input_tokens: int | None = Field(default=None, ge=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    max_elapsed_seconds: float | None = Field(default=None, gt=0)
    max_estimated_cost: float | None = Field(default=None, ge=0)


class EvaluationSettings(StrictModel):
    models: list[str] = Field(default_factory=list)
    attacks: list[str] = Field(default_factory=list)
    monitors: list[str] = Field(default_factory=list)
    dataset_path: str = "cot_redteam/eval/datasets/sample.jsonl"
    sample_count: int | None = Field(default=None, ge=1)
    sample_ids: list[str] | None = None
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1)
    cot_delimiters: list[str] = Field(
        default_factory=lambda: ["<think>", "</think>", "<reasoning>", "</reasoning>"]
    )
    budgets: BudgetSettings = Field(default_factory=BudgetSettings)
    monitor_config: dict[str, dict[str, Any]] = Field(default_factory=dict)
    attack_config: dict[str, dict[str, Any]] = Field(default_factory=dict)
    retain_prompts: bool = True
    retain_responses: bool = True
    retain_reasoning: bool = True

    @field_validator("models", "attacks", "monitors")
    @classmethod
    def _non_empty_strings(cls, value: list[str]) -> list[str]:
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("entries must be non-empty strings")
        return value


class ArtifactSettings(StrictModel):
    root: str = "./artifacts"
    save_prompts: bool = True
    save_responses: bool = True
    save_reasoning: bool = True


class StorageSettings(StrictModel):
    path: str = "./results/cot_redteam.db"


class ReportingSettings(StrictModel):
    formats: list[Literal["markdown", "csv", "latex"]] = Field(
        default_factory=lambda: ["markdown"]  # type: ignore[arg-type,return-value]
    )
    output_dir: str = "./results/reports"


class GenerativeSettings(StrictModel):
    generator_model: str = "openrouter:anthropic/claude-3.5-sonnet"
    target_models: list[str] = Field(default_factory=list)
    evolution_rounds: int = Field(default=3, ge=1)
    population_size: int = Field(default=5, ge=1)
    max_generation_attempts: int = Field(default=20, ge=1)
    mutation_rate: float = Field(default=0.3, ge=0.0, le=1.0)
    crossover_rate: float = Field(default=0.5, ge=0.0, le=1.0)
    fitness_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "attack_success": 0.4,
            "evasion": 0.4,
            "novelty": 0.2,
        }
    )
    archive_path: str = "./results/generative_archive.json"


class AppConfig(StrictModel):
    version: Literal[2] = 2
    global_: GlobalSettings = Field(default_factory=GlobalSettings, alias="global")
    providers: dict[str, ProviderSettings]
    evaluation: EvaluationSettings
    artifacts: ArtifactSettings = Field(default_factory=ArtifactSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)
    generative: GenerativeSettings = Field(default_factory=GenerativeSettings)

    @model_validator(mode="after")
    def _providers_non_empty(self) -> AppConfig:
        if not self.providers:
            raise ValueError("providers must not be empty")
        for model_ref in self.evaluation.models:
            try:
                ref = ModelRef.parse(model_ref)
            except ValueError as exc:
                raise ValueError(f"invalid model reference {model_ref!r}") from exc
            if ref.provider not in self.providers:
                raise ValueError(f"evaluation model provider {ref.provider!r} is not configured")
        return self


class ResolvedProviderSettings(StrictModel):
    name: str
    kind: Literal["openrouter", "openai", "anthropic", "vllm", "llamacpp"]
    base_url: str
    api_key: SecretStr | None = None
    api_key_env: str | None = None
    timeout: float
    max_retries: int
    concurrency: int
    aliases: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None

    def __repr__(self) -> str:
        return (
            f"ResolvedProviderSettings(name={self.name!r}, kind={self.kind!r}, "
            f"base_url={self.base_url!r}, api_key=***REDACTED***, "
            f"api_key_env={self.api_key_env!r})"
        )


DEFAULT_BASE_URLS: dict[str, str] = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "vllm": "http://localhost:8000/v1",
    "llamacpp": "http://localhost:8080/v1",
}

DOCUMENTED_OVERRIDES = {
    "evaluation.models",
    "evaluation.attacks",
    "evaluation.monitors",
    "evaluation.dataset_path",
    "evaluation.sample_count",
    "evaluation.temperature",
    "evaluation.max_tokens",
    "global.seed",
    "global.concurrency",
    "global.output_dir",
    "storage.path",
    "artifacts.root",
    "reporting.output_dir",
    "reporting.formats",
}


def _set_nested(data: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cursor: dict[str, Any] = data
    for part in parts[:-1]:
        next_val = cursor.get(part)
        if not isinstance(next_val, dict):
            next_val = {}
            cursor[part] = next_val
        cursor = next_val
    cursor[parts[-1]] = value


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"unable to read config {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in {path}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigurationError(f"config root must be a mapping: {path}")
    return data


def load_config(
    path: str | Path,
    *,
    overrides: Mapping[str, Any] | None = None,
) -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigurationError(f"config file not found: {config_path}")
    data = _load_yaml(config_path)
    if overrides:
        for key, value in overrides.items():
            if key not in DOCUMENTED_OVERRIDES:
                raise ConfigurationError(f"unsupported override key: {key}")
            _set_nested(data, key, value)
    try:
        return AppConfig.model_validate(data)
    except Exception as exc:
        message = str(exc)
        for secret_marker in ("api_key", "secret", "token", "password"):
            if secret_marker in message.lower() and "api_key_env" not in message:
                message = "configuration validation failed"
                break
        raise ConfigurationError(f"invalid configuration: {message}") from exc


def resolve_provider(
    config: AppConfig,
    provider_name: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> ResolvedProviderSettings:
    env = environ if environ is not None else os.environ
    if provider_name not in config.providers:
        available = ", ".join(sorted(config.providers))
        raise ConfigurationError(f"unknown provider {provider_name!r}. Available: {available}")
    settings = config.providers[provider_name]
    api_key: SecretStr | None = None
    if settings.api_key_env:
        value = env.get(settings.api_key_env)
        if not value:
            if settings.kind in ("vllm", "llamacpp"):
                api_key = None
            else:
                raise ConfigurationError(
                    f"missing required environment variable {settings.api_key_env}"
                )
        else:
            api_key = SecretStr(value)
    elif settings.kind not in ("vllm", "llamacpp"):
        raise ConfigurationError(f"remote provider {provider_name!r} requires api_key_env")

    base_url = settings.base_url or DEFAULT_BASE_URLS[settings.kind]
    return ResolvedProviderSettings(
        name=provider_name,
        kind=settings.kind,
        base_url=base_url,
        api_key=api_key,
        api_key_env=settings.api_key_env,
        timeout=settings.timeout,
        max_retries=settings.max_retries,
        concurrency=settings.concurrency,
        aliases=dict(settings.aliases),
        headers=dict(settings.headers),
        input_price_per_million=settings.input_price_per_million,
        output_price_per_million=settings.output_price_per_million,
    )


def redacted_config(config: AppConfig) -> dict[str, Any]:
    data = config.model_dump(mode="python", by_alias=True)
    providers = data.get("providers", {})
    if isinstance(providers, dict):
        for provider in providers.values():
            if isinstance(provider, dict) and "api_key" in provider:
                provider["api_key"] = "***REDACTED***"
            if isinstance(provider, dict) and provider.get("api_key_env"):
                # Keep env var name; never materialize secret values.
                pass
    return data


def config_digest(config: AppConfig) -> str:
    from cot_redteam.core.serialization import sha256_text

    return sha256_text(canonical_json(redacted_config(config)))
