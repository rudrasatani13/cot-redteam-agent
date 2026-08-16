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


class TargetCapabilitySettings(StrictModel):
    system_role: bool = True
    developer_role: bool = False
    multi_turn: bool = True
    tool_role: bool = False
    visible_reasoning: bool = False
    native_seed: bool = False


class ProviderSettings(StrictModel):
    kind: Literal[
        "openrouter",
        "openai",
        "anthropic",
        "vllm",
        "llamacpp",
        "openai_compatible",
        "mock",
    ]
    base_url: str | None = None
    api_key_env: str | None = None
    timeout: float = Field(default=120.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    concurrency: int = Field(default=4, ge=1)
    aliases: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    input_price_per_million: float | None = Field(default=None, ge=0)
    output_price_per_million: float | None = Field(default=None, ge=0)
    capabilities: TargetCapabilitySettings = Field(default_factory=TargetCapabilitySettings)
    mock_mode: Literal["auto", "refuse", "disclose", "error"] | None = None

    @model_validator(mode="after")
    def _remote_requires_api_key_env(self) -> ProviderSettings:
        if self.kind in ("vllm", "llamacpp", "mock"):
            return self
        if self.kind == "openai_compatible":
            if not self.base_url:
                raise ValueError("openai_compatible providers require base_url")
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


DEFAULT_FIXTURES: list[Literal["vulnerable", "patched", "clean"]] = ["vulnerable"]


class AgentRetentionSettings(StrictModel):
    """Privacy-first agent retention defaults."""

    retain_final_response: bool = False
    retain_tool_arguments: bool = False
    retain_tool_results: bool = False
    retain_memory_values: bool = False
    retain_world_values: bool = False
    retain_model_reasoning: bool = False


class AgentSecuritySettings(StrictModel):
    """Strict optional v0.6 agent-security configuration."""

    scenarios: list[str] = Field(default_factory=list)
    fixtures: list[Literal["vulnerable", "patched", "clean"]] = Field(
        default_factory=lambda: list(DEFAULT_FIXTURES)
    )
    target: Literal["scripted", "provider_adapter"] = "scripted"
    budgets: BudgetSettings = Field(default_factory=BudgetSettings)
    retention: AgentRetentionSettings = Field(default_factory=AgentRetentionSettings)
    max_actions: int = Field(default=100, ge=1)
    max_serialized_argument_bytes: int = Field(default=8192, ge=1)
    max_serialized_result_bytes: int = Field(default=65536, ge=1)
    tool_timeout_seconds: float = Field(default=5.0, gt=0)
    max_concurrent_tool_calls: int = Field(default=4, ge=1)
    output_dir: str = "./results/agent"
    target_model: str | None = None
    system_prompt: str | None = None
    # Deny dispatch when the trusted scope resolver returns UNAUTHORIZED.
    # Default false keeps scenarios observe-only: oracles prove impact from
    # executed unauthorized calls, which enforcement would prevent. Named to
    # avoid the SENSITIVE_KEY_RE "authorization" marker so manifests don't
    # have to weaken their redaction allowlist.
    deny_unauthorized_tools: bool = False

    @model_validator(mode="after")
    def _provider_adapter_requires_target_model(self) -> AgentSecuritySettings:
        if self.target == "provider_adapter" and not self.target_model:
            raise ValueError(
                "agent target=provider_adapter requires target_model (e.g. mock:mock-model)"
            )
        return self


class EvaluationSettings(StrictModel):
    models: list[str] = Field(default_factory=list)
    attacks: list[str] = Field(default_factory=list)
    monitors: list[str] = Field(default_factory=list)
    dataset_path: str = "pkg:sample.jsonl"
    suite_paths: list[str] = Field(default_factory=list)
    suite_ids: list[str] = Field(default_factory=list)
    policy_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    transformation_ids: list[str] = Field(default_factory=list)
    repetitions: int = Field(default=1, ge=1)
    judge_model: str | None = None
    judge_scorers: list[str] = Field(default_factory=list)
    max_expanded_trials: int = Field(default=10_000, ge=1)
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
    # Single retention policy for SQLite + artifacts (sensitive traces).
    retain_prompts: bool = True
    retain_responses: bool = True
    retain_reasoning: bool = True

    @field_validator(
        "models",
        "attacks",
        "monitors",
        "suite_paths",
        "suite_ids",
        "policy_ids",
        "technique_ids",
        "transformation_ids",
        "judge_scorers",
    )
    @classmethod
    def _non_empty_strings(cls, value: list[str]) -> list[str]:
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("entries must be non-empty strings")
        return value


class ArtifactSettings(StrictModel):
    root: str = "./artifacts"


class StorageSettings(StrictModel):
    path: str = "./results/cot_redteam.db"


class ReportingSettings(StrictModel):
    formats: list[Literal["markdown", "csv", "latex"]] = Field(
        default_factory=lambda: ["markdown"]  # type: ignore[arg-type,return-value]
    )
    output_dir: str = "./results/reports"


class GenerativeSettings(StrictModel):
    # None means "not configured": config validate must not require a provider
    # for a feature the user is not using. The evolve command errors clearly.
    generator_model: str | None = None
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
    #: Optional v0.6 agent settings. Absent configs validate and run exactly
    #: as before; the agent CLI requires this section or a dedicated agent
    #: example config.
    agent: AgentSecuritySettings | None = None

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
        if self.evaluation.judge_model:
            try:
                judge_ref = ModelRef.parse(self.evaluation.judge_model)
            except ValueError as exc:
                raise ValueError(
                    f"invalid judge model reference {self.evaluation.judge_model!r}"
                ) from exc
            if judge_ref.provider not in self.providers:
                raise ValueError(f"judge model provider {judge_ref.provider!r} is not configured")
        return self


class ResolvedProviderSettings(StrictModel):
    name: str
    kind: Literal[
        "openrouter",
        "openai",
        "anthropic",
        "vllm",
        "llamacpp",
        "openai_compatible",
        "mock",
    ]
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
    capabilities: TargetCapabilitySettings = Field(default_factory=TargetCapabilitySettings)
    mock_mode: Literal["auto", "refuse", "disclose", "error"] | None = None

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
    "evaluation.suite_paths",
    "evaluation.suite_ids",
    "evaluation.policy_ids",
    "evaluation.technique_ids",
    "evaluation.transformation_ids",
    "evaluation.repetitions",
    "evaluation.judge_model",
    "evaluation.judge_scorers",
    "evaluation.max_expanded_trials",
    "evaluation.sample_count",
    "evaluation.temperature",
    "evaluation.max_tokens",
    "evaluation.budgets.max_requests",
    "evaluation.budgets.max_elapsed_seconds",
    "global.seed",
    "global.concurrency",
    "global.output_dir",
    "storage.path",
    "artifacts.root",
    "reporting.output_dir",
    "reporting.formats",
    "agent.scenarios",
    "agent.fixtures",
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


def _resolve_runtime_paths(config: AppConfig, config_path: Path) -> AppConfig:
    """Resolve relative filesystem paths against the config file directory."""
    from cot_redteam.resources import is_package_dataset, resolve_path_against_config

    dataset = config.evaluation.dataset_path
    if not is_package_dataset(dataset):
        dataset = str(resolve_path_against_config(dataset, config_path))
    suite_paths = [
        str(resolve_path_against_config(path, config_path))
        for path in config.evaluation.suite_paths
    ]
    storage_path = str(resolve_path_against_config(config.storage.path, config_path))
    artifacts_root = str(resolve_path_against_config(config.artifacts.root, config_path))
    reporting_dir = str(resolve_path_against_config(config.reporting.output_dir, config_path))
    archive = str(resolve_path_against_config(config.generative.archive_path, config_path))
    output_dir = str(resolve_path_against_config(config.global_.output_dir, config_path))
    agent_settings = config.agent
    if agent_settings is not None and getattr(agent_settings, "output_dir", None):
        agent_output = str(
            resolve_path_against_config(agent_settings.output_dir, config_path)  # type: ignore[attr-defined]
        )
        agent_settings = agent_settings.model_copy(update={"output_dir": agent_output})  # type: ignore[union-attr]
    return config.model_copy(
        update={
            "global_": config.global_.model_copy(update={"output_dir": output_dir}),
            "evaluation": config.evaluation.model_copy(
                update={"dataset_path": dataset, "suite_paths": suite_paths}
            ),
            "storage": config.storage.model_copy(update={"path": storage_path}),
            "artifacts": config.artifacts.model_copy(update={"root": artifacts_root}),
            "reporting": config.reporting.model_copy(update={"output_dir": reporting_dir}),
            "generative": config.generative.model_copy(update={"archive_path": archive}),
            "agent": agent_settings,
        }
    )


def load_config(
    path: str | Path,
    *,
    overrides: Mapping[str, Any] | None = None,
) -> AppConfig:
    config_path = Path(path).resolve()
    if not config_path.exists():
        raise ConfigurationError(f"config file not found: {config_path}")
    data = _load_yaml(config_path)
    if overrides:
        for key, value in overrides.items():
            if key not in DOCUMENTED_OVERRIDES:
                raise ConfigurationError(f"unsupported override key: {key}")
            _set_nested(data, key, value)
    try:
        config = AppConfig.model_validate(data)
    except Exception as exc:
        message = str(exc)
        # Pydantic errors embed input values. Nuke the whole message when it
        # references a credential-bearing field — except the env-var NAME
        # fields (api_key_env), whose mentions carry no secret material.
        # Mask the env-var name first so it cannot satisfy the marker check.
        masked = message.replace("api_key_env", "").replace("api-key-env", "")
        lowered = masked.lower()
        secret_markers = (
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "authorization",
            "proxy-authorization",
            "secret",
            "token",
            "password",
            "cookie",
            "set-cookie",
            "session",
            "bearer",
        )
        if any(marker in lowered for marker in secret_markers):
            message = "configuration validation failed (input values redacted)"
        raise ConfigurationError(f"invalid configuration: {message}") from exc
    return _resolve_runtime_paths(config, config_path)


def _referenced_providers(config: AppConfig) -> set[str]:
    """Return provider names referenced by evaluation and generative model refs."""
    referenced: set[str] = set()
    refs: list[str] = list(config.evaluation.models)
    if config.evaluation.judge_model:
        refs.append(config.evaluation.judge_model)
    refs.extend(config.generative.target_models)
    if config.generative.generator_model:
        refs.append(config.generative.generator_model)
    for model_ref in refs:
        try:
            referenced.add(ModelRef.parse(model_ref).provider)
        except ValueError as exc:
            raise ConfigurationError(
                f"invalid model reference {model_ref!r}: expected provider:model-id"
            ) from exc
    return referenced


def validate_config(
    config: AppConfig,
    *,
    environ: Mapping[str, str] | None = None,
    require_credentials: bool = True,
) -> None:
    """Validate plugins, monitors, and dataset without contacting providers."""
    from cot_redteam.attacks.base import AttackRegistry
    from cot_redteam.core.errors import PluginError
    from cot_redteam.eval.dataset import Dataset
    from cot_redteam.monitors.base import MonitorRegistry
    from cot_redteam.plugins.bootstrap import bootstrap_plugins
    from cot_redteam.plugins.registry import PluginContext

    if require_credentials:
        for name in sorted(_referenced_providers(config)):
            if name not in config.providers:
                raise ConfigurationError(
                    f"referenced provider {name!r} is not configured. "
                    f"Available: {', '.join(sorted(config.providers))}"
                )
            settings = config.providers[name]
            if settings.kind in ("vllm", "llamacpp", "mock"):
                continue
            resolve_provider(config, name, environ=environ)

    bootstrap_plugins()
    context = PluginContext()
    for attack_id in config.evaluation.attacks:
        if attack_id not in AttackRegistry:
            raise PluginError(
                f"unknown attack {attack_id!r}. Available: {', '.join(AttackRegistry.ids())}"
            )
        AttackRegistry.create(
            attack_id,
            config.evaluation.attack_config.get(attack_id, {}),
            context,
        )

    for monitor_id in config.evaluation.monitors:
        if monitor_id not in MonitorRegistry:
            raise PluginError(
                f"unknown monitor {monitor_id!r}. Available: {', '.join(MonitorRegistry.ids())}"
            )
        MonitorRegistry.create(
            monitor_id,
            config.evaluation.monitor_config.get(monitor_id, {}),
            context,
        )

    if config.evaluation.suite_ids or config.evaluation.suite_paths:
        from cot_redteam.benchmark.validation import validate_benchmark_config

        validate_benchmark_config(config)

    # Dataset accessibility (no provider network calls).
    Dataset.load_jsonl(config.evaluation.dataset_path)


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
            if settings.kind in ("vllm", "llamacpp", "openai_compatible", "mock"):
                api_key = None
            else:
                raise ConfigurationError(
                    f"missing required environment variable {settings.api_key_env}"
                )
        else:
            api_key = SecretStr(value)
    elif settings.kind not in ("vllm", "llamacpp", "openai_compatible", "mock"):
        raise ConfigurationError(f"remote provider {provider_name!r} requires api_key_env")

    base_url: str | None
    if settings.kind == "mock":
        base_url = "mock://local"
    else:
        base_url = settings.base_url or DEFAULT_BASE_URLS.get(settings.kind)
    if base_url is None:
        raise ConfigurationError(f"provider {provider_name!r} requires base_url")
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
        capabilities=settings.capabilities,
        mock_mode=settings.mock_mode,
    )


def redacted_config(config: AppConfig) -> dict[str, Any]:
    data = config.model_dump(mode="python", by_alias=True)
    providers = data.get("providers", {})
    if isinstance(providers, dict):
        for provider in providers.values():
            if not isinstance(provider, dict):
                continue
            # Providers only carry the env var NAME (api_key_env); headers
            # may carry raw credential values, so they are always masked.
            headers = provider.get("headers")
            if isinstance(headers, dict):
                provider["headers"] = {str(name): "***REDACTED***" for name in headers}
    return data


def config_digest(config: AppConfig) -> str:
    from cot_redteam.core.serialization import sha256_text

    return sha256_text(canonical_json(redacted_config(config)))
