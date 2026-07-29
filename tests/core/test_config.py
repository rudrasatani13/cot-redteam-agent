"""Strict configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cot_redteam.core.config import (
    EvaluationSettings,
    ProviderSettings,
    load_config,
    redacted_config,
    resolve_provider,
)
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.serialization import canonical_json

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_remote_and_generic_provider_require_explicit_connection_settings() -> None:
    with pytest.raises(ValueError, match="requires api_key_env"):
        ProviderSettings(kind="openai")
    with pytest.raises(ValueError, match="require base_url"):
        ProviderSettings(kind="openai_compatible")


def test_load_config_rejects_unknown_keys() -> None:
    with pytest.raises(ConfigurationError, match="unexpected|extra|invalid"):
        load_config(FIXTURES / "config" / "unknown-key.yaml")


def test_remote_provider_requires_named_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="OPENROUTER_API_KEY"):
        resolve_provider(config, "openrouter")


def test_redacted_config_never_contains_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-value")
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    resolved = resolve_provider(config, "openrouter")
    assert "secret-value" not in repr(resolved)
    assert "secret-value" not in canonical_json(redacted_config(config))


def test_redacted_config_strips_custom_header_values() -> None:
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    provider = config.providers["openrouter"].model_copy(
        update={
            "headers": {
                "Authorization": "Bearer header-secret",
                "X-Project-Name": "private-project",
            }
        }
    )
    config = config.model_copy(update={"providers": {**config.providers, "openrouter": provider}})

    redacted = redacted_config(config)
    serialized = canonical_json(redacted)

    assert "header-secret" not in serialized
    assert "private-project" not in serialized
    assert redacted["providers"]["openrouter"]["headers"] == {
        "Authorization": "***REDACTED***",
        "X-Project-Name": "***REDACTED***",
    }


def test_local_provider_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    resolved = resolve_provider(config, "vllm")
    assert resolved.api_key is None
    assert resolved.base_url.endswith("/v1")


def test_overrides_merge() -> None:
    config = load_config(
        FIXTURES / "config" / "minimal.yaml",
        overrides={"evaluation.sample_count": 1, "global.seed": 99},
    )
    assert config.evaluation.sample_count == 1
    assert config.global_.seed == 99


def test_unsupported_override_rejected() -> None:
    with pytest.raises(ConfigurationError, match="unsupported override"):
        load_config(
            FIXTURES / "config" / "minimal.yaml",
            overrides={"providers.openrouter.api_key_env": "X"},
        )


def test_validate_config_loads_dataset(monkeypatch: pytest.MonkeyPatch) -> None:
    from cot_redteam.core.config import validate_config

    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    validate_config(config)


def test_validate_only_referenced_remote_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unused remote providers (e.g. OpenAI/Anthropic) do not require keys."""
    from cot_redteam.core.config import validate_config

    monkeypatch.setenv("OPENROUTER_API_KEY", "only-openrouter")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Root example configures all three remotes; evaluation only uses openrouter.
    config = load_config(Path("config.example.yaml"))
    # Should not raise for missing OpenAI/Anthropic keys.
    validate_config(config)


def test_validate_config_fails_missing_dataset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cot_redteam.core.config import validate_config
    from cot_redteam.core.errors import DatasetError

    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    config = config.model_copy(
        update={
            "evaluation": config.evaluation.model_copy(
                update={"dataset_path": str(tmp_path / "missing.jsonl")}
            )
        }
    )
    with pytest.raises((ConfigurationError, DatasetError, Exception), match="dataset|not found"):
        validate_config(config)


def test_validate_local_referenced_provider_without_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Referenced local providers (vllm) do not need API keys."""
    from cot_redteam.core.config import validate_config

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    config = config.model_copy(
        update={
            "evaluation": config.evaluation.model_copy(update={"models": ["vllm:local-model"]}),
            "generative": config.generative.model_copy(
                update={
                    "generator_model": "vllm:local-model",
                    "target_models": ["vllm:local-model"],
                }
            ),
        }
    )
    validate_config(config)


def test_validate_missing_credential_for_referenced_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cot_redteam.core.config import validate_config

    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    with pytest.raises(ConfigurationError, match="OPENROUTER_API_KEY"):
        validate_config(config)


def test_validate_generative_target_requires_its_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A generative target on a remote provider requires that provider's key."""
    from cot_redteam.core.config import validate_config

    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = load_config(Path("config.example.yaml"))
    config = config.model_copy(
        update={
            "generative": config.generative.model_copy(
                update={
                    "generator_model": "openrouter:anthropic/claude-3.5-sonnet",
                    "target_models": ["openai:gpt-4o"],
                }
            )
        }
    )
    with pytest.raises(ConfigurationError, match="OPENAI_API_KEY"):
        validate_config(config)


def test_validate_invalid_generative_model_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cot_redteam.core.config import validate_config

    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    config = config.model_copy(
        update={
            "generative": config.generative.model_copy(
                update={"generator_model": "not-a-valid-ref"}
            )
        }
    )
    with pytest.raises(ConfigurationError, match="invalid model reference"):
        validate_config(config)


def test_validate_unknown_referenced_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cot_redteam.core.config import validate_config

    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    config = config.model_copy(
        update={
            "generative": config.generative.model_copy(
                update={"generator_model": "missing-provider:model-x"}
            )
        }
    )
    with pytest.raises(ConfigurationError, match="not configured"):
        validate_config(config)


def test_referenced_providers_helper() -> None:
    from cot_redteam.core.config import _referenced_providers

    config = load_config(FIXTURES / "config" / "minimal.yaml")
    refs = _referenced_providers(config)
    assert "openrouter" in refs


def test_benchmark_settings_are_additive_and_paths_resolve_from_config(
    tmp_path: Path,
) -> None:
    source = FIXTURES / "config" / "minimal.yaml"
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    data["evaluation"].update(
        {
            "suite_paths": ["suites/core.jsonl"],
            "suite_ids": ["suite.core"],
            "policy_ids": ["policy.hierarchy"],
            "technique_ids": ["technique.direct"],
            "transformation_ids": ["transform.identity"],
            "repetitions": 3,
            "judge_model": "openrouter:judge/model",
            "judge_scorers": ["judge.attack_goal"],
            "max_expanded_trials": 500,
        }
    )
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")

    config = load_config(path)

    assert config.evaluation.suite_paths == [str(tmp_path / "suites" / "core.jsonl")]
    assert config.evaluation.repetitions == 3
    assert config.evaluation.max_expanded_trials == 500


def test_benchmark_repetitions_require_positive_value() -> None:
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    with pytest.raises(ValueError, match="greater than or equal to 1"):
        EvaluationSettings.model_validate(
            {**config.evaluation.model_dump(mode="python"), "repetitions": 0}
        )
