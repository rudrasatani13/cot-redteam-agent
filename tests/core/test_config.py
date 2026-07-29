"""Strict configuration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cot_redteam.core.config import load_config, redacted_config, resolve_provider
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.serialization import canonical_json

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


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
