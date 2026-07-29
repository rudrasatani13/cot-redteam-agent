"""Provider factory tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cot_redteam.core.config import AppConfig, load_config
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.types import ModelRef
from cot_redteam.providers.factory import ProviderFactory

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "config" / "minimal.yaml"


def test_alias_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    # extend minimal with alias via overrides not supported for aliases; mutate load
    config = load_config(FIXTURES)
    # inject alias
    providers = dict(config.providers)
    openrouter = providers["openrouter"].model_copy(update={"aliases": {"fast": "test/model-fast"}})
    providers["openrouter"] = openrouter
    config = config.model_copy(update={"providers": providers})
    factory = ProviderFactory(config, environ={"OPENROUTER_API_KEY": "k"})
    ref = factory.resolve_model("openrouter:fast")
    assert ref.model_id == "test/model-fast"


def test_local_without_key() -> None:
    config = load_config(FIXTURES)
    factory = ProviderFactory(config, environ={})
    provider = factory.create(ModelRef.parse("vllm:local-model"))
    assert provider is not None


def test_remote_requires_credentials() -> None:
    config = load_config(FIXTURES)
    factory = ProviderFactory(config, environ={})
    with pytest.raises(ConfigurationError, match="OPENROUTER_API_KEY"):
        factory.create(ModelRef.parse("openrouter:test/model"))


def test_provider_instance_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    config = load_config(FIXTURES)
    factory = ProviderFactory(config, environ={"OPENROUTER_API_KEY": "k"})
    a = factory.create(ModelRef.parse("openrouter:test/model"))
    b = factory.create(ModelRef.parse("openrouter:other/model"))
    assert a is b


def test_generic_openai_compatible_provider_allows_optional_key() -> None:
    base = load_config(FIXTURES)
    raw = base.model_dump(mode="python", by_alias=True)
    raw["providers"]["gateway"] = {
        "kind": "openai_compatible",
        "base_url": "https://gateway.example/v1",
        "timeout": 30,
        "max_retries": 0,
        "concurrency": 1,
        "capabilities": {
            "system_role": True,
            "developer_role": True,
            "multi_turn": True,
        },
    }
    config = AppConfig.model_validate(raw)
    factory = ProviderFactory(config, environ={})

    provider = factory.create(ModelRef.parse("gateway:model-a"))

    assert provider.capabilities.system_role is True
    assert provider.capabilities.developer_role is True
    assert provider.capabilities.multi_turn is True
