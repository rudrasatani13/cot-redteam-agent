"""Provider factory tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cot_redteam.core.config import load_config
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
