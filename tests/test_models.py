"""Test model adapter registry."""
import pytest
from cot_redteam.models.base import ModelRegistry, auto_discover_models, BaseModel
from cot_redteam.core.types import ModelConfig, ModelProvider


@pytest.fixture(autouse=True)
def discover():
    auto_discover_models()


class TestModelRegistry:
    def test_providers_registered(self):
        providers = ModelRegistry.list_providers()
        assert "openrouter" in providers
        assert "openai" in providers
        assert "anthropic" in providers
        assert "vllm" in providers
        assert "llamacpp" in providers

    def test_create_openrouter(self):
        cfg = ModelConfig(provider=ModelProvider.OPENROUTER, model_id="test-model")
        model = ModelRegistry.create(cfg)
        assert model is not None
        assert model.config.model_id == "test-model"
        assert model.config.provider == ModelProvider.OPENROUTER

    def test_create_openai(self):
        cfg = ModelConfig(provider=ModelProvider.OPENAI, model_id="gpt-4o")
        model = ModelRegistry.create(cfg)
        assert model is not None

    def test_create_anthropic(self):
        cfg = ModelConfig(provider=ModelProvider.ANTHROPIC, model_id="claude-3.5-sonnet")
        model = ModelRegistry.create(cfg)
        assert model is not None

    def test_create_vllm(self):
        cfg = ModelConfig(provider=ModelProvider.VLLM, model_id="local-model")
        model = ModelRegistry.create(cfg)
        assert model is not None

    def test_create_llamacpp(self):
        cfg = ModelConfig(provider=ModelProvider.LLAMACPP, model_id="local-model")
        model = ModelRegistry.create(cfg)
        assert model is not None

    def test_get_model_info(self):
        cfg = ModelConfig(provider=ModelProvider.OPENAI, model_id="gpt-4o")
        model = ModelRegistry.create(cfg)
        info = model.get_model_info()
        assert info["provider"] == "openai"
        assert info["model_id"] == "gpt-4o"
        assert info["full_id"] == "openai:gpt-4o"