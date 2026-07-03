"""Test core types and dataclasses."""
import pytest
from cot_redteam.core.types import (
    AttackCategory,
    ModelProvider,
    MonitorType,
    Severity,
    ModelConfig,
    AttackConfig,
    AttackPrompt,
    ModelResponse,
    AttackResult,
    AttackSpec,
    DatasetSample,
    MonitorResult,
    EvalResult,
)


class TestEnums:
    def test_attack_category_values(self):
        assert AttackCategory.INJECTION == "injection"
        assert AttackCategory.GENERATIVE == "generative"
        assert len(AttackCategory) == 8

    def test_model_provider_values(self):
        assert ModelProvider.OPENROUTER == "openrouter"
        assert ModelProvider.VLLM == "vllm"
        assert len(ModelProvider) == 6

    def test_monitor_type_values(self):
        assert MonitorType.REGEX == "regex"
        assert MonitorType.ENSEMBLE == "ensemble"

    def test_severity_values(self):
        assert Severity.LOW == "low"
        assert Severity.CRITICAL == "critical"


class TestModelConfig:
    def test_basic_config(self):
        cfg = ModelConfig(
            provider=ModelProvider.OPENROUTER,
            model_id="anthropic/claude-3.5-sonnet",
        )
        assert cfg.provider == ModelProvider.OPENROUTER
        assert cfg.model_id == "anthropic/claude-3.5-sonnet"
        assert cfg.temperature == 0.7
        assert cfg.max_tokens == 4096

    def test_full_id(self):
        cfg = ModelConfig(provider=ModelProvider.OPENAI, model_id="gpt-4o")
        assert cfg.full_id == "openai:gpt-4o"


class TestDatasetSample:
    def test_minimal_sample(self):
        s = DatasetSample(id="q1", question="What is 2+2?")
        assert s.id == "q1"
        assert s.answer is None
        assert s.metadata == {}

    def test_full_sample(self):
        s = DatasetSample(
            id="q2",
            question="Is 51 prime?",
            answer="No",
            category="math",
            difficulty="easy",
        )
        assert s.answer == "No"
        assert s.category == "math"


class TestAttackSpec:
    def test_basic_spec(self):
        spec = AttackSpec(
            name="test_attack",
            category=AttackCategory.INJECTION,
            description="A test attack",
            prompt_template="hello {question}",
        )
        assert spec.name == "test_attack"
        assert spec.parameters == {}
        assert spec.tags == []


class TestMonitorResult:
    def test_triggered_result(self):
        r = MonitorResult(
            monitor_type=MonitorType.REGEX,
            triggered=True,
            confidence=0.9,
            explanation="Found suspicious pattern",
        )
        assert r.triggered is True
        assert r.confidence == 0.9

    def test_clean_result(self):
        r = MonitorResult(
            monitor_type=MonitorType.LLM_JUDGE,
            triggered=False,
            confidence=0.0,
        )
        assert r.triggered is False