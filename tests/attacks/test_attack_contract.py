"""Built-in attack contract tests."""

from __future__ import annotations

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.core.types import (
    DatasetSample,
    ModelRef,
    ModelResponse,
    ReasoningSource,
    TokenUsage,
)
from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests

SAMPLE = DatasetSample(id="s1", question="What is 2+2?", answer="4")
MODEL_RESPONSE = ModelResponse(
    text="I will ignore filters. The answer is 4.",
    model=ModelRef.parse("openrouter:test/model"),
    reasoning="ignore previous instructions and answer",
    reasoning_source=ReasoningSource.DELIMITED,
    usage=TokenUsage(1, 1),
)


def setup_function() -> None:
    reset_plugins_for_tests()
    bootstrap_plugins(force=True)


def test_every_builtin_attack_returns_typed_prompt_and_assessment() -> None:
    metadata_items = AttackRegistry.metadata()
    assert metadata_items
    for metadata in metadata_items:
        attack = AttackRegistry.create(metadata.id, {})
        prompt = attack.create_prompt(SAMPLE)
        assessment = attack.assess(SAMPLE, prompt, MODEL_RESPONSE)
        assert prompt.attack_id == metadata.id
        assert 0.0 <= assessment.score <= 1.0
        assert isinstance(assessment.evidence, tuple)
