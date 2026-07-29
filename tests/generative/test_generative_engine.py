"""Bounded generative engine tests."""

from __future__ import annotations

import pytest

from cot_redteam.attacks.generative.engine import GenerativeAttackEngine
from cot_redteam.core.types import ModelRef, ModelResponse, TokenUsage


class MalformedProvider:
    async def generate(self, model, request):
        return ModelResponse(text="not json", model=model, usage=TokenUsage(1, 1))

    async def aclose(self):
        return None


class ValidProvider:
    async def generate(self, model, request):
        return ModelResponse(
            text='{"name":"gen1","prompt_template":"Think about {question}","tags":["t"]}',
            model=model,
            usage=TokenUsage(1, 1),
        )

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_stops_at_max_generation_attempts() -> None:
    engine = GenerativeAttackEngine(
        MalformedProvider(),
        ModelRef.parse("openrouter:m"),
        max_generation_attempts=3,
        population_size=5,
    )
    result = await engine.generate_population()
    assert result.attempts == 3
    assert result.candidates == []
    assert result.diagnostics


@pytest.mark.asyncio
async def test_valid_population() -> None:
    engine = GenerativeAttackEngine(
        ValidProvider(),
        ModelRef.parse("openrouter:m"),
        max_generation_attempts=5,
        population_size=2,
    )
    result = await engine.generate_population()
    assert len(result.candidates) == 2
    fitness = engine.compute_fitness(result.candidates[0], attack_success=1.0, evasion=0.5)
    assert 0.0 <= fitness <= 1.0
