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


@pytest.mark.asyncio
async def test_evolve_evaluates_through_engine(tmp_path, monkeypatch) -> None:
    import yaml

    from cot_redteam.core.config import load_config
    from cot_redteam.core.types import GenerationRequest
    from cot_redteam.providers.factory import ProviderFactory

    class CombinedProvider:
        async def generate(self, model, request: GenerationRequest):
            if "Generate one JSON attack" in request.prompt:
                return ModelResponse(
                    text='{"name":"e1","prompt_template":"Think carefully about {question}","tags":["t"]}',
                    model=model,
                    usage=TokenUsage(1, 1),
                )
            return ModelResponse(
                text="<think>normal</think>answer",
                model=model,
                usage=TokenUsage(1, 1),
            )

        async def aclose(self):
            return None

    cfg = {
        "version": 2,
        "global": {"seed": 1, "concurrency": 1},
        "providers": {"fake": {"kind": "vllm", "base_url": "http://localhost:9/v1"}},
        "evaluation": {
            "models": ["fake:local"],
            "attacks": ["injection.cot_injection"],
            "monitors": ["regex"],
            "dataset_path": "pkg:sample.jsonl",
            "sample_count": 1,
        },
        "generative": {
            "generator_model": "fake:local",
            "target_models": ["fake:local"],
            "evolution_rounds": 1,
            "population_size": 1,
            "max_generation_attempts": 3,
        },
        "storage": {"path": str(tmp_path / "db.sqlite")},
        "artifacts": {"root": str(tmp_path / "art")},
    }
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    config = load_config(path)

    class Factory(ProviderFactory):
        def __init__(self):
            self._config = config
            self._environ = {}
            self._transport_factory = None
            self._cache = {}
            self.provider = CombinedProvider()

        def create(self, model):
            return self.provider

        def resolve_model(self, value: str):
            return ModelRef.parse(value)

        async def aclose(self):
            await self.provider.aclose()

    factory = Factory()
    engine = GenerativeAttackEngine(
        factory.provider,
        ModelRef.parse("fake:local"),
        max_generation_attempts=3,
        population_size=1,
    )
    result = await engine.evolve(
        config=config,
        provider_factory=factory,
        target_models=["fake:local"],
        evolution_rounds=1,
    )
    assert result.candidates
    assert result.candidates[0].fitness is not None
    assert result.candidates[0].run_ids
    assert result.candidates[0].sample_ids
