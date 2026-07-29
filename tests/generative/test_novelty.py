"""Lexical novelty tests."""

from cot_redteam.attacks.generative.engine import lexical_novelty


def test_identical_prompts_score_zero() -> None:
    assert lexical_novelty("hello world foo bar", ["hello world foo bar"]) == 0.0


def test_disjoint_score_one() -> None:
    score = lexical_novelty("alpha beta gamma delta", ["one two three four"])
    assert score == 1.0


def test_deterministic() -> None:
    archive = ["the quick brown fox jumps", "lorem ipsum dolor sit"]
    a = lexical_novelty("quick brown fox jumps high", archive)
    b = lexical_novelty("quick brown fox jumps high", archive)
    assert a == b


def test_empty_tokens() -> None:
    assert lexical_novelty("!!!", ["hello world"]) == 0.0


def test_fitness_novelty_not_zero_against_empty_archive() -> None:
    from cot_redteam.attacks.generative.engine import (
        AttackCandidate,
        AttackSpec,
        GenerativeAttackEngine,
    )
    from cot_redteam.core.types import ModelRef

    class _P:
        async def generate(self, model, request):
            raise RuntimeError("unused")

        async def aclose(self):
            return None

    engine = GenerativeAttackEngine(
        _P(),
        ModelRef.parse("openrouter:m"),
        population_size=1,
    )
    assert engine.archive_templates == []
    candidate = AttackCandidate(
        candidate_id="c1",
        spec=AttackSpec(name="n1", prompt_template="unique template for {question}"),
        generation=0,
    )
    engine.compute_fitness(candidate, attack_success=1.0, evasion=1.0)
    assert candidate.components is not None
    assert candidate.components["novelty"] == 1.0


def test_fitness_excludes_self_from_archive() -> None:
    from cot_redteam.attacks.generative.engine import (
        AttackCandidate,
        AttackSpec,
        GenerativeAttackEngine,
    )
    from cot_redteam.core.types import ModelRef

    class _P:
        async def generate(self, model, request):
            raise RuntimeError("unused")

        async def aclose(self):
            return None

    engine = GenerativeAttackEngine(_P(), ModelRef.parse("openrouter:m"))
    template = "alpha beta gamma delta {question}"
    engine.archive_templates = [template]
    candidate = AttackCandidate(
        candidate_id="c1",
        spec=AttackSpec(name="n1", prompt_template=template),
        generation=0,
    )
    engine.compute_fitness(candidate, attack_success=0.5, evasion=0.5)
    # Self excluded → empty prior archive → novelty 1.0 for non-empty tokens
    assert candidate.components["novelty"] == 1.0
