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
