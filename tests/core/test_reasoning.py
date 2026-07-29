"""Visible reasoning extraction tests."""

from cot_redteam.core.reasoning import extract_visible_reasoning
from cot_redteam.core.types import ReasoningSource


def test_think_delimiters() -> None:
    text = "prefix <think>secret plan</think> answer"
    reasoning, source = extract_visible_reasoning(text)
    assert reasoning == "secret plan"
    assert source is ReasoningSource.DELIMITED


def test_reasoning_delimiters() -> None:
    text = "<reasoning>step one</reasoning>\nfinal"
    reasoning, source = extract_visible_reasoning(text)
    assert reasoning == "step one"
    assert source is ReasoningSource.DELIMITED


def test_no_delimiters() -> None:
    reasoning, source = extract_visible_reasoning("just an answer")
    assert reasoning is None
    assert source is ReasoningSource.ABSENT


def test_unclosed_delimiters() -> None:
    reasoning, source = extract_visible_reasoning("<think>partial")
    assert reasoning is None
    assert source is ReasoningSource.ABSENT


def test_ordinary_because_not_reasoning() -> None:
    reasoning, source = extract_visible_reasoning("I chose 4 because 2+2=4")
    assert reasoning is None
    assert source is ReasoningSource.ABSENT


def test_provider_reasoning_wins() -> None:
    reasoning, source = extract_visible_reasoning(
        "answer",
        provider_reasoning="provider chain",
    )
    assert reasoning == "provider chain"
    assert source is ReasoningSource.PROVIDER
