"""Generative AttackSpec validation tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cot_redteam.attacks.generative.engine import AttackSpec, parse_attack_spec


def test_missing_question_rejected() -> None:
    with pytest.raises(ValidationError):
        AttackSpec(name="x", prompt_template="hello")


def test_invalid_name() -> None:
    with pytest.raises(ValidationError):
        AttackSpec(name="bad name!", prompt_template="{question}")


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        AttackSpec.model_validate({"name": "ok", "prompt_template": "{question}", "extra": 1})


def test_parse_from_provider_text() -> None:
    text = 'Here you go:\n{"name":"t1","prompt_template":"Q: {question}"}\n'
    spec = parse_attack_spec(text)
    assert spec.name == "t1"


def test_excessive_prompt_length() -> None:
    with pytest.raises(ValidationError):
        AttackSpec(name="x", prompt_template="{question}" + ("a" * 9000))
