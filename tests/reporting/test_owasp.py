"""OWASP LLM Top 10 tagging tests."""

from __future__ import annotations

from cot_redteam.reporting.owasp import owasp_tags_for, reset_tag_cache


def setup_function() -> None:
    reset_tag_cache()


def test_canary_family_tags() -> None:
    tags = owasp_tags_for("injection.system_canary")
    assert "LLM01 — Prompt Injection" in tags
    assert "LLM02 — Sensitive Information Disclosure" in tags
    assert "LLM07 — System Prompt Leakage" in tags
    # adaptive and agent variants inherit via prefix
    for variant in (
        "injection.system_canary_adaptive",
        "injection.system_canary_agent",
        "injection.system_canary_agent_llm",
    ):
        tags = owasp_tags_for(variant)
        assert "LLM07 — System Prompt Leakage" in tags, variant


def test_crescendo_and_harm_tags() -> None:
    tags = owasp_tags_for("injection.crescendo_canary")
    assert "LLM01 — Prompt Injection" in tags
    assert "LLM07 — System Prompt Leakage" in tags
    tags = owasp_tags_for("harm.forbidden_behavior")
    assert "LLM01 — Prompt Injection" in tags
    assert "LLM05 — Improper Output Handling" in tags


def test_unknown_and_other_families() -> None:
    assert owasp_tags_for("faithfulness.entailment") == ()
    assert owasp_tags_for("completely.unknown") == ()
    # no cross-contamination between families
    tags = owasp_tags_for("steganography.hidden")
    assert "LLM02 — Sensitive Information Disclosure" in tags
    assert "LLM07" not in " ".join(tags)


def test_cache_consistent() -> None:
    first = owasp_tags_for("injection.system_canary_agent_llm")
    second = owasp_tags_for("injection.system_canary_agent_llm")
    assert first == second
