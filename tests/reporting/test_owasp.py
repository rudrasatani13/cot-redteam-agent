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
    # Jailbreak (forbidden behavior) is not prompt injection; only LLM05 applies.
    tags = owasp_tags_for("harm.forbidden_behavior")
    assert "LLM01 — Prompt Injection" not in tags  # pins the fixed mapping
    assert "LLM05 — Improper Output Handling" in tags


def test_cot_injection_family_maps_to_llm01() -> None:
    for attack_id in (
        "injection.cot_injection",
        "injection.ignore_previous_reasoning",
        "injection.roleplay_injection",
    ):
        tags = owasp_tags_for(attack_id)
        assert "LLM01 — Prompt Injection" in tags, attack_id


def test_evasion_family_has_no_llm06() -> None:
    """Monitor evasion is not excessive agency; no OWASP tag is claimed."""
    for attack_id in (
        "evasion.monitor_awareness",
        "evasion.stealth_reasoning",
        "evasion.dual_process_reasoning",
        "evasion.nl_camouflage",
    ):
        assert owasp_tags_for(attack_id) == (), attack_id


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
