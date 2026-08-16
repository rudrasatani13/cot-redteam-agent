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
    assert owasp_tags_for("completely.unknown") == ()
    # no cross-contamination between families
    tags = owasp_tags_for("steganography.hidden")
    assert "LLM02 — Sensitive Information Disclosure" in tags
    assert "LLM07" not in " ".join(tags)


def test_every_registered_attack_receives_at_least_one_tag() -> None:
    """No registered attack may render untagged: coverage gaps let a report
    silently drop an attack family from its risk summary."""
    from cot_redteam.attacks.base import AttackRegistry
    from cot_redteam.plugins.bootstrap import bootstrap_plugins, reset_plugins_for_tests

    reset_plugins_for_tests()
    bootstrap_plugins(force=True)
    try:
        ids = AttackRegistry.ids()
    finally:
        reset_plugins_for_tests()
        bootstrap_plugins(force=True)
    assert ids
    for attack_id in ids:
        assert owasp_tags_for(attack_id), attack_id


def test_injection_manipulation_and_generative_families_are_prompt_injection() -> None:
    for attack_id in (
        "injection.cot_injection",
        "injection.ignore_previous_reasoning",
        "injection.roleplay_injection",
        "injection.system_canary_adaptive",
        "manipulation.premise_injection",
        "manipulation.circular_reasoning",
        "generative.evolved",
    ):
        assert "LLM01 — Prompt Injection" in owasp_tags_for(attack_id), attack_id


def test_wrong_owasp_labels_are_corrected() -> None:
    distillation = " ".join(owasp_tags_for("distillation.few_shot_extraction"))
    assert "LLM10 — Model Theft" in distillation
    assert "LLM03" not in distillation  # was wrongly tagged Supply Chain
    evasion = " ".join(owasp_tags_for("evasion.stealth_reasoning"))
    assert "LLM05 — Improper Output Handling" in evasion
    assert "LLM06" not in evasion  # was wrongly tagged Excessive Agency
    assert "LLM08 — Misinformation" in owasp_tags_for("faithfulness.cot_hallucination")
    assert "LLM09 — Overreliance" in owasp_tags_for("sandbagging.capability_hiding")


def test_cache_consistent() -> None:
    first = owasp_tags_for("injection.system_canary_agent_llm")
    second = owasp_tags_for("injection.system_canary_agent_llm")
    assert first == second
