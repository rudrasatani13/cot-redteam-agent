"""OWASP GenAI LLM Top 10 (2026) tagging tests."""

from __future__ import annotations

from cot_redteam.reporting.owasp import (
    MAPPING_VERSION,
    owasp_mapping_version,
    owasp_tags_for,
    reset_tag_cache,
)


def setup_function() -> None:
    reset_tag_cache()


def test_mapping_version_is_2026() -> None:
    assert owasp_mapping_version() == "OWASP GenAI LLM Top 10 (2026)"
    assert MAPPING_VERSION == "OWASP GenAI LLM Top 10 (2026)"


def test_canary_family_tags() -> None:
    tags = owasp_tags_for("injection.system_canary")
    assert "LLM01 — Prompt Injection" in tags
    assert "LLM02 — Sensitive Information Disclosure" in tags
    # 2026: canary content hidden in the system context is hidden-context
    # exposure (LLM08), replacing the 2025 system-prompt-leakage tag.
    assert "LLM08 — Hidden Context Exposure" in tags
    # adaptive and agent variants inherit via prefix
    for variant in (
        "injection.system_canary_adaptive",
        "injection.system_canary_agent",
        "injection.system_canary_agent_llm",
    ):
        assert "LLM08 — Hidden Context Exposure" in owasp_tags_for(variant), variant


def test_crescendo_and_harm_tags() -> None:
    tags = owasp_tags_for("injection.crescendo_canary")
    assert "LLM01 — Prompt Injection" in tags
    assert "LLM08 — Hidden Context Exposure" in tags
    # Jailbreak (forbidden behavior) is not prompt injection; only LLM10
    # (2026 Improper Output Handling) applies.
    tags = owasp_tags_for("harm.forbidden_behavior")
    assert "LLM01 — Prompt Injection" not in tags  # pins the fixed mapping
    assert "LLM10 — Improper Output Handling" in tags


def test_cot_injection_family_maps_to_llm01() -> None:
    for attack_id in (
        "injection.cot_injection",
        "injection.ignore_previous_reasoning",
        "injection.roleplay_injection",
    ):
        assert "LLM01 — Prompt Injection" in owasp_tags_for(attack_id), attack_id


def test_evasion_family_maps_to_llm10_not_llm03() -> None:
    """Monitor evasion is not excessive agency (LLM03); it maps to improper
    output handling (LLM10) so evasion reports are not silently untagged."""
    for attack_id in (
        "evasion.monitor_awareness",
        "evasion.stealth_reasoning",
        "evasion.dual_process_reasoning",
        "evasion.nl_camouflage",
    ):
        assert "LLM10 — Improper Output Handling" in owasp_tags_for(attack_id), attack_id
        assert "LLM03" not in " ".join(owasp_tags_for(attack_id)), attack_id


def test_unknown_and_other_families() -> None:
    assert owasp_tags_for("completely.unknown") == ()
    # no cross-contamination between families
    tags = owasp_tags_for("steganography.hidden")
    assert "LLM02 — Sensitive Information Disclosure" in tags
    assert "LLM08 — Hidden Context Exposure" in tags
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


def test_2026_labels_replace_stale_2025_draft_labels() -> None:
    """Pins the 2026 renumbering; the old 2025-draft codes (LLM10 Model
    Theft, LLM08 Misinformation, LLM09 Overreliance, LLM07 System Prompt
    Leakage, LLM06 Excessive Agency) must never reappear."""
    distillation = " ".join(owasp_tags_for("distillation.few_shot_extraction"))
    # 2026 dropped Model Theft; distillation maps to the closest equivalent,
    # sensitive information disclosure.
    assert "LLM02 — Sensitive Information Disclosure" in distillation
    assert "LLM10 — Model Theft" not in distillation
    assert "LLM04" not in distillation  # was wrongly tagged Supply Chain
    evasion = " ".join(owasp_tags_for("evasion.stealth_reasoning"))
    assert "LLM10 — Improper Output Handling" in evasion
    assert "LLM06" not in evasion  # 2025 draft tagged Excessive Agency
    assert "LLM03" not in evasion
    faithfulness = " ".join(owasp_tags_for("faithfulness.cot_hallucination"))
    assert "LLM07 — Misinformation" in faithfulness
    assert "LLM08 — Misinformation" not in faithfulness
    sandbagging = " ".join(owasp_tags_for("sandbagging.capability_hiding"))
    assert "LLM07 — Misinformation" in sandbagging
    assert "LLM09 — Overreliance" not in sandbagging
    # 2025 System Prompt Leakage tag is gone from the 2026 list.
    assert "LLM07 — System Prompt Leakage" not in " ".join(
        owasp_tags_for("injection.system_canary_agent_llm")
    )


def test_agent_lane_prefix_maps_to_excessive_agency() -> None:
    """Agent-lane scenarios take or enable unauthorized tool actions:
    the 2026 agentic risk is Excessive Agency (LLM03)."""
    tags = owasp_tags_for("agent.support_agent_world")
    assert "LLM03 — Excessive Agency" in tags
    assert "LLM01 — Prompt Injection" in tags


def test_all_2026_entries_resolve() -> None:
    """Every entry of the published 2026 list must be resolvable even if
    no current attack family maps to it (future-proofing)."""
    from cot_redteam.reporting.owasp import _OWASP_ENTRIES

    expected = {
        "LLM01": "Prompt Injection",
        "LLM02": "Sensitive Information Disclosure",
        "LLM03": "Excessive Agency",
        "LLM04": "Supply Chain",
        "LLM05": "Data and Model Poisoning",
        "LLM06": "Unbounded Consumption",
        "LLM07": "Misinformation",
        "LLM08": "Hidden Context Exposure",
        "LLM09": "Vector and Embedding Weaknesses",
        "LLM10": "Improper Output Handling",
    }
    assert _OWASP_ENTRIES == expected


def test_cache_consistent() -> None:
    first = owasp_tags_for("injection.system_canary_agent_llm")
    second = owasp_tags_for("injection.system_canary_agent_llm")
    assert first == second
