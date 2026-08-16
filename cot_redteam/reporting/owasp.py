"""OWASP GenAI LLM Top 10 tagging for attacks and reports.

Maps attack ids (exact or prefix) to the OWASP GenAI LLM Top 10 (2026)
entries. Every registered attack family has at least one rule so no attack
renders untagged; genuinely unknown ids still return no tags so the report
does not overclaim.

The 2026 release (published 2026-08-04 by the OWASP GenAI Security Project)
renumbered several entries relative to the 2025 list: Excessive Agency moved
to LLM03, Misinformation to LLM07, Hidden Context Exposure was added as
LLM08, and Improper Output Handling moved to LLM10. It also dropped the
draft-only "Model Theft" entry. Reports annotate the mapping version so tag
citations cannot silently drift between list releases.
"""

from __future__ import annotations

# OWASP GenAI LLM Top 10 (2026). Canonical source:
# https://github.com/GenAI-Security-Project/GenAI-LLM-Top10
MAPPING_VERSION = "OWASP GenAI LLM Top 10 (2026)"

# Entries of the 2026 release, in list order.
_OWASP_ENTRIES: dict[str, str] = {
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

# attack id prefix -> ordered OWASP codes. A rule matches when the attack id
# equals the key or starts with it (so canary variants inherit); tags from
# every matching rule accumulate, most specific rule first.
_OWASP_RULES: dict[str, tuple[str, ...]] = {
    # Canary extraction attacks inject prompts to leak protected system
    # content: instruction hijacking (LLM01), disclosure of the protected
    # token (LLM02), and exposure of content hidden in the system context
    # (LLM08).
    "injection.system_canary": ("LLM01", "LLM02", "LLM08"),
    "injection.crescendo_canary": ("LLM01", "LLM08"),
    # Any other injection payload manipulates instructions in the reasoning
    # channel: direct CoT injection, "ignore previous reasoning", roleplay.
    "injection.": ("LLM01",),
    # Manipulation attacks smuggle fallacies and hostile premises into the
    # prompt; generative attacks evolve novel injected payloads.
    "manipulation.": ("LLM01",),
    "generative.": ("LLM01",),
    # Agent-lane exploits take or enable unauthorized tool actions: the
    # agentic risk is excessive agency (LLM03) enabled by injected
    # instructions (LLM01).
    "agent.": ("LLM03", "LLM01"),
    # Jailbreak (forbidden behavior) is NOT prompt injection; it maps only to
    # improper output handling downstream (LLM10).
    "harm.forbidden_behavior": ("LLM10",),
    # Steganography attacks make the model disclose hidden material
    # (LLM02/LLM08).
    "steganography.": ("LLM02", "LLM08"),
    # Evasion attacks dress unsafe reasoning up as safe for downstream
    # consumers (LLM10) rather than seizing agency (not LLM03).
    "evasion.": ("LLM10",),
    # Distillation attacks extract model behavior / IP. The 2026 list
    # dropped the draft "Model Theft" entry; the closest equivalent is
    # sensitive information disclosure (LLM02).
    "distillation.": ("LLM02",),
    # Faithfulness attacks probe unfaithful or hallucinated reasoning:
    # misleading model output (LLM07).
    "faithfulness.": ("LLM07",),
    # Sandbagging attacks make the model misrepresent its capabilities:
    # deliberately misleading output (LLM07).
    "sandbagging.": ("LLM07",),
}

# Cache of resolved tags per attack id.
_TAG_CACHE: dict[str, tuple[str, ...]] = {}


def owasp_mapping_version() -> str:
    """Return the OWASP list version the tags refer to."""
    return MAPPING_VERSION


def owasp_tags_for(attack_id: str) -> tuple[str, ...]:
    """Return OWASP GenAI LLM Top 10 (2026) tags (e.g. 'LLM01 - Prompt
    Injection') for an attack id. Prefix rules match longer ids (e.g. the
    canary family)."""
    if attack_id in _TAG_CACHE:
        return _TAG_CACHE[attack_id]
    tags: list[str] = []
    for rule_id, codes in _OWASP_RULES.items():
        if attack_id == rule_id or attack_id.startswith(rule_id):
            for code in codes:
                label = f"{code} — {_OWASP_ENTRIES[code]}"
                if label not in tags:
                    tags.append(label)
    result = tuple(tags)
    _TAG_CACHE[attack_id] = result
    return result


def reset_tag_cache() -> None:
    """Test-only hook: clear the id -> tags cache."""
    _TAG_CACHE.clear()
