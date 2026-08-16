"""OWASP LLM Top 10 tagging for attacks and reports.

Maps attack ids (exact or prefix) to the OWASP Top 10 for LLM Applications
(2025). Every registered attack family has at least one rule so no attack
renders untagged; genuinely unknown ids still return no tags so the report
does not overclaim.
"""

from __future__ import annotations

# OWASP Top 10 for LLM Applications (2025) entries used by the mapping.
_OWASP_ENTRIES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Misinformation",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}

# attack id prefix -> ordered OWASP codes. A rule matches when the attack id
# equals the key or starts with it (so canary variants inherit); tags from
# every matching rule accumulate, most specific rule first.
_OWASP_RULES: dict[str, tuple[str, ...]] = {
    # Canary extraction attacks inject prompts to leak the protected system
    # prompt (LLM07) and the secrets inside it (LLM02).
    "injection.system_canary": ("LLM01", "LLM02", "LLM07"),
    "injection.crescendo_canary": ("LLM01", "LLM07"),
    # Any other injection payload manipulates instructions in the reasoning
    # channel: direct CoT injection, "ignore previous reasoning", roleplay.
    "injection.": ("LLM01",),
    # Manipulation attacks smuggle fallacies and hostile premises into the
    # prompt; generative attacks evolve novel injected payloads.
    "manipulation.": ("LLM01",),
    "generative.": ("LLM01",),
    # Jailbreak (forbidden behavior) is NOT prompt injection; it maps only to
    # improper output handling downstream (LLM05).
    "harm.forbidden_behavior": ("LLM05",),
    # Steganography attacks make the model disclose hidden material.
    "steganography.": ("LLM02",),
    # Evasion attacks dress unsafe reasoning up as safe for downstream
    # consumers (LLM05) rather than seizing agency (not LLM06).
    "evasion.": ("LLM05",),
    # Distillation attacks extract model behavior, i.e. model/IP theft.
    "distillation.": ("LLM10",),
    # Faithfulness attacks probe unfaithful or hallucinated reasoning.
    "faithfulness.": ("LLM08",),
    # Sandbagging attacks make the model misrepresent its capabilities.
    "sandbagging.": ("LLM09",),
}

# Cache of resolved tags per attack id.
_TAG_CACHE: dict[str, tuple[str, ...]] = {}


def owasp_tags_for(attack_id: str) -> tuple[str, ...]:
    """Return OWASP LLM Top 10 tags (``LLM01 — Prompt Injection``) for an
    attack id. Prefix rules match longer ids (e.g. the canary family)."""
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
