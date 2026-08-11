"""OWASP LLM Top 10 tagging for attacks and reports.

Maps attack ids (exact or prefix) to the OWASP Top 10 for LLM Applications
(2025). The mapping is conservative: only clearly fitting families are
tagged; everything else renders as "—" so the report does not overclaim.
"""

from __future__ import annotations

# (prefix or exact id, (code, name))
_OWASP_RULES: tuple[tuple[str, tuple[str, str]], ...] = (
    ("injection.system_canary", ("LLM01", "Prompt Injection")),
    ("injection.crescendo_canary", ("LLM01", "Prompt Injection")),
    ("injection.cot_injection", ("LLM01", "Prompt Injection")),
    ("injection.ignore_previous_reasoning", ("LLM01", "Prompt Injection")),
    ("injection.roleplay_injection", ("LLM01", "Prompt Injection")),
    ("injection.system_canary", ("LLM02", "Sensitive Information Disclosure")),
    ("injection.system_canary", ("LLM07", "System Prompt Leakage")),
    ("injection.crescendo_canary", ("LLM07", "System Prompt Leakage")),
    # Jailbreak (forbidden behavior) is NOT prompt injection; it maps only to
    # improper output handling downstream (LLM05).
    ("harm.forbidden_behavior", ("LLM05", "Improper Output Handling")),
    ("steganography.", ("LLM02", "Sensitive Information Disclosure")),
    ("distillation.", ("LLM03", "Supply Chain")),
    # Monitor evasion is not excessive agency (LLM06) — no rule for "evasion.".
)

# Cache of resolved tags per attack id.
_TAG_CACHE: dict[str, tuple[str, ...]] = {}


def owasp_tags_for(attack_id: str) -> tuple[str, ...]:
    """Return OWASP LLM Top 10 tags (``LLM01 — Prompt Injection``) for an
    attack id. Prefix rules match longer ids (e.g. the canary family)."""
    if attack_id in _TAG_CACHE:
        return _TAG_CACHE[attack_id]
    tags: list[str] = []
    for rule_id, (code, name) in _OWASP_RULES:
        if attack_id == rule_id or attack_id.startswith(rule_id):
            label = f"{code} — {name}"
            if label not in tags:
                tags.append(label)
    result = tuple(tags)
    _TAG_CACHE[attack_id] = result
    return result


def reset_tag_cache() -> None:
    """Test-only hook: clear the id -> tags cache."""
    _TAG_CACHE.clear()
