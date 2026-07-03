"""
Attacks package - auto-discovers all attack modules.
"""
from cot_redteam.attacks.base import BaseAttack, AttackRegistry, auto_discover_attacks

# Auto-discover on import
auto_discover_attacks()

__all__ = ["BaseAttack", "AttackRegistry"]