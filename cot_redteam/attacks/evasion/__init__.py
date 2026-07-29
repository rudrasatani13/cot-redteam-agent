"""
Evasion attacks package.
"""

from cot_redteam.attacks.evasion.attacks import (
    DualProcessAttack,
    MonitorAwarenessAttack,
    NaturalLanguageCamouflageAttack,
    StealthReasoningAttack,
)

__all__ = [
    "MonitorAwarenessAttack",
    "StealthReasoningAttack",
    "DualProcessAttack",
    "NaturalLanguageCamouflageAttack",
]
