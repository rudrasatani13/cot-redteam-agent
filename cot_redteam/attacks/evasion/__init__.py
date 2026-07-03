"""
Evasion attacks package.
"""
from cot_redteam.attacks.evasion.attacks import (
    MonitorAwarenessAttack,
    StealthReasoningAttack,
    DualProcessAttack,
    NaturalLanguageCamouflageAttack,
)

__all__ = [
    "MonitorAwarenessAttack",
    "StealthReasoningAttack",
    "DualProcessAttack",
    "NaturalLanguageCamouflageAttack",
]