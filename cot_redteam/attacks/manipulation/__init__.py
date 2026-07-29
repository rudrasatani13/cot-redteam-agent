"""
Manipulation attacks package.
"""

from cot_redteam.attacks.manipulation.attacks import (
    CircularReasoningAttack,
    LogicalFallacyInjection,
    PremiseInjectionAttack,
    ReasoningPathForcing,
)

__all__ = [
    "ReasoningPathForcing",
    "CircularReasoningAttack",
    "LogicalFallacyInjection",
    "PremiseInjectionAttack",
]
