"""
Manipulation attacks package.
"""
from cot_redteam.attacks.manipulation.attacks import (
    ReasoningPathForcing,
    CircularReasoningAttack,
    LogicalFallacyInjection,
    PremiseInjectionAttack,
)

__all__ = [
    "ReasoningPathForcing",
    "CircularReasoningAttack",
    "LogicalFallacyInjection",
    "PremiseInjectionAttack",
]