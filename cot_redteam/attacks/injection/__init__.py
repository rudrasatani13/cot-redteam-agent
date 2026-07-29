"""
Injection attacks package.
"""

from cot_redteam.attacks.injection.attacks import (
    CoTInjectionAttack,
    CoTInjectionIgnorePrevious,
    CoTInjectionRoleplay,
)

__all__ = [
    "CoTInjectionAttack",
    "CoTInjectionIgnorePrevious",
    "CoTInjectionRoleplay",
]
