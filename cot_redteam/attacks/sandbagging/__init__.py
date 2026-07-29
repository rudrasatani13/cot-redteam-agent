"""
Sandbagging attacks package.
"""

from cot_redteam.attacks.sandbagging.attacks import (
    CapabilityHidingAttack,
    SandbaggingDetectionAttack,
    SelectiveCompetenceAttack,
)

__all__ = [
    "SandbaggingDetectionAttack",
    "CapabilityHidingAttack",
    "SelectiveCompetenceAttack",
]
