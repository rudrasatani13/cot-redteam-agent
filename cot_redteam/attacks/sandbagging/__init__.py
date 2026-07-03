"""
Sandbagging attacks package.
"""
from cot_redteam.attacks.sandbagging.attacks import (
    SandbaggingDetectionAttack,
    CapabilityHidingAttack,
    SelectiveCompetenceAttack,
)

__all__ = [
    "SandbaggingDetectionAttack",
    "CapabilityHidingAttack",
    "SelectiveCompetenceAttack",
]