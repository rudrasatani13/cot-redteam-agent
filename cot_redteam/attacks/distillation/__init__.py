"""
Distillation attacks package.
"""

from cot_redteam.attacks.distillation.attacks import (
    CoTDistillationAttack,
    FewShotExtractionAttack,
)

__all__ = [
    "CoTDistillationAttack",
    "FewShotExtractionAttack",
]
