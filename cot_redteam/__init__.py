"""
CoT Red Teaming Agent — Automated CoT Red Teaming Framework.
"""
__version__ = "0.1.0"

from cot_redteam.core import (
    AttackCategory,
    ModelProvider,
    MonitorType,
    ModelConfig,
    AttackResult,
    MonitorResult,
    EvalResult,
)
from cot_redteam.attacks import BaseAttack, AttackRegistry
from cot_redteam.models import BaseModel, ModelRegistry
from cot_redteam.monitors import BaseMonitor, MonitorRegistry

__all__ = [
    "AttackCategory",
    "ModelProvider",
    "MonitorType",
    "ModelConfig",
    "AttackResult",
    "MonitorResult",
    "EvalResult",
    "BaseAttack",
    "AttackRegistry",
    "BaseModel",
    "ModelRegistry",
    "BaseMonitor",
    "MonitorRegistry",
]