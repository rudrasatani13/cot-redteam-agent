"""
Core package for CoT Red Teaming Agent.
"""
from cot_redteam.core.types import (
    AttackCategory,
    ModelProvider,
    MonitorType,
    Severity,
    ModelConfig,
    AttackConfig,
    AttackPrompt,
    ModelResponse,
    AttackResult,
    AttackSpec,
    DatasetSample,
    MonitorResult,
    EvalResult,
)
from cot_redteam.core.config import Config, config

__all__ = [
    "AttackCategory",
    "ModelProvider",
    "MonitorType",
    "Severity",
    "ModelConfig",
    "AttackConfig",
    "AttackPrompt",
    "ModelResponse",
    "AttackResult",
    "AttackSpec",
    "DatasetSample",
    "MonitorResult",
    "EvalResult",
    "Config",
    "config",
]