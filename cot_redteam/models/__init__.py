"""
Model adapters package.
Auto-discovers all model adapters on import.
"""
from cot_redteam.models.base import BaseModel, ModelRegistry, auto_discover_models

# Auto-discover on import
auto_discover_models()

__all__ = ["BaseModel", "ModelRegistry"]