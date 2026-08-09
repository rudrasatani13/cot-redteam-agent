"""Built-in scripted and provider-adapter targets."""

from cot_redteam.agent.targets.provider_adapter import ProviderTargetAdapter
from cot_redteam.agent.targets.scripted import (
    ScriptedFinalResponse,
    ScriptedStep,
    ScriptedTarget,
    ScriptedToolCall,
)

__all__ = [
    "ProviderTargetAdapter",
    "ScriptedFinalResponse",
    "ScriptedStep",
    "ScriptedTarget",
    "ScriptedToolCall",
]
