"""Agent world registries (worlds never import scenarios)."""

from cot_redteam.agent.worlds.base import BaseWorld, WorldSnapshot, state_digest
from cot_redteam.agent.worlds.support import SupportAgentWorld

__all__ = [
    "BaseWorld",
    "SupportAgentWorld",
    "WorldSnapshot",
    "state_digest",
]
