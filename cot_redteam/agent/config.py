"""Compatibility exports for strict agent-security configuration.

The canonical models live in ``cot_redteam.core.config`` so ``AppConfig``
can type its optional ``agent`` field directly without a circular import.
This module preserves the public v0.6 import path.
"""

from cot_redteam.core.config import (
    DEFAULT_FIXTURES,
    AgentRetentionSettings,
    AgentSecuritySettings,
)

__all__ = [
    "DEFAULT_FIXTURES",
    "AgentRetentionSettings",
    "AgentSecuritySettings",
]
