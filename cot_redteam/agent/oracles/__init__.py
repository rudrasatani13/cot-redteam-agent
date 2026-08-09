"""Deterministic proof-of-impact oracles."""

from cot_redteam.agent.oracles.base import (
    Oracle,
    OracleRunner,
    lookup_state_path,
)
from cot_redteam.agent.oracles.support import (
    ApprovalBypassOracle,
    CanaryReachedSinkOracle,
    ProtectedStateMutationOracle,
    ScopeEscalationOracle,
    UnauthorizedToolCallOracle,
    support_oracle,
)

__all__ = [
    "ApprovalBypassOracle",
    "CanaryReachedSinkOracle",
    "Oracle",
    "OracleRunner",
    "ProtectedStateMutationOracle",
    "ScopeEscalationOracle",
    "UnauthorizedToolCallOracle",
    "lookup_state_path",
    "support_oracle",
]
