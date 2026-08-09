"""v0.6 agent-security domain: targets, trajectories, worlds, oracles.

The agent path evaluates *agent behavior*: only observed simulated actions
and deterministic state transitions may prove impact. Model text is
evidence about model behavior, never proof of agent impact.
"""

from cot_redteam.agent.types import (
    AGENT_EVENT_SCHEMA_VERSION,
    REPLAY_SCHEMA_VERSION,
    SUPPORT_WORLD_VERSION,
    AgentOutcome,
    AgentRun,
    AgentRunStatus,
    AgentTargetCapabilities,
    AgentTrajectory,
    OracleResult,
    OracleVerdict,
    aggregate_outcome,
)

__all__ = [
    "AGENT_EVENT_SCHEMA_VERSION",
    "REPLAY_SCHEMA_VERSION",
    "SUPPORT_WORLD_VERSION",
    "AgentOutcome",
    "AgentRun",
    "AgentRunStatus",
    "AgentTargetCapabilities",
    "AgentTrajectory",
    "OracleResult",
    "OracleVerdict",
    "aggregate_outcome",
]
