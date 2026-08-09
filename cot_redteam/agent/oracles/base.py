"""Deterministic oracle protocol and failure-safe runner.

Oracles operate only on immutable pre/post world snapshots and the
structured trajectory. LLM judges are never called by proof oracles; an
oracle exception becomes ``OracleResult(ERROR)`` and can never produce a
clean/secure outcome.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from cot_redteam.agent.types import AgentTrajectory, OracleResult, OracleVerdict
from cot_redteam.agent.worlds.base import WorldSnapshot


class Oracle(Protocol):
    id: str
    version: str

    def evaluate(
        self,
        pre: WorldSnapshot,
        post: WorldSnapshot,
        trajectory: AgentTrajectory,
    ) -> OracleResult: ...


class OracleRunner:
    """Executes an oracle and converts any exception into ERROR."""

    def __init__(self, oracle: Oracle) -> None:
        self.oracle = oracle

    def evaluate(
        self,
        pre: WorldSnapshot,
        post: WorldSnapshot,
        trajectory: AgentTrajectory,
    ) -> OracleResult:
        try:
            return self.oracle.evaluate(pre, post, trajectory)
        except Exception as exc:  # noqa: BLE001 - oracle failures never become clean
            return OracleResult(
                oracle_id=self.oracle.id,
                oracle_version=self.oracle.version,
                verdict=OracleVerdict.ERROR,
                summary="oracle evaluation failed",
                pre_snapshot_digest=pre.digest,
                post_snapshot_digest=post.digest,
                error=str(exc)[:500],
            )


def lookup_state_path(state: Mapping[str, object], dotted_path: str) -> object | None:
    """Look up a value in world state by a ``bucket:key:...`` path.

    The first segment maps to a state bucket (``crm`` -> ``crm_records``);
    the remaining segments traverse the bucket. ``crm:C-7:email`` ->
    ``state["crm_records"]["C-7"]["email"]``. Returns None when any
    intermediate key is missing.
    """
    parts = dotted_path.split(":")
    if not parts:
        return None
    bucket = {
        "support": "tickets",
        "crm": "crm_records",
        "outbound": "outbound_sink",
        "protected": "protected_state",
        "approval": "approval_state",
        "canary": "canaries",
    }.get(parts[0])
    if bucket is None or bucket not in state:
        return None
    container: object = state[bucket]
    for part in parts[1:]:
        if not isinstance(container, Mapping) or part not in container:
            return None
        container = container[part]
    return container
