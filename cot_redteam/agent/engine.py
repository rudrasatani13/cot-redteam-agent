"""Agent execution engine: target run + deterministic oracles.

The engine wires the constrained runtime (gateway, recorder, approval
gate, invocation boundary), runs the target against the simulated world,
captures immutable pre/post snapshots, evaluates the scenario's required
oracles, aggregates the outcome, and builds findings. Provider/target/
world/oracle/budget failures can never produce a clean security result.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.gateway import ToolGateway
from cot_redteam.agent.oracles.base import OracleRunner
from cot_redteam.agent.oracles.support import support_oracle
from cot_redteam.agent.scenarios.support import (
    SupportScenario,
    SupportWorldFixture,
)
from cot_redteam.agent.target import (
    AgentTargetRequest,
    Target,
    TargetRuntime,
)
from cot_redteam.agent.trajectory import TrajectoryRecorder
from cot_redteam.agent.types import (
    AgentOutcome,
    AgentRun,
    AgentRunStatus,
    Finding,
    OracleResult,
    OracleVerdict,
    VersionedRef,
    aggregate_outcome,
)
from cot_redteam.agent.worlds.base import BaseWorld
from cot_redteam.core.invocation import InvocationService
from cot_redteam.core.types import JsonValue
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import ProgressCallback


class PolicyApprovalGate:
    """Approval interface backed by the scenario's approval policy."""

    def __init__(self, *, approved_actions: tuple[str, ...] = ()) -> None:
        self.approved_actions = frozenset(approved_actions)

    async def request(
        self,
        *,
        approval_id: str,
        subject_action: str,
        principal: str,
        policy_id: str,
        policy_version: str,
    ) -> bool:
        del approval_id, principal, policy_id, policy_version
        return subject_action in self.approved_actions


def _status_for_outcome(outcome: AgentOutcome) -> AgentRunStatus:
    if outcome in (AgentOutcome.INVARIANT_HELD, AgentOutcome.VERIFIED_EXPLOIT):
        return AgentRunStatus.COMPLETED
    if outcome is AgentOutcome.INCONCLUSIVE:
        return AgentRunStatus.PARTIAL
    return AgentRunStatus.FAILED


def _budget_snapshot(budget: BudgetTracker, service: InvocationService) -> dict[str, JsonValue]:
    snap = budget.snapshot()
    roles: dict[str, JsonValue] = {}
    ledger = service.snapshot()
    for role, record in ledger.records.items():
        roles[role] = {
            "requests": record.requests,
            "input_tokens": record.input_tokens,
            "output_tokens": record.output_tokens,
            "estimated_cost": str(record.estimated_cost),
            "pricing_known": record.pricing_known,
            "failed": record.failed,
        }
    return {
        "requests": snap.requests,
        "input_tokens": snap.input_tokens,
        "output_tokens": snap.output_tokens,
        "estimated_cost": str(snap.estimated_cost),
        "elapsed_seconds": snap.elapsed_seconds,
        "exceeded": snap.exceeded,
        "unpriced_requests": ledger.unpriced_requests,
        "roles": roles,
    }


class AgentExecutionEngine:
    def __init__(
        self,
        *,
        scenario: SupportScenario,
        fixture: SupportWorldFixture,
        world: BaseWorld,
        target: Target,
        invocation_service: InvocationService,
        budget: BudgetTracker,
        settings: AgentSecuritySettings,
        progress: ProgressCallback | None = None,
        run_store: object | None = None,
        manifest: dict[str, Any] | None = None,
    ) -> None:
        self.scenario = scenario
        self.fixture = fixture
        self.world = world
        self.target = target
        self.invocation_service = invocation_service
        self.budget = budget
        self.settings = settings
        self.progress = progress
        self.run_store = run_store
        self.manifest = manifest

    def _new_gateway(self, recorder: TrajectoryRecorder) -> ToolGateway:
        return ToolGateway(
            world=self.world,
            trajectory=recorder,
            scenario_id=self.scenario.id,
            tool_allowlist=self.scenario.tool_allowlist,
            max_actions=self.scenario.max_actions,
            max_serialized_argument_bytes=self.settings.max_serialized_argument_bytes,
            max_serialized_result_bytes=self.settings.max_serialized_result_bytes,
            tool_timeout_seconds=self.settings.tool_timeout_seconds,
            max_concurrent_tool_calls=self.settings.max_concurrent_tool_calls,
            authorization_policy=self.scenario.authorization_policy,
        )

    def _run_required_oracles(
        self,
        pre,
        post,
        trajectory,
    ) -> tuple[OracleResult, ...]:
        canary = (
            next(iter(self.world.canaries.values()), "") if hasattr(self.world, "canaries") else ""
        )
        results: list[OracleResult] = []
        for oracle_id in self.scenario.required_oracles:
            oracle = support_oracle(
                self.scenario.id,
                oracle_id,
                canary=canary,
                required_approvals=self.scenario.required_approvals,
                protected_resources=self.scenario.protected_resources,
            )
            results.append(OracleRunner(oracle).evaluate(pre, post, trajectory))
        return tuple(results)

    @staticmethod
    def _build_findings(oracle_results: tuple[OracleResult, ...]) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for index, result in enumerate(oracle_results):
            if result.verdict is OracleVerdict.VERIFIED_EXPLOIT:
                severity = "high"
            elif result.verdict is OracleVerdict.ERROR:
                severity = "error"
            else:
                continue
            findings.append(
                Finding(
                    finding_id=f"finding-{index}",
                    oracle_id=result.oracle_id,
                    category=result.oracle_id,
                    severity=severity,
                    summary=result.summary,
                    evidence_event_ids=result.evidence_event_ids,
                )
            )
        return tuple(findings)

    async def run(
        self,
        *,
        run_id: str,
        session_id: str,
        seed: int,
    ) -> AgentRun:
        started_at = datetime.now(timezone.utc)
        retention_settings = self.settings.retention
        store = self.run_store
        event_sink = None
        if store is not None:

            def _sink(envelope: Any) -> None:
                store.append_agent_events(  # type: ignore[attr-defined]
                    run_id,
                    [envelope],
                    retention=retention_settings,
                )

            event_sink = _sink
            self._begin_run_row(run_id, session_id, started_at, store)
        recorder = TrajectoryRecorder(
            run_id=run_id,
            session_id=session_id,
            agent_id=self.target.id,
            progress=self.progress,
            event_sink=event_sink,
        )
        gateway = self._new_gateway(recorder)
        approvals = PolicyApprovalGate(approved_actions=self.scenario.approved_actions)
        runtime = TargetRuntime(
            run_id=run_id,
            session_id=session_id,
            invocation_service=self.invocation_service,
            tool_gateway=gateway,
            trajectory=recorder,
            approvals=approvals,
            budget=self.budget,
            progress=self.progress,
        )
        request = AgentTargetRequest(
            scenario_id=self.scenario.id,
            scenario_version=self.scenario.version,
            attack_id=f"scripted:{self.fixture.fixture}",
            attack_version=self.fixture.version,
            run_id=run_id,
            session_id=session_id,
            seed=seed,
            user_input=(
                f"Handle ticket content for scenario {self.scenario.id} "
                f"fixture {self.fixture.fixture}."
            ),
        )
        pre = self.world.snapshot()
        target_error: str | None = None
        try:
            await self.target.run(request, runtime)
        except Exception as exc:  # noqa: BLE001 - honest partial/failed semantics
            target_error = str(exc)[:500]
        post = self.world.snapshot()
        trajectory = recorder.build_trajectory()
        oracle_results = self._run_required_oracles(pre, post, trajectory)

        outcome = aggregate_outcome(oracle_results)
        if target_error is not None and outcome is not AgentOutcome.VERIFIED_EXPLOIT:
            # A target failure cannot produce a clean result; keep proven
            # exploit evidence when an oracle can still prove it.
            outcome = AgentOutcome.ERROR
        status = _status_for_outcome(outcome)
        findings = self._build_findings(oracle_results)

        metadata: dict[str, Any] = {
            "retained": {
                "final_response": retention_settings.retain_final_response,
                "tool_arguments": retention_settings.retain_tool_arguments,
                "tool_results": retention_settings.retain_tool_results,
                "memory_values": retention_settings.retain_memory_values,
                "world_values": retention_settings.retain_world_values,
            }
        }
        run = AgentRun(
            run_id=run_id,
            session_id=session_id,
            scenario_ref=VersionedRef(id=self.scenario.id, version=self.scenario.version),
            target_ref=VersionedRef(id=self.target.id, version=self.target.version),
            world_ref=VersionedRef(id=self.world.world_id, version=self.world.world_version),
            attack_ref=VersionedRef(
                id=f"scripted:{self.fixture.fixture}",
                version=self.fixture.version,
            ),
            status=status,
            outcome=outcome,
            trajectory=trajectory,
            pre_snapshot_digest=pre.digest,
            post_snapshot_digest=post.digest,
            oracle_results=oracle_results,
            findings=findings,
            budget_snapshot=_budget_snapshot(self.budget, self.invocation_service),
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            error=target_error,
            metadata=metadata,
        )
        if store is not None:
            store.finalize_agent_run(  # type: ignore[attr-defined]
                run,
                retention=retention_settings,
                manifest=self.manifest,
            )
        return run

    def _begin_run_row(
        self,
        run_id: str,
        session_id: str,
        started_at: datetime,
        store: object,
    ) -> None:
        from cot_redteam.agent.types import AgentTrajectory

        shell = AgentRun(
            run_id=run_id,
            session_id=session_id,
            scenario_ref=VersionedRef(id=self.scenario.id, version=self.scenario.version),
            target_ref=VersionedRef(id=self.target.id, version=self.target.version),
            world_ref=VersionedRef(id=self.world.world_id, version=self.world.world_version),
            attack_ref=VersionedRef(
                id=f"scripted:{self.fixture.fixture}",
                version=self.fixture.version,
            ),
            status=AgentRunStatus.RUNNING,
            trajectory=AgentTrajectory(run_id=run_id, session_id=session_id, events=()),
            budget_snapshot={},
            started_at=started_at,
        )
        store.begin_agent_run(  # type: ignore[attr-defined]
            shell,
            retention=self.settings.retention,
        )
