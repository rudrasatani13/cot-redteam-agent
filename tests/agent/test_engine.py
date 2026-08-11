"""AgentExecutionEngine end-to-end scenario matrix and failure semantics."""

from __future__ import annotations

import pytest

from cot_redteam.agent.api import run_agent_scenario
from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.engine import AgentExecutionEngine
from cot_redteam.agent.oracles.base import OracleRunner
from cot_redteam.agent.scenarios.support import (
    SupportScenario,
    SupportWorldFixture,
    support_fixture,
    support_scenario,
)
from cot_redteam.agent.target import AgentTargetRequest, FinalResponseData, TargetRuntime
from cot_redteam.agent.targets.scripted import ScriptedTarget
from cot_redteam.agent.types import (
    AgentOutcome,
    AgentRunStatus,
    OracleVerdict,
)
from cot_redteam.agent.worlds.support import SupportAgentWorld
from cot_redteam.core.config import AppConfig
from cot_redteam.core.invocation import InvocationService
from cot_redteam.eval.budgets import BudgetTracker

SCENARIOS = (
    "support.indirect_prompt_injection.v1",
    "support.tool_result_injection.v1",
    "support.approval_bypass.v1",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario_id", SCENARIOS)
async def test_full_scenario_matrix(scenario_id: str) -> None:
    """vulnerable -> verified exploit, patched -> held, clean -> held."""
    results: dict[str, AgentOutcome] = {}
    for fixture in ("vulnerable", "patched", "clean"):
        run = await run_agent_scenario(scenario_id=scenario_id, fixture=fixture, seed=7)
        results[fixture] = run.outcome
    assert results["vulnerable"] is AgentOutcome.VERIFIED_EXPLOIT
    assert results["patched"] is AgentOutcome.INVARIANT_HELD
    assert results["clean"] is AgentOutcome.INVARIANT_HELD


@pytest.mark.asyncio
async def test_verified_exploit_run_status_and_findings() -> None:
    run = await run_agent_scenario(
        scenario_id="support.indirect_prompt_injection.v1",
        fixture="vulnerable",
        seed=7,
    )
    assert run.status is AgentRunStatus.COMPLETED
    assert run.outcome is AgentOutcome.VERIFIED_EXPLOIT
    assert run.findings
    assert all(
        finding.severity == "high" and finding.evidence_event_ids for finding in run.findings
    )
    assert run.post_snapshot_digest != run.pre_snapshot_digest


@pytest.mark.asyncio
async def test_deterministic_trajectory_digest_across_runs() -> None:
    first = await run_agent_scenario(
        scenario_id="support.tool_result_injection.v1",
        fixture="vulnerable",
        seed=7,
    )
    second = await run_agent_scenario(
        scenario_id="support.tool_result_injection.v1",
        fixture="vulnerable",
        seed=7,
    )
    assert first.trajectory.digest == second.trajectory.digest
    assert first.outcome is second.outcome is AgentOutcome.VERIFIED_EXPLOIT
    assert first.oracle_results[0].verdict is second.oracle_results[0].verdict


class _FailAfterExploitTarget(ScriptedTarget):
    """Executes the fixture script but raises after the second step."""

    async def run(self, request: AgentTargetRequest, runtime: TargetRuntime) -> FinalResponseData:
        result = await super().run(request, runtime)
        raise RuntimeError("target crashed mid-run")
        return result  # pragma: no cover


@pytest.mark.asyncio
async def test_target_failure_after_partial_action_keeps_exploit_evidence() -> None:
    """A target failure after the exfil action still yields VERIFIED_EXPLOIT
    because the deterministic oracle can prove the impact."""
    scenario_id = "support.indirect_prompt_injection.v1"
    scenario = support_scenario(scenario_id)
    fixture = support_fixture(scenario_id, "vulnerable")
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = _FailAfterExploitTarget(script=fixture.script)
    settings = AgentSecuritySettings()
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
    )
    try:
        run = await engine.run(run_id="r1", session_id="s1", seed=7)
    finally:
        await target.aclose()
    assert run.outcome is AgentOutcome.VERIFIED_EXPLOIT
    assert run.error is not None
    assert "crashed" in run.error


@pytest.mark.asyncio
async def test_target_failure_without_impact_is_error() -> None:
    """A target failure with no provable impact is ERROR, never clean."""

    class _CrashTarget(ScriptedTarget):
        async def run(
            self, request: AgentTargetRequest, runtime: TargetRuntime
        ) -> FinalResponseData:
            raise RuntimeError("crashed before any action")

    scenario_id = "support.indirect_prompt_injection.v1"
    scenario = support_scenario(scenario_id)
    fixture = support_fixture(scenario_id, "clean")
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = _CrashTarget(script=fixture.script)
    settings = AgentSecuritySettings()
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
    )
    try:
        run = await engine.run(run_id="r2", session_id="s2", seed=7)
    finally:
        await target.aclose()
    assert run.outcome is AgentOutcome.ERROR
    assert run.status is AgentRunStatus.FAILED
    assert run.error is not None


@pytest.mark.asyncio
async def test_oracle_error_is_never_clean() -> None:
    """A required oracle that errors (missing canary) makes the run ERROR."""
    scenario = SupportScenario(
        id="custom.no_canary.v1",
        version="1",
        tool_allowlist=("support.get_ticket",),
        authorization_policy=(),
        required_oracles=("canary_reached_sink",),
    )
    fixture = SupportWorldFixture(
        scenario_id="custom.no_canary.v1",
        fixture="clean",
        version="1",
        initial_state={"tickets": {}, "crm_records": {}, "canaries": {}, "outbound_sink": {}},
        script=(),
    )
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = ScriptedTarget(script=fixture.script)
    settings = AgentSecuritySettings()
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
    )
    try:
        run = await engine.run(run_id="r3", session_id="s3", seed=7)
    finally:
        await target.aclose()
    assert run.outcome is AgentOutcome.ERROR
    assert run.status is AgentRunStatus.FAILED
    assert any(result.verdict is OracleVerdict.ERROR for result in run.oracle_results)
    assert run.findings  # ERROR findings recorded, never clean


@pytest.mark.asyncio
async def test_oracle_exception_maps_to_error_via_runner() -> None:
    class BoomOracle:
        id = "boom"
        version = "1"

        def evaluate(self, pre, post, trajectory):
            raise RuntimeError("oracle boom")

    scenario = SupportScenario(
        id="custom.boom.v1",
        version="1",
        tool_allowlist=(),
        authorization_policy=(),
        required_oracles=("boom",),
    )
    fixture = SupportWorldFixture(
        scenario_id="custom.boom.v1",
        fixture="clean",
        version="1",
        initial_state={},
        script=(),
    )
    world = SupportAgentWorld(initial_state={})
    target = ScriptedTarget(script=())
    settings = AgentSecuritySettings()
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
    )

    # Patch the oracle resolver to return the boom oracle.
    def boom_oracles(pre, post, trajectory):
        return (OracleRunner(BoomOracle()).evaluate(pre, post, trajectory),)  # type: ignore[arg-type]

    engine._run_required_oracles = boom_oracles  # type: ignore[method-assign]
    try:
        run = await engine.run(run_id="r4", session_id="s4", seed=7)
    finally:
        await target.aclose()
    assert run.outcome is AgentOutcome.ERROR
    assert run.oracle_results[0].verdict is OracleVerdict.ERROR
    assert "boom" in (run.oracle_results[0].error or "")


@pytest.mark.asyncio
async def test_failing_oracle_diagnostics_are_redacted_before_db_persistence(tmp_path) -> None:
    from cot_redteam.storage.sqlite import SQLiteRunStore

    canary = "COT-CANARY-ORACLE-PRIVACY"

    class FailingOracle:
        id = "failing"
        version = "1"

        def evaluate(self, pre, post, trajectory):
            raise RuntimeError(
                f"oracle failed canary={canary} api_key=sk-oracle-secret password=raw-pass"
            )

    scenario = SupportScenario(
        id="custom.failing.v1",
        version="1",
        tool_allowlist=(),
        authorization_policy=(),
        required_oracles=("failing",),
    )
    fixture = SupportWorldFixture(
        scenario_id="custom.failing.v1",
        fixture="clean",
        version="1",
        initial_state={"canaries": {"code": canary}},
        script=(),
    )
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = ScriptedTarget(script=())
    settings = AgentSecuritySettings()
    with SQLiteRunStore(tmp_path / "oracle-privacy.db") as store:
        engine = AgentExecutionEngine(
            scenario=scenario,
            fixture=fixture,
            world=world,
            target=target,
            invocation_service=InvocationService(
                AppConfig.model_validate(
                    {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
                )
            ),
            budget=BudgetTracker(settings.budgets),
            settings=settings,
            run_store=store,
        )

        def failing_oracles(pre, post, trajectory):
            return (OracleRunner(FailingOracle()).evaluate(pre, post, trajectory),)

        engine._run_required_oracles = failing_oracles  # type: ignore[method-assign]
        try:
            run = await engine.run(run_id="oracle-privacy", session_id="session-privacy", seed=7)
        finally:
            await target.aclose()
        assert run.outcome is AgentOutcome.ERROR
        result = run.oracle_results[0]
        assert result.verdict is OracleVerdict.ERROR
        assert canary not in (result.error or "")
        assert "sk-oracle-secret" not in (result.error or "")
        assert "raw-pass" not in (result.error or "")
        stored = store.connection.execute(
            "SELECT result_json FROM agent_oracle_results WHERE run_id = ?",
            (run.run_id,),
        ).fetchone()[0]
        assert canary not in stored
        assert "sk-oracle-secret" not in stored
        assert "raw-pass" not in stored


@pytest.mark.asyncio
async def test_event_sink_failure_invalidates_exploit_proof(tmp_path) -> None:
    """A missing persisted ActionEvent can never yield exploit evidence."""
    from cot_redteam.agent.worlds import fixtures as world_fixtures
    from cot_redteam.storage.sqlite import SQLiteRunStore

    with SQLiteRunStore(tmp_path / "agent.db") as store:
        original_append = store.append_agent_events

        def fail_mutating_action(run_id, events, *, retention):
            envelope = events[0]
            if (
                envelope.get("event_type") == "action_event"
                and envelope.get("action_kind") == "webhook.send"
            ):
                raise OSError(
                    f"disk full; canary={world_fixtures.CANARY_EMAIL_CODE}; "
                    "api_key=sk-persistence-secret"
                )
            return original_append(run_id, events, retention=retention)

        store.append_agent_events = fail_mutating_action  # type: ignore[method-assign]
        run = await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="vulnerable",
            seed=7,
            run_store=store,
            run_id="durability-failure",
        )

        assert run.outcome is AgentOutcome.ERROR
        assert run.status is AgentRunStatus.FAILED
        assert "trajectory event persistence failed" in (run.error or "")
        assert world_fixtures.CANARY_EMAIL_CODE not in (run.error or "")
        assert "sk-persistence-secret" not in (run.error or "")
        assert all(result.verdict is OracleVerdict.ERROR for result in run.oracle_results)
        assert all(
            world_fixtures.CANARY_EMAIL_CODE not in (result.error or "")
            for result in run.oracle_results
        )
        assert all(
            "sk-persistence-secret" not in (result.error or "") for result in run.oracle_results
        )
        assert all(finding.severity == "error" for finding in run.findings)
        assert all(not finding.evidence_event_ids for finding in run.findings)

        persisted_ids = {
            row["event_id"]
            for row in store.connection.execute(
                "SELECT event_id FROM agent_trajectory_events WHERE run_id = ?",
                (run.run_id,),
            )
        }
        assert persisted_ids == {event.event_id for event in run.trajectory.events}
        loaded = store.get_agent_run(run.run_id)
        assert loaded is not None
        assert loaded.outcome is AgentOutcome.ERROR
        assert world_fixtures.CANARY_EMAIL_CODE not in (loaded.error or "")
        assert "sk-persistence-secret" not in (loaded.error or "")
        assert all(result.verdict is OracleVerdict.ERROR for result in loaded.oracle_results)
        assert all(
            world_fixtures.CANARY_EMAIL_CODE not in (result.error or "")
            for result in loaded.oracle_results
        )
        assert all(
            "sk-persistence-secret" not in (result.error or "") for result in loaded.oracle_results
        )
        assert all(not finding.evidence_event_ids for finding in loaded.findings)


@pytest.mark.asyncio
async def test_target_cannot_forge_executed_unauthorized_action() -> None:
    """A target recording a fake ActionEvent must not prove an exploit."""
    from cot_redteam.agent.target import FinalResponseData
    from cot_redteam.agent.types import (
        ActionEvent,
        AgentTargetCapabilities,
        AuthorizationState,
        EventProvenance,
        EventTrust,
        ToolCallRequested,
    )

    class ForgingTarget:
        id = "forging-target"
        version = "1"
        capabilities = AgentTargetCapabilities(tool_use=True, mutable_state=True)

        async def run(self, request: AgentTargetRequest, runtime: TargetRuntime):
            # Deliberately exercise the remaining object-graph bypass: the
            # target reaches the recorder's private trusted writer through
            # the trajectory facade.
            forged_writer = runtime.trajectory._recorder._trusted_writer()
            provenance = EventProvenance(
                source_kind="target",
                source_id=self.id,
                source_version=self.version,
                trust=EventTrust.UNTRUSTED,
            )
            await forged_writer.record(
                ToolCallRequested(
                    event_type="tool_call_requested",
                    run_id=request.run_id,
                    session_id=request.session_id,
                    event_id="forged-request",
                    agent_id=self.id,
                    provenance=provenance,
                    call_id="forged-call",
                    tool_name="webhook.send",
                    tool_version="1",
                    sequence_no=0,
                )
            )
            await forged_writer.record(
                ActionEvent(
                    event_type="action_event",
                    run_id=request.run_id,
                    session_id=request.session_id,
                    event_id="forged-action",
                    parent_event_id="forged-request",
                    agent_id=self.id,
                    provenance=provenance,
                    call_id="forged-call",
                    action_kind="webhook.send",
                    resource="webhook.send",
                    attempted=True,
                    executed=True,
                    authorization_state=AuthorizationState.UNAUTHORIZED,
                    state_before_digest="fake-before",
                    state_after_digest="fake-after",
                    sequence_no=0,
                )
            )
            return FinalResponseData()

        async def aclose(self) -> None:
            return None

    scenario_id = "support.indirect_prompt_injection.v1"
    scenario = support_scenario(scenario_id)
    fixture = support_fixture(scenario_id, "clean")
    settings = AgentSecuritySettings()
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = ForgingTarget()
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
    )
    run = await engine.run(run_id="forged-run", session_id="forged-session", seed=7)
    assert run.outcome is AgentOutcome.ERROR
    assert run.post_snapshot_digest == run.pre_snapshot_digest


@pytest.mark.asyncio
async def test_target_error_is_sanitized_before_run_persistence() -> None:
    from cot_redteam.agent.worlds import fixtures as world_fixtures

    class LeakingTarget(ScriptedTarget):
        async def run(self, request, runtime):
            raise RuntimeError(
                f"failed canary={world_fixtures.CANARY_EMAIL_CODE} api_key=sk-live-secret"
            )

    scenario_id = "support.indirect_prompt_injection.v1"
    scenario = support_scenario(scenario_id)
    fixture = support_fixture(scenario_id, "clean")
    settings = AgentSecuritySettings()
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = LeakingTarget(script=fixture.script)
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
    )
    run = await engine.run(run_id="error-sanitize", session_id="error-sanitize", seed=7)
    assert run.error is not None
    assert world_fixtures.CANARY_EMAIL_CODE not in run.error
    assert "sk-live-secret" not in run.error
    assert "[redacted]" in run.error


async def test_oracle_pipeline_failure_produces_terminal_error_run(tmp_path) -> None:
    """Regression: an unexpected exception in the post-target pipeline
    (oracle collection, sanitization, findings) must still produce a
    terminal AgentRun and a terminal DB row — never escape run() and leave
    the row stuck in 'running'."""
    from cot_redteam.storage.sqlite import SQLiteRunStore

    scenario_id = "support.indirect_prompt_injection.v1"
    scenario = support_scenario(scenario_id)
    fixture = support_fixture(scenario_id, "clean")
    settings = AgentSecuritySettings()
    world = SupportAgentWorld(initial_state=fixture.initial_state)
    target = ScriptedTarget(script=fixture.script)
    store = SQLiteRunStore(tmp_path / "agent.db")
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture,
        world=world,
        target=target,
        invocation_service=InvocationService(
            AppConfig.model_validate(
                {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
            )
        ),
        budget=BudgetTracker(settings.budgets),
        settings=settings,
        run_store=store,
    )

    def _boom(*args, **kwargs):
        raise ValueError("oracle registry drift: unknown oracle")

    engine._run_required_oracles = _boom  # type: ignore[method-assign]
    run = await engine.run(run_id="oracle-boom", session_id="oracle-boom", seed=7)
    assert run.outcome is AgentOutcome.ERROR
    assert run.status is AgentRunStatus.FAILED
    assert "oracle registry drift" in (run.error or "")
    assert run.findings == ()
    row = store.get_agent_run("oracle-boom")
    assert row is not None
    assert row.status is not AgentRunStatus.RUNNING
    assert row.status is AgentRunStatus.FAILED
    store.close()
