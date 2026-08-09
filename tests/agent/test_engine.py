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
