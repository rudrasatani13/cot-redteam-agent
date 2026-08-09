"""Agent-security Python API: deterministic in-memory scenario runs."""

from __future__ import annotations

import uuid
from typing import Any

from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.engine import AgentExecutionEngine
from cot_redteam.agent.scenarios.support import (
    support_fixture,
    support_scenario,
)
from cot_redteam.agent.targets.scripted import ScriptedTarget
from cot_redteam.agent.types import AgentRun
from cot_redteam.agent.worlds.support import SupportAgentWorld
from cot_redteam.core.config import AppConfig
from cot_redteam.core.invocation import InvocationService
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import ProgressCallback
from cot_redteam.storage.sqlite import SQLiteRunStore


def _default_invocation_service() -> InvocationService:
    config = AppConfig.model_validate(
        {
            "providers": {"mock": {"kind": "mock"}},
            "evaluation": {"models": ["mock:m"]},
        }
    )
    return InvocationService(config)


async def run_agent_scenario(
    *,
    scenario_id: str,
    fixture: str,
    settings: AgentSecuritySettings | None = None,
    invocation_service: InvocationService | None = None,
    run_store: SQLiteRunStore | None = None,
    manifest: dict[str, Any] | None = None,
    run_id: str | None = None,
    session_id: str | None = None,
    seed: int = 42,
    progress: ProgressCallback | None = None,
) -> AgentRun:
    """Run one scripted scenario fixture entirely in memory.

    Deterministic for scripted fixtures: same scenario/fixture/seed yields
    the same trajectory digest and outcome with the mock provider. When a
    ``run_store`` is supplied, the run is persisted crash-safely: the run
    row begins as RUNNING before target execution, retained events append
    transactionally, and the row finalizes with status/outcome/digests.
    """
    scenario = support_scenario(scenario_id)
    fixture_spec = support_fixture(scenario_id, fixture)
    settings = settings or AgentSecuritySettings()
    world = SupportAgentWorld(initial_state=fixture_spec.initial_state)
    target = ScriptedTarget(
        script=fixture_spec.script,
        target_id="scripted",
        target_version=fixture_spec.version,
        retain_final_response=settings.retention.retain_final_response,
    )
    service = invocation_service or _default_invocation_service()
    resolved_run_id = run_id or f"agent-{uuid.uuid4().hex[:12]}"
    resolved_session_id = session_id or f"session-{uuid.uuid4().hex[:12]}"
    if run_store is not None:
        # Prior non-current RUNNING rows (crashed processes) become
        # INTERRUPTED; never completed or secure.
        run_store.recover_incomplete_agent_runs(exclude_run_id=resolved_run_id)
    engine = AgentExecutionEngine(
        scenario=scenario,
        fixture=fixture_spec,
        world=world,
        target=target,
        invocation_service=service,
        budget=BudgetTracker(settings.budgets),
        settings=settings,
        progress=progress,
        run_store=run_store,
        manifest=manifest,
    )
    try:
        run = await engine.run(
            run_id=resolved_run_id,
            session_id=resolved_session_id,
            seed=seed,
        )
    finally:
        await target.aclose()
    return run
