"""Agent-security Python API: deterministic in-memory scenario runs."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.engine import AgentExecutionEngine
from cot_redteam.agent.replay import build_replay_artifact
from cot_redteam.agent.scenarios.support import (
    SUPPORT_SCENARIOS,
    support_fixture,
    support_scenario,
)
from cot_redteam.agent.target import Target
from cot_redteam.agent.targets.provider_adapter import ProviderTargetAdapter
from cot_redteam.agent.targets.scripted import ScriptedTarget
from cot_redteam.agent.types import AgentOutcome, AgentRun
from cot_redteam.agent.worlds.support import SupportAgentWorld
from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.invocation import InvocationService
from cot_redteam.core.types import ModelRef
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import ProgressCallback
from cot_redteam.storage.artifacts import ArtifactStore
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
    owns_invocation_service = invocation_service is None
    service = _default_invocation_service() if invocation_service is None else invocation_service
    target: Target | None = None
    try:
        if settings.target == "provider_adapter":
            if not settings.target_model:
                raise ConfigurationError("agent target=provider_adapter requires target_model")
            model_ref = ModelRef.parse(settings.target_model)
            if model_ref.provider not in service.config.providers:
                raise ConfigurationError(
                    f"agent target provider {model_ref.provider!r} is not configured; "
                    f"available: {', '.join(sorted(service.config.providers))}"
                )
            target = ProviderTargetAdapter(
                model=model_ref,
                system_prompt=settings.system_prompt,
                retain_final_response=settings.retention.retain_final_response,
            )
        else:
            target = ScriptedTarget(
                script=fixture_spec.script,
                target_id="scripted",
                target_version=fixture_spec.version,
                retain_final_response=settings.retention.retain_final_response,
            )
        assert target is not None
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
            # One budget tracker for both the engine and the invocation service:
            # the run budget snapshot and the role ledger must agree.
            budget=service.budget,
            settings=settings,
            progress=progress,
            run_store=run_store,
            manifest=manifest,
            enforce_authorization=settings.deny_unauthorized_tools,
        )
        return await engine.run(
            run_id=resolved_run_id,
            session_id=resolved_session_id,
            seed=seed,
        )
    finally:
        # Targets are always API-owned.  Invocation services follow normal
        # dependency-injection ownership: only the service constructed here
        # is closed; caller-provided services remain usable after the run.
        try:
            if target is not None:
                await target.aclose()
        finally:
            if owns_invocation_service:
                await service.aclose()


def save_replay_artifact(
    run: AgentRun,
    *,
    fixture: Any,
    settings: AgentSecuritySettings,
    artifact_store: ArtifactStore,
    run_store: SQLiteRunStore | None = None,
) -> tuple[str, str] | None:
    """Persist a checksummed replay artifact for verified-exploit runs.

    Returns (absolute_path, sha256) or None for non-exploit outcomes. Only
    verified exploits are saved; the run is never replayed from prose.
    """
    if run.outcome is not AgentOutcome.VERIFIED_EXPLOIT:
        return None
    artifact = build_replay_artifact(
        run,
        fixture=fixture,
        budget_configuration=settings.budgets.model_dump(mode="python"),
    )
    body = json.dumps(artifact, indent=2, sort_keys=True)
    write = artifact_store.write_text(
        f"{run.run_id}/replay.json",
        body,
        media_type="application/json",
    )
    artifact_store.write_text(
        f"{run.run_id}/replay.json.sha256",
        f"{write.record.sha256}  replay.json\n",
        media_type="text/plain",
    )
    if run_store is not None:
        run_store.save_replay_record(
            replay_id=artifact["replay_id"],
            original_run_id=run.run_id,
            schema_version=int(artifact["schema_version"]),
            relative_path=f"{run.run_id}/replay.json",
            sha256=write.record.sha256,
            byte_length=write.record.byte_length,
            world_fixture_digest=artifact["world_fixture_digest"],
            trajectory_digest=artifact["trajectory_digest"],
            metadata={"scenario_id": run.scenario_ref.id, "target_family": fixture.fixture},
        )
    return str(write.absolute_path), write.record.sha256


@dataclass(frozen=True)
class AgentScanResult:
    runs: tuple[AgentRun, ...]
    replay_paths: dict[str, tuple[str, str]]


async def run_agent_scan(
    config: AppConfig,
    *,
    run_store: SQLiteRunStore | None = None,
    artifact_store: ArtifactStore | None = None,
    progress: ProgressCallback | None = None,
) -> AgentScanResult:
    """Run the configured agent scenarios/fixtures and save replay
    artifacts for verified exploits."""
    settings = config.agent
    if settings is None:
        raise ConfigurationError("agent scan requires an 'agent' section in the config")
    scenario_ids = settings.scenarios or list(SUPPORT_SCENARIOS)
    fixture_names = settings.fixtures or ["vulnerable"]
    owns_store = run_store is None
    store = run_store or SQLiteRunStore(config.storage.path)
    artifacts = artifact_store or ArtifactStore(config.artifacts.root)
    service = InvocationService(
        config,
        budget=BudgetTracker(settings.budgets),
    )
    runs: list[AgentRun] = []
    replay_paths: dict[str, tuple[str, str]] = {}
    try:
        for scenario_id in scenario_ids:
            for fixture_name in fixture_names:
                run = await run_agent_scenario(
                    scenario_id=scenario_id,
                    fixture=fixture_name,
                    settings=settings,
                    invocation_service=service,
                    run_store=store,
                    seed=config.global_.seed,
                    progress=progress,
                )
                runs.append(run)
                saved = save_replay_artifact(
                    run,
                    fixture=support_fixture(scenario_id, fixture_name),
                    settings=settings,
                    artifact_store=artifacts,
                    run_store=store,
                )
                if saved is not None:
                    replay_paths[run.run_id] = saved
    finally:
        try:
            if owns_store:
                store.close()
        finally:
            # This service is constructed by the scan API and is shared by
            # all scenario runs in the scan.  Individual runs receive it as
            # a caller-owned dependency, so the scan closes it exactly once
            # after the loop completes (including failure paths).
            await service.aclose()
    return AgentScanResult(runs=tuple(runs), replay_paths=replay_paths)
