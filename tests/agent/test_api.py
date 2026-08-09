"""Agent API surface tests: run_agent_scenario persistence and manifests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from cot_redteam.agent.api import run_agent_scenario
from cot_redteam.agent.types import AgentOutcome, AgentRunStatus
from cot_redteam.core.config import AppConfig
from cot_redteam.core.invocation import InvocationService
from cot_redteam.eval.manifest import build_agent_manifest
from cot_redteam.storage.sqlite import SQLiteRunStore


class _TrackingInvocationService(InvocationService):
    def __init__(self, config: AppConfig | None = None, *, budget=None) -> None:
        config = config or AppConfig.model_validate(
            {"providers": {"mock": {"kind": "mock"}}, "evaluation": {"models": ["mock:m"]}}
        )
        super().__init__(config, budget=budget)
        self.aclose_calls = 0

    async def aclose(self) -> None:
        self.aclose_calls += 1
        await super().aclose()


class _FalseyTrackingInvocationService(_TrackingInvocationService):
    def __bool__(self) -> bool:
        return False


@pytest.mark.asyncio
async def test_api_run_with_store_and_manifest(tmp_path: Path) -> None:
    with SQLiteRunStore(tmp_path / "agent.db") as store:
        run = await run_agent_scenario(
            scenario_id="support.tool_result_injection.v1",
            fixture="vulnerable",
            seed=7,
            run_store=store,
            run_id="api-run-1",
            session_id="api-session-1",
        )
        assert run.run_id == "api-run-1"
        assert run.session_id == "api-session-1"
        assert run.outcome is AgentOutcome.VERIFIED_EXPLOIT
        assert run.status is AgentRunStatus.COMPLETED
        # The run persists and loads identically.
        loaded = store.get_agent_run("api-run-1")
        assert loaded is not None
        assert loaded.outcome is AgentOutcome.VERIFIED_EXPLOIT
        # Sanitized persisted view: loaded digest describes its own content;
        # the original digest is the preserved proof anchor.
        assert loaded.original_trajectory_digest == run.trajectory.digest
        # Manifest is deterministic and self-consistent.
        manifest = build_agent_manifest(loaded)
        assert manifest["run_id"] == "api-run-1"
        assert manifest["outcome"] == "verified_exploit"
        assert manifest["trajectory_digest"] == run.trajectory.digest
        assert manifest["findings"]
        assert manifest["manifest_digest"]


@pytest.mark.asyncio
async def test_api_deterministic_with_fixed_run_id(tmp_path: Path) -> None:
    """Fixed run_id + scenario + fixture + seed => same trajectory digest."""
    with SQLiteRunStore(tmp_path / "agent.db") as store:
        first = await run_agent_scenario(
            scenario_id="support.approval_bypass.v1",
            fixture="patched",
            seed=11,
            run_store=store,
            run_id="deterministic-run-1",
        )
        second = await run_agent_scenario(
            scenario_id="support.approval_bypass.v1",
            fixture="patched",
            seed=11,
            run_store=store,
            run_id="deterministic-run-2",
        )
        assert first.trajectory.digest == second.trajectory.digest
        assert first.outcome is second.outcome is AgentOutcome.INVARIANT_HELD


def test_api_runs_without_store_and_with_manifest(tmp_path: Path) -> None:
    manifest: dict = {}

    async def _run() -> None:
        run = await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="clean",
            seed=3,
        )
        manifest.update(build_agent_manifest(run))

    asyncio.run(_run())
    assert manifest["outcome"] == "invariant_held"
    assert manifest["oracles"]
    assert manifest["manifest_digest"]


@pytest.mark.asyncio
async def test_api_closes_internally_created_invocation_service(monkeypatch) -> None:
    import cot_redteam.agent.api as api_module

    service = _TrackingInvocationService()
    monkeypatch.setattr(api_module, "_default_invocation_service", lambda: service)
    await run_agent_scenario(
        scenario_id="support.indirect_prompt_injection.v1",
        fixture="clean",
        seed=7,
    )
    assert service.aclose_calls == 1


@pytest.mark.asyncio
async def test_api_does_not_close_caller_owned_invocation_service() -> None:
    service = _TrackingInvocationService()
    await run_agent_scenario(
        scenario_id="support.indirect_prompt_injection.v1",
        fixture="clean",
        invocation_service=service,
        seed=7,
    )
    assert service.aclose_calls == 0
    await service.aclose()
    assert service.aclose_calls == 1


@pytest.mark.asyncio
async def test_api_uses_falsey_caller_owned_invocation_service(monkeypatch) -> None:
    import cot_redteam.agent.api as api_module

    service = _FalseyTrackingInvocationService()

    def unexpected_default() -> InvocationService:
        raise AssertionError("caller-provided service must not be replaced")

    monkeypatch.setattr(api_module, "_default_invocation_service", unexpected_default)
    await run_agent_scenario(
        scenario_id="support.indirect_prompt_injection.v1",
        fixture="clean",
        invocation_service=service,
        seed=7,
    )
    assert service.aclose_calls == 0
    await service.aclose()


@pytest.mark.asyncio
async def test_agent_scan_closes_shared_invocation_service_on_failure(
    tmp_path: Path, monkeypatch
) -> None:
    import cot_redteam.agent.api as api_module
    from cot_redteam.agent.api import run_agent_scan
    from cot_redteam.storage.artifacts import ArtifactStore

    created: list[_TrackingInvocationService] = []

    class TrackingScanService(_TrackingInvocationService):
        def __init__(self, config: AppConfig, *, budget) -> None:
            super().__init__(config, budget=budget)
            created.append(self)

    monkeypatch.setattr(api_module, "InvocationService", TrackingScanService)
    config = AppConfig.model_validate(
        {
            "providers": {"mock": {"kind": "mock"}},
            "evaluation": {"models": ["mock:m"]},
            "storage": {"path": str(tmp_path / "agent.db")},
            "artifacts": {"root": str(tmp_path / "artifacts")},
            "agent": {
                "scenarios": ["support.indirect_prompt_injection.v1"],
                "fixtures": ["clean"],
            },
        }
    )

    async def fail_run(**_kwargs):
        raise RuntimeError("scan target failed")

    monkeypatch.setattr(api_module, "run_agent_scenario", fail_run)
    with SQLiteRunStore(tmp_path / "scan.db") as store:
        with pytest.raises(RuntimeError, match="scan target failed"):
            await run_agent_scan(
                config,
                run_store=store,
                artifact_store=ArtifactStore(tmp_path / "scan-artifacts"),
            )
    assert len(created) == 1
    assert created[0].aclose_calls == 1


@pytest.mark.asyncio
async def test_agent_scan_closes_shared_invocation_service_on_success(
    tmp_path: Path, monkeypatch
) -> None:
    import cot_redteam.agent.api as api_module
    from cot_redteam.agent.api import run_agent_scan
    from cot_redteam.storage.artifacts import ArtifactStore

    created: list[_TrackingInvocationService] = []

    class TrackingScanService(_TrackingInvocationService):
        def __init__(self, config: AppConfig, *, budget) -> None:
            super().__init__(config, budget=budget)
            created.append(self)

    monkeypatch.setattr(api_module, "InvocationService", TrackingScanService)
    config = AppConfig.model_validate(
        {
            "providers": {"mock": {"kind": "mock"}},
            "evaluation": {"models": ["mock:m"]},
            "storage": {"path": str(tmp_path / "agent.db")},
            "artifacts": {"root": str(tmp_path / "artifacts")},
            "agent": {
                "scenarios": ["support.indirect_prompt_injection.v1"],
                "fixtures": ["clean"],
            },
        }
    )
    with SQLiteRunStore(tmp_path / "scan.db") as store:
        result = await run_agent_scan(
            config,
            run_store=store,
            artifact_store=ArtifactStore(tmp_path / "scan-artifacts"),
        )
    assert len(result.runs) == 1
    assert len(created) == 1
    assert created[0].aclose_calls == 1
