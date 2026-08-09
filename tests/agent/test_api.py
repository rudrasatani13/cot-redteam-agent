"""Agent API surface tests: run_agent_scenario persistence and manifests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from cot_redteam.agent.api import run_agent_scenario
from cot_redteam.agent.types import AgentOutcome, AgentRunStatus
from cot_redteam.eval.manifest import build_agent_manifest
from cot_redteam.storage.sqlite import SQLiteRunStore


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
        assert loaded.trajectory.digest == run.trajectory.digest
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
            run_id="deterministic-run",
        )
        second = await run_agent_scenario(
            scenario_id="support.approval_bypass.v1",
            fixture="patched",
            seed=11,
            run_store=store,
            run_id="deterministic-run",
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
