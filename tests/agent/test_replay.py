"""Replay artifact build/load and deterministic replay tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from cot_redteam.agent.api import run_agent_scenario, save_replay_artifact
from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.replay import (
    ReplayArtifactV1,
    ReplayError,
    ReplayResult,
    compute_payload_digest,
    load_regression_suite,
    load_replay,
    run_regression_suite,
    run_replay,
)
from cot_redteam.agent.scenarios.support import support_fixture
from cot_redteam.storage.artifacts import ArtifactStore
from cot_redteam.storage.sqlite import SQLiteRunStore


async def _save_exploit(tmp_path: Path) -> tuple[Path, str]:
    """Run a vulnerable fixture and save its replay artifact."""
    settings = AgentSecuritySettings()
    with SQLiteRunStore(tmp_path / "agent.db") as store:
        run = await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="vulnerable",
            seed=7,
            run_store=store,
        )
        artifact_store = ArtifactStore(tmp_path / "artifacts")
        saved = save_replay_artifact(
            run,
            fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
            settings=settings,
            artifact_store=artifact_store,
            run_store=store,
        )
        assert saved is not None
        path, checksum = saved
        return Path(path), checksum


def test_verified_exploit_creates_replay_json_and_detached_checksum(
    tmp_path: Path,
) -> None:
    asyncio.run(_save_exploit(tmp_path))
    replay_path = tmp_path / "artifacts"
    replay_files = list(replay_path.glob("*/replay.json"))
    assert len(replay_files) == 1
    checksum_files = list(replay_path.glob("*/replay.json.sha256"))
    assert len(checksum_files) == 1
    content = json.loads(replay_files[0].read_text(encoding="utf-8"))
    assert content["schema_version"] == 1
    assert content["original_outcome"] == "verified_exploit"
    assert content["checksums"]["payload_sha256"]
    # Detached checksum matches the file bytes.
    detached = checksum_files[0].read_text(encoding="utf-8").split()[0]
    import hashlib

    actual = hashlib.sha256(replay_files[0].read_bytes()).hexdigest()
    assert detached == actual


def test_exact_replay_reproduces_exploit(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact)

    result = asyncio.run(_replay())
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_patched_regression_holds(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact, fixture="patched")

    result = asyncio.run(_replay())
    assert result.status == "invariant_held"
    assert result.exit_code == 0


def test_clean_regression_holds(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact, fixture="clean")

    result = asyncio.run(_replay())
    assert result.status == "invariant_held"
    assert result.exit_code == 0


def test_corrupt_checksum_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["trajectory_digest"] = "f" * 64
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReplayError, match="checksum"):
        load_replay(corrupt)


def test_unknown_schema_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["schema_version"] = 99
    corrupt = tmp_path / "schema.json"
    corrupt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReplayError, match="schema"):
        load_replay(corrupt)


def test_truncated_json_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    truncated = tmp_path / "truncated.json"
    truncated.write_text(Path(path).read_text(encoding="utf-8")[:200], encoding="utf-8")
    with pytest.raises(ReplayError, match="parse"):
        load_replay(truncated)


def test_unknown_scenario_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["scenario"] = {"id": "support.does_not_exist.v1", "version": "1"}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    async def _replay() -> None:
        await run_replay(artifact)

    with pytest.raises(ReplayError, match="unknown scenario"):
        asyncio.run(_replay())


def test_unknown_fixture_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> None:
        await run_replay(artifact, fixture="nonexistent_fixture")

    with pytest.raises(ReplayError, match="fixture"):
        asyncio.run(_replay())


def test_unknown_world_version_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["world"] = {"id": "support", "version": "support-world/99"}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    async def _replay() -> None:
        await run_replay(artifact)

    with pytest.raises(ReplayError, match="incompatible world"):
        asyncio.run(_replay())


def test_result_mapping_error_and_inconclusive_are_partial() -> None:
    from cot_redteam.agent.types import AgentOutcome

    class _FakeRun:
        outcome = AgentOutcome.ERROR
        error = "boom"
        trajectory = None

    result = ReplayResult.from_run(
        _FakeRun(),  # type: ignore[arg-type]
        original_outcome="verified_exploit",
    )
    assert result.exit_code == 3
    assert result.status == "error"

    class _InconclusiveRun:
        outcome = AgentOutcome.INCONCLUSIVE
        error = None
        trajectory = None

    result2 = ReplayResult.from_run(
        _InconclusiveRun(),  # type: ignore[arg-type]
        original_outcome="verified_exploit",
    )
    assert result2.exit_code == 3
    assert result2.status == "inconclusive"


def test_regression_suite_aggregation(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    import shutil

    shutil.copy(path, suite_dir / "exploit-1.json")
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "exploit-1.json",
                        "target": "patched",
                        "expected": "INVARIANT_HELD",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    async def _run() -> None:
        report = await run_regression_suite(suite_dir)
        assert report.exit_code == 0  # patched target holds
        entry, result = report.entries[0]
        assert result.status == "regression_matched"

    asyncio.run(_run())


def test_suite_missing_artifact_rejected(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "missing.json",
                        "target": "patched",
                        "expected": "INVARIANT_HELD",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReplayError, match="missing"):
        load_regression_suite(suite_dir)


def test_replay_artifact_has_no_executable_content(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    blob = json.dumps(data)
    for marker in ("__import__", "pickle", "eval(", "exec(", "shell", "subprocess"):
        assert marker not in blob
