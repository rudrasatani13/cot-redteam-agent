"""agent scan / replay / regress CLI command tests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cot_redteam.cli.main import (
    EXIT_FAILED,
    EXIT_OK,
    cmd_agent_scan,
    cmd_regress,
    cmd_replay,
)
from cot_redteam.storage.artifacts import ArtifactStore
from cot_redteam.storage.sqlite import SQLiteRunStore

AGENT_CONFIG = """\
version: 2

global:
  seed: 7
  concurrency: 1
  output_dir: ./results

providers:
  mock:
    kind: mock

evaluation:
  models:
    - mock:mock-model
  attacks: []
  monitors: []
  dataset_path: pkg:sample.jsonl
  budgets:
    max_requests: 500

storage:
  path: ./results/cot_redteam.db

artifacts:
  root: ./artifacts

agent:
  scenarios:
    - support.indirect_prompt_injection.v1
  fixtures:
    - vulnerable
    - patched
    - clean
  budgets:
    max_requests: 500
  output_dir: ./results/agent
"""


def _write_config(tmp_path: Path) -> Path:
    path = tmp_path / "agent.yaml"
    path.write_text(AGENT_CONFIG, encoding="utf-8")
    return path


class _Args:
    def __init__(self, **kwargs) -> None:
        self.__dict__.update(kwargs)


def _config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    return path


def test_agent_scan_runs_and_saves_replays(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config_path(tmp_path, monkeypatch)
    args = _Args(config=str(config), scenario=None, fixture=None, seed=None)
    code = cmd_agent_scan(args)
    # Vulnerable fixture proves an exploit -> exit 1.
    assert code == EXIT_FAILED
    replays = list((tmp_path / "artifacts").glob("*/replay.json"))
    assert len(replays) == 1
    with SQLiteRunStore(tmp_path / "results" / "cot_redteam.db") as store:
        assert store.list_agent_runs()
        assert store.get_agent_run(replays[0].parent.name) is not None
        persisted_manifest = store.get_agent_manifest(replays[0].parent.name)
        assert persisted_manifest is not None
        assert persisted_manifest["run_id"] == replays[0].parent.name
        assert persisted_manifest["outcome"] == "verified_exploit"
        artifact_paths = {item["path"] for item in persisted_manifest["artifacts"]}
        assert f"{replays[0].parent.name}/replay.json" in artifact_paths
        assert f"{replays[0].parent.name}/replay.json.sha256" in artifact_paths
        assert persisted_manifest == json.loads(
            store.connection.execute(
                "SELECT manifest_json FROM agent_runs WHERE run_id = ?",
                (replays[0].parent.name,),
            ).fetchone()[0]
        )
    # Reports were written.
    reports = list((tmp_path / "results" / "agent").glob("*.md"))
    assert len(reports) == 3
    jsonl_reports = list((tmp_path / "results" / "agent").glob("*.jsonl"))
    assert len(jsonl_reports) == 3


def test_agent_scan_requires_agent_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "plain.yaml"
    config.write_text(
        """version: 2
providers:
  mock:
    kind: mock
evaluation:
  models: [mock:m]
  dataset_path: pkg:sample.jsonl
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    args = _Args(config=str(config), scenario=None, fixture=None, seed=None)
    from cot_redteam.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError, match="agent"):
        cmd_agent_scan(args)


def test_agent_scan_all_held_fixtures_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _write_config(tmp_path)
    agent_yaml = config.read_text(encoding="utf-8").replace(
        "  fixtures:\n    - vulnerable\n    - patched\n    - clean\n",
        "  fixtures:\n    - patched\n    - clean\n",
    )
    config.write_text(agent_yaml, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    args = _Args(config=str(config), scenario=None, fixture=None, seed=None)
    assert cmd_agent_scan(args) == EXIT_OK


def test_replay_cli_reproduces_exploit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cot_redteam.agent.api import run_agent_scenario, save_replay_artifact
    from cot_redteam.agent.config import AgentSecuritySettings
    from cot_redteam.agent.scenarios.support import support_fixture
    from cot_redteam.core.config import BudgetSettings

    asyncio = __import__("asyncio")
    settings = AgentSecuritySettings(
        budgets=BudgetSettings(max_requests=500, max_elapsed_seconds=600),
    )

    async def _save() -> str:
        with SQLiteRunStore(tmp_path / "agent.db") as store:
            run = await run_agent_scenario(
                scenario_id="support.indirect_prompt_injection.v1",
                fixture="vulnerable",
                settings=settings,
                seed=7,
                run_store=store,
            )
            saved = save_replay_artifact(
                run,
                fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
                settings=settings,
                artifact_store=ArtifactStore(tmp_path / "artifacts"),
            )
            assert saved is not None
            return saved[0]

    path = asyncio.run(_save())
    monkeypatch.chdir(tmp_path)
    args = _Args(artifact=path, config=None, fixture=None)
    assert cmd_replay(args) == EXIT_FAILED  # exploit reproduced


def test_replay_cli_explicit_config_budget_override_is_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit config remains a caller budget override for exact replay."""
    from cot_redteam.agent.api import run_agent_scenario, save_replay_artifact
    from cot_redteam.agent.config import AgentSecuritySettings
    from cot_redteam.agent.replay import ReplayError
    from cot_redteam.agent.scenarios.support import support_fixture
    from cot_redteam.core.config import BudgetSettings

    asyncio = __import__("asyncio")
    artifact_settings = AgentSecuritySettings(
        budgets=BudgetSettings(max_requests=500, max_elapsed_seconds=600),
    )

    async def _save() -> str:
        with SQLiteRunStore(tmp_path / "agent.db") as store:
            run = await run_agent_scenario(
                scenario_id="support.indirect_prompt_injection.v1",
                fixture="vulnerable",
                settings=artifact_settings,
                seed=7,
                run_store=store,
            )
            saved = save_replay_artifact(
                run,
                fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
                settings=artifact_settings,
                artifact_store=ArtifactStore(tmp_path / "artifacts"),
            )
            assert saved is not None
            return saved[0]

    path = asyncio.run(_save())
    config = _write_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    args = _Args(artifact=path, config=str(config), fixture=None)
    with pytest.raises(ReplayError, match="budget_configuration"):
        cmd_replay(args)


def test_replay_cli_corrupt_exit_config(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text('{"schema_version": 1, "not": "enough"}', encoding="utf-8")
    args = _Args(artifact=str(corrupt), config=None, fixture=None)
    from cot_redteam.agent.replay import ReplayError

    with pytest.raises(ReplayError):
        cmd_replay(args)


def test_regress_cli_patched_holds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cot_redteam.agent.api import run_agent_scenario, save_replay_artifact
    from cot_redteam.agent.config import AgentSecuritySettings
    from cot_redteam.agent.scenarios.support import support_fixture

    asyncio = __import__("asyncio")

    async def _save() -> str:
        with SQLiteRunStore(tmp_path / "agent.db") as store:
            run = await run_agent_scenario(
                scenario_id="support.tool_result_injection.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
            )
            saved = save_replay_artifact(
                run,
                fixture=support_fixture("support.tool_result_injection.v1", "vulnerable"),
                settings=AgentSecuritySettings(),
                artifact_store=ArtifactStore(tmp_path / "artifacts"),
            )
            assert saved is not None
            return saved[0]

    path = asyncio.run(_save())
    suite_dir = tmp_path / "security-regressions"
    suite_dir.mkdir()
    shutil.copy(path, suite_dir / "exploit.json")
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "exploit.json",
                        "target": "patched",
                        "expected": "INVARIANT_HELD",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    args = _Args(suite=str(suite_dir), config=None)
    assert cmd_regress(args) == EXIT_OK


def test_replay_cli_invalid_config_rejected(tmp_path: Path) -> None:
    """An invalid agent config fails the replay command cleanly."""
    from cot_redteam.agent.api import run_agent_scenario, save_replay_artifact
    from cot_redteam.agent.config import AgentSecuritySettings
    from cot_redteam.agent.scenarios.support import support_fixture

    asyncio = __import__("asyncio")

    async def _save() -> str:
        with SQLiteRunStore(tmp_path / "agent.db") as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
            )
            saved = save_replay_artifact(
                run,
                fixture=support_fixture("support.approval_bypass.v1", "vulnerable"),
                settings=AgentSecuritySettings(),
                artifact_store=ArtifactStore(tmp_path / "artifacts"),
            )
            assert saved is not None
            return saved[0]

    path = asyncio.run(_save())
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("not: [valid", encoding="utf-8")
    args = _Args(artifact=path, config=str(bad_config), fixture=None)
    from cot_redteam.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        cmd_replay(args)
