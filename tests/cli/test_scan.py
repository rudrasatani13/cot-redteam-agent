"""scan command tests: CI-friendly defaults and exit codes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from cot_redteam.cli.main import cmd_scan
from cot_redteam.core.errors import CotRedTeamError

_MOCK_REFUSE = """version: 2

global:
  seed: 1
  output_dir: ./results-scan
  concurrency: 1

providers:
  mock:
    kind: mock
    mock_mode: refuse

evaluation:
  models:
    - mock:target
  dataset_path: pkg:sample.jsonl
  sample_count: 1
  budgets:
    max_requests: 40
    max_elapsed_seconds: 120
  retain_prompts: false
  retain_responses: false

storage:
  path: ./results-scan/cot_redteam.db
"""

_MOCK_AUTO = _MOCK_REFUSE.replace("mock_mode: refuse", "mock_mode: auto")


class _Args:
    def __init__(self, **kwargs) -> None:
        self.dataset = None
        self.sample_count = None
        self.model = None
        self.attack = None
        self.seed = None
        self.sarif = None
        for key, value in kwargs.items():
            setattr(self, key, value)


def test_scan_clean_with_refusing_model(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(_MOCK_REFUSE, encoding="utf-8")
    exit_code = cmd_scan(_Args(config=str(cfg)))
    captured = capsys.readouterr().out
    assert exit_code == 0
    assert "VERDICT: no findings" in captured


def test_scan_detects_disclosure_with_auto_model(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    cfg = tmp_path / "scan-auto.yaml"
    cfg.write_text(_MOCK_AUTO, encoding="utf-8")
    exit_code = cmd_scan(_Args(config=str(cfg)))
    captured = capsys.readouterr().out
    assert exit_code == 1
    assert "finding" in captured


def test_scan_writes_sarif_log(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import json

    cfg = tmp_path / "scan-refuse.yaml"
    cfg.write_text(_MOCK_REFUSE, encoding="utf-8")
    sarif_path = tmp_path / "scan.sarif.json"
    exit_code = cmd_scan(_Args(config=str(cfg), sarif=str(sarif_path)))
    captured = capsys.readouterr().out
    assert exit_code == 0
    assert "SARIF written" in captured
    assert sarif_path.is_file()
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "cot-redteam-agent"


def test_scan_invalid_config_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("version: 2\nproviders: {}\n", encoding="utf-8")
    with pytest.raises(CotRedTeamError):
        cmd_scan(_Args(config=str(cfg)))


def test_scan_registered_in_cli() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "cot_redteam.cli.main", "scan", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "--dataset" in proc.stdout
    assert "--sample-count" in proc.stdout
    assert "--model" in proc.stdout


def test_scan_failed_run_exits_partial(
    tmp_path: Path, capsys: pytest.CaptureFixture, monkeypatch
) -> None:
    """Regression: a run where EVERY item failed (run-level FAILED) must
    exit 3 (partial), never 0 (false-clean CI signal)."""
    from datetime import datetime, timezone
    from importlib import import_module

    cli_main = import_module("cot_redteam.cli.main")
    from cot_redteam.core.types import EvaluationRun, RunStatus, RunSummary

    async def fake_run_evaluation(config):
        return EvaluationRun(
            run_id="audit-failed",
            status=RunStatus.FAILED,
            items=(),
            summary=RunSummary(
                status=RunStatus.FAILED,
                planned=1,
                succeeded=0,
                failed=1,
                cancelled=0,
                monitor_excluded=0,
            ),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            seed=42,
        )

    monkeypatch.setattr(cli_main, "run_evaluation", fake_run_evaluation)
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(_MOCK_REFUSE, encoding="utf-8")
    exit_code = cmd_scan(_Args(config=str(cfg)))
    captured = capsys.readouterr().out
    assert exit_code == 3
    assert "partial" in captured


def test_scan_errored_items_exit_partial(
    tmp_path: Path, capsys: pytest.CaptureFixture, monkeypatch
) -> None:
    """Regression: per-item provider/attack errors inside a COMPLETED-status
    run must still exit 3 (partial), never 0."""
    from datetime import datetime, timezone
    from importlib import import_module

    cli_main = import_module("cot_redteam.cli.main")
    from cot_redteam.core.types import (
        EvaluationItem,
        EvaluationRun,
        ItemStatus,
        ModelRef,
        RunStatus,
        RunSummary,
    )

    async def fake_run_evaluation(config):
        return EvaluationRun(
            run_id="audit-errored",
            status=RunStatus.COMPLETED,
            items=(
                EvaluationItem(
                    item_id="i1",
                    model=ModelRef.parse("mock:model"),
                    attack_id="injection.system_canary_adaptive",
                    sample_id="s1",
                    status=ItemStatus.PROVIDER_ERROR,
                    error="provider down",
                ),
            ),
            summary=RunSummary(
                status=RunStatus.COMPLETED,
                planned=1,
                succeeded=0,
                failed=1,
                cancelled=0,
                monitor_excluded=0,
            ),
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            seed=42,
        )

    monkeypatch.setattr(cli_main, "run_evaluation", fake_run_evaluation)
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(_MOCK_REFUSE, encoding="utf-8")
    exit_code = cmd_scan(_Args(config=str(cfg)))
    captured = capsys.readouterr().out
    assert exit_code == 3
    assert "partial" in captured
