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
  sample_count: 2
  budgets:
    max_requests: 20
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
