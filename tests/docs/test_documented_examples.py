"""Documentation example checks."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from cot_redteam.cli.main import main
from cot_redteam.core.config import load_config, validate_config

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"


def test_example_config_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    load_config(ROOT / "config.example.yaml")


def test_readme_has_no_unsupported_claims() -> None:
    text = README.read_text(encoding="utf-8").lower()
    # "dashboard" is allowed for the shipped interactive TUI; keep blocking
    # formats and products this project does not implement.
    assert "parquet" not in text
    assert "not published to pypi" not in text
    assert "pypi.org/project/cot-redteam-agent" in text


def test_mock_demo_config_matches_readme_and_validates() -> None:
    demo = ROOT / "cot_redteam" / "data" / "mock_demo.example.yaml"
    demo_text = demo.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    # The 30-second README demo must stay in sync with the packaged file.
    body_lines = [line for line in demo_text.splitlines() if not line.lstrip().startswith("#")]
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    assert "\n".join(body_lines) in readme
    load_config(demo)


def test_packaged_mock_variants_validate_without_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    data = ROOT / "cot_redteam" / "data"
    expected = {
        "mock_demo.example.yaml": "auto",
        "mock_refuse.example.yaml": "refuse",
        "mock_disclose.example.yaml": "disclose",
    }
    for name, mode in expected.items():
        path = data / name
        config = load_config(path)
        validate_config(config, require_credentials=True)
        assert config.providers["mock"].mock_mode == mode
        assert main(["config", "validate", "--config", str(path)]) == 0


def test_current_docs_match_v0_6_surface() -> None:
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "0.3.x" not in contributing
    assert "0.6.x" in contributing
    header = (ROOT / "config.example.yaml").read_text(encoding="utf-8").splitlines()[0]
    assert "0.6" in header
    assert "0.5" not in header
    heading = (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8").splitlines()[0]
    assert heading == "# Configuration reference (0.6)"
    benchmarking = (ROOT / "docs" / "benchmarking.md").read_text(encoding="utf-8")
    assert not benchmarking.startswith("# Prompt-Injection Benchmarking\n\nVersion 0.3")


def test_readme_links_comparison_and_ci_scan_docs() -> None:
    text = README.read_text(encoding="utf-8")
    assert "docs/comparisons.md" in text
    assert "docs/ci-scan.md" in text
    comparisons = (ROOT / "docs" / "comparisons.md").read_text(encoding="utf-8").lower()
    ci_scan = (ROOT / "docs" / "ci-scan.md").read_text(encoding="utf-8").lower()
    for blob in (comparisons, ci_scan, text.lower()):
        assert "please star" not in blob
        assert "buy stars" not in blob


def test_help_lists_commands() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_plugin_examples_import() -> None:
    # Contracts documented in docs/plugins.md import cleanly.
    from cot_redteam.attacks.base import BaseAttack, register_attack
    from cot_redteam.monitors.base import BaseMonitor, register_monitor

    assert BaseAttack is not None
    assert BaseMonitor is not None
    assert callable(register_attack)
    assert callable(register_monitor)


def test_python_snippets_parse() -> None:
    text = README.read_text(encoding="utf-8")
    # Extract fenced python blocks after test marker or all python fences in README.
    blocks = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
    assert blocks
    for block in blocks:
        ast.parse(block)
