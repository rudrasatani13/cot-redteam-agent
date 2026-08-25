"""Documentation example checks."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from cot_redteam.cli.main import main
from cot_redteam.core.config import load_config

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
    body_lines = [
        line for line in demo_text.splitlines() if not line.lstrip().startswith("#")
    ]
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    assert "\n".join(body_lines) in readme
    load_config(demo)


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
