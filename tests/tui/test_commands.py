"""Slash command parser tests."""

import re

from cot_redteam.tui.commands import CommandKind, parse_command


def test_tui_command_input_css_is_slim_not_tall() -> None:
    """Ultra-slim composer: no side-border glyphs (tall/solid), height-2 chrome."""
    from cot_redteam.tui.interactive import TEXTUAL_AVAILABLE, RedTeamTuiApp

    if not TEXTUAL_AVAILABLE:
        return
    css = RedTeamTuiApp.CSS
    cmd = re.search(r"#command \{([^}]+)\}", css, re.S)
    row = re.search(r"#command-row \{([^}]+)\}", css, re.S)
    bottom = re.search(r"#bottom \{([^}]+)\}", css, re.S)
    assert cmd is not None and row is not None and bottom is not None
    # No border styles that paint multi-line left edges on a height-1 field.
    for block in (cmd.group(1), row.group(1)):
        assert "border: tall" not in block
        assert "border: solid" not in block
        assert "border: none" in block
    # Total bottom chrome is 2 rows (input + keys) — not a tall box.
    assert "height: 2" in bottom.group(1)


def test_parse_help_and_aliases() -> None:
    assert parse_command("/help").kind is CommandKind.HELP
    assert parse_command("h").kind is CommandKind.HELP
    assert parse_command("/run").kind is CommandKind.RUN
    assert parse_command("/start").kind is CommandKind.RUN
    assert parse_command("/stop").kind is CommandKind.STOP
    assert parse_command("/quit").kind is CommandKind.QUIT


def test_parse_model_and_payloads() -> None:
    cmd = parse_command("/model xkiro:qwen/qwen3.5-flash")
    assert cmd.kind is CommandKind.MODEL
    assert cmd.args == ("xkiro:qwen/qwen3.5-flash",)

    cmd = parse_command("/payloads 8")
    assert cmd.kind is CommandKind.PAYLOADS
    assert cmd.args == ("8",)

    cmd = parse_command("/add xkiro:deepseek/deepseek-v4-flash")
    assert cmd.kind is CommandKind.ADD_MODEL


def test_unknown_command() -> None:
    cmd = parse_command("/nope")
    assert cmd.kind is CommandKind.UNKNOWN
    assert cmd.error is not None
