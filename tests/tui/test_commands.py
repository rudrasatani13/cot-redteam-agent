"""Slash command parser tests."""

import re

from cot_redteam.tui.commands import CommandKind, parse_command


def test_tui_command_input_css_is_slim_not_tall() -> None:
    """Slim composer: no tall 3-line side borders; row frame keeps it visible."""
    from cot_redteam.tui.interactive import TEXTUAL_AVAILABLE, RedTeamTuiApp

    if not TEXTUAL_AVAILABLE:
        return
    css = RedTeamTuiApp.CSS
    cmd = re.search(r"#command \{([^}]+)\}", css, re.S)
    row = re.search(r"#command-row \{([^}]+)\}", css, re.S)
    assert cmd is not None and row is not None
    assert "border: tall" not in cmd.group(1)
    assert "border: tall" not in row.group(1)
    # Outer row keeps a solid frame so the field stays visible.
    assert "border: solid" in row.group(1)


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
