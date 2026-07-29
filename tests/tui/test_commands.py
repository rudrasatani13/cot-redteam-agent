"""Slash command parser tests."""

from cot_redteam.tui.commands import CommandKind, parse_command


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
