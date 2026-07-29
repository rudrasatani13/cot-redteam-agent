"""Slash-command parser for the interactive red-team TUI."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CommandKind(str, Enum):
    HELP = "help"
    STATUS = "status"
    MODELS = "models"
    MODEL = "model"
    ADD_MODEL = "add_model"
    REMOVE_MODEL = "remove_model"
    ATTACK = "attack"
    PAYLOADS = "payloads"
    EFFORT = "effort"
    STOP_ON_SUCCESS = "stop_on_success"
    RUN = "run"
    STOP = "stop"
    CLEAR = "clear"
    QUIT = "quit"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ParsedCommand:
    kind: CommandKind
    args: tuple[str, ...] = ()
    raw: str = ""
    error: str | None = None


HELP_TEXT = """\
Slash commands
  /help                         this help
  /status                       show current session config
  /models                       list configured models
  /model <provider:model>       replace model list with one model
  /add <provider:model>         add a model to the board
  /rm <provider:model>          remove a model
  /attack <attack_id>           set attack (default adaptive canary)
  /payloads <N>                 max adaptive payloads per model
  /effort adaptive|fixed        adaptive loop vs single payload
  /sos on|off                   stop on first real success
  /run  (or /start)             start evaluation
  /stop                         cancel running evaluation
  /clear                        clear activity log panels
  /quit  (or /exit)             leave the TUI

Examples
  /model xkiro:qwen/qwen3.5-flash
  /add xkiro:deepseek/deepseek-v4-flash
  /payloads 8
  /run
"""


def parse_command(line: str) -> ParsedCommand:
    text = (line or "").strip()
    if not text:
        return ParsedCommand(CommandKind.UNKNOWN, raw=text, error="empty command")
    if not text.startswith("/"):
        text = "/" + text
    parts = text[1:].split()
    if not parts:
        return ParsedCommand(CommandKind.UNKNOWN, raw=line, error="empty command")
    name = parts[0].lower()
    args = tuple(parts[1:])

    aliases = {
        "h": CommandKind.HELP,
        "help": CommandKind.HELP,
        "?": CommandKind.HELP,
        "status": CommandKind.STATUS,
        "s": CommandKind.STATUS,
        "models": CommandKind.MODELS,
        "ls": CommandKind.MODELS,
        "model": CommandKind.MODEL,
        "m": CommandKind.MODEL,
        "add": CommandKind.ADD_MODEL,
        "add_model": CommandKind.ADD_MODEL,
        "rm": CommandKind.REMOVE_MODEL,
        "remove": CommandKind.REMOVE_MODEL,
        "attack": CommandKind.ATTACK,
        "a": CommandKind.ATTACK,
        "payloads": CommandKind.PAYLOADS,
        "payload": CommandKind.PAYLOADS,
        "p": CommandKind.PAYLOADS,
        "effort": CommandKind.EFFORT,
        "e": CommandKind.EFFORT,
        "sos": CommandKind.STOP_ON_SUCCESS,
        "stop_on_success": CommandKind.STOP_ON_SUCCESS,
        "run": CommandKind.RUN,
        "start": CommandKind.RUN,
        "go": CommandKind.RUN,
        "stop": CommandKind.STOP,
        "cancel": CommandKind.STOP,
        "clear": CommandKind.CLEAR,
        "quit": CommandKind.QUIT,
        "exit": CommandKind.QUIT,
        "q": CommandKind.QUIT,
    }
    kind = aliases.get(name)
    if kind is None:
        return ParsedCommand(
            CommandKind.UNKNOWN,
            args=args,
            raw=line,
            error=f"unknown command /{name} — try /help",
        )
    return ParsedCommand(kind=kind, args=args, raw=line)
