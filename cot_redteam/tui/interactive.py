"""Full interactive Codex-style Textual TUI for adaptive red-teaming."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from cot_redteam.api import run_evaluation
from cot_redteam.core.config import AppConfig, validate_config
from cot_redteam.core.types import RunStatus
from cot_redteam.eval.events import RunEvent
from cot_redteam.tui.commands import HELP_TEXT, CommandKind, parse_command
from cot_redteam.tui.render import (
    RICH_AVAILABLE,
    render_header,
    render_leak,
    render_model_board,
    render_now,
    render_output,
    render_timeline,
)
from cot_redteam.tui.state import TuiState

try:
    from textual import on
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Header, Input, Static

    TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover
    TEXTUAL_AVAILABLE = False
    App = object  # type: ignore[misc, assignment]


def _clone_config(config: AppConfig) -> AppConfig:
    return AppConfig.model_validate(config.model_dump(mode="python"))


def _set_attack_config(config: AppConfig, attack_id: str, **values: Any) -> AppConfig:
    attack_config = dict(config.evaluation.attack_config)
    current = dict(attack_config.get(attack_id, {}))
    current.update(values)
    attack_config[attack_id] = current
    evaluation = config.evaluation.model_copy(update={"attack_config": attack_config})
    return config.model_copy(update={"evaluation": evaluation})


if TEXTUAL_AVAILABLE:

    class RedTeamTuiApp(App[int]):
        """Interactive multi-model adaptive red-team dashboard."""

        CSS = """
        /* No Textual Footer — it docks and eats the input row.
           Bottom chrome is a fixed 4-row block: keys + type line. */
        Screen {
            layout: vertical;
            background: #0b0f14;
        }
        Header {
            background: #111827;
            color: #e5e7eb;
            text-style: bold;
            height: 1;
        }
        #body {
            height: 1fr;
            layout: vertical;
            min-height: 0;
            padding: 0 1 0 1;
            background: #0b0f14;
        }
        #hdr {
            height: auto;
            min-height: 4;
            max-height: 6;
        }
        #models {
            height: auto;
            min-height: 3;
            max-height: 6;
        }
        #now {
            height: 1;
            min-height: 1;
            max-height: 1;
            padding: 0 1;
            content-align: left middle;
        }
        #mid {
            height: 1fr;
            min-height: 6;
            layout: horizontal;
        }
        #timeline {
            width: 1fr;
            height: 1fr;
            min-width: 16;
            overflow-y: auto;
            overflow-x: hidden;
        }
        #output {
            width: 1fr;
            height: 1fr;
            min-width: 16;
            overflow-y: auto;
            overflow-x: hidden;
        }
        #leak {
            height: auto;
            min-height: 3;
            max-height: 4;
        }
        /*
         * Ultra-slim single-line composer (Codex-style):
         * - zero borders on input/row (border:solid/tall on height-1 draws
         *   ugly 3-stack side glyphs — user asked those removed)
         * - contrast fill only, total chrome = 2 rows (input + keys)
         */
        #bottom {
            height: 2;
            min-height: 2;
            max-height: 2;
            layout: vertical;
            background: #09090b;
            padding: 0 1;
        }
        #command-row {
            height: 1;
            min-height: 1;
            max-height: 1;
            layout: horizontal;
            background: #27272a;
            border: none;
            padding: 0;
            align: left middle;
        }
        #command {
            width: 1fr;
            height: 1;
            min-height: 1;
            max-height: 1;
            background: #27272a;
            color: #fafafa;
            border: none;
            padding: 0 1;
        }
        #command:focus {
            background: #3f3f46;
            color: #ffffff;
            border: none;
        }
        #keys-bar {
            height: 1;
            min-height: 1;
            max-height: 1;
            color: #71717a;
            background: #09090b;
            content-align: left middle;
            padding: 0 1;
        }
        """

        BINDINGS = [
            Binding("ctrl+c", "stop_or_quit", "Stop/Quit", priority=True),
            Binding("f1", "help", "Help"),
            Binding("f5", "run", "Run"),
            Binding("ctrl+l", "clear_log", "Clear"),
        ]

        def __init__(
            self,
            config: AppConfig,
            *,
            environ: Mapping[str, str] | None = None,
        ) -> None:
            super().__init__()
            self.base_config = config
            self.session_config = _clone_config(config)
            self.environ = environ
            self.state = TuiState()
            self._init_state_from_config()
            self._eval_task: asyncio.Task[Any] | None = None
            self._event_queue: asyncio.Queue[RunEvent | None] = asyncio.Queue()
            self._consumer_task: asyncio.Task[Any] | None = None
            self._exit_code = 0
            self._auto_start = False

        def _init_state_from_config(self) -> None:
            models = list(self.session_config.evaluation.models)
            attacks = list(self.session_config.evaluation.attacks)
            self.state.ensure_models(models)
            self.state.model = models[0] if models else "-"
            default_attack = "injection.system_canary_agent"
            self.state.attack_id = attacks[0] if attacks else default_attack
            self.state.attack_explicit = False
            self.state.effort = "agentic" if "agent" in self.state.attack_id else "adaptive"
            self.state.sandbox = "local-eval"
            attack_cfg = self.session_config.evaluation.attack_config.get(self.state.attack_id, {})
            max_payloads = attack_cfg.get("max_attempts") or attack_cfg.get("max_payloads") or 24
            self.state.max_payloads = int(max_payloads)
            self.state.stop_on_success = bool(attack_cfg.get("stop_on_success", True))
            self.state.current_activity = "ready — /run to start · F5 also works"
            self.state.command_hint = "/help /model /add /payloads /run /stop /quit"
            self.state.title = "CoT Red Team Agent"

        def compose(self) -> ComposeResult:
            # Header
            # body (flex): hdr | models | now | mid | leak
            # bottom (fixed 4 rows): keys + type line  ← always fully visible
            yield Header(show_clock=True)
            with Vertical(id="body"):
                yield Static(id="hdr")
                yield Static(id="models")
                yield Static(id="now")
                with Horizontal(id="mid"):
                    yield Static(id="timeline")
                    yield Static(id="output")
                yield Static(id="leak")
            with Vertical(id="bottom"):
                # Single-line Input (height 1) + keys bar — no borders (avoids side glyphs)
                with Horizontal(id="command-row"):
                    yield Input(
                        placeholder="Type /run here, then press Enter",
                        id="command",
                    )
                yield Static(
                    "Enter: send  ·  F5: run  ·  F1: help  ·  Ctrl+L: clear  ·  Ctrl+C: quit",
                    id="keys-bar",
                )

        def on_mount(self) -> None:
            self.title = "CoT Red Team"
            self.sub_title = self._subtitle()
            self._consumer_task = asyncio.create_task(self._consume_events())
            self.set_interval(0.15, self._refresh_dashboard)
            self.query_one("#command", Input).focus()
            self._refresh_dashboard()
            if self._auto_start:
                self.action_run()

        def _subtitle(self) -> str:
            st = self.state.status
            if st in {"running", "probing", "starting"}:
                return (
                    f"{st} · {self.state.attempt}/"
                    f"{self.state.attempts_total or self.state.max_payloads} · "
                    f"ok {self.state.successes} fail {self.state.failures}"
                )
            if self.state.successes:
                return f"{st} · leak found · ok {self.state.successes}"
            return f"{st} · educational canary red-team"

        def _refresh_dashboard(self) -> None:
            """Update each region so #mid can flex-fill remaining height."""
            self.query_one("#hdr", Static).update(render_header(self.state))
            self.query_one("#models", Static).update(render_model_board(self.state, max_rows=3))
            self.query_one("#now", Static).update(render_now(self.state))
            self.query_one("#timeline", Static).update(render_timeline(self.state, limit=50))
            self.query_one("#output", Static).update(render_output(self.state))
            self.query_one("#leak", Static).update(render_leak(self.state))
            self.sub_title = self._subtitle()

        async def _consume_events(self) -> None:
            while True:
                event = await self._event_queue.get()
                if event is None:
                    break
                self.state.apply_event(event)
                self._refresh_dashboard()

        def _on_progress(self, event: RunEvent) -> None:
            self._event_queue.put_nowait(event)

        def _is_running(self) -> bool:
            return self._eval_task is not None and not self._eval_task.done()

        def _note(self, message: str, *, ok: bool | None = True) -> None:
            self.state.current_activity = message
            self.state.push_activity("cmd", message, ok=ok)
            self._refresh_dashboard()

        def _status_dump(self) -> str:
            models = ", ".join(self.session_config.evaluation.models) or "(none)"
            return (
                f"models=[{models}] attack={self.state.attack_id} "
                f"effort={self.state.effort} payloads={self.state.max_payloads} "
                f"stop_on_success={self.state.stop_on_success} status={self.state.status}"
            )

        def _apply_session_to_config(self) -> AppConfig:
            cfg = _clone_config(self.session_config)
            models = list(self.state.configured_models) or list(cfg.evaluation.models)
            attacks = (
                [self.state.attack_id] if self.state.attack_id else list(cfg.evaluation.attacks)
            )
            if self.state.attack_explicit:
                # A /attack choice wins over the effort-derived default; the
                # effort selector only fills in an attack when the user did
                # not pick one explicitly.
                attacks = [self.state.attack_id]
            elif self.state.effort == "fixed":
                attacks = ["injection.system_canary"]
            elif self.state.effort == "adaptive":
                attacks = ["injection.system_canary_adaptive"]
            else:
                attacks = ["injection.system_canary_agent"]
            self.state.attack_id = attacks[0]
            evaluation = cfg.evaluation.model_copy(
                update={
                    "models": models,
                    "attacks": attacks,
                }
            )
            cfg = cfg.model_copy(update={"evaluation": evaluation})
            attack_id = attacks[0]
            cfg = _set_attack_config(
                cfg,
                attack_id,
                max_payloads=self.state.max_payloads,
                max_attempts=self.state.max_payloads,
                seed_payloads=min(4, self.state.max_payloads),
                require_final_text=True,
                stop_on_success=self.state.stop_on_success,
                bank_path="pkg:system_canary_bank.jsonl",
            )
            # Budget headroom: models * payloads * samples
            samples = cfg.evaluation.sample_count or 1
            needed = max(1, len(models) * self.state.max_payloads * samples + 2)
            budgets = cfg.evaluation.budgets.model_copy(
                update={
                    "max_requests": max(needed, cfg.evaluation.budgets.max_requests or needed),
                }
            )
            evaluation = cfg.evaluation.model_copy(update={"budgets": budgets})
            return cfg.model_copy(update={"evaluation": evaluation})

        async def _handle_command(self, line: str) -> None:
            parsed = parse_command(line)
            if parsed.error and parsed.kind is CommandKind.UNKNOWN:
                self._note(parsed.error, ok=False)
                return

            if parsed.kind is CommandKind.HELP:
                self.state.help_text = HELP_TEXT.splitlines()[0]
                self.state.last_output = HELP_TEXT
                self._note("help shown in output panel")
                return

            if parsed.kind is CommandKind.STATUS:
                self.state.last_output = self._status_dump()
                self._note(self._status_dump())
                return

            if parsed.kind is CommandKind.MODELS:
                models = self.state.configured_models or self.session_config.evaluation.models
                text = "\n".join(f"- {m}" for m in models) or "(no models)"
                self.state.last_output = text
                self._note(f"{len(models)} model(s) configured")
                return

            if parsed.kind is CommandKind.MODEL:
                if not parsed.args:
                    self._note("usage: /model provider:model-id", ok=False)
                    return
                model = parsed.args[0]
                self.state.ensure_models([model])
                evaluation = self.session_config.evaluation.model_copy(update={"models": [model]})
                self.session_config = self.session_config.model_copy(
                    update={"evaluation": evaluation}
                )
                self.state.model = model
                self._note(f"model set to {model}")
                return

            if parsed.kind is CommandKind.ADD_MODEL:
                if not parsed.args:
                    self._note("usage: /add provider:model-id", ok=False)
                    return
                model = parsed.args[0]
                models = list(self.state.configured_models)
                if model not in models:
                    models.append(model)
                self.state.ensure_models(models)
                evaluation = self.session_config.evaluation.model_copy(update={"models": models})
                self.session_config = self.session_config.model_copy(
                    update={"evaluation": evaluation}
                )
                self._note(f"added {model} ({len(models)} total)")
                return

            if parsed.kind is CommandKind.REMOVE_MODEL:
                if not parsed.args:
                    self._note("usage: /rm provider:model-id", ok=False)
                    return
                model = parsed.args[0]
                models = [m for m in self.state.configured_models if m != model]
                if not models:
                    self._note("cannot remove last model", ok=False)
                    return
                self.state.ensure_models(models)
                if model in self.state.model_board:
                    del self.state.model_board[model]
                evaluation = self.session_config.evaluation.model_copy(update={"models": models})
                self.session_config = self.session_config.model_copy(
                    update={"evaluation": evaluation}
                )
                self.state.model = models[0]
                self._note(f"removed {model}")
                return

            if parsed.kind is CommandKind.ATTACK:
                if not parsed.args:
                    self._note("usage: /attack injection.system_canary_adaptive", ok=False)
                    return
                attack = parsed.args[0]
                self.state.attack_id = attack
                self.state.attack_explicit = True
                evaluation = self.session_config.evaluation.model_copy(update={"attacks": [attack]})
                self.session_config = self.session_config.model_copy(
                    update={"evaluation": evaluation}
                )
                self._note(f"attack set to {attack}")
                return

            if parsed.kind is CommandKind.PAYLOADS:
                if not parsed.args:
                    self._note(f"payloads={self.state.max_payloads}", ok=True)
                    return
                try:
                    n = int(parsed.args[0])
                except ValueError:
                    self._note("usage: /payloads <positive int>", ok=False)
                    return
                if n < 1:
                    self._note("payloads must be >= 1", ok=False)
                    return
                self.state.max_payloads = n
                self._note(f"max payloads set to {n}")
                return

            if parsed.kind is CommandKind.EFFORT:
                if not parsed.args:
                    self._note(f"effort={self.state.effort}", ok=True)
                    return
                mode = parsed.args[0].lower()
                if mode not in {"adaptive", "fixed", "agentic", "agent"}:
                    self._note("usage: /effort agentic|adaptive|fixed", ok=False)
                    return
                # Explicit effort selects the attack too; a previous /attack
                # choice no longer applies.
                self.state.attack_explicit = False
                if mode in {"agentic", "agent"}:
                    self.state.effort = "agentic"
                    self.state.attack_id = "injection.system_canary_agent"
                elif mode == "adaptive":
                    self.state.effort = "adaptive"
                    self.state.attack_id = "injection.system_canary_adaptive"
                else:
                    self.state.effort = "fixed"
                    self.state.attack_id = "injection.system_canary"
                self._note(f"effort={self.state.effort} attack={self.state.attack_id}")
                return

            if parsed.kind is CommandKind.STOP_ON_SUCCESS:
                if not parsed.args:
                    self._note(f"stop_on_success={self.state.stop_on_success}")
                    return
                flag = parsed.args[0].lower()
                if flag in {"on", "true", "1", "yes"}:
                    self.state.stop_on_success = True
                elif flag in {"off", "false", "0", "no"}:
                    self.state.stop_on_success = False
                else:
                    self._note("usage: /sos on|off", ok=False)
                    return
                self._note(f"stop_on_success={self.state.stop_on_success}")
                return

            if parsed.kind is CommandKind.CLEAR:
                self.state.activity.clear()
                self.state.last_output = "cleared"
                self.state.help_text = ""
                self._note("activity cleared")
                return

            if parsed.kind is CommandKind.RUN:
                await self._start_run()
                return

            if parsed.kind is CommandKind.STOP:
                await self._stop_run()
                return

            if parsed.kind is CommandKind.QUIT:
                await self._stop_run()
                self.exit(self._exit_code)
                return

            self._note(f"unhandled command {parsed.kind}", ok=False)

        async def _start_run(self) -> None:
            if self._is_running():
                self._note("already running — /stop first", ok=False)
                return
            try:
                cfg = self._apply_session_to_config()
                validate_config(cfg, require_credentials=True, environ=self.environ)
            except Exception as exc:  # ConfigurationError etc.
                self._note(f"config error: {exc}", ok=False)
                self.state.last_output = str(exc)
                return

            self.state.reset_for_run()
            self.state.ensure_models(list(cfg.evaluation.models))
            self.state.attack_id = cfg.evaluation.attacks[0]
            self._note(
                f"starting {len(cfg.evaluation.models)} model(s) · "
                f"attack={self.state.attack_id} · payloads≤{self.state.max_payloads}"
            )
            self._eval_task = asyncio.create_task(self._run_eval(cfg))

        async def _run_eval(self, cfg: AppConfig) -> None:
            try:
                run = await run_evaluation(
                    cfg,
                    environ=self.environ,
                    progress=self._on_progress,
                )
                if run.status is RunStatus.COMPLETED:
                    self._exit_code = 0
                elif run.status is RunStatus.PARTIAL:
                    self._exit_code = 3
                else:
                    self._exit_code = 1
                self._note(
                    f"finished status={run.status.value} run_id={run.run_id} "
                    f"ok={self.state.successes} fail={self.state.failures}"
                )
            except asyncio.CancelledError:
                self.state.status = "cancelled"
                self.state.finished = True
                self._note("run cancelled", ok=False)
                raise
            except Exception as exc:
                self.state.status = "failed"
                self.state.finished = True
                self._exit_code = 1
                self.state.last_output = str(exc)
                self._note(f"run failed: {exc}", ok=False)

        async def _stop_run(self) -> None:
            if not self._is_running():
                self._note("no active run")
                return
            assert self._eval_task is not None
            self._eval_task.cancel()
            try:
                await self._eval_task
            except asyncio.CancelledError:
                pass
            self.state.status = "cancelled"
            self.state.finished = True
            self._note("stop requested", ok=False)

        @on(Input.Submitted, "#command")
        async def on_command(self, event: Input.Submitted) -> None:
            value = event.value.strip()
            event.input.value = ""
            if not value:
                return
            self.state.push_activity("cmd", value, ok=None)
            await self._handle_command(value)

        def action_help(self) -> None:
            self.run_worker(self._handle_command("/help"), exclusive=False)

        def action_run(self) -> None:
            self.run_worker(self._handle_command("/run"), exclusive=False)

        def action_clear_log(self) -> None:
            self.run_worker(self._handle_command("/clear"), exclusive=False)

        async def action_stop_or_quit(self) -> None:
            if self._is_running():
                await self._stop_run()
            else:
                self.exit(self._exit_code)

        async def on_unmount(self) -> None:
            if self._is_running() and self._eval_task is not None:
                self._eval_task.cancel()
                try:
                    await self._eval_task
                except (asyncio.CancelledError, Exception):
                    pass
            await self._event_queue.put(None)
            if self._consumer_task is not None:
                try:
                    await self._consumer_task
                except Exception:
                    pass


async def run_interactive_tui(
    config: AppConfig,
    *,
    environ: Mapping[str, str] | None = None,
    auto_start: bool = False,
) -> int:
    if not TEXTUAL_AVAILABLE or not RICH_AVAILABLE:
        raise RuntimeError(
            "Interactive TUI requires rich and textual. Install with:\n"
            "  pip install 'cot-redteam-agent[tui]'"
        )
    app = RedTeamTuiApp(config, environ=environ)
    app._auto_start = auto_start
    result = await app.run_async()
    if isinstance(result, int):
        return result
    return 0
