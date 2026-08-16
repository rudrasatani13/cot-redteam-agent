"""Run adaptive red-team evaluation inside a Codex-style live TUI."""

from __future__ import annotations

import asyncio
import contextlib
import sys
from collections.abc import Mapping
from pathlib import Path

from cot_redteam.api import run_evaluation
from cot_redteam.core.config import AppConfig, load_config, validate_config
from cot_redteam.core.types import RunStatus
from cot_redteam.eval.events import RunEvent
from cot_redteam.tui.render import RICH_AVAILABLE, render_dashboard
from cot_redteam.tui.state import TuiState


async def run_tui(
    config: AppConfig | str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    refresh_hz: float = 8.0,
    interactive: bool = True,
    auto_start: bool = False,
) -> int:
    """Execute a live evaluation with a dashboard.

    Prefer the full interactive Textual TUI when available; otherwise fall back
    to a Rich Live non-interactive dashboard that auto-runs once.

    Returns a process-style exit code (0 completed, 3 partial, 1 failed).
    """
    if not isinstance(config, AppConfig):
        config = load_config(config)
    validate_config(config, require_credentials=True, environ=environ)

    if interactive:
        # Only the import/availability check may fall back: a runtime crash
        # inside the interactive TUI must NOT silently start a second billed
        # evaluation through the fallback dashboard.
        interactive_ready = False
        try:
            from cot_redteam.tui.interactive import TEXTUAL_AVAILABLE

            interactive_ready = TEXTUAL_AVAILABLE and RICH_AVAILABLE
        except Exception as exc:  # pragma: no cover - fallback path
            print(
                f"interactive TUI unavailable ({exc}); falling back to live dashboard",
                file=sys.stderr,
            )
        if interactive_ready:
            from cot_redteam.tui.interactive import run_interactive_tui

            return await run_interactive_tui(
                config,
                environ=environ,
                auto_start=auto_start,
            )

    return await _run_rich_live(
        config,
        environ=environ,
        refresh_hz=refresh_hz,
    )


async def _run_rich_live(
    config: AppConfig,
    *,
    environ: Mapping[str, str] | None,
    refresh_hz: float,
) -> int:
    if not RICH_AVAILABLE:
        print(
            "TUI requires 'rich' (and preferably 'textual'). Install with:\n"
            "  pip install 'cot-redteam-agent[tui]'\n"
            "or: pip install rich textual",
            file=sys.stderr,
        )
        return 2

    from rich.console import Console
    from rich.live import Live

    state = TuiState()
    if config.evaluation.models:
        state.ensure_models(list(config.evaluation.models))
        state.model = config.evaluation.models[0]
    if config.evaluation.attacks:
        state.attack_id = config.evaluation.attacks[0]
    state.effort = "adaptive-loop"
    state.sandbox = "local-eval"
    state.items_planned = 0

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[RunEvent | None] = asyncio.Queue()

    def on_progress(event: RunEvent) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    async def consume_events() -> None:
        while True:
            event = await queue.get()
            if event is None:
                break
            state.apply_event(event)

    consumer = asyncio.create_task(consume_events())
    console = Console()
    exit_code = 1
    eval_task: asyncio.Task | None = None
    try:
        with Live(
            render_dashboard(state),
            console=console,
            refresh_per_second=refresh_hz,
            transient=False,
        ) as live:
            eval_task = asyncio.create_task(
                run_evaluation(config, environ=environ, progress=on_progress)
            )
            while not eval_task.done():
                live.update(render_dashboard(state))
                await asyncio.sleep(1.0 / max(refresh_hz, 1.0))
            run = await eval_task
            await asyncio.sleep(0.05)
            while not queue.empty():
                event = queue.get_nowait()
                if event is not None:
                    state.apply_event(event)
            live.update(render_dashboard(state))
            if run.status is RunStatus.COMPLETED:
                exit_code = 0
            elif run.status is RunStatus.PARTIAL:
                exit_code = 3
            else:
                exit_code = 1
            console.print(
                f"\n[bold]run_id={run.run_id}[/] status={run.status.value} "
                f"successes={state.successes} fails={state.failures}"
            )
    except KeyboardInterrupt:
        # Cancel the in-flight evaluation so no further billed requests are
        # issued while the interruption is handled.
        if eval_task is not None and not eval_task.done():
            eval_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await eval_task
        state.status = "cancelled"
        state.current_activity = "interrupted by user"
        state.push_activity("run", "Ctrl-C stop", ok=False)
        console.print("\n[yellow]interrupted[/]")
        exit_code = 130
    finally:
        await queue.put(None)
        await consumer

    return exit_code


def run_tui_sync(
    config: AppConfig | str | Path,
    *,
    environ: Mapping[str, str] | None = None,
    interactive: bool = True,
    auto_start: bool = False,
) -> int:
    return asyncio.run(
        run_tui(
            config,
            environ=environ,
            interactive=interactive,
            auto_start=auto_start,
        )
    )
