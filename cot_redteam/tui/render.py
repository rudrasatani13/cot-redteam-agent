"""Polished Codex-style panel layout for the adaptive red-team TUI."""

from __future__ import annotations

from cot_redteam.tui.state import TuiState

try:
    from rich import box
    from rich.console import Group, RenderableType
    from rich.panel import Panel
    from rich.progress_bar import ProgressBar
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    RICH_AVAILABLE = False
    RenderableType = object  # type: ignore[misc, assignment]


def _status_style(status: str) -> str:
    lowered = (status or "").lower()
    if lowered in {"running", "probing", "starting"}:
        return "bold cyan"
    if lowered in {"completed", "success", "defended"}:
        return "bold green"
    if lowered in {"partial", "idle", "ready"}:
        return "bold yellow"
    if lowered in {"failed", "error", "cancelled"}:
        return "bold red"
    return "bold white"


def _status_badge(status: str) -> Text:
    style = _status_style(status)
    label = (status or "idle").upper()
    return Text(f" {label} ", style=f"{style} reverse")


def _short_model(model: str, width: int = 36) -> str:
    if len(model) <= width:
        return model
    # Prefer keeping provider + tail of model id
    if ":" in model:
        provider, rest = model.split(":", 1)
        tail = rest[-max(8, width - len(provider) - 2) :]
        return f"{provider}:…{tail}" if len(rest) > len(tail) else model
    return "…" + model[-(width - 1) :]


def _kv(label: str, value: str | Text, *, label_style: str = "dim") -> Table:
    row = Table.grid(padding=(0, 1))
    row.add_column(style=label_style, width=9, no_wrap=True)
    row.add_column(overflow="ellipsis", no_wrap=True, ratio=1)
    if isinstance(value, str):
        value = Text(value)
    row.add_row(label, value)
    return row


def render_model_board(state: TuiState) -> RenderableType:
    table = Table(
        expand=True,
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        header_style="bold dim",
        row_styles=["", "on grey7"],
    )
    table.add_column("Model", overflow="ellipsis", no_wrap=True, ratio=3)
    table.add_column("Status", width=12)
    table.add_column("Try", justify="right", width=5)
    table.add_column("OK", justify="right", width=4)
    table.add_column("Fail", justify="right", width=5)
    table.add_column("Payload", overflow="ellipsis", no_wrap=True, ratio=2)
    table.add_column("Tok in/out", justify="right", width=11)

    if state.configured_models:
        models = list(state.configured_models)
    else:
        models = list(state.model_board.keys())

    if not models:
        table.add_row(Text("— no models —", style="dim italic"), "", "", "", "", "", "")
        return table

    for model in models:
        row = state.model_board.get(model)
        if row is None:
            table.add_row(
                Text(_short_model(model), style="white"),
                Text("pending", style="dim"),
                "0",
                "0",
                "0",
                "—",
                "0/0",
            )
            continue
        ok_style = "green" if row.successes else "dim"
        fail_style = "red" if row.failures else "dim"
        table.add_row(
            Text(_short_model(row.model), style="white"),
            Text(row.status, style=_status_style(row.status)),
            str(row.attempts),
            Text(str(row.successes), style=ok_style),
            Text(str(row.failures), style=fail_style),
            Text(row.last_payload or "—", style="cyan"),
            f"{row.tokens_in}/{row.tokens_out}",
        )
    return table


def _progress_section(state: TuiState) -> RenderableType:
    total = max(1, state.attempts_total or state.max_payloads or 1)
    completed = min(state.attempt, total)
    rate = state.successes / max(1, state.successes + state.failures)
    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(ratio=3)
    grid.add_column(ratio=2, justify="right")

    bar = ProgressBar(total=total, completed=completed, width=36, complete_style="cyan")
    meta = Text()
    meta.append(f" {completed}/{total}", style="bold")
    meta.append("  ·  ", style="dim")
    meta.append(f"ok {state.successes}", style="green")
    meta.append(" / ", style="dim")
    meta.append(f"fail {state.failures}", style="red")
    meta.append("  ·  ", style="dim")
    meta.append(f"hit {rate:.0%}", style="yellow")

    right = Text()
    right.append(f"{state.elapsed_seconds():.1f}s", style="bold white")
    right.append("  ", style="dim")
    right.append(f"in {state.tokens_input}", style="dim")
    right.append(" · ", style="dim")
    right.append(f"out {state.tokens_output}", style="dim")

    left = Table.grid(expand=True)
    left.add_row(bar)
    left.add_row(meta)
    grid.add_row(left, right)
    return grid


def _header_panel(state: TuiState) -> Panel:
    outer = Table.grid(expand=True, padding=(0, 0))
    outer.add_column(ratio=1)
    outer.add_column(ratio=1)

    left = Table.grid(padding=(0, 1))
    left.add_column()
    left.add_row(_kv("Status", _status_badge(state.status)))
    left.add_row(_kv("Attack", Text(_short_model(state.attack_id, 40), style="magenta")))
    left.add_row(_kv("Model", Text(_short_model(state.model, 40), style="white")))
    left.add_row(_kv("Payload", Text(state.payload_id or "—", style="cyan bold")))

    right = Table.grid(padding=(0, 1))
    right.add_column()
    run_id = (state.run_id or "—")[:20]
    right.add_row(_kv("Run", Text(run_id, style="dim")))
    right.add_row(_kv("Sample", Text(state.sample_id or "—", style="white")))
    right.add_row(
        _kv(
            "Mode",
            Text(
                f"{state.effort} · sos={'on' if state.stop_on_success else 'off'} · n={state.max_payloads}",
                style="yellow",
            ),
        )
    )
    right.add_row(_kv("Sandbox", Text(state.sandbox, style="dim")))
    outer.add_row(left, right)

    body = Group(
        outer,
        Rule(style="dim"),
        _progress_section(state),
    )
    return Panel(
        body,
        title=f"[bold white]⚡ {state.title}[/]",
        subtitle="[dim]educational canary red-team · refuse≠success[/]",
        subtitle_align="right",
        border_style="bright_cyan",
        box=box.HEAVY,
        padding=(0, 1),
    )


def _activity_feed(state: TuiState, *, limit: int = 10) -> RenderableType:
    feed = Table.grid(expand=True, padding=(0, 1))
    feed.add_column(style="dim", width=8, no_wrap=True)
    feed.add_column(width=2, no_wrap=True)
    feed.add_column(ratio=1, overflow="fold")

    lines = state.activity[-limit:]
    if not lines:
        feed.add_row(
            "--:--:--", Text("·", style="dim"), Text("waiting for events…", style="dim italic")
        )
        return feed

    for line in lines:
        local = line.timestamp.astimezone() if line.timestamp.tzinfo else line.timestamp
        ts = local.strftime("%H:%M:%S")
        if line.ok is True:
            mark = Text("✓", style="bold green")
        elif line.ok is False:
            mark = Text("✗", style="bold red")
        else:
            mark = Text("▸", style="bold yellow")
        msg = Text()
        if line.model:
            msg.append(_short_model(line.model, 18), style="dim")
            msg.append(" ", style="dim")
        msg.append(f"{line.kind}", style="bold bright_black")
        msg.append("  ", style="dim")
        msg.append(line.message, style="white")
        feed.add_row(ts, mark, msg)
    return feed


def render_dashboard(state: TuiState) -> RenderableType:
    if not RICH_AVAILABLE:
        raise RuntimeError("rich is required for the TUI (`pip install rich`)")

    # Mid row: board + live activity side by side feel via sequential panels
    board_panel = Panel(
        render_model_board(state),
        title="[bold yellow]◎ Models[/]",
        border_style="yellow",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    now_text = Text(state.current_activity or "…", style="bold white")
    activity_now = Panel(
        now_text,
        title="[bold cyan]◎ Now[/]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    recent_panel = Panel(
        _activity_feed(state, limit=11),
        title="[bold blue]◎ Timeline[/]",
        border_style="blue",
        box=box.ROUNDED,
        padding=(0, 0),
    )

    out_style = "green" if state.successes else "white"
    output_panel = Panel(
        Text(state.last_output or "— no model output yet —", style=out_style, overflow="fold"),
        title="[bold green]◎ Output[/]",
        border_style="green",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    if state.last_success and "No successful" not in state.last_success:
        success_body = Text(state.last_success, style="bold green", overflow="fold")
        success_border = "bright_green"
        success_title = "[bold bright_green]◎ Leak found[/]"
    else:
        success_body = Text("No compliant disclosure yet (refuse+quote ≠ success).", style="dim")
        success_border = "grey50"
        success_title = "[dim]◎ Leak found[/]"

    success_panel = Panel(
        success_body,
        title=success_title,
        border_style=success_border,
        box=box.ROUNDED,
        padding=(0, 1),
    )

    cmds = Text(state.command_hint, style="dim")
    command_panel = Panel(
        cmds,
        title="[bold magenta]◎ Commands[/] [dim]/help · /model · /run · /stop · /quit[/]",
        border_style="magenta",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    footer = Text()
    footer.append(" F1 ", style="bold reverse")
    footer.append(" help  ", style="dim")
    footer.append(" F5 ", style="bold reverse")
    footer.append(" run  ", style="dim")
    footer.append(" Ctrl+C ", style="bold reverse")
    footer.append(" stop/quit  ", style="dim")
    footer.append("· real success = final-text canary dump only", style="dim")

    # Compact two-column block for timeline + output
    mid = Table.grid(expand=True, padding=(0, 1))
    mid.add_column(ratio=1)
    mid.add_column(ratio=1)
    mid.add_row(recent_panel, output_panel)

    return Group(
        _header_panel(state),
        command_panel,
        board_panel,
        activity_now,
        mid,
        success_panel,
        footer,
    )
