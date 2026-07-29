"""Codex-style panel layout rendered with Rich (fallback + Textual widgets)."""

from __future__ import annotations

from cot_redteam.tui.state import TuiState

try:
    from rich import box
    from rich.console import Group, RenderableType
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    RICH_AVAILABLE = False
    RenderableType = object  # type: ignore[misc, assignment]


def _status_color(status: str) -> str:
    lowered = status.lower()
    if lowered in {"running", "probing", "starting"}:
        return "bold cyan"
    if lowered in {"completed", "success", "defended"}:
        return "bold green"
    if lowered in {"partial", "idle"}:
        return "bold yellow"
    if lowered in {"failed", "error", "cancelled"}:
        return "bold red"
    return "white"


def render_model_board(state: TuiState) -> RenderableType:
    table = Table(expand=True, box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False)
    table.add_column("Model", overflow="ellipsis", no_wrap=True, ratio=3)
    table.add_column("Status", width=10)
    table.add_column("Try", justify="right", width=5)
    table.add_column("OK", justify="right", width=4)
    table.add_column("Fail", justify="right", width=5)
    table.add_column("Payload", overflow="ellipsis", no_wrap=True, ratio=2)
    table.add_column("Tokens", justify="right", width=12)

    if state.configured_models:
        models = list(state.configured_models)
    else:
        models = list(state.model_board.keys())
    if not models:
        table.add_row("-", "empty", "0", "0", "0", "-", "0/0")
    else:
        for model in models:
            row = state.model_board.get(model)
            if row is None:
                table.add_row(model, "pending", "0", "0", "0", "-", "0/0")
                continue
            table.add_row(
                row.model,
                Text(row.status, style=_status_color(row.status)),
                str(row.attempts),
                str(row.successes),
                str(row.failures),
                row.last_payload,
                f"{row.tokens_in}/{row.tokens_out}",
            )
    return table


def render_dashboard(state: TuiState) -> RenderableType:
    if not RICH_AVAILABLE:
        raise RuntimeError("rich is required for the TUI (`pip install rich`)")

    header = Table.grid(expand=True)
    header.add_column(justify="left", ratio=1)
    header.add_column(justify="left", ratio=1)

    left = Table.grid(padding=(0, 2))
    left.add_column(style="dim", width=10)
    left.add_column(overflow="ellipsis", no_wrap=True)
    left.add_row("Status", Text(state.status, style=_status_color(state.status)))
    left.add_row("Attempt", f"{state.attempt}/{state.attempts_total or '-'}")
    left.add_row("Run ID", (state.run_id or "-")[:28])
    left.add_row("Model", state.model)
    left.add_row("Attack", state.attack_id)
    left.add_row("Sandbox", state.sandbox)

    right = Table.grid(padding=(0, 2))
    right.add_column(style="dim", width=10)
    right.add_column(overflow="ellipsis", no_wrap=True)
    right.add_row("Elapsed", f"{state.elapsed_seconds():.1f}s")
    right.add_row("Sample", state.sample_id)
    right.add_row("Payload", state.payload_id or "-")
    right.add_row("Effort", f"{state.effort} · n={state.max_payloads}")
    right.add_row(
        "Tokens",
        f"in={state.tokens_input} out={state.tokens_output}",
    )
    right.add_row(
        "Score",
        f"ok={state.successes} fail={state.failures} "
        f"items={state.items_done}/{state.items_planned or '-'}",
    )
    header.add_row(left, right)

    status_panel = Panel(
        header,
        title=f"[bold cyan]{state.title}[/]",
        border_style="cyan",
        box=box.ROUNDED,
    )

    command_panel = Panel(
        Text(state.command_hint, style="dim"),
        title="[magenta]Command · slash cmds apply before /run[/]",
        border_style="magenta",
        box=box.ROUNDED,
    )

    board_panel = Panel(
        render_model_board(state),
        title="[yellow]Multi-model board[/]",
        border_style="yellow",
        box=box.ROUNDED,
    )

    activity_panel = Panel(
        Text(state.current_activity or "…", style="white"),
        title="[cyan]Current activity[/]",
        border_style="cyan",
        box=box.ROUNDED,
    )

    recent = Table.grid(expand=True)
    recent.add_column(style="dim", min_width=10)
    recent.add_column(min_width=3)
    recent.add_column()
    for line in state.activity[-12:]:
        local = line.timestamp.astimezone() if line.timestamp.tzinfo else line.timestamp
        ts = local.strftime("%H:%M:%S")
        if line.ok is True:
            mark = Text("✓", style="green")
        elif line.ok is False:
            mark = Text("✗", style="red")
        else:
            mark = Text("▸", style="yellow")
        prefix = f"[{line.model}] " if line.model else ""
        recent.add_row(ts, mark, f"{prefix}{line.kind}: {line.message}")
    if not state.activity:
        recent.add_row("--:--:--", Text("·", style="dim"), "waiting for events…")

    recent_panel = Panel(
        recent,
        title="[blue]Recent activity[/]",
        border_style="blue",
        box=box.ROUNDED,
    )

    output_panel = Panel(
        Text(state.last_output or "", overflow="fold"),
        title="[green]Model / assessment output[/]",
        border_style="green",
        box=box.ROUNDED,
    )

    success_panel = Panel(
        Text(state.last_success or "", overflow="fold"),
        title="[green]Last successful disclosure[/]",
        border_style="green",
        box=box.ROUNDED,
    )

    help_or_footer = state.help_text or (
        "Real success = canary leak only · refusal analysis not counted · "
        "Ctrl-C or /stop cancels · /quit exits"
    )
    footer = Text(help_or_footer, style="dim")

    return Group(
        status_panel,
        command_panel,
        board_panel,
        activity_panel,
        recent_panel,
        output_panel,
        success_panel,
        footer,
    )
