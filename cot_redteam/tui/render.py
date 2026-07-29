"""Compact single-screen layout for the adaptive red-team TUI."""

from __future__ import annotations

from cot_redteam.tui.state import TuiState

try:
    from rich import box
    from rich.console import Group, RenderableType
    from rich.panel import Panel
    from rich.progress_bar import ProgressBar
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
    if ":" in model:
        provider, rest = model.split(":", 1)
        keep = max(8, width - len(provider) - 2)
        tail = rest[-keep:]
        return f"{provider}:…{tail}" if len(rest) > keep else model
    return "…" + model[-(width - 1) :]


def _clip(text: str, max_lines: int = 4, max_chars: int = 480) -> str:
    text = (text or "").strip()
    if not text:
        return "—"
    lines = text.splitlines()
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines]) + "\n…"
    if len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return text


def render_model_board(state: TuiState, *, max_rows: int = 4) -> RenderableType:
    table = Table(
        expand=True,
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        header_style="bold dim",
        padding=(0, 1),
    )
    table.add_column("Model", overflow="ellipsis", no_wrap=True, ratio=3)
    table.add_column("Status", width=10)
    table.add_column("Try", justify="right", width=4)
    table.add_column("OK", justify="right", width=3)
    table.add_column("Fail", justify="right", width=4)
    table.add_column("Payload", overflow="ellipsis", no_wrap=True, ratio=2)
    table.add_column("Tok", justify="right", width=9)

    if state.configured_models:
        models = list(state.configured_models)
    else:
        models = list(state.model_board.keys())

    if not models:
        table.add_row(Text("— no models —", style="dim italic"), "", "", "", "", "", "")
        return table

    shown = models[:max_rows]
    for model in shown:
        row = state.model_board.get(model)
        if row is None:
            table.add_row(
                Text(_short_model(model, 32), style="white"),
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
            Text(_short_model(row.model, 32), style="white"),
            Text(row.status, style=_status_style(row.status)),
            str(row.attempts),
            Text(str(row.successes), style=ok_style),
            Text(str(row.failures), style=fail_style),
            Text(row.last_payload or "—", style="cyan"),
            f"{row.tokens_in}/{row.tokens_out}",
        )
    if len(models) > max_rows:
        table.add_row(
            Text(f"… +{len(models) - max_rows} more", style="dim"),
            "",
            "",
            "",
            "",
            "",
            "",
        )
    return table


def _header_block(state: TuiState) -> Panel:
    """Compact 3-line header: identity + progress on one strip."""
    total = max(1, state.attempts_total or state.max_payloads or 1)
    completed = min(state.attempt, total)
    rate = state.successes / max(1, state.successes + state.failures)

    top = Table.grid(expand=True, padding=(0, 1))
    top.add_column(ratio=3)
    top.add_column(ratio=2, justify="right")

    left = Text()
    left.append_text(_status_badge(state.status))
    left.append("  ")
    left.append(_short_model(state.attack_id, 34), style="magenta")
    left.append("\n")
    left.append(_short_model(state.model, 42), style="white")
    left.append("  ")
    left.append(state.payload_id or "—", style="cyan bold")

    right = Text()
    right.append(f"{state.effort}", style="yellow")
    right.append(f" · sos={'on' if state.stop_on_success else 'off'}", style="dim")
    right.append(f" · n={state.max_payloads}\n", style="dim")
    right.append(f"{state.elapsed_seconds():.1f}s", style="bold")
    right.append(f"  in {state.tokens_input} · out {state.tokens_output}", style="dim")
    if state.run_id and state.run_id != "-":
        right.append(f"\n{(state.run_id or '')[:18]}", style="dim")
    top.add_row(left, right)

    prog = Table.grid(expand=True, padding=(0, 1))
    prog.add_column(ratio=1)
    bar = ProgressBar(total=total, completed=completed, width=40, complete_style="cyan")
    meta = Text.assemble(
        (f"{completed}/{total}", "bold"),
        (" · ", "dim"),
        (f"ok {state.successes}", "green"),
        (" / ", "dim"),
        (f"fail {state.failures}", "red"),
        (" · ", "dim"),
        (f"hit {rate:.0%}", "yellow"),
        ("  ", "dim"),
    )
    # one visual row: bar + stats
    strip = Table.grid(expand=True, padding=(0, 1))
    strip.add_column(ratio=1)
    strip.add_column(justify="right", no_wrap=True)
    strip.add_row(bar, meta)
    prog.add_row(strip)

    body = Group(top, prog)
    return Panel(
        body,
        title=f"[bold white]{state.title}[/]",
        border_style="bright_cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _activity_feed(state: TuiState, *, limit: int = 5) -> RenderableType:
    feed = Table.grid(expand=True, padding=(0, 1))
    feed.add_column(style="dim", width=8, no_wrap=True)
    feed.add_column(width=2, no_wrap=True)
    feed.add_column(ratio=1, overflow="ellipsis", no_wrap=True)

    lines = state.activity[-limit:]
    if not lines:
        feed.add_row(
            "--:--:--",
            Text("·", style="dim"),
            Text("waiting for events…", style="dim italic"),
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
        msg = f"{line.kind}: {line.message}"
        if len(msg) > 72:
            msg = msg[:71] + "…"
        feed.add_row(ts, mark, Text(msg, style="white"))
    return feed


def render_dashboard(state: TuiState) -> RenderableType:
    """Single-viewport dashboard: everything fits without scrolling off-screen."""
    if not RICH_AVAILABLE:
        raise RuntimeError("rich is required for the TUI (`pip install rich`)")

    header = _header_block(state)

    board = Panel(
        render_model_board(state, max_rows=3),
        title="[bold yellow]Models[/]",
        border_style="yellow",
        box=box.ROUNDED,
        padding=(0, 0),
    )

    # Single-line "now" strip — no tall empty panel
    now = Text.assemble(
        (" NOW ", "bold cyan reverse"),
        (" ", ""),
        (state.current_activity or "…", "bold white"),
    )

    timeline = Panel(
        _activity_feed(state, limit=6),
        title="[bold blue]Timeline[/]",
        border_style="blue",
        box=box.ROUNDED,
        padding=(0, 0),
    )

    out_style = "green" if state.successes else "white"
    output = Panel(
        Text(
            _clip(state.last_output or "No model output yet.", max_lines=6, max_chars=420),
            style=out_style,
            overflow="fold",
        ),
        title="[bold green]Output[/]",
        border_style="green",
        box=box.ROUNDED,
        padding=(0, 1),
    )

    mid = Table.grid(expand=True, padding=(0, 1))
    mid.add_column(ratio=1)
    mid.add_column(ratio=1)
    mid.add_row(timeline, output)

    if state.last_success and "No successful" not in state.last_success:
        leak_text = _clip(state.last_success, max_lines=2, max_chars=220)
        leak_style = "bold green"
        leak_border = "bright_green"
        leak_title = "[bold bright_green]Leak[/]"
    else:
        leak_text = "No compliant disclosure yet (refuse+quote ≠ success)."
        leak_style = "dim"
        leak_border = "grey37"
        leak_title = "[dim]Leak[/]"

    leak = Panel(
        Text(leak_text, style=leak_style, overflow="ellipsis"),
        title=leak_title,
        border_style=leak_border,
        box=box.ROUNDED,
        padding=(0, 1),
    )

    # Compact stack: fits typical terminals; dashboard remains scrollable if needed.
    return Group(header, board, now, mid, leak)
