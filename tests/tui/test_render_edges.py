"""Edge-case tests for TUI render helpers and the Rich live dashboard."""

from __future__ import annotations

import pytest

from cot_redteam.core.config import AppConfig
from cot_redteam.tui.render import (
    RICH_AVAILABLE,
    _clip,
    _short_model,
    _status_badge,
    _status_style,
    render_dashboard,
    render_header,
    render_leak,
    render_model_board,
    render_now,
    render_output,
    render_timeline,
)
from cot_redteam.tui.state import TuiState


def _state() -> TuiState:
    state = TuiState()
    state.ensure_models(["mock:a", "mock:very-long-model-name-that-exceeds-width"])
    state.model = "mock:a"
    state.attack_id = "injection.system_canary_agent"
    return state


def test_status_style_and_badge() -> None:
    for status in (
        "idle",
        "running",
        "probing",
        "completed",
        "partial",
        "failed",
        "cancelled",
        "weird",
    ):
        style = _status_style(status)
        assert isinstance(style, str)
        badge = _status_badge(status)
        assert badge is not None


def test_short_model_truncation() -> None:
    assert _short_model("mock:a") == "mock:a"
    assert (
        _short_model("mock:abcdefghijklmnopqrstuvwxyz0123456789", width=20)
        != "mock:abcdefghijklmnopqrstuvwxyz0123456789"
    )
    assert len(_short_model("mock:a", width=10)) <= 11  # ellipsis allowance


def test_clip_limits() -> None:
    assert _clip("short", max_lines=4, max_chars=480) == "short"
    long_text = "\n".join(f"line {i}" for i in range(20))
    clipped = _clip(long_text, max_lines=3, max_chars=480)
    assert clipped.count("\n") <= 3
    wide = "x" * 1000
    clipped_wide = _clip(wide, max_lines=4, max_chars=100)
    assert len(clipped_wide) <= 120


def test_render_all_regions_empty_state() -> None:
    state = TuiState()  # completely fresh, no models
    for render in (render_header, render_now, render_output, render_leak):
        assert render(state) is not None
    assert render_timeline(state, limit=5) is not None
    assert render_model_board(state, max_rows=2) is not None


def test_render_regions_with_activity() -> None:
    state = _state()
    state.push_activity("run", "started", ok=True)
    state.push_activity("payload", "try p1", ok=None)
    state.push_activity("result", "failed", ok=False)
    state.last_output = "model said something"
    state.last_success = "SUCCESS payload=p1"
    state.items_done = 1
    state.items_planned = 2
    for render in (render_header, render_now, render_output, render_leak):
        assert render(state) is not None
    assert render_timeline(state, limit=2) is not None
    assert render_model_board(state, max_rows=2) is not None


def test_render_dashboard_smoke_with_rich() -> None:
    if not RICH_AVAILABLE:
        pytest.skip("rich not installed")
    from rich.console import Console

    rendered = render_dashboard(_state())
    assert rendered is not None
    console = Console(record=True, width=100)
    console.print(rendered)
    text = console.export_text()
    assert "CoT Red Team" in text or "mock:a" in text


def _mock_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "providers": {"mock": {"kind": "mock", "mock_mode": "auto"}},
            "evaluation": {
                "models": ["mock:a"],
                "attacks": ["injection.system_canary"],
                "monitors": ["regex"],
                "dataset_path": "pkg:sample.jsonl",
                "sample_count": 1,
                "budgets": {"max_requests": 10},
            },
        }
    )


@pytest.mark.asyncio
async def test_run_rich_live_completes_with_mock() -> None:
    if not RICH_AVAILABLE:
        pytest.skip("rich not installed")
    from cot_redteam.tui.app import _run_rich_live

    exit_code = await _run_rich_live(_mock_config(), environ=None, refresh_hz=4.0)
    assert exit_code in (0, 1, 3)


@pytest.mark.asyncio
async def test_run_tui_path_uses_interactive_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_tui with interactive=True must delegate to the Textual TUI when
    the deps are present, else fall back to the rich live dashboard."""
    import cot_redteam.tui.app as app_module
    import cot_redteam.tui.interactive as interactive_module

    called = {"interactive": False, "rich": False}

    async def fake_interactive(config, *, environ=None, auto_start=False):
        called["interactive"] = True
        return 0

    async def fake_rich(config, *, environ=None, refresh_hz=8.0):
        called["rich"] = True
        return 0

    monkeypatch.setattr(interactive_module, "TEXTUAL_AVAILABLE", True)
    monkeypatch.setattr(interactive_module, "RICH_AVAILABLE", True)
    monkeypatch.setattr(interactive_module, "run_interactive_tui", fake_interactive)
    monkeypatch.setattr(app_module, "_run_rich_live", fake_rich)
    result = await app_module.run_tui(
        _mock_config(),
        interactive=True,
        environ=None,
    )
    assert result == 0
    assert called["interactive"] is True
    assert called["rich"] is False


@pytest.mark.asyncio
async def test_run_tui_falls_back_to_rich_when_textual_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import cot_redteam.tui.app as app_module
    import cot_redteam.tui.interactive as interactive_module

    called = {"rich": False}

    async def fake_rich(config, *, environ=None, refresh_hz=8.0):
        called["rich"] = True
        return 3

    monkeypatch.setattr(interactive_module, "TEXTUAL_AVAILABLE", False)
    monkeypatch.setattr(app_module, "_run_rich_live", fake_rich)
    result = await app_module.run_tui(_mock_config(), interactive=True, environ=None)
    assert result == 3
    assert called["rich"] is True


@pytest.mark.asyncio
async def test_run_tui_runtime_crash_does_not_restart_billed_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash inside the interactive TUI must not silently start a second
    (billed) evaluation through the Rich fallback dashboard."""
    import cot_redteam.tui.app as app_module
    import cot_redteam.tui.interactive as interactive_module

    called = {"rich": False}

    async def fake_rich(config, *, environ=None, refresh_hz=8.0):
        called["rich"] = True
        return 3

    async def boom_interactive(*args, **kwargs):
        raise RuntimeError("textual broken")

    monkeypatch.setattr(interactive_module, "TEXTUAL_AVAILABLE", True)
    monkeypatch.setattr(interactive_module, "RICH_AVAILABLE", True)
    monkeypatch.setattr(interactive_module, "run_interactive_tui", boom_interactive)
    monkeypatch.setattr(app_module, "_run_rich_live", fake_rich)
    with pytest.raises(RuntimeError, match="textual broken"):
        await app_module.run_tui(_mock_config(), interactive=True, environ=None)
    assert called["rich"] is False


@pytest.mark.asyncio
async def test_run_tui_non_interactive_uses_rich(monkeypatch: pytest.MonkeyPatch) -> None:
    import cot_redteam.tui.app as app_module

    called = {"rich": False}

    async def fake_rich(config, *, environ=None, refresh_hz=8.0):
        called["rich"] = True
        return 0

    monkeypatch.setattr(app_module, "_run_rich_live", fake_rich)
    result = await app_module.run_tui(_mock_config(), interactive=False, environ=None)
    assert result == 0
    assert called["rich"] is True


def test_run_tui_sync_wraps_async(monkeypatch: pytest.MonkeyPatch) -> None:
    import cot_redteam.tui.app as app_module

    async def fake_rich(config, *, environ=None, refresh_hz=8.0):
        return 0

    monkeypatch.setattr(app_module, "_run_rich_live", fake_rich)
    assert app_module.run_tui_sync(_mock_config(), interactive=False) == 0
