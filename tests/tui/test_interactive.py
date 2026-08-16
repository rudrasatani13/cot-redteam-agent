"""Headless tests for the interactive TUI logic (no terminal needed).

The RedTeamTuiApp constructor and all pure helpers run without a display;
widget-dependent refresh is patched to a no-op where a mounted screen would
be required. One Textual ``run_test`` pilot test exercises mount/unmount.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from cot_redteam.core.config import AppConfig
from cot_redteam.eval.events import RunEvent, RunEventKind
from cot_redteam.tui.interactive import (
    TEXTUAL_AVAILABLE,
    RedTeamTuiApp,
    _clone_config,
    _set_attack_config,
    run_interactive_tui,
)


def _config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "providers": {"mock": {"kind": "mock", "mock_mode": "auto"}},
            "evaluation": {
                "models": ["mock:a", "mock:b"],
                "attacks": ["injection.system_canary_agent"],
                "monitors": ["regex"],
                "dataset_path": "pkg:sample.jsonl",
                "sample_count": 1,
                "budgets": {"max_requests": 100},
                "attack_config": {
                    "injection.system_canary_agent": {
                        "max_attempts": 6,
                        "stop_on_success": True,
                    }
                },
            },
        }
    )


def _make_app(**kwargs) -> RedTeamTuiApp:
    app = RedTeamTuiApp(_config(), **kwargs)
    app._refresh_dashboard = lambda: None  # type: ignore[method-assign]
    return app


def test_clone_config_round_trip() -> None:
    cfg = _config()
    cloned = _clone_config(cfg)
    assert cloned.model_dump() == cfg.model_dump()
    assert cloned is not cfg


def test_set_attack_config_updates_nested() -> None:
    cfg = _config()
    updated = _set_attack_config(cfg, "injection.system_canary_agent", max_attempts=12)
    assert updated.evaluation.attack_config["injection.system_canary_agent"]["max_attempts"] == 12
    # original untouched
    assert cfg.evaluation.attack_config["injection.system_canary_agent"]["max_attempts"] == 6


def test_init_state_from_config() -> None:
    app = _make_app()
    assert app.state.model == "mock:a"
    assert app.state.attack_id == "injection.system_canary_agent"
    assert app.state.effort == "agentic"
    assert app.state.max_payloads == 6
    assert app.state.stop_on_success is True
    assert "mock:a" in app.state.configured_models
    assert "mock:b" in app.state.configured_models


def test_init_state_defaults_without_attacks() -> None:
    cfg = _config().model_copy(
        update={"evaluation": _config().evaluation.model_copy(update={"models": [], "attacks": []})}
    )
    app = RedTeamTuiApp(cfg)
    app._refresh_dashboard = lambda: None  # type: ignore[method-assign]
    assert app.state.model == "-"
    assert app.state.attack_id == "injection.system_canary_agent"
    assert app.state.effort == "agentic"


def test_subtitle_states() -> None:
    app = _make_app()
    app.state.status = "running"
    app.state.attempt = 3
    app.state.attempts_total = 6
    assert "3/6" in app._subtitle()
    app.state.successes = 1
    app.state.status = "completed"
    assert "leak found" in app._subtitle()
    app.state.successes = 0
    app.state.status = "idle"
    assert "educational" in app._subtitle()


def test_status_dump_contains_state() -> None:
    app = _make_app()
    dump = app._status_dump()
    assert "mock:a" in dump
    assert "attack=injection.system_canary_agent" in dump
    assert "payloads=6" in dump


@pytest.mark.parametrize(
    ("effort", "expected_attack"),
    [
        ("agentic", "injection.system_canary_agent"),
        ("adaptive", "injection.system_canary_adaptive"),
        ("fixed", "injection.system_canary"),
    ],
)
def test_apply_session_to_config_effort_mapping(effort: str, expected_attack: str) -> None:
    app = _make_app()
    # Mirrors the /effort handler: choosing a preset un-pins an explicit attack.
    app.state.effort = effort
    app.state.attack_explicit = False
    cfg = app._apply_session_to_config()
    assert cfg.evaluation.attacks == [expected_attack]
    assert cfg.evaluation.models == ["mock:a", "mock:b"]
    attack_cfg = cfg.evaluation.attack_config[expected_attack]
    assert attack_cfg["stop_on_success"] is True
    assert attack_cfg["require_final_text"] is True
    assert attack_cfg["bank_path"] == "pkg:system_canary_bank.jsonl"
    # budget headroom: models * payloads * samples + 2
    assert cfg.evaluation.budgets.max_requests >= 2 * 6 * 1 + 2


def test_apply_session_to_config_explicit_attack_survives_effort() -> None:
    app = _make_app()
    app.state.attack_id = "injection.crescendo_canary"
    app.state.attack_explicit = True
    app.state.effort = "fixed"
    cfg = app._apply_session_to_config()
    # An explicit /attack selection must not be overwritten by effort presets.
    assert cfg.evaluation.attacks == ["injection.crescendo_canary"]


def test_apply_session_to_config_models_override() -> None:
    app = _make_app()
    app.state.configured_models = ["mock:c"]
    cfg = app._apply_session_to_config()
    assert cfg.evaluation.models == ["mock:c"]


def test_handle_command_help_and_status() -> None:
    app = _make_app()
    asyncio.run(app._handle_command("/help"))
    assert "help" in app.state.last_output.lower() or app.state.help_text
    asyncio.run(app._handle_command("/status"))
    assert "attack=" in app.state.last_output


def test_handle_command_model_add_remove() -> None:
    app = _make_app()
    asyncio.run(app._handle_command("/model mock:c"))
    assert app.state.model == "mock:c"
    assert app.session_config.evaluation.models == ["mock:c"]
    asyncio.run(app._handle_command("/add mock:d"))
    assert "mock:d" in app.state.configured_models
    asyncio.run(app._handle_command("/rm mock:c"))
    assert "mock:c" not in app.state.configured_models
    assert "mock:d" in app.state.configured_models
    # cannot remove last model
    asyncio.run(app._handle_command("/rm mock:d"))
    assert "mock:d" in app.state.configured_models


def test_handle_command_model_usage_errors() -> None:
    app = _make_app()
    asyncio.run(app._handle_command("/model"))
    assert "usage" in app.state.current_activity
    asyncio.run(app._handle_command("/add"))
    assert "usage" in app.state.current_activity


def test_handle_command_attack_payloads_effort_sos() -> None:
    app = _make_app()
    asyncio.run(app._handle_command("/attack injection.system_canary"))
    assert app.state.attack_id == "injection.system_canary"
    asyncio.run(app._handle_command("/payloads 3"))
    assert app.state.max_payloads == 3
    asyncio.run(app._handle_command("/payloads 0"))
    assert ">= 1" in app.state.current_activity
    asyncio.run(app._handle_command("/payloads abc"))
    assert "usage" in app.state.current_activity
    asyncio.run(app._handle_command("/effort adaptive"))
    assert app.state.effort == "adaptive"
    assert app.state.attack_id == "injection.system_canary_adaptive"
    asyncio.run(app._handle_command("/effort bogus"))
    assert "usage" in app.state.current_activity
    asyncio.run(app._handle_command("/sos off"))
    assert app.state.stop_on_success is False
    asyncio.run(app._handle_command("/sos on"))
    assert app.state.stop_on_success is True
    asyncio.run(app._handle_command("/sos maybe"))
    assert "usage" in app.state.current_activity


def test_handle_command_clear_and_unknown() -> None:
    app = _make_app()
    app.state.push_activity("run", "something", ok=True)
    asyncio.run(app._handle_command("/clear"))
    # /clear empties the activity log, then notes "activity cleared"
    assert len(app.state.activity) == 1
    assert app.state.activity[0].message == "activity cleared"
    assert app.state.last_output == "cleared"
    asyncio.run(app._handle_command("/frobnicate"))
    assert "unknown command" in app.state.current_activity


def test_consume_events_updates_state() -> None:
    app = _make_app()
    events = [
        RunEvent(
            kind=RunEventKind.RUN_STARTED,
            run_id="r1",
            message="planned 2 items",
            detail={"planned": 2},
        ),
        RunEvent(
            kind=RunEventKind.ITEM_STARTED,
            model="mock:a",
            message="starting",
        ),
        RunEvent(
            kind=RunEventKind.ATTEMPT_STARTED,
            model="mock:a",
            payload_id="p1",
            attempt=1,
            attempts_total=6,
            message="try p1",
        ),
        RunEvent(
            kind=RunEventKind.ATTEMPT_FINISHED,
            model="mock:a",
            payload_id="p1",
            attempt=1,
            success=True,
            tokens_input=10,
            tokens_output=5,
            message="payload p1: SUCCESS",
            detail={"response_preview": "the token is X"},
        ),
        RunEvent(kind=RunEventKind.RUN_FINISHED, status="completed", message="done"),
        None,  # terminates the consumer loop
    ]
    for event in events:
        app._event_queue.put_nowait(event)
    asyncio.run(app._consume_events())
    assert app.state.run_id == "r1"
    assert app.state.items_planned == 2
    assert app.state.status == "completed"  # RUN_FINISHED sets it
    assert app.state.finished is True
    assert app.state.successes == 1
    assert app.state.attempt == 1
    assert app.state.tokens_input == 10
    assert app.state.tokens_output == 5
    assert app.state.last_success.startswith("SUCCESS payload=p1")


def test_consume_events_none_terminates() -> None:
    app = _make_app()
    app._event_queue.put_nowait(None)
    asyncio.run(app._consume_events())  # must return without hanging


def test_start_run_with_mock_provider() -> None:
    app = _make_app()

    async def go() -> None:
        consumer = asyncio.create_task(app._consume_events())
        await app._start_run()
        assert app._eval_task is not None
        await asyncio.wait_for(app._eval_task, timeout=30)
        app._event_queue.put_nowait(None)
        await consumer
        assert app.state.finished is True
        assert app._exit_code in (0, 1, 3)

    asyncio.run(go())


def test_start_run_while_running_is_rejected() -> None:
    app = _make_app()

    async def go() -> None:
        await app._start_run()

        class _FakeTask:
            def done(self) -> bool:
                return False

            async def cancel(self) -> None:
                return None

        app._eval_task = _FakeTask()  # type: ignore[assignment]
        await app._start_run()
        assert "already running" in app.state.current_activity

    asyncio.run(go())


def test_stop_run_cancels_eval(monkeypatch: pytest.MonkeyPatch) -> None:
    import types

    import cot_redteam.tui.interactive as interactive
    from cot_redteam.core.types import RunStatus

    async def slow_eval(cfg, *, environ=None, progress=None):
        await asyncio.sleep(30)  # outlive the test; must be cancelled
        return types.SimpleNamespace(status=RunStatus.COMPLETED, run_id="slow")

    monkeypatch.setattr(interactive, "run_evaluation", slow_eval)
    app = _make_app()

    async def go() -> None:
        await app._start_run()
        assert app._eval_task is not None
        await asyncio.sleep(0.05)  # let the slow eval start
        await app._stop_run()
        assert app.state.status == "cancelled"
        assert app.state.finished is True

    asyncio.run(go())


def test_handle_command_run_stop_flow() -> None:
    app = _make_app()

    async def go() -> None:
        consumer = asyncio.create_task(app._consume_events())
        await app._handle_command("/run")
        assert app._eval_task is not None
        await asyncio.wait_for(app._eval_task, timeout=30)
        app._event_queue.put_nowait(None)
        await consumer
        await app._handle_command("/stop")
        assert "no active run" in app.state.current_activity

    asyncio.run(go())


@pytest.mark.asyncio
async def test_mount_compose_via_pilot() -> None:
    if not TEXTUAL_AVAILABLE:
        pytest.skip("textual not installed")
    from textual.widgets import Input

    app = RedTeamTuiApp(_config())
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#command", Input) is not None
        assert app.query_one("#keys-bar") is not None
        assert app.title == "CoT Red Team"
    # unmount completed cleanly


def test_run_interactive_tui_requires_deps(monkeypatch: pytest.MonkeyPatch) -> None:
    import cot_redteam.tui.interactive as interactive

    monkeypatch.setattr(interactive, "TEXTUAL_AVAILABLE", False)
    monkeypatch.setattr(interactive, "RICH_AVAILABLE", False)
    with pytest.raises(RuntimeError, match="requires rich and textual"):
        asyncio.run(run_interactive_tui(_config()))


def test_config_error_surfaces_in_output() -> None:
    # A dataset path that does not exist passes AppConfig validation but
    # fails validate_config inside _start_run.
    cfg = _config().model_copy(
        update={
            "evaluation": _config().evaluation.model_copy(
                update={"dataset_path": "/nonexistent/definitely-missing.jsonl"}
            )
        }
    )
    app = RedTeamTuiApp(cfg)
    app._refresh_dashboard = lambda: None  # type: ignore[method-assign]
    asyncio.run(app._start_run())
    assert "config error" in app.state.current_activity
    assert app._eval_task is None


def test_event_timestamp_used_for_run_started() -> None:
    app = _make_app()
    ts = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
    app._event_queue.put_nowait(
        RunEvent(
            kind=RunEventKind.RUN_STARTED,
            timestamp=ts,
            message="started",
            detail={"planned": 1},
        )
    )
    app._event_queue.put_nowait(None)
    asyncio.run(app._consume_events())
    assert app.state.started_at == ts


def test_apply_session_to_config_honors_explicit_attack() -> None:
    """Regression: a /attack choice must win over the effort-derived
    default; previously the effort mapping overwrote the user's selection."""
    app = _make_app()
    app.state.attack_id = "custom_attack"
    app.state.attack_explicit = True
    cfg = app._apply_session_to_config()
    assert cfg.evaluation.attacks == ["custom_attack"]


def test_attack_command_marks_explicit_and_applies() -> None:
    """The /attack command path marks the selection explicit so the run
    config keeps it (regression: selection was silently discarded)."""
    app = _make_app()

    async def _drive() -> None:
        await app._handle_command("/attack custom_attack")

    asyncio.run(_drive())
    assert app.state.attack_explicit is True
    cfg = app._apply_session_to_config()
    assert cfg.evaluation.attacks == ["custom_attack"]
