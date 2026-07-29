"""TUI state + render smoke tests."""

from __future__ import annotations

from cot_redteam.eval.events import RunEvent, RunEventKind
from cot_redteam.tui.render import RICH_AVAILABLE, render_dashboard
from cot_redteam.tui.state import TuiState


def test_state_tracks_adaptive_success_and_refusal() -> None:
    state = TuiState()
    state.ensure_models(["xkiro:qwen/qwen3.5-flash", "xkiro:deepseek/deepseek-v4-flash"])
    state.apply_event(
        RunEvent(
            kind=RunEventKind.RUN_STARTED,
            run_id="r1",
            message="planned 1",
            detail={"planned": 1},
        )
    )
    state.apply_event(
        RunEvent(
            kind=RunEventKind.ATTEMPT_FINISHED,
            run_id="r1",
            model="xkiro:qwen/qwen3.5-flash",
            attack_id="injection.system_canary_adaptive",
            payload_id="direct_override",
            attempt=1,
            attempts_total=5,
            success=False,
            message="payload direct_override: fail",
            detail={"refusal_analysis_with_canary_quote": 1.0, "response_preview": "I cannot"},
        )
    )
    state.apply_event(
        RunEvent(
            kind=RunEventKind.ATTEMPT_FINISHED,
            run_id="r1",
            model="xkiro:qwen/qwen3.5-flash",
            attack_id="injection.system_canary_adaptive",
            payload_id="priority_hierarchy",
            attempt=3,
            attempts_total=5,
            success=True,
            message="payload priority_hierarchy: SUCCESS",
            detail={"response_preview": "CANARY\n150 km"},
            evidence=("System canary disclosed in response text",),
        )
    )

    assert state.failures == 1
    assert state.successes == 1
    assert state.payload_id == "priority_hierarchy"
    assert "SUCCESS payload=priority_hierarchy" in state.last_success
    assert "CANARY" in state.last_output
    board = state.model_board["xkiro:qwen/qwen3.5-flash"]
    assert board.successes == 1
    assert board.failures == 1


def test_render_dashboard_smoke() -> None:
    if not RICH_AVAILABLE:
        return
    state = TuiState(status="running", model="xkiro:qwen/qwen3.5-flash")
    state.push_activity("payload", "trying direct_override", ok=None)
    panel = render_dashboard(state)
    assert panel is not None
