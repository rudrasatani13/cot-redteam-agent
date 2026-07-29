"""LaTeX report tests."""

from __future__ import annotations

from datetime import datetime, timezone

from cot_redteam.core.types import (
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    ModelRef,
    RunSummary,
)
from cot_redteam.reporting.model import ReportModel
from cot_redteam.reporting.renderers import render_latex


def report_with_model_id(model_id: str) -> ReportModel:
    items = [
        EvaluationItem(
            item_id="i",
            model=ModelRef(provider="p", model_id=model_id),
            attack_id="a",
            sample_id="s",
            status=ItemStatus.PROVIDER_ERROR,
            error="e",
        )
    ]
    summary = RunSummary.from_items(items)
    run = EvaluationRun(
        run_id="r",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    return ReportModel.from_run(run)


def test_latex_escapes_all_control_characters() -> None:
    from cot_redteam.reporting.renderers import latex_escape

    raw = r"a_b%#&{}$"
    assert latex_escape(raw) == r"a\_b\%\#\&\{\}\$"
    output = render_latex(report_with_model_id(raw))
    # Full model ref is provider:model_id
    assert latex_escape(f"p:{raw}") in output
