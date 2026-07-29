"""Markdown report tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.core.types import (
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    ModelRef,
    RunSummary,
)
from cot_redteam.reporting.model import ReportModel
from cot_redteam.reporting.renderers import render_markdown
from cot_redteam.reporting.report import ReportFormat, ReportWriter


def _failed_run() -> EvaluationRun:
    items = [
        EvaluationItem(
            item_id="i",
            model=ModelRef.parse("p:m"),
            attack_id="a",
            sample_id="s",
            status=ItemStatus.PROVIDER_ERROR,
            error="e",
        )
    ]
    summary = RunSummary.from_items(items)
    return EvaluationRun(
        run_id="r1",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


def test_markdown_contains_status() -> None:
    report = ReportModel.from_run(_failed_run())
    md = render_markdown(report)
    assert "Status" in md
    assert "N/A" in md


def test_writer_markdown(tmp_path: Path) -> None:
    path = ReportWriter(tmp_path).write(_failed_run(), ReportFormat.MARKDOWN)
    assert path.suffix == ".md"
    assert path.exists()
