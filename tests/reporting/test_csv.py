"""CSV report tests."""

from __future__ import annotations

import csv
import io
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
from cot_redteam.reporting.renderers import render_csv
from cot_redteam.reporting.report import ReportFormat, ReportWriter


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


def test_requested_format_matches_content(tmp_path: Path) -> None:
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
    run = EvaluationRun(
        run_id="r",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    writer = ReportWriter(tmp_path)
    csv_path = writer.write(run, ReportFormat.CSV)
    assert csv_path.suffix == ".csv"
    assert csv_path.read_text().startswith("section,")


def test_csv_quotes_newlines_and_neutralizes_formulas() -> None:
    output = render_csv(report_with_model_id("=IMPORTXML(...)\nnext"))
    rows = list(csv.reader(io.StringIO(output)))
    bare_rows = [r for r in rows if r[0] == "models" and r[1] == "bare_model_id"]
    assert bare_rows
    assert bare_rows[0][2].startswith("'=")
    assert "\n" in bare_rows[0][2]
