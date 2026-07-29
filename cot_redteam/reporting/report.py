"""Format dispatcher and file writer."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from cot_redteam.core.types import EvaluationRun
from cot_redteam.reporting.model import ReportModel
from cot_redteam.reporting.renderers import render_csv, render_latex, render_markdown
from cot_redteam.storage.artifacts import ArtifactStore


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    CSV = "csv"
    LATEX = "latex"


_EXTENSIONS = {
    ReportFormat.MARKDOWN: ".md",
    ReportFormat.CSV: ".csv",
    ReportFormat.LATEX: ".tex",
}

_MEDIA = {
    ReportFormat.MARKDOWN: "text/markdown",
    ReportFormat.CSV: "text/csv",
    ReportFormat.LATEX: "application/x-tex",
}


class ReportWriter:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.store = ArtifactStore(self.output_dir)

    def write(
        self,
        run: EvaluationRun,
        fmt: ReportFormat,
        *,
        manifest: dict | None = None,
        filename: str | None = None,
    ) -> Path:
        report = ReportModel.from_run(run, manifest=manifest)
        if fmt is ReportFormat.MARKDOWN:
            content = render_markdown(report)
        elif fmt is ReportFormat.CSV:
            content = render_csv(report)
        elif fmt is ReportFormat.LATEX:
            content = render_latex(report)
        else:
            raise ValueError(f"unsupported format: {fmt}")
        name = filename or f"{run.run_id}{_EXTENSIONS[fmt]}"
        result = self.store.write_text(name, content, media_type=_MEDIA[fmt])
        return result.absolute_path
