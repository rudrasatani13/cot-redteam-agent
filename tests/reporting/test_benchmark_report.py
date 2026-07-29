from __future__ import annotations

import json
from pathlib import Path

from cot_redteam.reporting.benchmark import (
    BenchmarkReport,
    BenchmarkReportFormat,
    BenchmarkReportWriter,
    render_benchmark_csv,
    render_benchmark_jsonl,
    render_benchmark_markdown,
)
from tests.benchmark.test_results import benchmark_run_result


def test_benchmark_markdown_separates_security_utility_and_channels(
    tmp_path: Path,
) -> None:
    report = BenchmarkReport.from_run(benchmark_run_result(tmp_path))

    markdown = render_benchmark_markdown(report)

    assert "Security outcomes" in markdown
    assert "Utility outcomes" in markdown
    assert "final" in markdown
    assert "reasoning" in markdown
    assert "universal score" not in markdown.lower()
    assert "COTRT3-abcdef01-12345678" in markdown


def test_benchmark_jsonl_is_lossless_trial_level_export(tmp_path: Path) -> None:
    run = benchmark_run_result(tmp_path)

    rows = [json.loads(line) for line in render_benchmark_jsonl(run).splitlines()]

    assert len(rows) == 1
    assert rows[0]["trial"]["trial_id"] == run.trials[0].trial.trial_id
    assert rows[0]["transcript"]["turns"][0]["response"]["reasoning"].startswith("private")
    assert rows[0]["scoring"]["outcomes"]


def test_benchmark_csv_is_flattened_per_scorer_outcome(tmp_path: Path) -> None:
    run = benchmark_run_result(tmp_path)

    output = render_benchmark_csv(run)

    assert output.startswith("run_id,trial_id,model,")
    assert "scorer_id" in output.splitlines()[0]
    assert run.trials[0].trial.scenario.id in output


def test_benchmark_writer_uses_requested_extension(tmp_path: Path) -> None:
    run = benchmark_run_result(tmp_path)
    writer = BenchmarkReportWriter(tmp_path / "reports")

    path = writer.write(run, BenchmarkReportFormat.JSONL)

    assert path.suffix == ".jsonl"
    assert path.exists()
