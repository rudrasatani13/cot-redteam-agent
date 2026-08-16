"""Benchmark-specific aggregate and evidence reports."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from cot_redteam.benchmark.metrics import (
    BenchmarkObservation,
    BenchmarkRateSummary,
    summarize_observations,
)
from cot_redteam.benchmark.results import BenchmarkRunResult
from cot_redteam.benchmark.scoring import EvidenceChannel
from cot_redteam.core.serialization import canonical_json
from cot_redteam.reporting.renderers import (
    csv_neutralize,
    latex_escape,
    md_escape,
    md_inline_code,
)
from cot_redteam.storage.artifacts import ArtifactStore


@dataclass(frozen=True)
class BenchmarkMetricRow:
    dimension: str
    value: str
    scorer_id: str
    channel: EvidenceChannel
    summary: BenchmarkRateSummary


@dataclass(frozen=True)
class BenchmarkReport:
    run: BenchmarkRunResult
    primary_security: BenchmarkRateSummary
    reasoning_security: BenchmarkRateSummary
    utility: BenchmarkRateSummary
    false_refusal: BenchmarkRateSummary
    grouped: tuple[BenchmarkMetricRow, ...]

    @classmethod
    def from_run(cls, run: BenchmarkRunResult) -> BenchmarkReport:
        primary_final: list[BenchmarkObservation] = []
        primary_reasoning: list[BenchmarkObservation] = []
        utility: list[BenchmarkObservation] = []
        false_refusal: list[BenchmarkObservation] = []
        grouped_values: dict[tuple[str, str, str, EvidenceChannel], list[BenchmarkObservation]] = {}
        for result in run.trials:
            # The scenario schema has no explicit primary-scorer designation,
            # so the primary security metric uses the lexicographically first
            # non-utility scorer id. Sorting makes the choice deterministic
            # and reorder-proof: shuffling the scenario's scorer list cannot
            # silently change which scorer drives the headline metric.
            scorer_ids = sorted(
                scorer.id
                for scorer in result.trial.scenario.scorers
                if not scorer.id.startswith("scorer.utility.")
                and scorer.id != "scorer.response.present"
            )
            primary_id = scorer_ids[0] if scorer_ids else None
            dimensions = {
                "model": str(result.trial.model),
                "policy": result.trial.policy_id,
                "family": result.trial.scenario.family,
                "delivery_channel": result.trial.scenario.channel,
                "transformation": result.trial.transformation_id,
                "scenario": result.trial.scenario.id,
            }
            for outcome in result.scoring.outcomes:
                observation = BenchmarkObservation(outcome.verdict)
                if outcome.scorer_id == primary_id:
                    if outcome.channel is EvidenceChannel.FINAL:
                        primary_final.append(observation)
                    else:
                        primary_reasoning.append(observation)
                if (
                    outcome.scorer_id == "scorer.utility.expected_output"
                    and outcome.channel is EvidenceChannel.FINAL
                ):
                    utility.append(observation)
                if (
                    outcome.scorer_id == "scorer.utility.false_refusal"
                    and outcome.channel is EvidenceChannel.FINAL
                ):
                    false_refusal.append(observation)
                for dimension, value in dimensions.items():
                    grouped_values.setdefault(
                        (dimension, value, outcome.scorer_id, outcome.channel),
                        [],
                    ).append(observation)
                grouped_values.setdefault(
                    ("scorer", outcome.scorer_id, outcome.scorer_id, outcome.channel),
                    [],
                ).append(observation)
        grouped = tuple(
            BenchmarkMetricRow(
                dimension=key[0],
                value=key[1],
                scorer_id=key[2],
                channel=key[3],
                summary=summarize_observations(tuple(observations)),
            )
            for key, observations in sorted(
                grouped_values.items(),
                key=lambda item: (
                    item[0][0],
                    item[0][1],
                    item[0][2],
                    item[0][3].value,
                ),
            )
        )
        return cls(
            run=run,
            primary_security=summarize_observations(tuple(primary_final)),
            reasoning_security=summarize_observations(tuple(primary_reasoning)),
            utility=summarize_observations(tuple(utility)),
            false_refusal=summarize_observations(tuple(false_refusal)),
            grouped=grouped,
        )


def _rate(summary: BenchmarkRateSummary) -> str:
    if summary.rate is None:
        return f"N/A (eligible=0, excluded={summary.excluded})"
    return (
        f"{summary.rate:.3f} (eligible={summary.eligible}, excluded={summary.excluded}, "
        f"95% CI={summary.ci_low:.3f}–{summary.ci_high:.3f})"
    )


def _indented(value: str | None) -> list[str]:
    if value is None:
        return ["    (not retained or unavailable)"]
    return [f"    {line}" for line in (value.splitlines() or [""])]


def render_benchmark_markdown(report: BenchmarkReport) -> str:
    lines = [
        f"# CoT Red Team Benchmark: {report.run.run_id}",
        "",
        "Security and utility are reported separately; this benchmark does not produce a "
        "universal security score.",
        "",
        "## Security outcomes",
        "",
        f"- Primary objective, final: {_rate(report.primary_security)}",
        f"- Primary objective, reasoning: {_rate(report.reasoning_security)}",
        "",
        "## Utility outcomes",
        "",
        f"- Benign task success: {_rate(report.utility)}",
        f"- False refusal: {_rate(report.false_refusal)}",
        "",
        "## Trial evidence",
        "",
    ]
    for result in report.run.trials:
        trial = result.trial
        lines.extend(
            [
                f"### {trial.scenario.id} — repetition {trial.repetition}",
                "",
                f"- Model: {md_inline_code(str(trial.model))}",
                f"- Policy / technique / transformation: {md_inline_code(trial.policy_id)} / "
                f"{md_inline_code(trial.technique_id)} / {md_inline_code(trial.transformation_id)}",
                f"- Status: {md_inline_code(result.transcript.status.value)}",
                "",
            ]
        )
        for turn in result.transcript.turns:
            lines.extend([f"#### Turn {turn.turn_index}", ""])
            if turn.response is None:
                lines.extend([f"- Error: {md_escape(turn.error or 'No response')}", ""])
                continue
            lines.extend(
                [
                    "Final response:",
                    "",
                    *_indented(turn.response.text),
                    "",
                    "Visible reasoning:",
                    "",
                    *_indented(turn.response.reasoning),
                    "",
                ]
            )
        lines.extend(["Scorer outcomes:", ""])
        for outcome in result.scoring.outcomes:
            score = "N/A" if outcome.score is None else f"{outcome.score:.3f}"
            lines.append(
                f"- {md_inline_code(outcome.scorer_id)} / {outcome.channel.value}: "
                f"**{outcome.verdict.value}** (eligible={str(outcome.eligible).lower()}, "
                f"score={score}) — {md_escape(outcome.explanation)}"
            )
            for evidence in outcome.evidence:
                lines.append(
                    f"  - turn {evidence.turn_index}, [{evidence.start}:{evidence.end}]: "
                    f"{md_inline_code(evidence.text)}"
                )
        lines.append("")
    return "\n".join(lines)


def render_benchmark_jsonl(run: BenchmarkRunResult) -> str:
    return "\n".join(
        canonical_json(
            {
                "run_id": run.run_id,
                "trial": result.trial,
                "transcript": result.transcript,
                "scoring": result.scoring,
                "canary_metadata": result.canary_metadata,
                "transformation_digest": result.transformation_digest,
                "judge_results": result.judge_results,
            }
        )
        for result in run.trials
    ) + ("\n" if run.trials else "")


def render_benchmark_csv(run: BenchmarkRunResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "run_id",
            "trial_id",
            "model",
            "suite_id",
            "scenario_id",
            "family",
            "delivery_channel",
            "policy_id",
            "technique_id",
            "transformation_id",
            "repetition",
            "status",
            "scorer_id",
            "scorer_version",
            "evidence_channel",
            "verdict",
            "eligible",
            "score",
            "metrics_json",
            "error",
        ]
    )
    for result in run.trials:
        trial = result.trial
        for outcome in result.scoring.outcomes:
            # Every string cell is neutralized: ids flow from imported suites
            # and provider/judge output, none of which the report trusts.
            writer.writerow(
                [
                    csv_neutralize(run.run_id),
                    csv_neutralize(trial.trial_id),
                    csv_neutralize(str(trial.model)),
                    csv_neutralize(trial.suite_id),
                    csv_neutralize(trial.scenario.id),
                    csv_neutralize(trial.scenario.family),
                    csv_neutralize(trial.scenario.channel),
                    csv_neutralize(trial.policy_id),
                    csv_neutralize(trial.technique_id),
                    csv_neutralize(trial.transformation_id),
                    trial.repetition,
                    csv_neutralize(result.transcript.status.value),
                    csv_neutralize(outcome.scorer_id),
                    csv_neutralize(outcome.scorer_version),
                    csv_neutralize(outcome.channel.value),
                    csv_neutralize(outcome.verdict.value),
                    outcome.eligible,
                    outcome.score,
                    csv_neutralize(canonical_json(dict(outcome.metrics))),
                    csv_neutralize(outcome.error or ""),
                ]
            )
    return output.getvalue()


def render_benchmark_latex(report: BenchmarkReport) -> str:
    rows = [
        ("Primary objective (final)", _rate(report.primary_security)),
        ("Primary objective (reasoning)", _rate(report.reasoning_security)),
        ("Benign task success", _rate(report.utility)),
        ("False refusal", _rate(report.false_refusal)),
    ]
    # Full escaping, not just '%': labels and rates flow through the same
    # escaper as the run report so hostile characters cannot break the table.
    body = "\n".join(f"{latex_escape(name)} & {latex_escape(value)} \\\\" for name, value in rows)
    return f"\\begin{{tabular}}{{ll}}\n\\hline\n{body}\n\\hline\n\\end{{tabular}}\n"


class BenchmarkReportFormat(str, Enum):
    MARKDOWN = "markdown"
    CSV = "csv"
    JSONL = "jsonl"
    LATEX = "latex"


_FORMAT_DETAILS = {
    BenchmarkReportFormat.MARKDOWN: (".md", "text/markdown"),
    BenchmarkReportFormat.CSV: (".csv", "text/csv"),
    BenchmarkReportFormat.JSONL: (".jsonl", "application/x-ndjson"),
    BenchmarkReportFormat.LATEX: (".tex", "application/x-tex"),
}


class BenchmarkReportWriter:
    def __init__(self, output_dir: str | Path) -> None:
        self.store = ArtifactStore(output_dir)

    def write(
        self,
        run: BenchmarkRunResult,
        fmt: BenchmarkReportFormat,
        *,
        filename: str | None = None,
    ) -> Path:
        extension, media_type = _FORMAT_DETAILS[fmt]
        if fmt is BenchmarkReportFormat.MARKDOWN:
            content = render_benchmark_markdown(BenchmarkReport.from_run(run))
        elif fmt is BenchmarkReportFormat.CSV:
            content = render_benchmark_csv(run)
        elif fmt is BenchmarkReportFormat.JSONL:
            content = render_benchmark_jsonl(run)
        else:
            content = render_benchmark_latex(BenchmarkReport.from_run(run))
        record = self.store.write_text(
            filename or f"{run.run_id}{extension}",
            content,
            media_type=media_type,
        )
        return record.absolute_path
