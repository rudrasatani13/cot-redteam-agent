from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.benchmark.conversation import (
    ConversationStatus,
    ConversationTranscript,
    ConversationTurn,
)
from cot_redteam.benchmark.planner import PlannedTrial
from cot_redteam.benchmark.results import BenchmarkRunResult, BenchmarkTrialResult
from cot_redteam.benchmark.schema import (
    ObjectiveSpec,
    ScenarioSpec,
    ScorerSpec,
    SourceSpec,
    TaskSpec,
)
from cot_redteam.benchmark.scoring import (
    EvidenceChannel,
    EvidenceSpan,
    ScorerOutcome,
    ScorerVerdict,
    TranscriptScoring,
)
from cot_redteam.core.types import ModelRef
from cot_redteam.reporting.benchmark import (
    BenchmarkReport,
    BenchmarkReportFormat,
    BenchmarkReportWriter,
    render_benchmark_csv,
    render_benchmark_jsonl,
    render_benchmark_latex,
    render_benchmark_markdown,
)
from tests.benchmark.test_results import benchmark_run_result


def _scenario(
    scorers: tuple[ScorerSpec, ...] = (),
    *,
    hostile: bool = False,
) -> ScenarioSpec:
    """Build a scenario without validation so tests can exercise renderer
    defenses against hostile imported-suite fields (schema validation would
    normally reject them; the renderer must not rely on that)."""
    return ScenarioSpec.model_construct(
        version=1,
        id="=CMD('scenario_id')" if hostile else "extraction.direct.001",
        title="Direct canary extraction",
        family="=CMD('family')" if hostile else "system_prompt_extraction",
        channel="=CMD('channel')" if hostile else "direct_user",
        task=TaskSpec(prompt="task"),
        objective=ObjectiveSpec(type="emit_rogue_string"),
        steps=(),
        required_capabilities=(),
        policy_ids=(),
        technique_ids=(),
        transformation_ids=(),
        scorers=scorers,
        source=SourceSpec(license="MIT", citation="fixture"),
        tags=(),
        difficulty="basic",
    )


def _run_with(
    trial: PlannedTrial,
    outcomes: tuple[ScorerOutcome, ...],
    *,
    transcript: ConversationTranscript | None = None,
    run_id: str = "run-1",
) -> BenchmarkRunResult:
    transcript = transcript or ConversationTranscript(
        trial_id=trial.trial_id,
        status=ConversationStatus.COMPLETED,
        messages=(),
        turns=(),
    )
    result = BenchmarkTrialResult(
        trial=trial,
        transcript=transcript,
        scoring=TranscriptScoring(trial_id=trial.trial_id, outcomes=outcomes),
        canary_metadata={},
        transformation_digest="digest",
    )
    return BenchmarkRunResult(
        run_id=run_id,
        started_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 29, 0, 1, tzinfo=timezone.utc),
        trials=(result,),
    )


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


def test_benchmark_markdown_escapes_hostile_judge_and_evidence_text() -> None:
    """Judge explanations and evidence spans carved from model output are
    hostile: they must not forge headings, links, HTML, or code spans."""
    outcome = ScorerOutcome(
        scorer_id="scorer.canary`<b>",
        scorer_version="1.0.0",
        channel=EvidenceChannel.FINAL,
        verdict=ScorerVerdict.SUCCESS,
        score=1.0,
        eligible=True,
        explanation=" judge approved\n# PWNED HEADING\n`code` [x](http://evil) <script>alert(1)</script>",
        evidence=(
            EvidenceSpan(
                channel=EvidenceChannel.FINAL,
                turn_index=0,
                start=0,
                end=9,
                text="leak `COTRT3` <b>&payload</b>",
            ),
        ),
    )
    trial = PlannedTrial(
        trial_id="run-1:trial:1",
        model=ModelRef(provider="gw", model_id="bad`model"),
        suite_id="suite.test",
        scenario=_scenario(),
        policy_id="policy.hierarchy",
        technique_id="technique.direct_extraction",
        transformation_id="transform.identity",
        repetition=1,
        target_request_count=1,
        judge_request_count=0,
    )
    turn = ConversationTurn(
        turn_index=0,
        request_messages=(),
        response=None,
        error="<img src=x onerror=alert(1)>",
    )
    run = _run_with(
        trial,
        (outcome,),
        transcript=ConversationTranscript(
            trial_id=trial.trial_id,
            status=ConversationStatus.PROVIDER_ERROR,
            messages=(),
            turns=(turn,),
        ),
    )

    markdown = render_benchmark_markdown(BenchmarkReport.from_run(run))

    # Raw HTML is neutralized in prose (judge explanation, turn error).
    assert "<script>alert(1)</script>" not in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    assert "<img src=x" not in markdown
    assert "&lt;img src=x onerror=alert(1)&gt;" in markdown
    # Hostile newlines cannot start a heading; link syntax is inert.
    assert "\n# PWNED HEADING" not in markdown
    assert r"\[x\]" in markdown
    # Backticks in prose are escaped so they cannot open a live code span.
    assert r"\`code\`" in markdown
    # Backticked fields become CommonMark-safe code spans: the fence is one
    # longer than any backtick run inside the payload, with padding.
    assert "`` gw:bad`model ``" in markdown
    assert "`` scorer.canary`<b> ``" in markdown
    assert "`` leak `COTRT3` <b>&payload</b> ``" in markdown


def test_benchmark_csv_neutralizes_every_column() -> None:
    """Every string cell is neutralized, including imported-suite fields:
    "=CMD(...)" payloads must never reach a spreadsheet as live formulas."""
    trial = PlannedTrial(
        trial_id="=run:trial:1",
        model=ModelRef(provider="=CMD('model')", model_id="m"),
        suite_id="@CMD('suite')",
        scenario=_scenario(hostile=True),
        policy_id="+CMD('policy')",
        technique_id="-CMD('technique')",
        transformation_id="\tCMD('transform')",
        repetition=1,
        target_request_count=1,
        judge_request_count=0,
    )
    outcome = ScorerOutcome(
        scorer_id="=CMD('scorer')",
        scorer_version="@CMD('version')",
        channel=EvidenceChannel.FINAL,
        verdict=ScorerVerdict.ERROR,
        score=None,
        eligible=False,
        explanation="=CMD('explanation')",
        error="\rCMD('error')",
    )
    run = _run_with(trial, (outcome,), run_id="=run")

    output = render_benchmark_csv(run)
    rows = list(csv.reader(io.StringIO(output)))
    header, data = rows[0], rows[1]

    formula_starts = ("=", "+", "-", "@", "\t", "\r")
    for row in rows[1:]:
        for cell in row:
            starts_formula = cell[:1] in formula_starts
            assert not starts_formula or cell.startswith("'"), cell

    by_column = dict(zip(header, data, strict=True))
    assert by_column["run_id"] == "'=run"
    assert by_column["trial_id"] == "'=run:trial:1"
    assert by_column["model"] == "'=CMD('model'):m"
    assert by_column["suite_id"] == "'@CMD('suite')"
    assert by_column["scenario_id"] == "'=CMD('scenario_id')"
    assert by_column["family"] == "'=CMD('family')"
    assert by_column["delivery_channel"] == "'=CMD('channel')"
    assert by_column["policy_id"] == "'+CMD('policy')"
    assert by_column["technique_id"] == "'-CMD('technique')"
    assert by_column["transformation_id"] == "'\tCMD('transform')"
    assert by_column["scorer_id"] == "'=CMD('scorer')"
    assert by_column["scorer_version"] == "'@CMD('version')"
    assert by_column["error"] == "'\rCMD('error')"


def test_primary_scorer_selection_is_independent_of_scorer_order() -> None:
    """The headline security metric must not silently change when a suite
    author reorders the scenario's scorer list."""

    def report_for(scorer_ids_order: tuple[str, ...]) -> BenchmarkReport:
        scorers = tuple(ScorerSpec(id=scorer_id) for scorer_id in scorer_ids_order)
        trial = PlannedTrial(
            trial_id="run-1:trial:1",
            model=ModelRef.parse("gw:model"),
            suite_id="suite.test",
            scenario=_scenario(scorers),
            policy_id="policy.hierarchy",
            technique_id="technique.direct_extraction",
            transformation_id="transform.identity",
            repetition=1,
            target_request_count=1,
            judge_request_count=0,
        )
        outcomes = (
            ScorerOutcome(
                scorer_id="scorer.alpha",
                scorer_version="1.0.0",
                channel=EvidenceChannel.FINAL,
                verdict=ScorerVerdict.FAILURE,
                score=0.0,
                eligible=True,
            ),
            ScorerOutcome(
                scorer_id="scorer.beta",
                scorer_version="1.0.0",
                channel=EvidenceChannel.FINAL,
                verdict=ScorerVerdict.SUCCESS,
                score=1.0,
                eligible=True,
            ),
        )
        return BenchmarkReport.from_run(_run_with(trial, outcomes))

    beta_listed_first = report_for(("scorer.beta", "scorer.alpha"))
    alpha_listed_first = report_for(("scorer.alpha", "scorer.beta"))

    assert beta_listed_first.primary_security == alpha_listed_first.primary_security
    # The lexicographically first scorer (alpha) drives the metric, not the
    # first-listed one (beta): alpha's verdict is failure, so the rate is 0.
    assert beta_listed_first.primary_security.rate == 0.0
    assert beta_listed_first.primary_security.successes == 0


def test_benchmark_latex_escapes_rate_strings() -> None:
    trial = PlannedTrial(
        trial_id="run-1:trial:1",
        model=ModelRef.parse("gw:model"),
        suite_id="suite.test",
        scenario=_scenario((ScorerSpec(id="scorer.alpha"),)),
        policy_id="policy.hierarchy",
        technique_id="technique.direct_extraction",
        transformation_id="transform.identity",
        repetition=1,
        target_request_count=1,
        judge_request_count=0,
    )
    outcome = ScorerOutcome(
        scorer_id="scorer.alpha",
        scorer_version="1.0.0",
        channel=EvidenceChannel.FINAL,
        verdict=ScorerVerdict.SUCCESS,
        score=1.0,
        eligible=True,
    )
    latex = render_benchmark_latex(BenchmarkReport.from_run(_run_with(trial, (outcome,))))

    # The full escaper handles the percent sign in "95% CI" and every other
    # LaTeX special that may appear in labels or rate strings.
    assert "95\\% CI" in latex
    for line in latex.splitlines():
        assert "%" not in line.replace("\\%", "")
