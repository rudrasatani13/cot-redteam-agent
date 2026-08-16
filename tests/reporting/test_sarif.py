"""SARIF 2.1.0 export tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    ModelRef,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    RunSummary,
    TokenUsage,
)
from cot_redteam.reporting.report import ReportFormat, ReportWriter
from cot_redteam.reporting.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    build_sarif_report,
    render_sarif,
)


def _run(items: list[EvaluationItem]) -> EvaluationRun:
    summary = RunSummary.from_items(items)
    return EvaluationRun(
        run_id="r",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        seed=7,
        dataset_digest="abc123",
    )


def _clean_item(attack_id: str = "injection.cot_injection") -> EvaluationItem:
    model = ModelRef.parse("p:m")
    return EvaluationItem(
        item_id="i",
        model=model,
        attack_id=attack_id,
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id=attack_id, text="p", sample_id="s"),
        response=ModelResponse(text="no canary", model=model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=False, score=0.0),
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.CLEAN,
                confidence=None,
                explanation="clean",
            ),
        ),
    )


def _finding_item(attack_id: str = "injection.system_canary") -> EvaluationItem:
    model = ModelRef.parse("p:m")
    return EvaluationItem(
        item_id="i",
        model=model,
        attack_id=attack_id,
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id=attack_id, text="p", sample_id="s"),
        response=ModelResponse(text="TOKEN", model=model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=True, score=1.0),
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.TRIGGERED,
                confidence=None,
                explanation="canary detected",
            ),
        ),
    )


def _error_item() -> EvaluationItem:
    model = ModelRef.parse("p:m")
    return EvaluationItem(
        item_id="i",
        model=model,
        attack_id="injection.crescendo_canary",
        sample_id="s",
        status=ItemStatus.PROVIDER_ERROR,
        error="provider down",
    )


def test_clean_run_emits_no_results() -> None:
    report = build_sarif_report(_run([_clean_item()]))
    run = report["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["name"] == TOOL_NAME
    assert run["tool"]["driver"]["rules"] == []
    assert run["invocations"][0]["executionSuccessful"] is True


def test_schema_and_version_fields() -> None:
    report = build_sarif_report(_run([_finding_item()]))
    assert report["$schema"] == SARIF_SCHEMA
    assert report["version"] == SARIF_VERSION
    assert report["runs"][0]["tool"]["driver"]["version"]
    assert report["runs"][0]["tool"]["driver"]["informationUri"].startswith("https://")


def test_finding_is_error_result_with_owasp_rule() -> None:
    report = build_sarif_report(_run([_finding_item()]))
    run = report["runs"][0]
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["ruleId"] == "cot-redteam/injection.system_canary"
    assert "succeeded" in result["message"]["text"]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "cot-redteam/injection.system_canary"
    props = rule["properties"]
    assert props["owasp_version"] == "OWASP GenAI LLM Top 10 (2026)"
    assert "LLM01 — Prompt Injection" in props["owasp_tags"]
    assert "LLM08 — Hidden Context Exposure" in props["owasp_tags"]


def test_triggered_monitor_is_warning() -> None:
    item = _finding_item(attack_id="evasion.stealth_reasoning")
    item = EvaluationItem(
        item_id="i",
        model=item.model,
        attack_id="evasion.stealth_reasoning",
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id="evasion.stealth_reasoning", text="p", sample_id="s"),
        response=ModelResponse(text="t", model=item.model, usage=TokenUsage(1, 1)),
        assessment=AttackAssessment(success=False, score=0.0),
        monitors=(
            MonitorOutcome(
                monitor_id="regex",
                status=MonitorStatus.TRIGGERED,
                confidence=None,
                explanation="evasion",
            ),
        ),
    )
    report = build_sarif_report(_run([item]))
    assert report["runs"][0]["results"][0]["level"] == "warning"


def test_incomplete_item_is_note() -> None:
    report = build_sarif_report(_run([_error_item()]))
    run = report["runs"][0]
    result = run["results"][0]
    assert result["level"] == "note"
    assert "provider down" in result["message"]["text"]
    assert run["invocations"][0]["executionSuccessful"] is False


def test_mixed_run_invocation_properties() -> None:
    report = build_sarif_report(_run([_finding_item(), _clean_item()]))
    invocation = report["runs"][0]["invocations"][0]
    assert invocation["properties"]["run_id"] == "r"
    assert invocation["properties"]["seed"] == 7
    assert invocation["properties"]["dataset_digest"] == "abc123"
    assert "endTimeUtc" in invocation


def test_render_sarif_is_deterministic_json(tmp_path) -> None:
    run = _run([_finding_item()])
    first = render_sarif(run)
    second = render_sarif(run)
    assert first == second
    parsed = json.loads(first)
    assert parsed["version"] == "2.1.0"


def test_report_writer_writes_sarif_file(tmp_path) -> None:
    writer = ReportWriter(tmp_path)
    run = _run([_finding_item()])
    path = writer.write(run, ReportFormat.SARIF)
    assert path.name == "r.sarif.json"
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["runs"][0]["results"][0]["level"] == "error"
