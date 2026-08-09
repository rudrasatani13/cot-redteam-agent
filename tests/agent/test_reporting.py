"""Agent Markdown/JSONL reporting tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from cot_redteam.agent.api import run_agent_scenario
from cot_redteam.agent.config import AgentRetentionSettings
from cot_redteam.agent.reporting import (
    render_agent_jsonl,
    render_agent_markdown,
)
from cot_redteam.agent.types import OracleEvidenceItem, OracleResult, OracleVerdict
from cot_redteam.storage.sqlite import SQLiteRunStore

CANARY = "COT-REDTEAM-CANARY-9F3A1C8E"


def _vulnerable_run(tmp_path: Path):
    async def _run():
        with SQLiteRunStore(tmp_path / "agent.db") as store:
            return await run_agent_scenario(
                scenario_id="support.indirect_prompt_injection.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
            )

    return asyncio.run(_run())


def test_markdown_contains_structure_and_retention_notice(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path)
    markdown = render_agent_markdown(run)
    assert run.scenario_ref.id in markdown
    assert run.run_id in markdown
    assert "verified_exploit" in markdown
    assert "Oracle results" in markdown
    assert "| seq | event | detail | status |" in markdown
    assert "tool_call_requested" in markdown
    assert "canary_reached_sink" in markdown
    assert "Retention" in markdown
    assert "omitted by default" in markdown
    assert run.trajectory.digest in markdown


def test_markdown_replay_metadata(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path)
    markdown = render_agent_markdown(run, replay_path="/tmp/x/replay.json", replay_checksum="abc")
    assert "/tmp/x/replay.json" in markdown
    assert "abc" in markdown


def test_markdown_contains_no_retained_raw_secret_with_default_retention(
    tmp_path: Path,
) -> None:
    run = _vulnerable_run(tmp_path)
    markdown = render_agent_markdown(run, retention=AgentRetentionSettings())
    assert CANARY not in markdown
    assert "Forwarded the requested" not in markdown


def test_jsonl_structure_and_record_types(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path)
    lines = render_agent_jsonl(run, retention=AgentRetentionSettings()).strip().splitlines()
    record_types = [json.loads(line)["record_type"] for line in lines]
    assert "agent_run" in record_types
    assert "agent_event" in record_types
    assert "agent_oracle" in record_types
    assert "agent_finding" in record_types
    for line in lines:
        record = json.loads(line)
        assert record["schema_version"] == 1
        assert record["run_id"] == run.run_id
    run_record = json.loads(lines[0])
    assert run_record["outcome"] == "verified_exploit"
    assert run_record["trajectory_digest"] == run.trajectory.digest


def test_jsonl_omits_raw_secret_with_default_retention(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path)
    blob = render_agent_jsonl(run, retention=AgentRetentionSettings())
    assert CANARY not in blob
    assert "Forwarded the requested" not in blob


def test_jsonl_deterministic(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path)
    first = render_agent_jsonl(run)
    second = render_agent_jsonl(run)
    assert first == second


def test_error_text_is_sanitized_in_reports(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path).model_copy(
        update={"error": "target failed api_key=sk-report-secret"}
    )
    markdown = render_agent_markdown(run)
    jsonl = render_agent_jsonl(run)
    assert "sk-report-secret" not in markdown
    assert "sk-report-secret" not in jsonl
    assert "api_key=[redacted]" in markdown
    assert "api_key=[redacted]" in jsonl


def test_oracle_diagnostics_are_sanitized_in_reports(tmp_path: Path) -> None:
    run = _vulnerable_run(tmp_path).model_copy(
        update={
            "oracle_results": (
                OracleResult(
                    oracle_id="custom",
                    oracle_version="1",
                    verdict=OracleVerdict.ERROR,
                    summary="failed api_key=sk-report-oracle",
                    evidence=(
                        OracleEvidenceItem(
                            kind="diagnostic",
                            detail={"password": "raw-report-password"},
                        ),
                    ),
                    error="exception secret=raw-report-secret",
                ),
            )
        }
    )
    markdown = render_agent_markdown(run)
    jsonl = render_agent_jsonl(run)
    assert "sk-report-oracle" not in markdown + jsonl
    assert "raw-report-password" not in markdown + jsonl
    assert "raw-report-secret" not in markdown + jsonl
