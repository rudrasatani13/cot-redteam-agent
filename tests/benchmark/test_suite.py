"""Scenario-suite loader tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.errors import DatasetError

from .test_schema import valid_scenario


def write_rows(path: Path, rows: list[dict]) -> Path:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )
    return path


def test_suite_digest_is_content_based(tmp_path: Path) -> None:
    row = valid_scenario()
    first = ScenarioSuite.load_jsonl(
        write_rows(tmp_path / "first.jsonl", [row]),
        suite_id="suite.test",
    )
    second = ScenarioSuite.load_jsonl(
        write_rows(tmp_path / "second.jsonl", [row]),
        suite_id="suite.test",
    )
    assert first.digest == second.digest
    assert first.scenarios[0].digest


def test_suite_rejects_duplicate_ids_and_content(tmp_path: Path) -> None:
    row = valid_scenario()
    duplicate_id = valid_scenario()
    duplicate_id["title"] = "Changed title"
    with pytest.raises(DatasetError, match="duplicate scenario id"):
        ScenarioSuite.load_jsonl(
            write_rows(tmp_path / "ids.jsonl", [row, duplicate_id]),
            suite_id="suite.test",
        )

    duplicate_content = valid_scenario()
    duplicate_content["id"] = "extraction.direct.002"
    with pytest.raises(DatasetError, match="duplicate scenario content"):
        ScenarioSuite.load_jsonl(
            write_rows(tmp_path / "content.jsonl", [row, duplicate_content]),
            suite_id="suite.test",
        )


def test_suite_reports_invalid_line_without_executing_grader_text(tmp_path: Path) -> None:
    row = valid_scenario()
    row["grader_code_python"] = "raise RuntimeError('must never execute')"
    path = write_rows(tmp_path / "hostile.jsonl", [row])
    with pytest.raises(DatasetError, match="line 1"):
        ScenarioSuite.load_jsonl(path, suite_id="suite.test")


def test_suite_enforces_row_size_limit(tmp_path: Path) -> None:
    row = valid_scenario()
    row["steps"][0]["content"] = "x" * 300_000
    path = write_rows(tmp_path / "large.jsonl", [row])
    with pytest.raises(DatasetError, match="row exceeds"):
        ScenarioSuite.load_jsonl(path, suite_id="suite.test")
