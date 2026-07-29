"""Dataset loader tests."""

from __future__ import annotations

import json
from pathlib import Path

from cot_redteam.eval.dataset import Dataset

SAMPLE_ROWS = [
    {"id": "1", "question": "Q1", "answer": "A1"},
    {"id": "2", "question": "Q2", "answer": "A2"},
]


def write_dataset(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_dataset_digest_is_independent_of_file_path(tmp_path: Path) -> None:
    first = write_dataset(tmp_path / "a.jsonl", SAMPLE_ROWS)
    second = write_dataset(tmp_path / "b.jsonl", SAMPLE_ROWS)
    assert Dataset.load_jsonl(first).digest == Dataset.load_jsonl(second).digest


def test_malformed_json_reports_line(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"id":"1","question":"ok"}\n{not-json}\n', encoding="utf-8")
    try:
        Dataset.load_jsonl(path)
        raise AssertionError("expected error")
    except Exception as exc:
        assert "line 2" in str(exc)
