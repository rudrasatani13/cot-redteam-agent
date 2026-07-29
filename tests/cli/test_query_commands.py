"""CLI list/show/report tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from cot_redteam.cli.main import main
from cot_redteam.core.types import (
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    ModelRef,
    RunSummary,
)
from cot_redteam.storage.sqlite import SQLiteRunStore


def test_list_show_report(tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite"
    store = SQLiteRunStore(db)
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
        run_id="run-xyz",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    store.save(run, {"x": 1})

    cfg = {
        "version": 2,
        "providers": {"vllm": {"kind": "vllm", "base_url": "http://localhost:8000/v1"}},
        "evaluation": {
            "models": ["vllm:m"],
            "attacks": ["injection.cot_injection"],
            "monitors": ["regex"],
            "dataset_path": "cot_redteam/eval/datasets/sample.jsonl",
        },
        "storage": {"path": str(db)},
        "reporting": {"output_dir": str(tmp_path / "reports")},
    }
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg), encoding="utf-8")

    assert main(["list-runs", "--config", str(cfg_path)]) == 0
    assert main(["show-run", "--config", str(cfg_path), "--run-id", "run-xyz"]) == 0
    assert (
        main(
            [
                "report",
                "--config",
                str(cfg_path),
                "--run-id",
                "run-xyz",
                "--format",
                "csv",
            ]
        )
        == 0
    )
