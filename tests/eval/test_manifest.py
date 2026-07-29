"""Manifest generation tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.core.config import load_config
from cot_redteam.core.types import (
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    ModelRef,
    RunSummary,
)
from cot_redteam.eval.manifest import ArtifactRecord, build_manifest


def test_manifest_redaction_and_stability(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-value-xyz")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    items = [
        EvaluationItem(
            item_id="i",
            model=ModelRef.parse("openrouter:test/model"),
            attack_id="injection.cot_injection",
            sample_id="s1",
            status=ItemStatus.PROVIDER_ERROR,
            error="x",
        )
    ]
    summary = RunSummary.from_items(items)
    run = EvaluationRun(
        run_id="run-x",
        status=summary.status,
        items=tuple(items),
        summary=summary,
        started_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 2, 1, 1, tzinfo=timezone.utc),
        seed=7,
        dataset_digest="dataset-digest",
        config_digest="config-digest",
    )
    manifest = build_manifest(
        run,
        config,
        artifacts=(
            ArtifactRecord(
                relative_path="a.json",
                media_type="application/json",
                byte_length=2,
                sha256="ab",
            ),
        ),
        git_reader=lambda: {"revision": "abc", "dirty": True},
        dist_reader=lambda: {"cot-redteam-agent": "0.2.0"},
    )
    text = str(manifest)
    assert "secret-value-xyz" not in text
    assert manifest["dataset_digest"] == "dataset-digest"
    assert manifest["config_digest"]
    assert manifest["artifacts"][0]["byte_length"] == 2
    assert any("dirty" in str(x).lower() for x in manifest["limitations"])
