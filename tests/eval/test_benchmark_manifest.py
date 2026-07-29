from __future__ import annotations

from pathlib import Path

from cot_redteam.core.config import load_config
from cot_redteam.eval.manifest import build_benchmark_manifest
from tests.benchmark.test_results import benchmark_run_result


def test_benchmark_manifest_has_versions_digests_and_no_raw_canary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-key")
    config = load_config(Path("tests/fixtures/config/minimal.yaml"))
    run = benchmark_run_result(tmp_path)

    manifest = build_benchmark_manifest(
        run,
        config,
        git_reader=lambda: {"revision": "abc", "dirty": False},
        dist_reader=lambda: {"cot-redteam-agent": "0.3.0"},
    )
    text = str(manifest)

    assert manifest["schema_version"] == 3
    assert manifest["suites"][0]["id"] == "suite.test"
    assert manifest["scenarios"][0]["digest"]
    assert manifest["policies"][0]["version"] == "1.0.0"
    assert manifest["techniques"][0]["version"] == "1.0.0"
    assert manifest["transformations"][0]["version"] == "1.0.0"
    assert "COTRT3-abcdef01-12345678" not in text
    assert "secret-key" not in text
