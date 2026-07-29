"""Wheel-safe init and packaged dataset tests."""

from __future__ import annotations

from pathlib import Path

from cot_redteam.cli.main import main
from cot_redteam.core.config import load_config
from cot_redteam.eval.dataset import Dataset
from cot_redteam.resources import read_example_config_text


def test_packaged_example_config_readable() -> None:
    text = read_example_config_text()
    assert "version: 2" in text
    assert "pkg:sample.jsonl" in text


def test_init_writes_from_package_resources(tmp_path: Path) -> None:
    dest = tmp_path / "nested" / "config.yaml"
    assert main(["init", "--path", str(dest)]) == 0
    assert dest.exists()
    assert "version: 2" in dest.read_text(encoding="utf-8")


def test_packaged_dataset_loads() -> None:
    ds = Dataset.load_jsonl("pkg:sample.jsonl")
    assert len(ds.samples) >= 1


def test_load_config_with_packaged_dataset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    dest = tmp_path / "config.yaml"
    assert main(["init", "--path", str(dest)]) == 0
    config = load_config(dest)
    assert config.evaluation.dataset_path == "pkg:sample.jsonl"
    assert config.evaluation.attacks == ["injection.system_canary_adaptive"]
    assert "injection.system_canary_adaptive" in config.evaluation.attack_config
    Dataset.load_jsonl(config.evaluation.dataset_path)
