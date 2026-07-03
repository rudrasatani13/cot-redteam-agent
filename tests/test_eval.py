"""Test eval harness — dataset loading, metrics, run creation."""
import pytest
from pathlib import Path
from cot_redteam.eval.harness import (
    EvalHarness, DatasetLoader, MetricsCalculator, RunConfig, ArtifactManager
)
from cot_redteam.core.types import (
    ModelConfig, ModelProvider, AttackCategory, AttackResult, AttackPrompt,
    AttackConfig, ModelResponse, Severity
)


SAMPLE_DATASET = Path(__file__).parent.parent / "cot_redteam" / "eval" / "datasets" / "sample.jsonl"


class TestDatasetLoader:
    def test_load_jsonl(self):
        samples = DatasetLoader.from_jsonl(str(SAMPLE_DATASET))
        assert len(samples) == 15
        assert samples[0].id == "q1"
        assert samples[0].question == "What is 15 * 17?"
        assert samples[0].answer == "255"

    def test_from_list(self):
        items = [
            {"id": "t1", "question": "What is 2+2?", "answer": "4"},
            {"id": "t2", "question": "Capital of France?", "answer": "Paris"},
        ]
        samples = DatasetLoader.from_list(items)
        assert len(samples) == 2
        assert samples[0].id == "t1"

    def test_to_jsonl_roundtrip(self, tmp_path):
        items = [{"id": "x1", "question": "Test?", "answer": "Yes"}]
        samples = DatasetLoader.from_list(items)
        path = str(tmp_path / "test.jsonl")
        DatasetLoader.to_jsonl(samples, path)
        loaded = DatasetLoader.from_jsonl(path)
        assert len(loaded) == 1
        assert loaded[0].id == "x1"


class TestMetricsCalculator:
    def _make_result(self, success: bool, category=AttackCategory.INJECTION):
        cfg = AttackConfig(category=category, name="test", description="test")
        prompt = AttackPrompt(prompt="test", attack_config=cfg)
        resp = ModelResponse(full_response="test", cot="test")
        return AttackResult(
            attack_prompt=prompt,
            model_response=resp,
            success=success,
            severity=Severity.LOW,
        )

    def test_attack_success_rate(self):
        results = [self._make_result(True), self._make_result(False), self._make_result(True)]
        rate = MetricsCalculator.attack_success_rate(results)
        assert rate == pytest.approx(2/3, rel=0.01)

    def test_empty_results(self):
        assert MetricsCalculator.attack_success_rate([]) == 0.0

    def test_per_category_breakdown(self):
        results = [
            self._make_result(True, AttackCategory.INJECTION),
            self._make_result(False, AttackCategory.INJECTION),
            self._make_result(True, AttackCategory.EVASION),
        ]
        breakdown = MetricsCalculator.per_category_breakdown(results)
        assert "injection" in breakdown
        assert "evasion" in breakdown
        assert breakdown["injection"]["count"] == 2
        assert breakdown["evasion"]["count"] == 1


class TestEvalHarness:
    def test_create_run(self):
        harness = EvalHarness()
        run = harness.create_run(
            model_configs=[ModelConfig(provider=ModelProvider.OPENROUTER, model_id="test")],
            attack_categories=[AttackCategory.INJECTION],
            num_samples=3,
            seed=42,
        )
        assert run.run_id.startswith("run_")
        assert run.seed == 42
        assert len(run.model_configs) == 1
        assert run.num_samples == 3

    def test_get_attacks(self):
        harness = EvalHarness()
        run = harness.create_run(
            model_configs=[ModelConfig(provider=ModelProvider.OPENROUTER, model_id="test")],
            attack_categories=[AttackCategory.INJECTION],
        )
        attacks = harness._get_attacks(run)
        assert len(attacks) >= 3
        for a in attacks:
            assert a.category == AttackCategory.INJECTION


class TestArtifactManager:
    def test_save_and_hash(self, tmp_path):
        am = ArtifactManager(str(tmp_path))
        import json
        path = am.save_artifact("test_run", "test_file", json.dumps({"key": "value"}), "json")
        assert Path(path).exists()
        h = am.compute_hash("test content")
        assert len(h) == 64  # SHA256 hex

    def test_save_run_config(self, tmp_path):
        am = ArtifactManager(str(tmp_path))
        run = RunConfig(
            run_id="test_123",
            seed=42,
            model_configs=[ModelConfig(provider=ModelProvider.OPENROUTER, model_id="test")],
        )
        path = am.save_run_config(run)
        assert Path(path).exists()