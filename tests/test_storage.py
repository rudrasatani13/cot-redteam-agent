"""Test storage layer."""
import pytest
import json
from cot_redteam.storage.results import ResultsStore
from cot_redteam.core.types import (
    EvalResult, AttackResult, AttackPrompt, AttackConfig,
    ModelResponse, ModelConfig, ModelProvider, AttackCategory, Severity
)


@pytest.fixture
def store(tmp_path):
    return ResultsStore(str(tmp_path / "test.db"))


@pytest.fixture
def sample_eval_result():
    cfg = AttackConfig(category=AttackCategory.INJECTION, name="test_attack", description="test")
    prompt = AttackPrompt(prompt="test prompt", attack_config=cfg)
    resp = ModelResponse(
        full_response="full response",
        cot="chain of thought",
        model_config=ModelConfig(provider=ModelProvider.OPENROUTER, model_id="test-model"),
    )
    result = AttackResult(
        attack_prompt=prompt,
        model_response=resp,
        success=True,
        severity=Severity.HIGH,
        evidence=["evidence1"],
        metrics={"score": 0.8},
        run_id="test_run_001",
    )
    return EvalResult(
        run_id="test_run_001",
        attack_results=[result],
        summary={"total_attacks": 1, "successful_attacks": 1, "attack_success_rate": 1.0},
        config_snapshot={"seed": 42},
    )


class TestResultsStore:
    def test_init(self, store):
        assert store.db_path.endswith("test.db")

    def test_save_and_get_run(self, store, sample_eval_result):
        store.save_run(sample_eval_result)
        run = store.get_run("test_run_001")
        assert run is not None
        assert run["run_id"] == "test_run_001"
        assert run["summary"]["total_attacks"] == 1

    def test_get_results(self, store, sample_eval_result):
        store.save_run(sample_eval_result)
        results = store.get_results("test_run_001")
        assert len(results) == 1
        assert results[0]["attack_name"] == "test_attack"
        assert results[0]["success"] is True

    def test_list_runs(self, store, sample_eval_result):
        store.save_run(sample_eval_result)
        runs = store.list_runs()
        assert len(runs) == 1
        assert runs[0]["run_id"] == "test_run_001"

    def test_compare_runs(self, store, sample_eval_result):
        store.save_run(sample_eval_result)
        comparison = store.compare_runs(["test_run_001"])
        assert "test_run_001" in comparison

    def test_query_results(self, store, sample_eval_result):
        store.save_run(sample_eval_result)
        results = store.query_results(attack_category="injection")
        assert len(results) == 1
        results = store.query_results(attack_category="evasion")
        assert len(results) == 0

    def test_query_success_only(self, store, sample_eval_result):
        store.save_run(sample_eval_result)
        results = store.query_results(success_only=True)
        assert len(results) == 1