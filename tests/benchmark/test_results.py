from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.benchmark.canary import CanaryBundle
from cot_redteam.benchmark.conversation import (
    ConversationStatus,
    ConversationTranscript,
    ConversationTurn,
)
from cot_redteam.benchmark.planner import BenchmarkPlanner
from cot_redteam.benchmark.results import BenchmarkRunResult, BenchmarkTrialResult
from cot_redteam.benchmark.scoring import ScoringContext, score_transcript
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.types import (
    Message,
    MessageRole,
    ModelRef,
    ModelResponse,
    ReasoningSource,
    TargetCapabilities,
)

from .test_schema import valid_scenario


def benchmark_trial_result(tmp_path: Path) -> BenchmarkTrialResult:
    row = valid_scenario()
    path = tmp_path / "suite.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    trial = (
        BenchmarkPlanner(
            models=[ModelRef.parse("gateway:model")],
            suites=[ScenarioSuite.load_jsonl(path, suite_id="suite.test")],
            target_capabilities={"gateway": TargetCapabilities(system_role=True)},
            run_id="run-1",
        )
        .create()
        .trials[0]
    )
    response = ModelResponse(
        text="COTRT3-abcdef01-12345678",
        reasoning="private COTRT3-abcdef01-12345678",
        reasoning_source=ReasoningSource.PROVIDER,
        model=trial.model,
    )
    messages = (
        Message(role=MessageRole.SYSTEM, content="secret policy"),
        Message(role=MessageRole.USER, content="attack"),
        Message(role=MessageRole.ASSISTANT, content=response.text),
    )
    transcript = ConversationTranscript(
        trial_id=trial.trial_id,
        status=ConversationStatus.COMPLETED,
        messages=messages,
        turns=(
            ConversationTurn(
                turn_index=0,
                request_messages=messages[:2],
                response=response,
            ),
        ),
    )
    canary = CanaryBundle(
        fragments=("abcdef01", "12345678"),
        token="COTRT3-abcdef01-12345678",
        digest="canary-digest",
    )
    return BenchmarkTrialResult(
        trial=trial,
        transcript=transcript,
        scoring=score_transcript(
            transcript,
            trial.scenario.scorers,
            ScoringContext(canary=canary, rogue_string="PWNED"),
        ),
        canary_metadata=canary.manifest_metadata(),
        transformation_digest="transform-digest",
    )


def benchmark_run_result(tmp_path: Path) -> BenchmarkRunResult:
    return BenchmarkRunResult(
        run_id="run-1",
        started_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
        completed_at=datetime(2026, 7, 29, 0, 1, tzinfo=timezone.utc),
        trials=(benchmark_trial_result(tmp_path),),
        metadata={"version": "0.3"},
        manifest={"suite": "suite.test"},
    )


def test_result_contract_rejects_cross_run_trial(tmp_path: Path) -> None:
    trial = benchmark_trial_result(tmp_path)

    try:
        BenchmarkRunResult(
            run_id="other-run",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            trials=(trial,),
        )
    except ValueError as exc:
        assert "does not belong" in str(exc)
    else:
        raise AssertionError("cross-run trial was accepted")
