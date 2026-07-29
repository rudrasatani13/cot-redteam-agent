"""Auditable benchmark run and trial result contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from cot_redteam.benchmark.conversation import ConversationTranscript
from cot_redteam.benchmark.judge import JudgeResult
from cot_redteam.benchmark.planner import PlannedTrial
from cot_redteam.benchmark.scoring import TranscriptScoring
from cot_redteam.core.types import JsonValue


@dataclass(frozen=True)
class BenchmarkTrialResult:
    trial: PlannedTrial
    transcript: ConversationTranscript
    scoring: TranscriptScoring
    canary_metadata: Mapping[str, JsonValue]
    transformation_digest: str
    judge_results: tuple[JudgeResult, ...] = ()

    def __post_init__(self) -> None:
        if self.transcript.trial_id != self.trial.trial_id:
            raise ValueError("transcript trial_id does not match planned trial")
        if self.scoring.trial_id != self.trial.trial_id:
            raise ValueError("scoring trial_id does not match planned trial")
        object.__setattr__(self, "canary_metadata", dict(self.canary_metadata))


@dataclass(frozen=True)
class BenchmarkRunResult:
    run_id: str
    started_at: datetime
    completed_at: datetime
    trials: tuple[BenchmarkTrialResult, ...]
    metadata: Mapping[str, JsonValue] = field(default_factory=dict)
    manifest: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if any(result.trial.trial_id.split(":trial:", 1)[0] != self.run_id for result in self.trials):
            raise ValueError("benchmark trial does not belong to this run")
        object.__setattr__(self, "metadata", dict(self.metadata))
        object.__setattr__(self, "manifest", dict(self.manifest))
