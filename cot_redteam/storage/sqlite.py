"""Transactional SQLite run persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cot_redteam.benchmark.conversation import (
    ConversationStatus,
    ConversationTranscript,
    ConversationTurn,
)
from cot_redteam.benchmark.judge import JudgeResult
from cot_redteam.benchmark.planner import PlannedTrial
from cot_redteam.benchmark.results import BenchmarkRunResult, BenchmarkTrialResult
from cot_redteam.benchmark.schema import ScenarioSpec
from cot_redteam.benchmark.scoring import (
    EvidenceChannel,
    EvidenceSpan,
    ScorerOutcome,
    ScorerVerdict,
    TranscriptScoring,
)
from cot_redteam.core.serialization import canonical_json
from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
    Message,
    MessageRole,
    MessageTrust,
    ModelRef,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    ReasoningSource,
    RunStatus,
    RunSummary,
    TokenUsage,
)

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            seed INTEGER,
            config_digest TEXT,
            dataset_digest TEXT,
            summary_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            manifest_json TEXT
        );
        CREATE TABLE evaluation_items (
            item_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            model TEXT NOT NULL,
            attack_id TEXT NOT NULL,
            sample_id TEXT NOT NULL,
            status TEXT NOT NULL,
            prompt_json TEXT,
            response_json TEXT,
            assessment_json TEXT,
            error TEXT,
            started_at TEXT,
            completed_at TEXT
        );
        CREATE TABLE monitor_outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id TEXT NOT NULL REFERENCES evaluation_items(item_id) ON DELETE CASCADE,
            monitor_id TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence REAL,
            explanation TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        """
        CREATE TABLE benchmark_runs (
            run_id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            manifest_json TEXT NOT NULL
        );
        CREATE TABLE benchmark_trials (
            trial_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES benchmark_runs(run_id) ON DELETE CASCADE,
            model TEXT NOT NULL,
            suite_id TEXT NOT NULL,
            scenario_id TEXT NOT NULL,
            scenario_json TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            transformation_id TEXT NOT NULL,
            transformation_digest TEXT NOT NULL,
            repetition INTEGER NOT NULL,
            target_request_count INTEGER NOT NULL,
            judge_request_count INTEGER NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            canary_metadata_json TEXT NOT NULL
        );
        CREATE TABLE benchmark_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id TEXT NOT NULL REFERENCES benchmark_trials(trial_id) ON DELETE CASCADE,
            message_index INTEGER NOT NULL,
            role TEXT NOT NULL,
            trust TEXT NOT NULL,
            name TEXT,
            source TEXT,
            content TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            UNIQUE(trial_id, message_index)
        );
        CREATE TABLE benchmark_turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id TEXT NOT NULL REFERENCES benchmark_trials(trial_id) ON DELETE CASCADE,
            turn_index INTEGER NOT NULL,
            request_messages_json TEXT NOT NULL,
            response_json TEXT,
            error TEXT,
            UNIQUE(trial_id, turn_index)
        );
        CREATE TABLE benchmark_scorer_outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id TEXT NOT NULL REFERENCES benchmark_trials(trial_id) ON DELETE CASCADE,
            outcome_index INTEGER NOT NULL,
            outcome_json TEXT NOT NULL,
            UNIQUE(trial_id, outcome_index)
        );
        CREATE TABLE benchmark_judge_calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id TEXT NOT NULL REFERENCES benchmark_trials(trial_id) ON DELETE CASCADE,
            judge_index INTEGER NOT NULL,
            outcome_json TEXT NOT NULL,
            raw_input TEXT NOT NULL,
            raw_output TEXT,
            UNIQUE(trial_id, judge_index)
        );
        """,
    ),
]


def _dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


class SQLiteRunStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._closed = False
        self._migrate()

    def __enter__(self) -> SQLiteRunStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _migrate(self) -> None:
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        self.connection.commit()
        applied = {
            row[0] for row in self.connection.execute("SELECT version FROM schema_migrations")
        }
        for version, sql in MIGRATIONS:
            if version in applied:
                continue
            self.connection.executescript(sql)
            self.connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )
            self.connection.commit()

    def save(self, run: EvaluationRun, manifest: dict[str, Any] | None = None) -> None:
        conn = self.connection
        try:
            conn.execute("BEGIN")
            conn.execute(
                "DELETE FROM monitor_outcomes WHERE item_id IN "
                "(SELECT item_id FROM evaluation_items WHERE run_id = ?)",
                (run.run_id,),
            )
            conn.execute("DELETE FROM evaluation_items WHERE run_id = ?", (run.run_id,))
            conn.execute("DELETE FROM runs WHERE run_id = ?", (run.run_id,))
            conn.execute(
                """
                INSERT INTO runs(
                    run_id, status, started_at, completed_at, seed,
                    config_digest, dataset_digest, summary_json, metadata_json, manifest_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.status.value,
                    _dt(run.started_at),
                    _dt(run.completed_at),
                    run.seed,
                    run.config_digest,
                    run.dataset_digest,
                    canonical_json(run.summary),
                    canonical_json(dict(run.metadata)),
                    canonical_json(manifest) if manifest is not None else None,
                ),
            )
            for item in run.items:
                conn.execute(
                    """
                    INSERT INTO evaluation_items(
                        item_id, run_id, model, attack_id, sample_id, status,
                        prompt_json, response_json, assessment_json, error,
                        started_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.item_id,
                        run.run_id,
                        str(item.model),
                        item.attack_id,
                        item.sample_id,
                        item.status.value,
                        canonical_json(item.prompt) if item.prompt else None,
                        canonical_json(item.response) if item.response else None,
                        canonical_json(item.assessment) if item.assessment else None,
                        item.error,
                        _dt(item.started_at),
                        _dt(item.completed_at),
                    ),
                )
                for outcome in item.monitors:
                    conn.execute(
                        """
                        INSERT INTO monitor_outcomes(
                            item_id, monitor_id, status, confidence, explanation, details_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            item.item_id,
                            outcome.monitor_id,
                            outcome.status.value,
                            outcome.confidence,
                            outcome.explanation,
                            canonical_json(dict(outcome.details)),
                        ),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def save_benchmark(self, run: BenchmarkRunResult) -> None:
        """Transactionally replace a benchmark run and all child evidence."""
        conn = self.connection
        try:
            conn.execute("BEGIN")
            conn.execute("DELETE FROM benchmark_runs WHERE run_id = ?", (run.run_id,))
            conn.execute(
                """
                INSERT INTO benchmark_runs(
                    run_id, started_at, completed_at, metadata_json, manifest_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    _dt(run.started_at),
                    _dt(run.completed_at),
                    canonical_json(dict(run.metadata)),
                    canonical_json(dict(run.manifest)),
                ),
            )
            for result in run.trials:
                trial = result.trial
                conn.execute(
                    """
                    INSERT INTO benchmark_trials(
                        trial_id, run_id, model, suite_id, scenario_id, scenario_json,
                        policy_id, technique_id, transformation_id, transformation_digest,
                        repetition, target_request_count, judge_request_count, status, error,
                        canary_metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trial.trial_id,
                        run.run_id,
                        str(trial.model),
                        trial.suite_id,
                        trial.scenario.id,
                        canonical_json(trial.scenario),
                        trial.policy_id,
                        trial.technique_id,
                        trial.transformation_id,
                        result.transformation_digest,
                        trial.repetition,
                        trial.target_request_count,
                        trial.judge_request_count,
                        result.transcript.status.value,
                        result.transcript.error,
                        canonical_json(dict(result.canary_metadata)),
                    ),
                )
                for message_index, message in enumerate(result.transcript.messages):
                    conn.execute(
                        """
                        INSERT INTO benchmark_messages(
                            trial_id, message_index, role, trust, name, source, content,
                            metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            trial.trial_id,
                            message_index,
                            message.role.value,
                            message.trust.value,
                            message.name,
                            message.source,
                            message.content,
                            canonical_json(dict(message.metadata)),
                        ),
                    )
                for turn in result.transcript.turns:
                    conn.execute(
                        """
                        INSERT INTO benchmark_turns(
                            trial_id, turn_index, request_messages_json, response_json, error
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            trial.trial_id,
                            turn.turn_index,
                            canonical_json(turn.request_messages),
                            canonical_json(turn.response) if turn.response else None,
                            turn.error,
                        ),
                    )
                for outcome_index, outcome in enumerate(result.scoring.outcomes):
                    conn.execute(
                        """
                        INSERT INTO benchmark_scorer_outcomes(
                            trial_id, outcome_index, outcome_json
                        ) VALUES (?, ?, ?)
                        """,
                        (trial.trial_id, outcome_index, canonical_json(outcome)),
                    )
                for judge_index, judge in enumerate(result.judge_results):
                    conn.execute(
                        """
                        INSERT INTO benchmark_judge_calls(
                            trial_id, judge_index, outcome_json, raw_input, raw_output
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            trial.trial_id,
                            judge_index,
                            canonical_json(judge.outcome),
                            judge.raw_input,
                            judge.raw_output,
                        ),
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def get_benchmark(self, run_id: str) -> BenchmarkRunResult | None:
        row = self.connection.execute(
            "SELECT * FROM benchmark_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        trial_rows = self.connection.execute(
            "SELECT * FROM benchmark_trials WHERE run_id = ? ORDER BY rowid",
            (run_id,),
        ).fetchall()
        results: list[BenchmarkTrialResult] = []
        for trial_row in trial_rows:
            trial_id = trial_row["trial_id"]
            scenario = ScenarioSpec.model_validate(json.loads(trial_row["scenario_json"]))
            trial = PlannedTrial(
                trial_id=trial_id,
                model=ModelRef.parse(trial_row["model"]),
                suite_id=trial_row["suite_id"],
                scenario=scenario,
                policy_id=trial_row["policy_id"],
                technique_id=trial_row["technique_id"],
                transformation_id=trial_row["transformation_id"],
                repetition=int(trial_row["repetition"]),
                target_request_count=int(trial_row["target_request_count"]),
                judge_request_count=int(trial_row["judge_request_count"]),
            )
            message_rows = self.connection.execute(
                """
                SELECT * FROM benchmark_messages
                WHERE trial_id = ? ORDER BY message_index
                """,
                (trial_id,),
            ).fetchall()
            messages = tuple(
                Message(
                    role=MessageRole(message["role"]),
                    content=message["content"],
                    name=message["name"],
                    trust=MessageTrust(message["trust"]),
                    source=message["source"],
                    metadata=json.loads(message["metadata_json"]),
                )
                for message in message_rows
            )
            turn_rows = self.connection.execute(
                "SELECT * FROM benchmark_turns WHERE trial_id = ? ORDER BY turn_index",
                (trial_id,),
            ).fetchall()
            turns = tuple(
                ConversationTurn(
                    turn_index=int(turn["turn_index"]),
                    request_messages=tuple(
                        self._message_from_data(value)
                        for value in json.loads(turn["request_messages_json"])
                    ),
                    response=(
                        self._response_from_json(turn["response_json"])
                        if turn["response_json"]
                        else None
                    ),
                    error=turn["error"],
                )
                for turn in turn_rows
            )
            transcript = ConversationTranscript(
                trial_id=trial_id,
                status=ConversationStatus(trial_row["status"]),
                messages=messages,
                turns=turns,
                error=trial_row["error"],
            )
            outcome_rows = self.connection.execute(
                """
                SELECT outcome_json FROM benchmark_scorer_outcomes
                WHERE trial_id = ? ORDER BY outcome_index
                """,
                (trial_id,),
            ).fetchall()
            scoring = TranscriptScoring(
                trial_id=trial_id,
                outcomes=tuple(
                    self._scorer_outcome_from_data(json.loads(value["outcome_json"]))
                    for value in outcome_rows
                ),
            )
            judge_rows = self.connection.execute(
                """
                SELECT * FROM benchmark_judge_calls
                WHERE trial_id = ? ORDER BY judge_index
                """,
                (trial_id,),
            ).fetchall()
            judges = tuple(
                JudgeResult(
                    outcome=self._scorer_outcome_from_data(json.loads(value["outcome_json"])),
                    raw_input=value["raw_input"],
                    raw_output=value["raw_output"],
                )
                for value in judge_rows
            )
            results.append(
                BenchmarkTrialResult(
                    trial=trial,
                    transcript=transcript,
                    scoring=scoring,
                    canary_metadata=json.loads(trial_row["canary_metadata_json"]),
                    transformation_digest=trial_row["transformation_digest"],
                    judge_results=judges,
                )
            )
        started = _parse_dt(row["started_at"])
        completed = _parse_dt(row["completed_at"])
        if started is None or completed is None:
            raise ValueError(f"benchmark run {run_id!r} has invalid timestamps")
        return BenchmarkRunResult(
            run_id=run_id,
            started_at=started,
            completed_at=completed,
            trials=tuple(results),
            metadata=json.loads(row["metadata_json"]),
            manifest=json.loads(row["manifest_json"]),
        )

    def count_items(self, run_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) FROM evaluation_items WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return int(row[0])

    def get(self, run_id: str) -> EvaluationRun | None:
        row = self.connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        item_rows = self.connection.execute(
            "SELECT * FROM evaluation_items WHERE run_id = ? ORDER BY rowid",
            (run_id,),
        ).fetchall()
        items: list[EvaluationItem] = []
        for item_row in item_rows:
            mon_rows = self.connection.execute(
                "SELECT * FROM monitor_outcomes WHERE item_id = ? ORDER BY id",
                (item_row["item_id"],),
            ).fetchall()
            monitors = tuple(
                MonitorOutcome(
                    monitor_id=m["monitor_id"],
                    status=MonitorStatus(m["status"]),
                    confidence=m["confidence"],
                    explanation=m["explanation"],
                    details=json.loads(m["details_json"]),
                )
                for m in mon_rows
            )
            prompt = (
                self._prompt_from_json(item_row["prompt_json"]) if item_row["prompt_json"] else None
            )
            response = (
                self._response_from_json(item_row["response_json"])
                if item_row["response_json"]
                else None
            )
            assessment = (
                self._assessment_from_json(item_row["assessment_json"])
                if item_row["assessment_json"]
                else None
            )
            items.append(
                EvaluationItem(
                    item_id=item_row["item_id"],
                    model=ModelRef.parse(item_row["model"]),
                    attack_id=item_row["attack_id"],
                    sample_id=item_row["sample_id"],
                    status=ItemStatus(item_row["status"]),
                    prompt=prompt,
                    response=response,
                    assessment=assessment,
                    monitors=monitors,
                    error=item_row["error"],
                    started_at=_parse_dt(item_row["started_at"]),
                    completed_at=_parse_dt(item_row["completed_at"]),
                )
            )
        summary_data = json.loads(row["summary_json"])
        summary = RunSummary(
            status=RunStatus(summary_data["status"]),
            planned=summary_data["planned"],
            succeeded=summary_data["succeeded"],
            failed=summary_data["failed"],
            cancelled=summary_data["cancelled"],
            monitor_excluded=summary_data["monitor_excluded"],
        )
        started = _parse_dt(row["started_at"]) or datetime.now(timezone.utc)
        completed = _parse_dt(row["completed_at"]) or datetime.now(timezone.utc)
        return EvaluationRun(
            run_id=row["run_id"],
            status=RunStatus(row["status"]),
            items=tuple(items),
            summary=summary,
            started_at=started,
            completed_at=completed,
            seed=row["seed"],
            config_digest=row["config_digest"],
            dataset_digest=row["dataset_digest"],
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT run_id, status, started_at, completed_at, summary_json "
            "FROM runs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        result = []
        for row in rows:
            summary = json.loads(row["summary_json"])
            result.append(
                {
                    "run_id": row["run_id"],
                    "status": row["status"],
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                    "summary": summary,
                }
            )
        return result

    def list_benchmark_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT r.run_id, r.started_at, r.completed_at, COUNT(t.trial_id) AS trials
            FROM benchmark_runs r
            LEFT JOIN benchmark_trials t ON t.run_id = r.run_id
            GROUP BY r.run_id
            ORDER BY r.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "run_id": row["run_id"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "trials": int(row["trials"]),
            }
            for row in rows
        ]

    def get_manifest(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT manifest_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None or row["manifest_json"] is None:
            return None
        data = json.loads(row["manifest_json"])
        return data if isinstance(data, dict) else None

    def close(self) -> None:
        if getattr(self, "_closed", False):
            return
        self.connection.close()
        self._closed = True

    @staticmethod
    def _message_from_data(data: dict[str, Any]) -> Message:
        return Message(
            role=MessageRole(data["role"]),
            content=data["content"],
            name=data.get("name"),
            trust=MessageTrust(data.get("trust", "trusted")),
            source=data.get("source"),
            metadata=data.get("metadata") or {},
        )

    @staticmethod
    def _scorer_outcome_from_data(data: dict[str, Any]) -> ScorerOutcome:
        evidence = tuple(
            EvidenceSpan(
                channel=EvidenceChannel(value["channel"]),
                turn_index=int(value["turn_index"]),
                start=int(value["start"]),
                end=int(value["end"]),
                text=value["text"],
            )
            for value in data.get("evidence") or ()
        )
        return ScorerOutcome(
            scorer_id=data["scorer_id"],
            scorer_version=data["scorer_version"],
            channel=EvidenceChannel(data["channel"]),
            verdict=ScorerVerdict(data["verdict"]),
            score=data.get("score"),
            eligible=bool(data["eligible"]),
            metrics=data.get("metrics") or {},
            evidence=evidence,
            explanation=data.get("explanation") or "",
            error=data.get("error"),
            judge_metadata=data.get("judge_metadata") or {},
        )

    @staticmethod
    def _prompt_from_json(raw: str) -> AttackPrompt:
        data = json.loads(raw)
        return AttackPrompt(
            attack_id=data["attack_id"],
            text=data["text"],
            sample_id=data["sample_id"],
            system_prompt=data.get("system_prompt"),
            metadata=data.get("metadata") or {},
        )

    @staticmethod
    def _response_from_json(raw: str) -> ModelResponse:
        data = json.loads(raw)
        usage = data.get("usage") or {}
        model = data["model"]
        if isinstance(model, dict):
            model_ref = ModelRef(provider=model["provider"], model_id=model["model_id"])
        else:
            model_ref = ModelRef.parse(str(model))
        return ModelResponse(
            text=data["text"],
            model=model_ref,
            reasoning=data.get("reasoning"),
            reasoning_source=ReasoningSource(data.get("reasoning_source", "absent")),
            latency_ms=float(data.get("latency_ms") or 0.0),
            usage=TokenUsage(
                input_tokens=int(usage.get("input_tokens") or 0),
                output_tokens=int(usage.get("output_tokens") or 0),
                total_tokens=usage.get("total_tokens"),
            ),
            provider_request_id=data.get("provider_request_id"),
            finish_reason=data.get("finish_reason"),
            model_revision=data.get("model_revision"),
            metadata=data.get("metadata") or {},
        )

    @staticmethod
    def _assessment_from_json(raw: str) -> AttackAssessment:
        data = json.loads(raw)
        return AttackAssessment(
            success=bool(data["success"]),
            score=float(data["score"]),
            evidence=tuple(data.get("evidence") or ()),
            metrics=data.get("metrics") or {},
            explanation=data.get("explanation") or "",
        )
