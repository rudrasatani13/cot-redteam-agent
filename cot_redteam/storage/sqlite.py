"""Transactional SQLite run persistence."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from cot_redteam.agent.config import AgentRetentionSettings
from cot_redteam.agent.retention import AgentSanitizer
from cot_redteam.agent.types import (
    AGENT_EVENT_SCHEMA_VERSION,
    AgentEventUnion,
    AgentOutcome,
    AgentRun,
    AgentRunStatus,
    Finding,
    OracleResult,
    VersionedRef,
    validate_agent_event,
)
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
from cot_redteam.eval.manifest import validate_agent_manifest

logger = logging.getLogger(__name__)

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS runs (
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
        CREATE TABLE IF NOT EXISTS evaluation_items (
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
        CREATE TABLE IF NOT EXISTS monitor_outcomes (
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
        CREATE TABLE IF NOT EXISTS benchmark_runs (
            run_id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            manifest_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS benchmark_trials (
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
        CREATE TABLE IF NOT EXISTS benchmark_messages (
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
        CREATE TABLE IF NOT EXISTS benchmark_turns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id TEXT NOT NULL REFERENCES benchmark_trials(trial_id) ON DELETE CASCADE,
            turn_index INTEGER NOT NULL,
            request_messages_json TEXT NOT NULL,
            response_json TEXT,
            error TEXT,
            UNIQUE(trial_id, turn_index)
        );
        CREATE TABLE IF NOT EXISTS benchmark_scorer_outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trial_id TEXT NOT NULL REFERENCES benchmark_trials(trial_id) ON DELETE CASCADE,
            outcome_index INTEGER NOT NULL,
            outcome_json TEXT NOT NULL,
            UNIQUE(trial_id, outcome_index)
        );
        CREATE TABLE IF NOT EXISTS benchmark_judge_calls (
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
    (
        3,
        """
        CREATE TABLE IF NOT EXISTS agent_runs (
            run_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            scenario_id TEXT NOT NULL,
            scenario_version TEXT NOT NULL,
            target_id TEXT NOT NULL,
            target_version TEXT NOT NULL,
            world_id TEXT NOT NULL,
            world_version TEXT NOT NULL,
            attack_id TEXT NOT NULL,
            attack_version TEXT NOT NULL,
            status TEXT NOT NULL,
            outcome TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            pre_snapshot_digest TEXT,
            post_snapshot_digest TEXT,
            trajectory_digest TEXT,
            budget_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            manifest_json TEXT,
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_trajectory_events (
            run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
            sequence_no INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            parent_event_id TEXT,
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            event_json TEXT NOT NULL,
            PRIMARY KEY(run_id, sequence_no),
            UNIQUE(run_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS agent_oracle_results (
            run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
            oracle_id TEXT NOT NULL,
            oracle_version TEXT NOT NULL,
            verdict TEXT NOT NULL,
            result_json TEXT NOT NULL,
            PRIMARY KEY(run_id, oracle_id, oracle_version)
        );
        CREATE TABLE IF NOT EXISTS agent_findings (
            finding_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES agent_runs(run_id) ON DELETE CASCADE,
            oracle_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            finding_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS replay_artifacts (
            replay_id TEXT PRIMARY KEY,
            original_run_id TEXT NOT NULL,
            schema_version INTEGER NOT NULL,
            relative_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            byte_length INTEGER NOT NULL,
            world_fixture_digest TEXT NOT NULL,
            trajectory_digest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL
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


def _split_sql_statements(sql: str) -> list[str]:
    """Split a migration script into individual statements.

    ``executescript`` cannot be used inside an explicit transaction (it
    implicitly commits first), so migrations execute statement-by-statement.
    Migration SQL in this module is plain DDL with no embedded semicolons.
    """
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


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
            # executescript() implicitly commits any pending transaction
            # before running, so a crash mid-script left a partially
            # applied schema that re-running could never repair.  Instead,
            # execute each statement inside an explicit transaction (with
            # IF NOT EXISTS guards) so a failure rolls the whole migration
            # back and re-opening the store recovers cleanly.
            self.connection.execute("BEGIN")
            try:
                for statement in _split_sql_statements(sql):
                    self.connection.execute(statement)
                self.connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

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

    def get_agent_manifest(self, run_id: str) -> dict[str, Any] | None:
        """Load the redacted manifest attached to one agent run."""
        row = self.connection.execute(
            "SELECT manifest_json FROM agent_runs WHERE run_id = ?",
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

    # -- agent persistence --------------------------------------------------

    def begin_agent_run(
        self,
        run: AgentRun,
        *,
        retention: AgentRetentionSettings,
    ) -> None:
        """Insert one RUNNING row before target execution.

        ``retention`` is REQUIRED: the store is the last privacy boundary
        and sanitizes even when the caller claims the run is already
        sanitized.  Run IDs are immutable storage identities; attempting to
        begin an existing ID is rejected rather than deleting its trajectory
        and evidence.
        """
        sanitizer = AgentSanitizer(retention)
        run = sanitizer.sanitize_run(run)
        if run.status is not AgentRunStatus.RUNNING:
            raise ValueError("begin_agent_run requires a RUNNING run")
        if run.metadata.get("manifest") is not None:
            raise ValueError("agent manifests may only be attached after finalization")
        conn = self.connection
        try:
            conn.execute("BEGIN")
            existing = conn.execute(
                "SELECT 1 FROM agent_runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            if existing is not None:
                raise ValueError(f"agent run {run.run_id!r} already exists")
            conn.execute(
                """
                INSERT INTO agent_runs(
                    run_id, session_id, schema_version,
                    scenario_id, scenario_version, target_id, target_version,
                    world_id, world_version, attack_id, attack_version,
                    status, outcome, started_at, completed_at,
                    pre_snapshot_digest, post_snapshot_digest, trajectory_digest,
                    budget_json, metadata_json, manifest_json, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.session_id,
                    run.schema_version,
                    run.scenario_ref.id,
                    run.scenario_ref.version,
                    run.target_ref.id,
                    run.target_ref.version,
                    run.world_ref.id,
                    run.world_ref.version,
                    run.attack_ref.id,
                    run.attack_ref.version,
                    run.status.value,
                    run.outcome.value if run.outcome else None,
                    _dt(run.started_at),
                    _dt(run.completed_at),
                    run.pre_snapshot_digest,
                    run.post_snapshot_digest,
                    run.trajectory.digest if run.trajectory.events else None,
                    canonical_json(run.budget_snapshot),
                    canonical_json(run.metadata),
                    None,
                    run.error,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def append_agent_events(
        self,
        run_id: str,
        events: Sequence[Mapping[str, object]],
        *,
        retention: AgentRetentionSettings,
    ) -> None:
        """Append sanitized event envelopes transactionally (append-only).

        ``retention`` is REQUIRED and applied unconditionally: the store is
        the last privacy boundary and sanitizes again even when the caller
        claims the envelopes are already sanitized (defense in depth).
        """
        if not events:
            return
        sanitizer = AgentSanitizer(retention)
        conn = self.connection
        try:
            conn.execute("BEGIN")
            for envelope in events:
                data = sanitizer.sanitize_event(envelope)
                conn.execute(
                    """
                    INSERT INTO agent_trajectory_events(
                        run_id, sequence_no, event_id, event_type, parent_event_id,
                        session_id, agent_id, schema_version, event_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        int(cast("Any", data["sequence_no"])),
                        str(data["event_id"]),
                        str(data["event_type"]),
                        data.get("parent_event_id"),
                        str(data["session_id"]),
                        str(data["agent_id"]),
                        int(cast("Any", data.get("schema_version", AGENT_EVENT_SCHEMA_VERSION))),
                        canonical_json(data),
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def save_agent_oracle_results(
        self,
        run_id: str,
        results: Sequence[OracleResult],
    ) -> None:
        """Replace oracle results for a run in one transaction."""
        conn = self.connection
        owns_transaction = not conn.in_transaction
        try:
            if owns_transaction:
                conn.execute("BEGIN")
            conn.execute("DELETE FROM agent_oracle_results WHERE run_id = ?", (run_id,))
            for result in results:
                conn.execute(
                    """
                    INSERT INTO agent_oracle_results(
                        run_id, oracle_id, oracle_version, verdict, result_json
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        result.oracle_id,
                        result.oracle_version,
                        result.verdict.value,
                        canonical_json(result),
                    ),
                )
            if owns_transaction:
                conn.commit()
        except Exception:
            if owns_transaction:
                conn.rollback()
            raise

    def save_agent_findings(self, run_id: str, findings: Sequence[Finding]) -> None:
        """Replace findings for a run in one transaction."""
        conn = self.connection
        owns_transaction = not conn.in_transaction
        try:
            if owns_transaction:
                conn.execute("BEGIN")
            conn.execute("DELETE FROM agent_findings WHERE run_id = ?", (run_id,))
            for finding in findings:
                conn.execute(
                    """
                    INSERT INTO agent_findings(
                        finding_id, run_id, oracle_id, category, severity, finding_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.finding_id,
                        run_id,
                        finding.oracle_id,
                        finding.category,
                        finding.severity,
                        canonical_json(finding),
                    ),
                )
            if owns_transaction:
                conn.commit()
        except Exception:
            if owns_transaction:
                conn.rollback()
            raise

    def finalize_agent_run(
        self,
        run: AgentRun,
        *,
        retention: AgentRetentionSettings,
        manifest: dict[str, Any] | None = None,
    ) -> None:
        """Finalize status/outcome/digests plus oracle results and findings.

        ``retention`` is REQUIRED: the run is sanitized again at this
        storage boundary before any persistence (defense in depth).  The
        final run row and all evidence tables commit atomically, and only a
        RUNNING row may transition to a terminal result.

        Finalization is idempotent for rows that already reached a terminal
        state (e.g. marked INTERRUPTED by a concurrent
        ``recover_incomplete_agent_runs()`` while the scenario was still
        finalizing): the status/outcome update is skipped with a warning
        instead of raising.  A missing row is still an error.
        """
        sanitizer = AgentSanitizer(retention)
        run = sanitizer.sanitize_run(run)
        if run.status in (AgentRunStatus.RUNNING, AgentRunStatus.INTERRUPTED):
            raise ValueError(f"cannot finalize agent run with status {run.status.value!r}")
        conn = self.connection
        try:
            conn.execute("BEGIN")
            row = conn.execute(
                """
                SELECT status, manifest_json, session_id,
                       scenario_id, scenario_version,
                       target_id, target_version,
                       world_id, world_version,
                       attack_id, attack_version,
                       outcome, pre_snapshot_digest, post_snapshot_digest,
                       trajectory_digest
                FROM agent_runs WHERE run_id = ?
                """,
                (run.run_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"agent run {run.run_id!r} does not exist")
            if row["status"] != AgentRunStatus.RUNNING.value:
                # A concurrent recover_incomplete_agent_runs() can mark the
                # row INTERRUPTED while the scenario is still finalizing.
                # The row has already reached a terminal state, so skip the
                # status/outcome update instead of raising (finalize is
                # idempotent for terminal rows).
                logger.warning(
                    "agent run %r is already %r; skipping finalization status/outcome update",
                    run.run_id,
                    row["status"],
                )
                conn.rollback()
                return

            stored_refs = {
                "session_id": row["session_id"],
                "scenario": {
                    "id": row["scenario_id"],
                    "version": row["scenario_version"],
                },
                "target": {
                    "id": row["target_id"],
                    "version": row["target_version"],
                },
                "world": {
                    "id": row["world_id"],
                    "version": row["world_version"],
                },
                "attack": {
                    "id": row["attack_id"],
                    "version": row["attack_version"],
                },
            }
            supplied_refs = {
                "session_id": run.session_id,
                "scenario": {
                    "id": run.scenario_ref.id,
                    "version": run.scenario_ref.version,
                },
                "target": {
                    "id": run.target_ref.id,
                    "version": run.target_ref.version,
                },
                "world": {
                    "id": run.world_ref.id,
                    "version": run.world_ref.version,
                },
                "attack": {
                    "id": run.attack_ref.id,
                    "version": run.attack_ref.version,
                },
            }
            if supplied_refs != stored_refs:
                raise ValueError("final agent run identity does not match the stored run")
            for field, supplied in (
                ("outcome", run.outcome.value if run.outcome else None),
                ("pre_snapshot_digest", run.pre_snapshot_digest),
                ("post_snapshot_digest", run.post_snapshot_digest),
                ("trajectory_digest", run.original_trajectory_digest or run.trajectory.digest),
            ):
                stored = row[field]
                if stored is not None and stored != supplied:
                    raise ValueError(f"final agent run {field} does not match the stored run")

            existing_manifest = row["manifest_json"]
            expected_manifest = {
                "run_id": run.run_id,
                **stored_refs,
                "status": run.status.value,
                "outcome": run.outcome.value if run.outcome else None,
                "pre_snapshot_digest": run.pre_snapshot_digest,
                "post_snapshot_digest": run.post_snapshot_digest,
                "trajectory_digest": run.original_trajectory_digest or run.trajectory.digest,
            }
            if manifest is not None:
                validated_manifest = validate_agent_manifest(
                    manifest,
                    expected=expected_manifest,
                )
                if existing_manifest is not None:
                    raise ValueError("agent manifest is already attached")
                manifest_json: str | None = canonical_json(validated_manifest)
            else:
                if existing_manifest is None:
                    manifest_json = None
                else:
                    try:
                        existing_data = json.loads(existing_manifest)
                    except (TypeError, ValueError) as exc:
                        raise ValueError("stored agent manifest is invalid JSON") from exc
                    validated_existing = validate_agent_manifest(
                        existing_data,
                        expected=expected_manifest,
                    )
                    manifest_json = canonical_json(validated_existing)

            cursor = conn.execute(
                """
                UPDATE agent_runs SET
                    status = ?, outcome = ?, completed_at = ?,
                    pre_snapshot_digest = ?, post_snapshot_digest = ?,
                    trajectory_digest = ?, budget_json = ?, manifest_json = ?, error = ?
                WHERE run_id = ? AND status = ?
                """,
                (
                    run.status.value,
                    run.outcome.value if run.outcome else None,
                    _dt(run.completed_at),
                    run.pre_snapshot_digest,
                    run.post_snapshot_digest,
                    # The row keeps the ORIGINAL semantic digest (the proof
                    # anchor used by replay); the sanitized view's own digest
                    # describes the persisted events.
                    run.original_trajectory_digest or run.trajectory.digest,
                    canonical_json(run.budget_snapshot),
                    manifest_json,
                    run.error,
                    run.run_id,
                    AgentRunStatus.RUNNING.value,
                ),
            )
            if cursor.rowcount != 1:
                # The row changed state between the SELECT and the guarded
                # UPDATE (concurrent recovery marked it INTERRUPTED).  The
                # row reached a terminal state on its own; skip the
                # status/outcome update rather than raising.
                logger.warning(
                    "agent run %r changed state before finalization; "
                    "skipping finalization status/outcome update",
                    run.run_id,
                )
                conn.rollback()
                return
            # These methods detect the outer transaction and deliberately do
            # not commit independently.  Any failure rolls back status,
            # oracle rows, and finding rows together below.
            self.save_agent_oracle_results(run.run_id, run.oracle_results)
            self.save_agent_findings(run.run_id, run.findings)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def update_agent_manifest(self, run_id: str, manifest: dict[str, Any]) -> None:
        """Attach a manifest generated after an agent run is finalized.

        Agent manifests include final run digests and therefore cannot be
        constructed before target execution.  The update is kept as a small,
        explicit transaction so CLI/API callers can persist the artifact
        metadata without rewriting append-only trajectory events.
        """
        conn = self.connection
        try:
            conn.execute("BEGIN")
            row = conn.execute(
                """
                SELECT run_id, session_id, status, outcome,
                       scenario_id, scenario_version,
                       target_id, target_version,
                       world_id, world_version,
                       attack_id, attack_version,
                       pre_snapshot_digest, post_snapshot_digest, trajectory_digest,
                       manifest_json
                FROM agent_runs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"agent run {run_id!r} does not exist")
            if row["status"] == AgentRunStatus.RUNNING.value:
                raise ValueError("cannot attach a manifest to a RUNNING agent run")
            if row["manifest_json"] is not None:
                raise ValueError("agent manifest is already attached")
            validated_manifest = validate_agent_manifest(
                manifest,
                expected={
                    "run_id": row["run_id"],
                    "session_id": row["session_id"],
                    "status": row["status"],
                    "outcome": row["outcome"],
                    "pre_snapshot_digest": row["pre_snapshot_digest"],
                    "post_snapshot_digest": row["post_snapshot_digest"],
                    "trajectory_digest": row["trajectory_digest"],
                    "scenario": {
                        "id": row["scenario_id"],
                        "version": row["scenario_version"],
                    },
                    "target": {
                        "id": row["target_id"],
                        "version": row["target_version"],
                    },
                    "world": {
                        "id": row["world_id"],
                        "version": row["world_version"],
                    },
                    "attack": {
                        "id": row["attack_id"],
                        "version": row["attack_version"],
                    },
                },
            )
            cursor = conn.execute(
                "UPDATE agent_runs SET manifest_json = ? "
                "WHERE run_id = ? AND manifest_json IS NULL",
                (canonical_json(validated_manifest), run_id),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"agent run {run_id!r} does not exist")
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def recover_incomplete_agent_runs(self, exclude_run_id: str | None = None) -> int:
        """Mark prior non-current RUNNING rows as INTERRUPTED.

        This operation is intentionally conservative about outcome (it never
        marks a run completed or secure), but the v3 schema has no owner or
        heartbeat column. Callers must serialize startup recovery per store;
        concurrent workers sharing a database cannot be distinguished from a
        crashed worker and may otherwise interrupt one another.
        """
        params: tuple[Any, ...] = ()
        sql = "UPDATE agent_runs SET status = ? WHERE status = ?"
        if exclude_run_id is not None:
            sql += " AND run_id != ?"
            params = (
                AgentRunStatus.INTERRUPTED.value,
                AgentRunStatus.RUNNING.value,
                exclude_run_id,
            )
        else:
            params = (AgentRunStatus.INTERRUPTED.value, AgentRunStatus.RUNNING.value)
        cursor = self.connection.execute(sql, params)
        self.connection.commit()
        return int(cursor.rowcount)

    def get_agent_run(
        self,
        run_id: str,
        *,
        retention_view: AgentRetentionSettings | None = None,
    ) -> AgentRun | None:
        """Load a complete agent run; rejects malformed/incompatible data."""
        row = self.connection.execute(
            "SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        event_rows = self.connection.execute(
            "SELECT * FROM agent_trajectory_events WHERE run_id = ? ORDER BY sequence_no",
            (run_id,),
        ).fetchall()
        events: list[AgentEventUnion] = []
        for event_row in event_rows:
            data = json.loads(event_row["event_json"])
            events.append(validate_agent_event(data))
        from cot_redteam.agent.types import AgentTrajectory

        # The loaded events are the persisted (sanitized) view; its digest
        # describes those events. The original semantic digest is preserved
        # on the run for replay/proof anchoring.
        trajectory = AgentTrajectory(
            run_id=run_id,
            session_id=row["session_id"],
            events=tuple(events),
        )
        oracle_rows = self.connection.execute(
            "SELECT result_json FROM agent_oracle_results WHERE run_id = ? ORDER BY oracle_id",
            (run_id,),
        ).fetchall()
        oracle_results = tuple(
            OracleResult.model_validate(json.loads(value["result_json"])) for value in oracle_rows
        )
        finding_rows = self.connection.execute(
            "SELECT finding_json FROM agent_findings WHERE run_id = ? ORDER BY finding_id",
            (run_id,),
        ).fetchall()
        findings = tuple(
            Finding.model_validate(json.loads(value["finding_json"])) for value in finding_rows
        )
        started = _parse_dt(row["started_at"]) or datetime.now(timezone.utc)
        run = AgentRun(
            run_id=run_id,
            session_id=row["session_id"],
            schema_version=int(row["schema_version"]),
            scenario_ref=VersionedRef(id=row["scenario_id"], version=row["scenario_version"]),
            target_ref=VersionedRef(id=row["target_id"], version=row["target_version"]),
            world_ref=VersionedRef(id=row["world_id"], version=row["world_version"]),
            attack_ref=VersionedRef(id=row["attack_id"], version=row["attack_version"]),
            status=AgentRunStatus(row["status"]),
            outcome=AgentOutcome(row["outcome"]) if row["outcome"] else None,
            trajectory=trajectory,
            original_trajectory_digest=row["trajectory_digest"],
            pre_snapshot_digest=row["pre_snapshot_digest"],
            post_snapshot_digest=row["post_snapshot_digest"],
            oracle_results=oracle_results,
            findings=findings,
            budget_snapshot=json.loads(row["budget_json"]),
            started_at=started,
            completed_at=_parse_dt(row["completed_at"]),
            error=row["error"],
            metadata=json.loads(row["metadata_json"] or "{}"),
        )
        if retention_view is not None:
            from cot_redteam.agent.retention import sanitize_agent_run

            run = sanitize_agent_run(run, retention_view)
        return run

    def list_agent_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT run_id, session_id, scenario_id, target_id, status, outcome,
                   started_at, completed_at, trajectory_digest
            FROM agent_runs ORDER BY started_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "run_id": row["run_id"],
                "session_id": row["session_id"],
                "scenario_id": row["scenario_id"],
                "target_id": row["target_id"],
                "status": row["status"],
                "outcome": row["outcome"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "trajectory_digest": row["trajectory_digest"],
            }
            for row in rows
        ]

    def save_replay_record(
        self,
        *,
        replay_id: str,
        original_run_id: str,
        schema_version: int,
        relative_path: str,
        sha256: str,
        byte_length: int,
        world_fixture_digest: str,
        trajectory_digest: str,
        metadata: Mapping[str, Any],
    ) -> None:
        metadata_json = canonical_json(dict(metadata))
        conn = self.connection
        try:
            conn.execute("BEGIN")
            existing = conn.execute(
                """
                SELECT original_run_id, schema_version, relative_path, sha256,
                       byte_length, world_fixture_digest, trajectory_digest, metadata_json
                FROM replay_artifacts WHERE replay_id = ?
                """,
                (replay_id,),
            ).fetchone()
            if existing is not None:
                candidate = (
                    original_run_id,
                    schema_version,
                    relative_path,
                    sha256,
                    byte_length,
                    world_fixture_digest,
                    trajectory_digest,
                    metadata_json,
                )
                stored = tuple(
                    existing[key]
                    for key in (
                        "original_run_id",
                        "schema_version",
                        "relative_path",
                        "sha256",
                        "byte_length",
                        "world_fixture_digest",
                        "trajectory_digest",
                        "metadata_json",
                    )
                )
                if stored != candidate:
                    raise ValueError(f"replay record {replay_id!r} is immutable")
                conn.commit()
                return
            conn.execute(
                """
                INSERT INTO replay_artifacts(
                    replay_id, original_run_id, schema_version, relative_path,
                    sha256, byte_length, world_fixture_digest, trajectory_digest,
                    created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    replay_id,
                    original_run_id,
                    schema_version,
                    relative_path,
                    sha256,
                    byte_length,
                    world_fixture_digest,
                    trajectory_digest,
                    _dt(datetime.now(timezone.utc)),
                    metadata_json,
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
