"""Transactional SQLite run persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cot_redteam.core.serialization import canonical_json
from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    ItemStatus,
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
    )
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
        self._migrate()

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

    def close(self) -> None:
        self.connection.close()

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
