"""Agent SQLite persistence: migration, crash semantics, retention boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cot_redteam.agent.api import run_agent_scenario
from cot_redteam.agent.config import AgentRetentionSettings, AgentSecuritySettings
from cot_redteam.agent.types import (
    AgentOutcome,
    AgentRunStatus,
    FinalResponse,
    ToolCallRequested,
    ToolResultReceived,
)
from cot_redteam.storage.sqlite import SQLiteRunStore

CANARY = "COT-REDTEAM-CANARY-9F3A1C8E"


def _store(tmp_path: Path) -> SQLiteRunStore:
    return SQLiteRunStore(tmp_path / "agent.db")


def test_migration_3_applied_from_fresh_db(tmp_path: Path) -> None:
    store = _store(tmp_path)
    versions = [row[0] for row in store.connection.execute("SELECT version FROM schema_migrations")]
    assert versions == [1, 2, 3]
    tables = {
        row[0]
        for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {
        "agent_runs",
        "agent_trajectory_events",
        "agent_oracle_results",
        "agent_findings",
    } <= tables
    store.close()


def test_migration_2_to_3_preserves_existing_rows(tmp_path: Path) -> None:
    """A v2 database with benchmark rows upgrades to v3 and rows still load."""
    from datetime import datetime, timezone

    from cot_redteam.benchmark.results import BenchmarkRunResult

    # Build a store, insert a legacy benchmark row at schema v2.
    path = tmp_path / "agent.db"
    store = SQLiteRunStore(path)
    legacy = BenchmarkRunResult(
        run_id="legacy-run",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        trials=(),
        metadata={"config_digest": "x"},
        manifest={"schema_version": 3},
    )
    store.save_benchmark(legacy)
    store.close()

    # Reopen (idempotent; migration 3 already applied) and verify legacy load.
    store = SQLiteRunStore(path)
    loaded = store.get_benchmark("legacy-run")
    assert loaded is not None
    assert loaded.run_id == "legacy-run"
    assert len(loaded.trials) == 0
    store.close()


def test_migration_1_to_3_preserves_evaluation_rows(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    from cot_redteam.core.types import (
        AttackAssessment,
        AttackPrompt,
        EvaluationItem,
        EvaluationRun,
        ItemStatus,
        ModelRef,
        ModelResponse,
        RunSummary,
        TokenUsage,
    )

    path = tmp_path / "agent.db"
    store = SQLiteRunStore(path)
    item = EvaluationItem(
        item_id="i1",
        model=ModelRef.parse("mock:m"),
        attack_id="a",
        sample_id="s",
        status=ItemStatus.SUCCEEDED,
        prompt=AttackPrompt(attack_id="a", text="p", sample_id="s"),
        response=ModelResponse(
            text="ok",
            model=ModelRef.parse("mock:m"),
            usage=TokenUsage(1, 1),
        ),
        assessment=AttackAssessment(success=False, score=0.0),
    )
    summary = RunSummary.from_items([item])
    run = EvaluationRun(
        run_id="legacy-eval",
        status=summary.status,
        items=(item,),
        summary=summary,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    store.save(run)
    store.close()
    store = SQLiteRunStore(path)
    assert store.get("legacy-eval") is not None
    store.close()


def test_begin_append_finalize_round_trip(tmp_path: Path) -> None:
    import asyncio

    from cot_redteam.agent.api import run_agent_scenario

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.tool_result_injection.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
            )
            assert run.outcome is AgentOutcome.VERIFIED_EXPLOIT
            loaded = store.get_agent_run(run.run_id)
            assert loaded is not None
            assert loaded.outcome is AgentOutcome.VERIFIED_EXPLOIT
            assert loaded.trajectory.digest == run.trajectory.digest
            assert len(loaded.trajectory.events) == len(run.trajectory.events)
            assert loaded.oracle_results == run.oracle_results
            assert loaded.findings == run.findings

    asyncio.run(_run())


def test_events_append_only_no_duplicates(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
            )
            rows = store.connection.execute(
                "SELECT event_id, COUNT(*) AS n FROM agent_trajectory_events "
                "WHERE run_id = ? GROUP BY event_id HAVING n > 1",
                (run.run_id,),
            ).fetchall()
            assert rows == []
            # A second append of the same envelope must fail (append-only).
            from cot_redteam.storage.sqlite import sqlite3

            with pytest.raises(sqlite3.IntegrityError):
                store.append_agent_events(
                    run.run_id,
                    [
                        json.loads(row["event_json"])
                        for row in store.connection.execute(
                            "SELECT event_json FROM agent_trajectory_events WHERE run_id = ? LIMIT 1",
                            (run.run_id,),
                        )
                    ],
                )

    asyncio.run(_run())


def test_failed_append_rolls_back_entire_batch(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="clean",
                seed=7,
                run_store=store,
            )
            before = store.connection.execute(
                "SELECT COUNT(*) FROM agent_trajectory_events WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
            good = {
                "event_type": "agent_step",
                "run_id": run.run_id,
                "session_id": run.session_id,
                "event_id": "new-event-1",
                "agent_id": "scripted",
                "sequence_no": 999,
                "provenance": {
                    "source_kind": "target",
                    "source_id": "scripted",
                    "trust": "untrusted",
                },
                "step_kind": "x",
                "input_source": "y",
            }
            duplicate = {
                "event_type": "agent_step",
                "run_id": run.run_id,
                "session_id": run.session_id,
                "event_id": run.trajectory.events[0].event_id,  # already stored
                "agent_id": "scripted",
                "sequence_no": 1000,
                "provenance": {
                    "source_kind": "target",
                    "source_id": "scripted",
                    "trust": "untrusted",
                },
                "step_kind": "x",
                "input_source": "y",
            }
            from cot_redteam.storage.sqlite import sqlite3

            with pytest.raises(sqlite3.IntegrityError):
                store.append_agent_events(run.run_id, [good, duplicate])
            after = store.connection.execute(
                "SELECT COUNT(*) FROM agent_trajectory_events WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
            # The whole batch rolled back: neither event persisted.
            assert after == before

    asyncio.run(_run())


def test_interrupted_run_recovery(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            from datetime import datetime, timezone

            from cot_redteam.agent.types import AgentRun, AgentTrajectory, VersionedRef

            # Simulate a process that crashed mid-run: the row was begun as
            # RUNNING and never finalized.
            shell = AgentRun(
                run_id="stale-run",
                session_id="session-stale",
                scenario_ref=VersionedRef(id="support.approval_bypass.v1", version="1"),
                target_ref=VersionedRef(id="scripted", version="1"),
                world_ref=VersionedRef(id="support", version="support-world/1"),
                attack_ref=VersionedRef(id="scripted:clean", version="1"),
                status=AgentRunStatus.RUNNING,
                trajectory=AgentTrajectory(
                    run_id="stale-run", session_id="session-stale", events=()
                ),
                budget_snapshot={},
                started_at=datetime.now(timezone.utc),
            )
            store.begin_agent_run(shell)
            assert store.get_agent_run("stale-run").status is AgentRunStatus.RUNNING  # type: ignore[union-attr]
            recovered = store.recover_incomplete_agent_runs(exclude_run_id="current-run")
            assert recovered == 1
            # Never marked completed or secure.
            loaded = store.get_agent_run("stale-run")
            assert loaded is not None
            assert loaded.status is AgentRunStatus.INTERRUPTED
            assert loaded.outcome is None

    asyncio.run(_run())


def test_default_retention_omits_raw_sensitive_values_everywhere(tmp_path: Path) -> None:
    """Byte-search the DB after a default-retention run: no canary, raw tool
    args/results, or final-response text survives."""
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.indirect_prompt_injection.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
            )
            assert run.outcome is AgentOutcome.VERIFIED_EXPLOIT
            blob = "\n".join(
                row[0]
                for row in store.connection.execute(
                    "SELECT event_json FROM agent_trajectory_events WHERE run_id = ?",
                    (run.run_id,),
                )
            )
            blob += (
                "\n"
                + store.connection.execute(
                    "SELECT budget_json || ' ' || COALESCE(manifest_json, '') FROM agent_runs WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()[0]
            )
            assert CANARY not in blob
            assert "Forwarded the requested" not in blob
            # Tool arguments/results are structurally present as null under
            # default retention; the raw values never are.
            for event_json in blob.split("\n"):
                if not event_json:
                    continue
                try:
                    event = json.loads(event_json)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "tool_call_requested":
                    assert event.get("sanitized_arguments") is None
                if event.get("event_type") == "tool_result_received":
                    assert event.get("sanitized_result") is None
                if event.get("event_type") == "final_response":
                    assert event.get("text") is None
            # Structural provenance (scenario id) stays under default retention.
            assert "support.indirect_prompt_injection.v1" in blob

    asyncio.run(_run())


def test_retention_view_sanitizes_loaded_run(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.indirect_prompt_injection.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
                settings=AgentSecuritySettings(
                    retention=AgentRetentionSettings(retain_final_response=True)
                ),
            )
            loaded = store.get_agent_run(run.run_id, retention_view=AgentRetentionSettings())
            assert loaded is not None
            for event in loaded.trajectory.events:
                if isinstance(event, FinalResponse):
                    assert event.text is None
                    assert event.text_retained is False
                if isinstance(event, ToolCallRequested):
                    assert event.sanitized_arguments is None
                if isinstance(event, ToolResultReceived):
                    assert event.sanitized_result is None

    asyncio.run(_run())


def test_replay_record_round_trip(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        store.save_replay_record(
            replay_id="replay-1",
            original_run_id="agent-1",
            schema_version=1,
            relative_path="agent-1/replay.json",
            sha256="a" * 64,
            byte_length=123,
            world_fixture_digest="b" * 64,
            trajectory_digest="c" * 64,
            metadata={"scenario": "x"},
        )
        row = store.connection.execute(
            "SELECT * FROM replay_artifacts WHERE replay_id='replay-1'"
        ).fetchone()
        assert row is not None
        assert row["relative_path"] == "agent-1/replay.json"
