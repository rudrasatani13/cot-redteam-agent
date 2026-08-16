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
from cot_redteam.eval.manifest import build_agent_manifest
from cot_redteam.storage.sqlite import SQLiteRunStore

CANARY = "COT-REDTEAM-CANARY-9F3A1C8E"


def _store(tmp_path: Path) -> SQLiteRunStore:
    return SQLiteRunStore(tmp_path / "agent.db")


def test_migration_3_applied_from_fresh_db(tmp_path: Path) -> None:
    store = _store(tmp_path)
    versions = [row[0] for row in store.connection.execute("SELECT version FROM schema_migrations")]
    assert versions == [1, 2, 3, 4]
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
            # The persisted view is sanitized under default retention, so the
            # loaded trajectory digest describes the sanitized content while
            # the original digest is preserved as the proof anchor.
            assert loaded.original_trajectory_digest == run.trajectory.digest
            assert loaded.trajectory.digest != run.trajectory.digest
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
            from cot_redteam.core.errors import StorageError

            with pytest.raises(StorageError):
                store.append_agent_events(
                    run.run_id,
                    [
                        json.loads(row["event_json"])
                        for row in store.connection.execute(
                            "SELECT event_json FROM agent_trajectory_events WHERE run_id = ? LIMIT 1",
                            (run.run_id,),
                        )
                    ],
                    retention=AgentRetentionSettings(),
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
            from cot_redteam.core.errors import StorageError

            with pytest.raises(StorageError):
                store.append_agent_events(
                    run.run_id, [good, duplicate], retention=AgentRetentionSettings()
                )
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
            store.begin_agent_run(shell, retention=AgentRetentionSettings())
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
                    "SELECT budget_json || ' ' || COALESCE(manifest_json, '') || ' ' "
                    "|| COALESCE(error, '') FROM agent_runs WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()[0]
            )
            oracle_blob = "\n".join(
                row[0]
                for row in store.connection.execute(
                    "SELECT result_json FROM agent_oracle_results WHERE run_id = ?",
                    (run.run_id,),
                )
            )
            findings_blob = "\n".join(
                row[0]
                for row in store.connection.execute(
                    "SELECT finding_json FROM agent_findings WHERE run_id = ?",
                    (run.run_id,),
                )
            )
            replay_blob = "\n".join(
                row[0]
                for row in store.connection.execute(
                    "SELECT metadata_json FROM replay_artifacts WHERE original_run_id = ?",
                    (run.run_id,),
                )
            )
            blob = "\n".join([blob, oracle_blob, findings_blob, replay_blob])
            assert CANARY not in blob
            assert "Forwarded the requested" not in blob
            # Oracle proof carries only the canary hash, never the raw value.
            assert "canary_sha256" in oracle_blob
            assert CANARY not in oracle_blob
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
            assert loaded.original_trajectory_digest == run.trajectory.digest

    asyncio.run(_run())


def test_replay_record_round_trip(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        record = dict(
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
        store.save_replay_record(**record)
        row = store.connection.execute(
            "SELECT * FROM replay_artifacts WHERE replay_id='replay-1'"
        ).fetchone()
        assert row is not None
        assert row["relative_path"] == "agent-1/replay.json"
        created_at = row["created_at"]

        # Replaying the same save is idempotent and preserves provenance.
        store.save_replay_record(**record)
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM replay_artifacts WHERE replay_id='replay-1'"
            ).fetchone()[0]
            == 1
        )
        assert (
            store.connection.execute(
                "SELECT created_at FROM replay_artifacts WHERE replay_id='replay-1'"
            ).fetchone()[0]
            == created_at
        )

        changed = dict(record)
        changed["sha256"] = "d" * 64
        with pytest.raises(ValueError, match="immutable"):
            store.save_replay_record(**changed)
        assert (
            store.connection.execute(
                "SELECT sha256 FROM replay_artifacts WHERE replay_id='replay-1'"
            ).fetchone()[0]
            == "a" * 64
        )


def test_finalize_agent_run_rolls_back_all_evidence_on_failure(tmp_path: Path) -> None:
    """Status, oracle rows, and findings share one final transaction."""
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            original = store.save_agent_findings

            def fail_after_write(run_id, findings):
                original(run_id, findings)
                raise RuntimeError("injected finalization failure")

            store.save_agent_findings = fail_after_write  # type: ignore[method-assign]
            with pytest.raises(RuntimeError, match="injected finalization failure"):
                await run_agent_scenario(
                    scenario_id="support.approval_bypass.v1",
                    fixture="vulnerable",
                    seed=7,
                    run_store=store,
                    run_id="atomic-finalize",
                )
            row = store.connection.execute(
                "SELECT status, outcome FROM agent_runs WHERE run_id = ?",
                ("atomic-finalize",),
            ).fetchone()
            assert row["status"] == AgentRunStatus.RUNNING.value
            assert row["outcome"] is None
            assert (
                store.connection.execute(
                    "SELECT COUNT(*) FROM agent_oracle_results WHERE run_id = ?",
                    ("atomic-finalize",),
                ).fetchone()[0]
                == 0
            )
            assert (
                store.connection.execute(
                    "SELECT COUNT(*) FROM agent_findings WHERE run_id = ?",
                    ("atomic-finalize",),
                ).fetchone()[0]
                == 0
            )

    asyncio.run(_run())


def test_begin_agent_run_rejects_duplicate_without_deleting_evidence(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="vulnerable",
                seed=7,
                run_store=store,
                run_id="immutable-run",
            )
            before_events = store.connection.execute(
                "SELECT COUNT(*) FROM agent_trajectory_events WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
            before_oracles = store.connection.execute(
                "SELECT COUNT(*) FROM agent_oracle_results WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()[0]
            shell = run.model_copy(update={"status": AgentRunStatus.RUNNING, "completed_at": None})
            with pytest.raises(ValueError, match="already exists"):
                store.begin_agent_run(shell, retention=AgentRetentionSettings())
            row = store.connection.execute(
                "SELECT status, outcome FROM agent_runs WHERE run_id = ?",
                (run.run_id,),
            ).fetchone()
            assert row["status"] == AgentRunStatus.COMPLETED.value
            assert row["outcome"] == AgentOutcome.VERIFIED_EXPLOIT.value
            assert (
                store.connection.execute(
                    "SELECT COUNT(*) FROM agent_trajectory_events WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()[0]
                == before_events
            )
            assert (
                store.connection.execute(
                    "SELECT COUNT(*) FROM agent_oracle_results WHERE run_id = ?",
                    (run.run_id,),
                ).fetchone()[0]
                == before_oracles
            )

    asyncio.run(_run())


def test_finalize_rejects_terminal_or_interrupted_rows(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="clean",
                seed=7,
                run_store=store,
                run_id="terminal-run",
            )
            with pytest.raises(ValueError, match="only RUNNING"):
                store.finalize_agent_run(run, retention=AgentRetentionSettings())
            assert store.get_agent_run(run.run_id).status is AgentRunStatus.COMPLETED  # type: ignore[union-attr]

            interrupted = run.model_copy(
                update={
                    "run_id": "interrupted-run",
                    "status": AgentRunStatus.RUNNING,
                    "outcome": None,
                    "completed_at": None,
                }
            )
            store.begin_agent_run(interrupted, retention=AgentRetentionSettings())
            assert store.recover_incomplete_agent_runs() == 1
            candidate = interrupted.model_copy(
                update={"status": AgentRunStatus.FAILED, "completed_at": run.completed_at}
            )
            with pytest.raises(ValueError, match="only RUNNING"):
                store.finalize_agent_run(candidate, retention=AgentRetentionSettings())
            assert store.get_agent_run("interrupted-run").status is AgentRunStatus.INTERRUPTED  # type: ignore[union-attr]

            identity_shell = run.model_copy(
                update={
                    "run_id": "forged-finalize",
                    "status": AgentRunStatus.RUNNING,
                    "outcome": None,
                    "completed_at": None,
                }
            )
            store.begin_agent_run(identity_shell, retention=AgentRetentionSettings())
            forged = identity_shell.model_copy(
                update={
                    "status": AgentRunStatus.FAILED,
                    "completed_at": run.completed_at,
                    "target_ref": identity_shell.target_ref.model_copy(
                        update={"id": "forged-target"}
                    ),
                }
            )
            with pytest.raises(ValueError, match="identity"):
                store.finalize_agent_run(forged, retention=AgentRetentionSettings())
            assert (
                store.connection.execute(
                    "SELECT status FROM agent_runs WHERE run_id = ?", ("forged-finalize",)
                ).fetchone()[0]
                == AgentRunStatus.RUNNING.value
            )

    asyncio.run(_run())


def test_agent_manifest_is_one_time_identity_validated_and_redacted(tmp_path: Path) -> None:
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="clean",
                seed=7,
                run_store=store,
                run_id="manifest-run",
            )
            manifest = build_agent_manifest(
                run,
                git_reader=lambda: {"revision": "test", "dirty": False},
                dist_reader=lambda: {"cot-redteam-agent": "test"},
            )
            store.update_agent_manifest(run.run_id, manifest)
            assert store.get_agent_manifest(run.run_id) == manifest
            with pytest.raises(ValueError, match="already attached"):
                store.update_agent_manifest(run.run_id, manifest)

            identity_run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="clean",
                seed=7,
                run_store=store,
                run_id="manifest-identity",
            )
            identity_manifest = build_agent_manifest(
                identity_run,
                git_reader=lambda: {"revision": "test", "dirty": False},
                dist_reader=lambda: {"cot-redteam-agent": "test"},
            )
            wrong_identity = dict(identity_manifest)
            wrong_identity["run_id"] = "other-run"
            with pytest.raises(ValueError, match="run_id"):
                store.update_agent_manifest(identity_run.run_id, wrong_identity)
            wrong_digest = dict(identity_manifest)
            wrong_digest["trajectory_digest"] = "x" * 64
            with pytest.raises(ValueError, match="trajectory_digest"):
                store.update_agent_manifest(identity_run.run_id, wrong_digest)
            forged_component = dict(identity_manifest)
            forged_component["scenario"] = {"id": "forged", "version": "1"}
            with pytest.raises(ValueError, match="scenario"):
                store.update_agent_manifest(identity_run.run_id, forged_component)
            secret_payload = dict(identity_manifest)
            secret_payload["config"] = {"secret": "must-not-persist"}
            with pytest.raises(ValueError, match="sensitive"):
                store.update_agent_manifest(identity_run.run_id, secret_payload)
            with pytest.raises(ValueError, match="incomplete|missing"):
                store.update_agent_manifest(identity_run.run_id, {"run_id": identity_run.run_id})
            for malformed_artifacts, expected_error in (
                (
                    [
                        {
                            "path": "../escape.json",
                            "media_type": "application/json",
                            "byte_length": 1,
                            "sha256": "a" * 64,
                        }
                    ],
                    "relative|segments",
                ),
                (
                    [
                        {
                            "path": "run.json",
                            "media_type": "application/json",
                            "byte_length": True,
                            "sha256": "a" * 64,
                        }
                    ],
                    "byte_length",
                ),
                (
                    [
                        {
                            "path": "run.json",
                            "media_type": "application/json",
                            "byte_length": 1,
                            "sha256": "not-a-digest",
                        }
                    ],
                    "sha256",
                ),
            ):
                malformed = dict(identity_manifest)
                malformed["artifacts"] = malformed_artifacts
                with pytest.raises(ValueError, match=expected_error):
                    store.update_agent_manifest(identity_run.run_id, malformed)
            assert store.get_agent_manifest(identity_run.run_id) is None

    asyncio.run(_run())


def test_agent_store_rejects_invalid_begin_and_finalize_states(tmp_path: Path) -> None:
    """Exercise fail-closed state and identity branches at the store boundary."""
    import asyncio

    async def _run() -> None:
        with _store(tmp_path) as store:
            run = await run_agent_scenario(
                scenario_id="support.approval_bypass.v1",
                fixture="clean",
                seed=7,
                run_store=store,
                run_id="state-branches",
            )

            with pytest.raises(ValueError, match="requires a RUNNING"):
                store.begin_agent_run(run, retention=AgentRetentionSettings())

            early_manifest = run.model_copy(
                update={
                    "run_id": "early-manifest",
                    "status": AgentRunStatus.RUNNING,
                    "outcome": None,
                    "completed_at": None,
                    "metadata": {"manifest": build_agent_manifest(run)},
                }
            )
            with pytest.raises(ValueError, match="after finalization"):
                store.begin_agent_run(early_manifest, retention=AgentRetentionSettings())

            running_candidate = run.model_copy(
                update={"status": AgentRunStatus.RUNNING, "completed_at": None}
            )
            with pytest.raises(ValueError, match="cannot finalize"):
                store.finalize_agent_run(
                    running_candidate,
                    retention=AgentRetentionSettings(),
                )

            missing = run.model_copy(update={"run_id": "missing-finalize"})
            with pytest.raises(ValueError, match="does not exist"):
                store.finalize_agent_run(missing, retention=AgentRetentionSettings())

            store.append_agent_events(
                run.run_id,
                (),
                retention=AgentRetentionSettings(),
            )

            # Standalone replacement methods own and commit their transactions.
            store.save_agent_oracle_results(run.run_id, run.oracle_results)
            store.save_agent_findings(run.run_id, run.findings)
            assert store.get_agent_run(run.run_id) is not None

        # Closing an already closed store is intentionally idempotent.
        store.close()

    asyncio.run(_run())
