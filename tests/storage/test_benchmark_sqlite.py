from __future__ import annotations

from pathlib import Path

from cot_redteam.storage.sqlite import SQLiteRunStore
from tests.benchmark.test_results import benchmark_run_result


def test_benchmark_roundtrip_and_idempotent_replace(tmp_path: Path) -> None:
    run = benchmark_run_result(tmp_path)
    with SQLiteRunStore(tmp_path / "benchmark.db") as store:
        store.save_benchmark(run)
        store.save_benchmark(run)
        loaded = store.get_benchmark(run.run_id)

        assert loaded is not None
        assert loaded == run
        assert store.connection.execute("SELECT COUNT(*) FROM benchmark_trials").fetchone()[0] == 1
        assert (
            store.connection.execute("SELECT COUNT(*) FROM benchmark_messages").fetchone()[0] == 3
        )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM benchmark_scorer_outcomes"
        ).fetchone()[0] == len(run.trials[0].scoring.outcomes)


def test_v2_migration_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "benchmark.db"
    with SQLiteRunStore(path):
        pass
    with SQLiteRunStore(path) as store:
        versions = [
            row[0]
            for row in store.connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
    # Migration 3 (agent tables) is additive; reopening stays idempotent.
    assert versions == [1, 2, 3]
