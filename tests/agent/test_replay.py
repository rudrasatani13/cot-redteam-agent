"""Replay artifact build/load and deterministic replay tests."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from cot_redteam.agent.api import run_agent_scenario, save_replay_artifact
from cot_redteam.agent.config import AgentRetentionSettings, AgentSecuritySettings
from cot_redteam.agent.replay import (
    ReplayArtifactV1,
    ReplayError,
    ReplayResult,
    build_replay_artifact,
    compute_payload_digest,
    load_regression_suite,
    load_replay,
    run_regression_suite,
    run_replay,
)
from cot_redteam.agent.scenarios.support import support_fixture
from cot_redteam.storage.artifacts import ArtifactStore
from cot_redteam.storage.sqlite import SQLiteRunStore

CHECKED_IN_ARTIFACT = Path("tests/fixtures/security_regressions/exploit-indirect-injection.json")


def _checked_in_artifact() -> ReplayArtifactV1:
    return load_replay(CHECKED_IN_ARTIFACT)


def _mutate_artifact(artifact: ReplayArtifactV1, **updates: object) -> ReplayArtifactV1:
    data = artifact.model_dump(mode="python")
    for field, value in updates.items():
        data[field] = value
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    return ReplayArtifactV1.model_validate(data)


async def _save_exploit(tmp_path: Path) -> tuple[Path, str]:
    """Run a vulnerable fixture and save its replay artifact."""
    settings = AgentSecuritySettings()
    with SQLiteRunStore(tmp_path / "agent.db") as store:
        run = await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="vulnerable",
            seed=7,
            run_store=store,
        )
        artifact_store = ArtifactStore(tmp_path / "artifacts")
        saved = save_replay_artifact(
            run,
            fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
            settings=settings,
            artifact_store=artifact_store,
            run_store=store,
        )
        assert saved is not None
        path, checksum = saved
        return Path(path), checksum


def test_verified_exploit_creates_replay_json_and_detached_checksum(
    tmp_path: Path,
) -> None:
    asyncio.run(_save_exploit(tmp_path))
    replay_path = tmp_path / "artifacts"
    replay_files = list(replay_path.glob("*/replay.json"))
    assert len(replay_files) == 1
    checksum_files = list(replay_path.glob("*/replay.json.sha256"))
    assert len(checksum_files) == 1
    content = json.loads(replay_files[0].read_text(encoding="utf-8"))
    assert content["schema_version"] == 1
    assert content["original_outcome"] == "verified_exploit"
    assert content["checksums"]["payload_sha256"]
    # Detached checksum matches the file bytes.
    detached = checksum_files[0].read_text(encoding="utf-8").split()[0]
    import hashlib

    actual = hashlib.sha256(replay_files[0].read_bytes()).hexdigest()
    assert detached == actual


def test_exact_replay_reproduces_exploit(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact)

    result = asyncio.run(_replay())
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_exact_replay_rejects_oracle_drift_with_matching_trajectory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A matching trajectory cannot hide changed oracle verdict/evidence."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)
    import cot_redteam.agent.api as agent_api
    from cot_redteam.agent.types import OracleVerdict

    original = agent_api.run_agent_scenario

    async def changed_oracle(**kwargs: object):
        run = await original(**kwargs)  # type: ignore[arg-type]
        first = run.oracle_results[0].model_copy(
            update={
                "verdict": OracleVerdict.INVARIANT_HELD,
                "summary": "oracle result changed without a trajectory change",
                "evidence_event_ids": ("gw-call-0-action",),
            }
        )
        return run.model_copy(update={"oracle_results": (first, *run.oracle_results[1:])})

    monkeypatch.setattr(agent_api, "run_agent_scenario", changed_oracle)
    result = asyncio.run(run_replay(artifact))

    assert result.status == "inconclusive"
    assert result.exit_code == 3
    assert "oracle" in result.message


def test_exact_replay_does_not_map_matching_trajectory_invariant_to_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A checked legacy artifact with changed outcome is never exit 0."""
    artifact = _checked_in_artifact()
    import cot_redteam.agent.api as agent_api
    from cot_redteam.agent.types import AgentOutcome

    original = agent_api.run_agent_scenario

    async def changed_outcome(**kwargs: object):
        run = await original(**kwargs)  # type: ignore[arg-type]
        return run.model_copy(update={"outcome": AgentOutcome.INVARIANT_HELD})

    monkeypatch.setattr(agent_api, "run_agent_scenario", changed_outcome)
    result = asyncio.run(run_replay(artifact))

    assert result.status == "inconclusive"
    assert result.exit_code == 3


def test_exact_replay_requires_verified_original_outcome() -> None:
    artifact = _mutate_artifact(_checked_in_artifact(), original_outcome="invariant_held")

    with pytest.raises(ReplayError, match="original_outcome"):
        asyncio.run(run_replay(artifact))


@pytest.mark.parametrize(
    "target",
    [
        {
            "id": "scripted",
            "original_version": "1",
            "family": "vulnerable",
            "unexpected": "field",
        },
        {"id": "scripted", "original_version": "1"},
        {"id": " ", "original_version": "1", "family": "vulnerable"},
    ],
)
def test_replay_rejects_noncanonical_target_mapping(target: dict[str, str]) -> None:
    artifact = _mutate_artifact(_checked_in_artifact(), target=target)

    with pytest.raises(ReplayError, match="target metadata"):
        asyncio.run(run_replay(artifact))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("world_fixture_digest", "A" * 64),
        ("world_fixture_digest", "0" * 63),
        ("trajectory_digest", "B" * 64),
        ("trajectory_digest", "0" * 65),
        ("oracle_results_digest", "C" * 64),
        ("oracle_results_digest", "0" * 65),
    ],
)
def test_replay_rejects_noncanonical_digests(field: str, value: str) -> None:
    artifact = _mutate_artifact(_checked_in_artifact(), **{field: value})

    with pytest.raises(ReplayError, match=field):
        asyncio.run(run_replay(artifact))


def test_exact_replay_applies_recorded_budgets_when_settings_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        budget_configuration={
            "max_requests": 1,
            "max_input_tokens": None,
            "max_output_tokens": None,
            "max_elapsed_seconds": None,
            "max_estimated_cost": None,
        },
    )
    import cot_redteam.agent.api as agent_api

    original = agent_api.run_agent_scenario
    seen: dict[str, AgentSecuritySettings | None] = {}

    async def capture(**kwargs: object):
        seen["settings"] = kwargs.get("settings")  # type: ignore[assignment]
        return await original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_api, "run_agent_scenario", capture)
    asyncio.run(run_replay(artifact))

    assert seen["settings"] is not None
    assert seen["settings"].budgets.max_requests == 1  # type: ignore[union-attr]


def test_exact_replay_rejects_different_caller_budgets() -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        budget_configuration={
            "max_requests": 1,
            "max_input_tokens": None,
            "max_output_tokens": None,
            "max_elapsed_seconds": None,
            "max_estimated_cost": None,
        },
    )

    with pytest.raises(ReplayError, match="budget_configuration"):
        asyncio.run(run_replay(artifact, settings=AgentSecuritySettings()))


def test_regression_override_uses_caller_budgets() -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        budget_configuration={
            "max_requests": 1,
            "max_input_tokens": None,
            "max_output_tokens": None,
            "max_elapsed_seconds": None,
            "max_estimated_cost": None,
        },
    )

    result = asyncio.run(run_replay(artifact, fixture="patched"))
    assert result.run is not None
    assert result.run.outcome is not None


def test_replay_rejects_non_strict_budget_values() -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        budget_configuration={"max_requests": "1"},
    )

    with pytest.raises(ReplayError, match="budget_configuration"):
        asyncio.run(run_replay(artifact))


def test_exact_replay_uses_embedded_seed_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        sanitized_inputs={"seed": 7},
    )
    import cot_redteam.agent.api as agent_api

    original = agent_api.run_agent_scenario
    seen: dict[str, int] = {}

    async def capture(**kwargs: object):
        seen["seed"] = kwargs["seed"]  # type: ignore[assignment]
        return await original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_api, "run_agent_scenario", capture)
    asyncio.run(run_replay(artifact))

    assert seen["seed"] == 7


def test_exact_replay_rejects_nonmatching_seed_override() -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        sanitized_inputs={"seed": 7},
    )

    with pytest.raises(ReplayError, match="exact replay seed"):
        asyncio.run(run_replay(artifact, seed=42))


def test_replay_rejects_non_integer_embedded_seed() -> None:
    artifact = _mutate_artifact(
        _checked_in_artifact(),
        sanitized_inputs={"seed": "7"},
    )

    with pytest.raises(ReplayError, match="replay seed"):
        asyncio.run(run_replay(artifact))


def test_build_replay_artifact_records_validated_seed() -> None:
    async def _run():
        return await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="vulnerable",
            seed=7,
        )

    run = asyncio.run(_run())
    run_with_seed = run.model_copy(update={"metadata": {"seed": 7}})
    artifact = build_replay_artifact(
        run_with_seed,
        fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
        budget_configuration=AgentSecuritySettings().budgets.model_dump(mode="python"),
    )
    assert artifact["sanitized_inputs"] == {"seed": 7}


def test_build_replay_artifact_rejects_invalid_seed() -> None:
    async def _run():
        return await run_agent_scenario(
            scenario_id="support.indirect_prompt_injection.v1",
            fixture="vulnerable",
            seed=7,
        )

    run = asyncio.run(_run())
    run_with_seed = run.model_copy(update={"metadata": {"seed": "7"}})
    with pytest.raises(ReplayError, match="replay seed"):
        build_replay_artifact(
            run_with_seed,
            fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
            budget_configuration=AgentSecuritySettings().budgets.model_dump(mode="python"),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "scenario",
            {"id": "support.indirect_prompt_injection.v1", "version": "99"},
            "scenario",
        ),
        ("attack", {"id": "scripted:vulnerable", "version": "99"}, "attack"),
        (
            "target",
            {"id": "scripted", "original_version": "99", "family": "vulnerable"},
            "target",
        ),
        (
            "oracles",
            [
                {"id": "canary_reached_sink", "version": "99"},
                {"id": "unauthorized_tool_call", "version": "1"},
            ],
            "oracle",
        ),
        ("package", {"cot-redteam-agent": "99.0.0"}, "package"),
        ("source", {"revision": "0" * 40, "dirty": False}, "source"),
    ],
)
def test_exact_replay_rejects_incompatible_contracts(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    """A valid checksum does not make incompatible replay metadata usable."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data[field] = value
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    with pytest.raises(ReplayError, match=message):
        asyncio.run(run_replay(artifact))


def test_patched_regression_holds(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact, fixture="patched")

    result = asyncio.run(_replay())
    assert result.status == "invariant_held"
    assert result.exit_code == 0


def test_target_override_does_not_waive_original_fixture_contract(
    tmp_path: Path,
) -> None:
    """Regression target overrides still verify the saved world fixture."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["world_fixture_digest"] = "0" * 64
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    with pytest.raises(ReplayError, match="world fixture digest"):
        asyncio.run(run_replay(artifact, fixture="patched"))


def test_target_override_allows_provenance_drift(tmp_path: Path) -> None:
    """Regression artifacts remain usable after package/source updates."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["package"] = {"cot-redteam-agent": "99.0.0"}
    data["source"] = {"revision": "0" * 40, "dirty": False}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    result = asyncio.run(run_replay(artifact, fixture="patched"))
    assert result.status == "invariant_held"
    assert result.exit_code == 0


def test_target_override_does_not_waive_package_contract_id(
    tmp_path: Path,
) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["package"] = {"unrelated-package": "99.0.0"}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    with pytest.raises(ReplayError, match="package contract IDs"):
        asyncio.run(run_replay(artifact, fixture="patched"))


def test_exact_replay_allows_source_unavailable_on_both_sides(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clean wheels outside Git can replay when both provenance records are null."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["source"] = {"revision": None, "dirty": None}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)
    monkeypatch.setattr(
        "cot_redteam.agent.replay._git_source",
        lambda: {"revision": None, "dirty": None},
    )

    result = asyncio.run(run_replay(artifact))
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_exact_replay_allows_known_artifact_with_runtime_source_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wheel runtime may lack Git while the saved artifact has provenance."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)
    monkeypatch.setattr(
        "cot_redteam.agent.replay._git_source",
        lambda: {"revision": None, "dirty": None},
    )

    result = asyncio.run(run_replay(artifact))
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_exact_replay_rejects_missing_artifact_source_when_runtime_is_known(
    tmp_path: Path,
) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["source"] = {"revision": None, "dirty": None}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    with pytest.raises(ReplayError, match="artifact provenance unavailable"):
        asyncio.run(run_replay(artifact))


def test_exact_replay_rejects_malformed_artifact_source(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["source"] = {"revision": None, "dirty": False}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    with pytest.raises(ReplayError, match="invalid artifact provenance"):
        asyncio.run(run_replay(artifact))


def test_exact_replay_accepts_ancestor_source_revision(tmp_path: Path) -> None:
    """Compatible commits retain exact replay; trajectory digest remains authoritative."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["source"] = {
        "revision": "a28db61975887ebced8c8caad38b02298f786c2f",
        "dirty": False,
    }
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    result = asyncio.run(run_replay(artifact))
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_exact_replay_rejects_unrelated_source_revision(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["source"] = {"revision": "0" * 40, "dirty": False}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    with pytest.raises(ReplayError, match="not an ancestor"):
        asyncio.run(run_replay(artifact))


def test_exact_replay_ignores_dirty_marker_drift(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    original = load_replay(path)
    data = original.model_dump(mode="python")
    data["source"] = {
        "revision": original.source["revision"],
        "dirty": not bool(original.source["dirty"]),
    }
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    result = asyncio.run(run_replay(artifact))
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_clean_regression_holds(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact, fixture="clean")

    result = asyncio.run(_replay())
    assert result.status == "invariant_held"
    assert result.exit_code == 0


def test_corrupt_checksum_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["trajectory_digest"] = "f" * 64
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReplayError, match="checksum"):
        load_replay(corrupt)


def test_unknown_schema_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["schema_version"] = 99
    corrupt = tmp_path / "schema.json"
    corrupt.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ReplayError, match="schema"):
        load_replay(corrupt)


def test_truncated_json_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    truncated = tmp_path / "truncated.json"
    truncated.write_text(Path(path).read_text(encoding="utf-8")[:200], encoding="utf-8")
    with pytest.raises(ReplayError, match="parse"):
        load_replay(truncated)


def test_unknown_scenario_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["scenario"] = {"id": "support.does_not_exist.v1", "version": "1"}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    async def _replay() -> None:
        await run_replay(artifact)

    with pytest.raises(ReplayError, match="unknown scenario"):
        asyncio.run(_replay())


def test_unknown_fixture_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = load_replay(path)

    async def _replay() -> None:
        await run_replay(artifact, fixture="nonexistent_fixture")

    with pytest.raises(ReplayError, match="fixture"):
        asyncio.run(_replay())


def test_unknown_world_version_rejected(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["world"] = {"id": "support", "version": "support-world/99"}
    data["checksums"]["payload_sha256"] = compute_payload_digest(data)
    artifact = ReplayArtifactV1.model_validate(data)

    async def _replay() -> None:
        await run_replay(artifact)

    with pytest.raises(ReplayError, match="incompatible world"):
        asyncio.run(_replay())


def test_result_mapping_error_and_inconclusive_are_partial() -> None:
    from cot_redteam.agent.types import AgentOutcome

    class _FakeRun:
        outcome = AgentOutcome.ERROR
        error = "boom"
        trajectory = None

    result = ReplayResult.from_run(
        _FakeRun(),  # type: ignore[arg-type]
        original_outcome="verified_exploit",
    )
    assert result.exit_code == 3
    assert result.status == "error"

    class _InconclusiveRun:
        outcome = AgentOutcome.INCONCLUSIVE
        error = None
        trajectory = None

    result2 = ReplayResult.from_run(
        _InconclusiveRun(),  # type: ignore[arg-type]
        original_outcome="verified_exploit",
    )
    assert result2.exit_code == 3
    assert result2.status == "inconclusive"


def test_regression_suite_aggregation(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    import shutil

    shutil.copy(path, suite_dir / "exploit-1.json")
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "exploit-1.json",
                        "target": "patched",
                        "expected": "INVARIANT_HELD",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    async def _run() -> None:
        report = await run_regression_suite(suite_dir)
        assert report.exit_code == 0  # patched target holds
        entry, result = report.entries[0]
        assert result.status == "regression_matched"

    asyncio.run(_run())


def test_suite_missing_artifact_rejected(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "missing.json",
                        "target": "patched",
                        "expected": "INVARIANT_HELD",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReplayError, match="missing"):
        load_regression_suite(suite_dir)


def test_replay_artifact_has_no_executable_content(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    blob = json.dumps(data)
    for marker in ("__import__", "pickle", "eval(", "exec(", "shell", "subprocess"):
        assert marker not in blob


# -- retention inputs are recorded and applied -------------------------------


async def _save_exploit_with_retention(
    tmp_path: Path,
    *,
    retain_final_response: bool,
) -> Path:
    settings = AgentSecuritySettings(
        retention=AgentRetentionSettings(retain_final_response=retain_final_response)
    )
    run = await run_agent_scenario(
        scenario_id="support.indirect_prompt_injection.v1",
        fixture="vulnerable",
        seed=7,
        settings=settings,
    )
    assert run.outcome is not None and run.outcome.value == "verified_exploit"
    artifact_store = ArtifactStore(tmp_path / "artifacts")
    saved = save_replay_artifact(
        run,
        fixture=support_fixture("support.indirect_prompt_injection.v1", "vulnerable"),
        settings=settings,
        artifact_store=artifact_store,
    )
    assert saved is not None
    return Path(saved[0])


def test_replay_artifact_records_load_bearing_retention(tmp_path: Path) -> None:
    path = asyncio.run(_save_exploit_with_retention(tmp_path, retain_final_response=True))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["sanitized_inputs"]["retention"] == {"retain_final_response": True}


def test_exact_replay_applies_recorded_retention(tmp_path: Path) -> None:
    """Replaying an artifact saved with retain_final_response=true under
    default (None) settings must reproduce the same trajectory digest."""
    path = asyncio.run(_save_exploit_with_retention(tmp_path, retain_final_response=True))
    artifact = load_replay(path)

    async def _replay() -> ReplayResult:
        return await run_replay(artifact)

    result = asyncio.run(_replay())
    assert result.status == "exploit_reproduced"
    assert result.exit_code == 1


def test_exact_replay_rejects_conflicting_caller_retention(tmp_path: Path) -> None:
    path = asyncio.run(_save_exploit_with_retention(tmp_path, retain_final_response=True))
    artifact = load_replay(path)

    with pytest.raises(ReplayError, match="retention"):
        asyncio.run(run_replay(artifact, settings=AgentSecuritySettings()))


def test_replay_rejects_unknown_retention_fields(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = _mutate_artifact(
        load_replay(path),
        sanitized_inputs={"seed": 7, "retention": {"retain_final_response": True, "x": 1}},
    )
    with pytest.raises(ReplayError, match="unknown fields"):
        asyncio.run(run_replay(artifact))


def test_replay_rejects_non_boolean_retention_flag(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    artifact = _mutate_artifact(
        load_replay(path),
        sanitized_inputs={"seed": 7, "retention": {"retain_final_response": "yes"}},
    )
    with pytest.raises(ReplayError, match="must be a boolean"):
        asyncio.run(run_replay(artifact))


# -- detached checksum and duplicate JSON keys -------------------------------


def test_load_replay_accepts_matching_detached_checksum(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    copied = tmp_path / "copied.json"
    copied.write_bytes(Path(path).read_bytes())
    Path(str(copied) + ".sha256").write_text(Path(str(path) + ".sha256").read_text())
    assert load_replay(copied).replay_id == load_replay(path).replay_id


def test_load_replay_rejects_detached_checksum_mismatch(tmp_path: Path) -> None:
    """Re-serialized (whitespace-only) content keeps the payload checksum
    valid but changes the raw bytes: the detached checksum must catch it."""
    path, _ = asyncio.run(_save_exploit(tmp_path))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    reformatted = tmp_path / "reformatted.json"
    reformatted.write_text(json.dumps(data, indent=4), encoding="utf-8")
    Path(str(reformatted) + ".sha256").write_text(
        Path(str(path) + ".sha256").read_text(encoding="utf-8")
    )
    with pytest.raises(ReplayError, match="detached replay checksum mismatch"):
        load_replay(reformatted)


def test_load_replay_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    text = Path(path).read_text(encoding="utf-8")
    duplicated = tmp_path / "duplicated.json"
    duplicated.write_text(text.replace("{", '{"replay_id": "smuggled", ', 1), encoding="utf-8")
    with pytest.raises(ReplayError, match="duplicate JSON object key"):
        load_replay(duplicated)


# -- regression suite path containment and seeds ------------------------------


def _write_suite(tmp_path: Path, entries: list[dict[str, str]]) -> Path:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir(exist_ok=True)
    (suite_dir / "suite.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return suite_dir


@pytest.mark.parametrize(
    "artifact_ref",
    ["../exploit.json", "nested/../../exploit.json", "/etc/passwd", "./"],
)
def test_regression_suite_rejects_artifact_path_escape(tmp_path: Path, artifact_ref: str) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    import shutil

    shutil.copy(path, suite_dir / "exploit.json")
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {"artifact": artifact_ref, "target": "patched", "expected": "INVARIANT_HELD"}
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReplayError, match="relative|traverse|escape|control"):
        load_regression_suite(suite_dir)


def test_regression_suite_rejects_control_characters_in_artifact_path(
    tmp_path: Path,
) -> None:
    suite_dir = _write_suite(
        tmp_path,
        [{"artifact": "exploit\n.json", "target": "patched", "expected": "INVARIANT_HELD"}],
    )
    with pytest.raises(ReplayError, match="control characters"):
        load_regression_suite(suite_dir)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("vulnerable", "INVARIANT_HELD"),
        ("vulnerable", "INCONCLUSIVE"),
        ("clean", "VERIFIED_EXPLOIT"),
        ("patched", "ERROR"),
    ],
)
def test_regression_suite_rejects_invalid_expectation_combos(
    tmp_path: Path, target: str, expected: str
) -> None:
    suite_dir = _write_suite(
        tmp_path, [{"artifact": "exploit.json", "target": target, "expected": expected}]
    )
    with pytest.raises(ReplayError, match="invalid regression expectation"):
        load_regression_suite(suite_dir)


def test_regression_suite_honors_recorded_artifact_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """seed=None (the default) replays each artifact with ITS recorded seed."""
    path, _ = asyncio.run(_save_exploit(tmp_path))  # saved with seed=7
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    import shutil

    shutil.copy(path, suite_dir / "exploit.json")
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "exploit.json",
                        "target": "vulnerable",
                        "expected": "VERIFIED_EXPLOIT",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    import cot_redteam.agent.api as agent_api

    original = agent_api.run_agent_scenario
    seen: dict[str, int] = {}

    async def capture(**kwargs: object):
        seen["seed"] = kwargs["seed"]  # type: ignore[assignment]
        return await original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_api, "run_agent_scenario", capture)
    report = asyncio.run(run_regression_suite(suite_dir))
    assert seen["seed"] == 7
    assert report.exit_code == 0  # artifact seed reproduces the exploit


def test_regression_suite_explicit_seed_overrides_artifact_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, _ = asyncio.run(_save_exploit(tmp_path))  # recorded seed=7
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    import shutil

    shutil.copy(path, suite_dir / "exploit.json")
    (suite_dir / "suite.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "artifact": "exploit.json",
                        "target": "vulnerable",
                        "expected": "VERIFIED_EXPLOIT",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    import cot_redteam.agent.api as agent_api

    original = agent_api.run_agent_scenario
    seen: dict[str, int] = {}

    async def capture(**kwargs: object):
        seen["seed"] = kwargs["seed"]  # type: ignore[assignment]
        return await original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_api, "run_agent_scenario", capture)
    asyncio.run(run_regression_suite(suite_dir, seed=99))
    assert seen["seed"] == 99
