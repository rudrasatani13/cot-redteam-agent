"""Checksummed replay artifacts and the deterministic replay engine.

A replay artifact is declarative data, never executable code: exact
scenario/fixture/world/oracle versions, sanitized inputs, fixture and
trajectory digests, and budget configuration. Replaying reconstructs the
deterministic world and target through the fixed built-in registry,
validates all digests/checksums, then runs the agent engine again.

Replay outcome semantics:
- exit 1: a verified exploit reproduces;
- exit 0: the security invariant holds;
- exit 3: environment/run/oracle inconclusive or error;
- exit 2: corrupt or incompatible artifact (never guessed compatibility).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.scenarios.support import support_fixture, support_scenario
from cot_redteam.agent.types import (
    REPLAY_SCHEMA_VERSION,
    AgentOutcome,
    AgentRun,
    VersionedRef,
)
from cot_redteam.core.errors import CotRedTeamError
from cot_redteam.core.serialization import canonical_json, sha256_text

MAX_REPLAY_BYTES = 16 * 1024 * 1024

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2
EXIT_PARTIAL = 3


class ReplayError(CotRedTeamError):
    """Corrupt, oversized, or incompatible replay artifact."""


class ReplayArtifactV1(BaseModel):
    """Strict declarative replay artifact. No executable content accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    replay_id: str
    scenario: VersionedRef
    attack: VersionedRef
    target: dict[str, str] = Field(description="target id/version/family (family = fixture name)")
    world: VersionedRef
    oracles: tuple[VersionedRef, ...] = ()
    sanitized_inputs: dict[str, Any] = Field(default_factory=dict)
    world_fixture_digest: str
    original_outcome: str
    trajectory_digest: str
    budget_configuration: dict[str, Any] = Field(default_factory=dict)
    package: dict[str, str] = Field(default_factory=dict)
    source: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    checksums: dict[str, str] = Field(default_factory=dict)

    @property
    def target_family(self) -> str:
        return str(self.target.get("family") or "")


def _package_version() -> dict[str, str]:
    try:
        from importlib.metadata import version

        return {"cot-redteam-agent": version("cot-redteam-agent")}
    except Exception:
        from cot_redteam import __version__

        return {"cot-redteam-agent": __version__}


def _git_source() -> dict[str, Any]:
    import subprocess

    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL, text=True
            ).strip()
        )
        return {"revision": rev, "dirty": dirty}
    except Exception:
        return {"revision": None, "dirty": None}


def build_replay_artifact(
    run: AgentRun,
    *,
    fixture: Any,
    budget_configuration: dict[str, Any],
    settings: AgentSecuritySettings | None = None,
) -> dict[str, Any]:
    """Build a strict replay artifact dict for a verified-exploit run."""
    del settings
    base = {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "replay_id": f"replay-{run.run_id}",
        "scenario": run.scenario_ref.model_dump(mode="python"),
        "attack": run.attack_ref.model_dump(mode="python"),
        "target": {
            "id": run.target_ref.id,
            "original_version": run.target_ref.version,
            "family": fixture.fixture,
        },
        "world": run.world_ref.model_dump(mode="python"),
        "oracles": [
            {"id": result.oracle_id, "version": result.oracle_version}
            for result in run.oracle_results
        ],
        "sanitized_inputs": {},
        "world_fixture_digest": fixture.digest,
        "original_outcome": run.outcome.value if run.outcome else "error",
        "trajectory_digest": run.trajectory.digest,
        "budget_configuration": budget_configuration,
        "package": _package_version(),
        "source": _git_source(),
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "checksums": {},
    }
    base["checksums"]["payload_sha256"] = compute_payload_digest(base)
    return base


def compute_payload_digest(artifact: dict[str, Any]) -> str:
    """Checksum over the artifact with the checksums block omitted (no
    self-reference)."""
    payload = {key: value for key, value in artifact.items() if key != "checksums"}
    return sha256_text(canonical_json(payload))


def load_replay(path: str | Path) -> ReplayArtifactV1:
    """Size-bounded, strict, checksum-validated replay loading."""
    artifact_path = Path(path)
    try:
        size = artifact_path.stat().st_size
    except OSError as exc:
        raise ReplayError(f"cannot stat replay artifact {artifact_path}: {exc}") from exc
    if size > MAX_REPLAY_BYTES:
        raise ReplayError(f"replay artifact exceeds {MAX_REPLAY_BYTES} bytes")
    try:
        raw = artifact_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayError(f"cannot parse replay artifact {artifact_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ReplayError("replay artifact root must be a JSON object")
    schema_version = data.get("schema_version")
    if schema_version != REPLAY_SCHEMA_VERSION:
        raise ReplayError(
            f"unsupported replay schema version {schema_version!r}; "
            f"expected {REPLAY_SCHEMA_VERSION}"
        )
    try:
        artifact = ReplayArtifactV1.model_validate(data)
    except Exception as exc:
        raise ReplayError(f"replay artifact is invalid: {exc}") from exc
    payload_digest = compute_payload_digest(data)
    if artifact.checksums.get("payload_sha256") != payload_digest:
        raise ReplayError("replay payload checksum mismatch")
    return artifact


@dataclass(frozen=True)
class ReplayResult:
    status: str
    exit_code: int
    message: str
    run: AgentRun | None = None

    @classmethod
    def from_run(
        cls,
        run: AgentRun,
        *,
        original_outcome: str,
    ) -> ReplayResult:
        if run.outcome is AgentOutcome.VERIFIED_EXPLOIT:
            status = "exploit_reproduced"
            exit_code = EXIT_FAILED
            message = "verified exploit reproduced"
        elif run.outcome is AgentOutcome.INVARIANT_HELD:
            status = "invariant_held"
            exit_code = EXIT_OK
            message = "security invariant held"
        elif run.outcome is AgentOutcome.INCONCLUSIVE:
            status = "inconclusive"
            exit_code = EXIT_PARTIAL
            message = "replay outcome inconclusive"
        else:
            status = "error"
            exit_code = EXIT_PARTIAL
            message = f"replay run errored: {run.error or 'unknown'}"
        return cls(status=status, exit_code=exit_code, message=message, run=run)


async def run_replay(
    artifact: ReplayArtifactV1,
    *,
    fixture: str | None = None,
    settings: AgentSecuritySettings | None = None,
    run_id: str | None = None,
    seed: int = 42,
) -> ReplayResult:
    """Replay a validated artifact deterministically.

    ``fixture`` overrides the replayed fixture (regression suites replay a
    saved exploit against a different target-under-test). Exact replays
    default to the artifact's original target family and validate the
    fixture digest.
    """
    scenario_id = artifact.scenario.id
    try:
        scenario = support_scenario(scenario_id)
    except CotRedTeamError as exc:
        raise ReplayError(f"unknown scenario {scenario_id!r}: {exc}") from exc
    target_family = fixture or artifact.target_family
    try:
        fixture_spec = support_fixture(scenario_id, target_family)
    except CotRedTeamError as exc:
        raise ReplayError(
            f"unknown fixture {target_family!r} for scenario {scenario_id!r}: {exc}"
        ) from exc
    exact = fixture is None
    if exact and fixture_spec.digest != artifact.world_fixture_digest:
        raise ReplayError(
            f"world fixture digest mismatch: artifact expects "
            f"{artifact.world_fixture_digest}, registry has {fixture_spec.digest}"
        )
    if artifact.world.id != scenario.world_id or artifact.world.version != scenario.world_version:
        raise ReplayError(
            f"incompatible world {artifact.world.id}/{artifact.world.version}; "
            f"scenario {scenario_id!r} requires {scenario.world_id}/{scenario.world_version}"
        )
    from cot_redteam.agent.api import run_agent_scenario

    run = await run_agent_scenario(
        scenario_id=scenario_id,
        fixture=target_family,
        settings=settings,
        run_id=run_id or f"replay-{artifact.replay_id}",
        seed=seed,
    )
    result = ReplayResult.from_run(run, original_outcome=artifact.original_outcome)
    if exact:
        if run.trajectory.digest != artifact.trajectory_digest:
            result = ReplayResult(
                status="inconclusive",
                exit_code=EXIT_PARTIAL,
                message=(
                    "replay trajectory digest differs from the artifact; "
                    "environment produced different semantics"
                ),
                run=run,
            )
        elif run.outcome is AgentOutcome.VERIFIED_EXPLOIT:
            result = ReplayResult(
                status="exploit_reproduced",
                exit_code=EXIT_FAILED,
                message="verified exploit reproduced deterministically",
                run=run,
            )
    return result


@dataclass(frozen=True)
class RegressionEntry:
    artifact: str
    target_fixture: str
    expected_outcome: str


@dataclass(frozen=True)
class RegressionSuite:
    schema_version: int
    entries: tuple[RegressionEntry, ...]


def load_regression_suite(suite_dir: str | Path) -> RegressionSuite:
    """Load a declarative regression suite (suite.json + replay artifacts)."""
    directory = Path(suite_dir)
    manifest_path = directory / "suite.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayError(f"cannot load regression suite {manifest_path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ReplayError("regression suite requires schema_version=1")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raise ReplayError("regression suite requires an entries list")
    entries: list[RegressionEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise ReplayError("regression entries must be objects")
        artifact = str(raw.get("artifact") or "")
        target = str(raw.get("target") or "")
        expected = str(raw.get("expected") or "")
        if not artifact or not target or not expected:
            raise ReplayError(f"incomplete regression entry: {raw!r}")
        artifact_path = directory / artifact
        if not artifact_path.exists():
            raise ReplayError(f"regression artifact missing: {artifact_path}")
        entries.append(
            RegressionEntry(artifact=artifact, target_fixture=target, expected_outcome=expected)
        )
    return RegressionSuite(schema_version=1, entries=tuple(entries))


@dataclass(frozen=True)
class RegressionReport:
    entries: tuple[tuple[RegressionEntry, ReplayResult], ...]

    @property
    def exit_code(self) -> int:
        """1 if any entry mismatches its expected outcome (or an exploit
        reproduces against a target expected to hold); 3 if any entry is
        incomplete/inconclusive/error; else 0."""
        reproduced = 0
        partial = 0
        for _entry, result in self.entries:
            if result.exit_code == EXIT_FAILED:
                reproduced += 1
            elif result.exit_code == EXIT_PARTIAL:
                partial += 1
        if reproduced:
            return EXIT_FAILED
        if partial:
            return EXIT_PARTIAL
        return EXIT_OK


async def run_regression_suite(
    suite_dir: str | Path,
    *,
    settings: AgentSecuritySettings | None = None,
    seed: int = 42,
) -> RegressionReport:
    suite = load_regression_suite(suite_dir)
    results: list[tuple[RegressionEntry, ReplayResult]] = []
    for entry in suite.entries:
        artifact = load_replay(Path(suite_dir) / entry.artifact)
        result = await run_replay(
            artifact,
            fixture=entry.target_fixture,
            settings=settings,
            seed=seed,
        )
        # Purely expectation-based: a mismatch is a failed regression, never
        # a silent pass; a matched expectation passes regardless of the raw
        # replay exit semantics. suite.json uses enum NAMES
        # (INVARIANT_HELD); outcomes expose values (invariant_held), so
        # compare case-insensitively against the enum name.
        expected = entry.expected_outcome.upper()
        actual = (
            result.run.outcome.name
            if result.run is not None and result.run.outcome is not None
            else None
        )
        if actual is None:
            result = ReplayResult(
                status="inconclusive",
                exit_code=EXIT_PARTIAL,
                message=f"no outcome produced: {result.message}",
                run=result.run,
            )
        elif actual != expected:
            result = ReplayResult(
                status="regression_mismatch",
                exit_code=EXIT_FAILED,
                message=(f"expected {expected}, got {actual} ({result.message})"),
                run=result.run,
            )
        elif result.exit_code == EXIT_PARTIAL:
            result = ReplayResult(
                status=result.status,
                exit_code=EXIT_PARTIAL,
                message=f"incomplete: {result.message}",
                run=result.run,
            )
        else:
            result = ReplayResult(
                status="regression_matched",
                exit_code=EXIT_OK,
                message=f"expected {expected} confirmed ({result.message})",
                run=result.run,
            )
        results.append((entry, result))
    return RegressionReport(entries=tuple(results))
