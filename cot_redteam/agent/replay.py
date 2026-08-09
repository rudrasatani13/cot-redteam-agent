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
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from cot_redteam.agent.config import AgentSecuritySettings
from cot_redteam.agent.oracles.support import support_oracle
from cot_redteam.agent.scenarios.support import support_fixture, support_scenario
from cot_redteam.agent.types import (
    REPLAY_SCHEMA_VERSION,
    AgentOutcome,
    AgentRun,
    AgentTrajectory,
    OracleResult,
    VersionedRef,
)
from cot_redteam.agent.worlds.support import SupportAgentWorld
from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import CotRedTeamError
from cot_redteam.core.serialization import canonical_json, sha256_text

MAX_REPLAY_BYTES = 16 * 1024 * 1024

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2
EXIT_PARTIAL = 3

_GIT_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_TARGET_FIELDS = frozenset({"id", "original_version", "family"})


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
    # Optional for compatibility with schema-1 artifacts written before
    # oracle evidence was anchored.  New artifacts carry this digest so an
    # exact replay cannot accept a trajectory whose oracle verdict/evidence
    # changed while the aggregate outcome stayed exploitable.
    oracle_results_digest: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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

    # Resolve Git relative to the installed source tree rather than the
    # caller's working directory.  ``cot-redteam replay`` is commonly invoked
    # from a temporary artifact directory; using the process cwd would make
    # otherwise comparable provenance appear unavailable.
    source_root = Path(__file__).resolve().parents[2]
    try:
        rev = subprocess.check_output(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "-C", str(source_root), "status", "--porcelain"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        )
        return {"revision": rev, "dirty": dirty}
    except Exception:
        return {"revision": None, "dirty": None}


def _valid_git_revision(revision: str) -> bool:
    return bool(_GIT_REVISION_RE.fullmatch(revision))


def _git_revision_is_ancestor(ancestor: str, descendant: str) -> bool:
    """Return whether ``ancestor`` is reachable from the current source tree."""
    import subprocess

    source_root = Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(source_root),
                "merge-base",
                "--is-ancestor",
                ancestor,
                descendant,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def _oracle_results_digest(
    results: tuple[OracleResult, ...],
    *,
    trajectory: AgentTrajectory,
) -> str:
    """Hash deterministic oracle semantics with normalized evidence references.

    Event IDs are diagnostic references tied to a particular run and therefore
    are not stable across replays.  Normalize references to trajectory
    sequence positions so a changed evidence mapping is still detected while
    run-specific IDs do not break exact replay.  Verdicts, summaries,
    snapshot digests, evidence payloads, and errors remain in the projection.
    """
    event_sequences = {event.event_id: event.sequence_no for event in trajectory.events}
    projection = [
        {
            **result.model_dump(mode="python", exclude={"evidence_event_ids"}),
            "evidence_event_sequences": [
                event_sequences.get(event_id, {"unresolved_event_id": event_id})
                for event_id in result.evidence_event_ids
            ],
        }
        for result in results
    ]
    return sha256_text(canonical_json(projection))


def build_replay_artifact(
    run: AgentRun,
    *,
    fixture: Any,
    budget_configuration: dict[str, Any],
    settings: AgentSecuritySettings | None = None,
) -> dict[str, Any]:
    """Build a strict replay artifact dict for a verified-exploit run."""
    del settings
    sanitized_inputs: dict[str, Any] = {}
    if "seed" in run.metadata:
        seed = run.metadata["seed"]
        _validate_seed_value(seed)
        sanitized_inputs["seed"] = seed
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
        "oracle_results_digest": _oracle_results_digest(
            run.oracle_results,
            trajectory=run.trajectory,
        ),
        "sanitized_inputs": sanitized_inputs,
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


def _current_oracle_refs(scenario: Any) -> tuple[VersionedRef, ...]:
    """Resolve the scenario's built-in oracle contracts without executing them."""
    refs: list[VersionedRef] = []
    for oracle_id in scenario.required_oracles:
        try:
            oracle = support_oracle(
                scenario.id,
                oracle_id,
                canary="",
                required_approvals=scenario.required_approvals,
                protected_resources=scenario.protected_resources,
            )
        except Exception as exc:  # noqa: BLE001 - registry drift is incompatibility
            raise ReplayError(
                f"incompatible oracle registry for scenario {scenario.id!r}: "
                f"cannot resolve {oracle_id!r}: {exc}"
            ) from exc
        refs.append(VersionedRef(id=oracle.id, version=oracle.version))
    return tuple(refs)


def _validate_provenance_shape(artifact: ReplayArtifactV1) -> None:
    """Validate replay provenance fields before any compatibility comparison.

    Regression replays intentionally permit package/source drift while a
    saved exploit is exercised against a patched target.  They still require
    the declarative metadata to retain its expected primitive shape.
    Exact replays additionally compare these fields to the current runtime.
    """
    if not artifact.package:
        raise ReplayError("incompatible replay package metadata: no package version recorded")
    if any(not isinstance(name, str) or not name for name in artifact.package):
        raise ReplayError("incompatible replay package metadata: invalid package id")
    if any(not isinstance(version, str) or not version for version in artifact.package.values()):
        raise ReplayError("incompatible replay package metadata: invalid package version")
    source = artifact.source
    if not isinstance(source, dict):
        raise ReplayError("incompatible replay source metadata: expected an object")
    unknown_source_keys = set(source).difference({"revision", "dirty"})
    if unknown_source_keys:
        raise ReplayError(
            f"incompatible replay source metadata: unknown fields {sorted(unknown_source_keys)!r}"
        )
    revision = source.get("revision")
    dirty = source.get("dirty")
    if revision is not None and (
        not isinstance(revision, str) or not _valid_git_revision(revision)
    ):
        raise ReplayError("incompatible replay source metadata: invalid revision")
    if dirty is not None and not isinstance(dirty, bool):
        raise ReplayError("incompatible replay source metadata: invalid dirty marker")


def _source_contract(source: dict[str, Any], *, label: str) -> tuple[str, bool] | None:
    """Return a valid source identity, or ``None`` when it is unavailable."""
    revision = source.get("revision")
    dirty = source.get("dirty")
    if revision is None and dirty is None:
        return None
    if (
        not isinstance(revision, str)
        or not _valid_git_revision(revision)
        or not isinstance(dirty, bool)
    ):
        raise ReplayError(f"incompatible source contract: invalid {label} provenance")
    return revision, dirty


def _validate_digest(value: str, *, field: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ReplayError(f"invalid {field}: expected a lowercase 64-hex digest")


def _validate_seed_value(value: object) -> None:
    if type(value) is not int:  # bool is an int subclass but not a valid seed
        raise ReplayError("invalid replay seed: expected an integer")


def _recorded_budget_settings(artifact: ReplayArtifactV1) -> BudgetSettings:
    try:
        return BudgetSettings.model_validate(artifact.budget_configuration, strict=True)
    except Exception as exc:
        raise ReplayError(f"invalid replay budget_configuration: {exc}") from exc


def _validate_artifact_contract(
    artifact: ReplayArtifactV1,
    *,
    exact: bool,
) -> BudgetSettings:
    """Validate fields that must be trusted before registry resolution/execution."""
    if exact and artifact.original_outcome != AgentOutcome.VERIFIED_EXPLOIT.value:
        raise ReplayError("incompatible exact replay: original_outcome must be 'verified_exploit'")
    if set(artifact.target) != _TARGET_FIELDS:
        raise ReplayError(
            "invalid replay target metadata: expected exactly id, original_version, and family"
        )
    for field in _TARGET_FIELDS:
        value = artifact.target.get(field)
        if type(value) is not str or not value.strip():
            raise ReplayError(f"invalid replay target metadata: {field} must be non-empty")
    _validate_digest(artifact.world_fixture_digest, field="world_fixture_digest")
    _validate_digest(artifact.trajectory_digest, field="trajectory_digest")
    if artifact.oracle_results_digest is not None:
        _validate_digest(artifact.oracle_results_digest, field="oracle_results_digest")
    if "seed" in artifact.sanitized_inputs:
        _validate_seed_value(artifact.sanitized_inputs["seed"])
    return _recorded_budget_settings(artifact)


def _resolve_replay_settings(
    *,
    exact: bool,
    settings: AgentSecuritySettings | None,
    recorded_budgets: BudgetSettings,
) -> AgentSecuritySettings | None:
    """Apply recorded budgets only to exact replays; regressions may override them."""
    if not exact:
        return settings
    expected = recorded_budgets.model_dump(mode="python")
    if settings is None:
        return AgentSecuritySettings(budgets=recorded_budgets)
    try:
        actual = settings.budgets.model_dump(mode="python")
    except Exception as exc:
        raise ReplayError(f"invalid replay settings budgets: {exc}") from exc
    if actual != expected:
        raise ReplayError(
            "incompatible exact replay budget_configuration: "
            f"artifact has {expected!r}, caller has {actual!r}"
        )
    return settings


def _resolve_replay_seed(
    artifact: ReplayArtifactV1,
    *,
    exact: bool,
    seed: int | None,
) -> int:
    """Use an embedded seed by default; legacy artifacts fall back to 42."""
    has_stored_seed = "seed" in artifact.sanitized_inputs
    stored = artifact.sanitized_inputs.get("seed")
    if has_stored_seed:
        _validate_seed_value(stored)
        if exact and seed is not None:
            _validate_seed_value(seed)
            if seed != stored:
                raise ReplayError(
                    f"incompatible exact replay seed: artifact has {stored}, caller has {seed}"
                )
        if seed is None or exact:
            return cast(int, stored)
    if seed is not None:
        _validate_seed_value(seed)
        return seed
    return 42


def _validate_replay_compatibility(
    artifact: ReplayArtifactV1,
    *,
    scenario: Any,
    original_fixture: Any,
    exact: bool,
) -> None:
    """Preflight all stable replay contracts before executing a target.

    ``original_fixture`` is always resolved from the artifact's recorded
    target family, even for regression overrides.  This prevents an override
    from turning a tampered original artifact into a valid regression input.
    """
    if artifact.scenario.version != scenario.version:
        raise ReplayError(
            f"incompatible scenario {artifact.scenario.id}/{artifact.scenario.version}; "
            f"registry has {scenario.id}/{scenario.version}"
        )

    if artifact.world.id != scenario.world_id or artifact.world.version != scenario.world_version:
        raise ReplayError(
            f"incompatible world {artifact.world.id}/{artifact.world.version}; "
            f"scenario {scenario.id!r} requires {scenario.world_id}/{scenario.world_version}"
        )
    if (
        artifact.world.id != SupportAgentWorld.world_id
        or artifact.world.version != SupportAgentWorld.world_version
    ):
        raise ReplayError(
            f"incompatible world {artifact.world.id}/{artifact.world.version}; "
            f"registry has {SupportAgentWorld.world_id}/{SupportAgentWorld.world_version}"
        )

    expected_target_id = "scripted"
    expected_target_version = original_fixture.version
    if (
        artifact.target.get("id") != expected_target_id
        or artifact.target.get("original_version") != expected_target_version
    ):
        raise ReplayError(
            "incompatible original target "
            f"{artifact.target.get('id')}/{artifact.target.get('original_version')}; "
            f"fixture {original_fixture.fixture!r} requires "
            f"{expected_target_id}/{expected_target_version}"
        )

    expected_attack = VersionedRef(
        id=f"scripted:{original_fixture.fixture}",
        version=original_fixture.version,
    )
    if artifact.attack != expected_attack:
        raise ReplayError(
            f"incompatible attack {artifact.attack.id}/{artifact.attack.version}; "
            f"fixture {original_fixture.fixture!r} requires "
            f"{expected_attack.id}/{expected_attack.version}"
        )

    if artifact.world_fixture_digest != original_fixture.digest:
        raise ReplayError(
            "world fixture digest mismatch: artifact expects "
            f"{artifact.world_fixture_digest}, registry has {original_fixture.digest}"
        )

    expected_oracles = _current_oracle_refs(scenario)
    if artifact.oracles != expected_oracles:
        expected = ", ".join(f"{ref.id}/{ref.version}" for ref in expected_oracles) or "<none>"
        actual = ", ".join(f"{ref.id}/{ref.version}" for ref in artifact.oracles) or "<none>"
        raise ReplayError(
            f"incompatible oracle contracts: artifact has [{actual}], registry requires [{expected}]"
        )

    _validate_provenance_shape(artifact)
    current_package = _package_version()
    if set(artifact.package) != set(current_package):
        raise ReplayError(
            "incompatible package contract IDs: artifact has "
            f"{sorted(artifact.package)!r}, runtime has {sorted(current_package)!r}"
        )
    if not exact:
        return

    if artifact.package != current_package:
        raise ReplayError(
            f"incompatible package contract: artifact has {artifact.package!r}, "
            f"runtime has {current_package!r}"
        )

    current_source = _git_source()
    if not isinstance(current_source, dict):
        raise ReplayError("incompatible source contract: invalid runtime provenance")
    unknown_runtime_keys = set(current_source).difference({"revision", "dirty"})
    if unknown_runtime_keys:
        raise ReplayError(
            f"incompatible source contract: unknown runtime fields {sorted(unknown_runtime_keys)!r}"
        )
    artifact_contract = _source_contract(artifact.source, label="artifact")
    current_contract = _source_contract(current_source, label="runtime")
    if current_contract is None:
        # Installed wheels may not have a Git checkout.  Stable replay
        # contracts were already checked above; source comparison is possible
        # only when the runtime exposes a valid identity.
        return
    if artifact_contract is None:
        raise ReplayError("incompatible source contract: artifact provenance unavailable")
    # The dirty marker is advisory provenance, not a semantic identity.  A
    # strict dirty-flag equality check would reject legitimate wheel/ancestor
    # replays; trajectory and oracle-result digests below are the semantic
    # compatibility gates.
    artifact_revision, _artifact_dirty = artifact_contract
    current_revision, _current_dirty = current_contract
    if artifact_revision != current_revision and not _git_revision_is_ancestor(
        artifact_revision,
        current_revision,
    ):
        raise ReplayError(
            "incompatible source contract: artifact revision "
            f"{artifact_revision} is not an ancestor of runtime revision {current_revision}"
        )


async def run_replay(
    artifact: ReplayArtifactV1,
    *,
    fixture: str | None = None,
    settings: AgentSecuritySettings | None = None,
    run_id: str | None = None,
    seed: int | None = None,
) -> ReplayResult:
    """Replay a validated artifact deterministically.

    ``fixture`` overrides the replayed fixture (regression suites replay a
    saved exploit against a different target-under-test). Exact replays
    default to the artifact's original target family and validate the
    fixture digest.
    """
    exact = fixture is None
    recorded_budgets = _validate_artifact_contract(artifact, exact=exact)
    effective_settings = _resolve_replay_settings(
        exact=exact,
        settings=settings,
        recorded_budgets=recorded_budgets,
    )
    resolved_seed = _resolve_replay_seed(artifact, exact=exact, seed=seed)
    scenario_id = artifact.scenario.id
    try:
        scenario = support_scenario(scenario_id)
    except CotRedTeamError as exc:
        raise ReplayError(f"unknown scenario {scenario_id!r}: {exc}") from exc
    try:
        original_fixture = support_fixture(scenario_id, artifact.target_family)
    except CotRedTeamError as exc:
        raise ReplayError(
            f"unknown original fixture {artifact.target_family!r} for "
            f"scenario {scenario_id!r}: {exc}"
        ) from exc
    _validate_replay_compatibility(
        artifact,
        scenario=scenario,
        original_fixture=original_fixture,
        exact=exact,
    )
    target_family = fixture or artifact.target_family
    try:
        support_fixture(scenario_id, target_family)
    except CotRedTeamError as exc:
        raise ReplayError(
            f"unknown fixture {target_family!r} for scenario {scenario_id!r}: {exc}"
        ) from exc
    from cot_redteam.agent.api import run_agent_scenario

    run = await run_agent_scenario(
        scenario_id=scenario_id,
        fixture=target_family,
        settings=effective_settings,
        run_id=run_id or f"replay-{artifact.replay_id}",
        seed=resolved_seed,
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
        elif (
            tuple(
                VersionedRef(id=result.oracle_id, version=result.oracle_version)
                for result in run.oracle_results
            )
            != artifact.oracles
        ):
            # Keep legacy artifacts useful while still refusing a run whose
            # required oracle set/order no longer matches the saved contract.
            result = ReplayResult(
                status="inconclusive",
                exit_code=EXIT_PARTIAL,
                message=(
                    "replay oracle contracts differ from the artifact; required oracle set changed"
                ),
                run=run,
            )
        elif run.outcome is not AgentOutcome.VERIFIED_EXPLOIT:
            # An exact artifact is proof of a verified exploit.  A matching
            # trajectory alone is insufficient: an oracle implementation may
            # have changed its verdict/evidence while producing the same
            # event sequence.  Never map that semantic drift to exit 0.
            result = ReplayResult(
                status="inconclusive",
                exit_code=EXIT_PARTIAL,
                message=("replay outcome differs from the artifact: expected verified exploit"),
                run=run,
            )
        elif artifact.oracle_results_digest is not None and (
            _oracle_results_digest(run.oracle_results, trajectory=run.trajectory)
            != artifact.oracle_results_digest
        ):
            result = ReplayResult(
                status="inconclusive",
                exit_code=EXIT_PARTIAL,
                message=(
                    "replay oracle results digest differs from the artifact; "
                    "oracle verdict or evidence changed"
                ),
                run=run,
            )
        else:
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
