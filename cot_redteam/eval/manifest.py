"""Redacted reproducibility manifest generation."""

from __future__ import annotations

import platform
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cot_redteam.agent.types import AgentRun

from cot_redteam.benchmark.policies import BUILTIN_POLICIES
from cot_redteam.benchmark.results import BenchmarkRunResult
from cot_redteam.benchmark.scoring import SCORER_VERSION
from cot_redteam.benchmark.techniques import TECHNIQUE_VERSION
from cot_redteam.benchmark.transforms import TRANSFORM_VERSION
from cot_redteam.core.config import AppConfig, redacted_config
from cot_redteam.core.serialization import canonical_json, sha256_text
from cot_redteam.core.types import EvaluationRun, JsonValue
from cot_redteam.eval.retention import SENSITIVE_KEY_RE
from cot_redteam.plugins.registry import PluginMetadata


@dataclass(frozen=True)
class ArtifactRecord:
    relative_path: str
    media_type: str
    byte_length: int
    sha256: str


GitReader = Callable[[], dict[str, JsonValue]]
DistReader = Callable[[], dict[str, str]]


def _default_git_reader() -> dict[str, JsonValue]:
    try:
        rev = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        )
        return {"revision": rev, "dirty": dirty}
    except Exception:
        return {"revision": None, "dirty": None}


def _default_dist_reader() -> dict[str, str]:
    try:
        from importlib.metadata import version

        return {"cot-redteam-agent": version("cot-redteam-agent")}
    except Exception:
        from cot_redteam import __version__

        return {"cot-redteam-agent": __version__}


def build_manifest(
    run: EvaluationRun,
    config: AppConfig,
    *,
    plugins: Sequence[PluginMetadata] = (),
    artifacts: Sequence[ArtifactRecord] = (),
    git_reader: GitReader | None = None,
    dist_reader: DistReader | None = None,
    limitations: Sequence[str] | None = None,
) -> dict[str, JsonValue]:
    git_reader = git_reader or _default_git_reader
    dist_reader = dist_reader or _default_dist_reader
    redacted = redacted_config(config)
    cfg_digest = sha256_text(canonical_json(redacted))
    sample_ids = sorted({item.sample_id for item in run.items})
    model_ids = sorted({str(item.model) for item in run.items})
    attack_ids = sorted({item.attack_id for item in run.items})
    monitor_ids = sorted({outcome.monitor_id for item in run.items for outcome in item.monitors})
    git_info = git_reader()
    packages = dist_reader()
    default_limitations = [
        "Provider nondeterminism is not controlled.",
        "Visible reasoning extraction only uses provider fields or explicit delimiters.",
        "Automated monitors are not ground truth.",
    ]
    if git_info.get("dirty") is True:
        default_limitations.append("Git worktree was dirty at manifest generation.")
    if limitations:
        default_limitations.extend(limitations)

    manifest: dict[str, JsonValue] = {
        "run_id": run.run_id,
        "status": run.status.value,
        "started_at": run.started_at.isoformat().replace("+00:00", "Z")
        if isinstance(run.started_at, datetime)
        else str(run.started_at),
        "completed_at": run.completed_at.isoformat().replace("+00:00", "Z")
        if isinstance(run.completed_at, datetime)
        else str(run.completed_at),
        "summary": {
            "planned": run.summary.planned,
            "succeeded": run.summary.succeeded,
            "failed": run.summary.failed,
            "cancelled": run.summary.cancelled,
            "monitor_excluded": run.summary.monitor_excluded,
        },
        "config": redacted,
        "config_digest": cfg_digest,
        "dataset_digest": run.dataset_digest,
        "seed": run.seed,
        "sample_ids": sample_ids,
        "models": model_ids,
        "attacks": attack_ids,
        "monitors": monitor_ids,
        "plugins": [
            {
                "id": p.id,
                "version": p.version,
                "description": p.description,
                "category": p.category,
            }
            for p in plugins
        ],
        "python": {
            "version": sys.version,
            "platform": platform.platform(),
        },
        "packages": packages,
        "git": git_info,
        "artifacts": [
            {
                "path": a.relative_path,
                "media_type": a.media_type,
                "byte_length": a.byte_length,
                "sha256": a.sha256,
            }
            for a in artifacts
        ],
        "limitations": list(default_limitations),
    }
    manifest["manifest_digest"] = sha256_text(canonical_json(manifest))
    return manifest


def build_benchmark_manifest(
    run: BenchmarkRunResult,
    config: AppConfig,
    *,
    artifacts: Sequence[ArtifactRecord] = (),
    git_reader: GitReader | None = None,
    dist_reader: DistReader | None = None,
    limitations: Sequence[str] = (),
) -> dict[str, JsonValue]:
    """Build a sanitized, version-complete v0.3 benchmark manifest."""
    git_reader = git_reader or _default_git_reader
    dist_reader = dist_reader or _default_dist_reader
    trials = run.trials
    scenario_by_id = {result.trial.scenario.id: result.trial.scenario for result in trials}
    policy_ids = sorted({result.trial.policy_id for result in trials})
    technique_ids = sorted({result.trial.technique_id for result in trials})
    transformation_ids = sorted({result.trial.transformation_id for result in trials})
    scorer_ids = sorted(
        {outcome.scorer_id for result in trials for outcome in result.scoring.outcomes}
    )
    responses = [
        turn.response
        for result in trials
        for turn in result.transcript.turns
        if turn.response is not None
    ]
    eligible = sum(outcome.eligible for result in trials for outcome in result.scoring.outcomes)
    outcome_count = sum(len(result.scoring.outcomes) for result in trials)
    raw_suite_digests = run.metadata.get("suite_digests", {})
    suite_digests = raw_suite_digests if isinstance(raw_suite_digests, dict) else {}
    manifest: dict[str, JsonValue] = {
        "schema_version": 3,
        "run_id": run.run_id,
        "started_at": _dt_manifest(run.started_at),
        "completed_at": _dt_manifest(run.completed_at),
        "config": redacted_config(config),
        "config_digest": sha256_text(canonical_json(redacted_config(config))),
        "suites": [
            {"id": suite_id, "digest": suite_digests.get(suite_id)}
            for suite_id in sorted({result.trial.suite_id for result in trials})
        ],
        "scenarios": [
            {
                "id": scenario.id,
                "digest": scenario.digest,
                "source": scenario.source.model_dump(mode="python"),
            }
            for scenario in sorted(scenario_by_id.values(), key=lambda value: value.id)
        ],
        "policies": [
            {
                "id": policy_id,
                "version": (
                    BUILTIN_POLICIES[policy_id].version if policy_id in BUILTIN_POLICIES else None
                ),
            }
            for policy_id in policy_ids
        ],
        "techniques": [
            {"id": technique_id, "version": TECHNIQUE_VERSION} for technique_id in technique_ids
        ],
        "transformations": [
            {"id": transform_id, "version": TRANSFORM_VERSION}
            for transform_id in transformation_ids
        ],
        "scorers": [{"id": scorer_id, "version": SCORER_VERSION} for scorer_id in scorer_ids],
        "repetitions": config.evaluation.repetitions,
        "target_capabilities": {
            name: provider.capabilities.model_dump(mode="python")
            for name, provider in config.providers.items()
        },
        "models": sorted({str(result.trial.model) for result in trials}),
        "model_revisions": sorted(
            {
                response.model_revision
                for response in responses
                if response.model_revision is not None
            }
        ),
        "judges": [
            dict(outcome.judge_metadata)
            for result in trials
            for outcome in result.scoring.outcomes
            if outcome.judge_metadata
        ],
        "canaries": [dict(result.canary_metadata) for result in trials],
        "outcomes": {
            "eligible": eligible,
            "excluded": outcome_count - eligible,
        },
        "artifacts": [
            {
                "path": artifact.relative_path,
                "media_type": artifact.media_type,
                "byte_length": artifact.byte_length,
                "sha256": artifact.sha256,
            }
            for artifact in artifacts
        ],
        "python": {"version": sys.version, "platform": platform.platform()},
        "packages": dist_reader(),
        "git": git_reader(),
        "limitations": [
            "Provider nondeterminism may remain even with repeated trials.",
            "This release evaluates raw text model APIs, not live agent side effects.",
            "Automated scorer and judge outputs are not universal security proof.",
            *limitations,
        ],
    }
    manifest["manifest_digest"] = sha256_text(canonical_json(manifest))
    return manifest


def _dt_manifest(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def build_agent_manifest(
    run: AgentRun,
    *,
    config: AppConfig | None = None,
    artifacts: Sequence[ArtifactRecord] = (),
    git_reader: GitReader | None = None,
    dist_reader: DistReader | None = None,
) -> dict[str, JsonValue]:
    """Build a sanitized, version-complete v0.6 agent run manifest."""
    from cot_redteam.agent.types import AGENT_EVENT_SCHEMA_VERSION

    git_reader = git_reader or _default_git_reader
    dist_reader = dist_reader or _default_dist_reader
    manifest: dict[str, JsonValue] = {
        "schema_version": AGENT_EVENT_SCHEMA_VERSION,
        "run_id": run.run_id,
        "session_id": run.session_id,
        "status": run.status.value,
        "outcome": run.outcome.value if run.outcome else None,
        "started_at": _dt_manifest(run.started_at),
        "completed_at": _dt_manifest(run.completed_at) if run.completed_at else None,
        "scenario": {"id": run.scenario_ref.id, "version": run.scenario_ref.version},
        "target": {"id": run.target_ref.id, "version": run.target_ref.version},
        "world": {"id": run.world_ref.id, "version": run.world_ref.version},
        "attack": {"id": run.attack_ref.id, "version": run.attack_ref.version},
        "config": redacted_config(config) if config is not None else None,
        "config_digest": (
            sha256_text(canonical_json(redacted_config(config))) if config is not None else None
        ),
        "pre_snapshot_digest": run.pre_snapshot_digest,
        "post_snapshot_digest": run.post_snapshot_digest,
        "trajectory_digest": run.original_trajectory_digest or run.trajectory.digest,
        "event_count": len(run.trajectory.events),
        "oracles": [
            {
                "oracle_id": result.oracle_id,
                "oracle_version": result.oracle_version,
                "verdict": result.verdict.value,
                "evidence_event_ids": list(result.evidence_event_ids),
            }
            for result in run.oracle_results
        ],
        "findings": [
            {
                "finding_id": finding.finding_id,
                "oracle_id": finding.oracle_id,
                "category": finding.category,
                "severity": finding.severity,
                "evidence_event_ids": list(finding.evidence_event_ids),
            }
            for finding in run.findings
        ],
        "budget": run.budget_snapshot,
        "artifacts": [
            {
                "path": artifact.relative_path,
                "media_type": artifact.media_type,
                "byte_length": artifact.byte_length,
                "sha256": artifact.sha256,
            }
            for artifact in artifacts
        ],
        "python": {"version": sys.version, "platform": platform.platform()},
        "packages": dist_reader(),
        "git": git_reader(),
        "limitations": [
            "Agent impact is proven only by observed simulated actions and "
            "deterministic world state transitions.",
            "Assistant text and LLM judge opinion are never proof of impact.",
            "Support Agent World is the only executable world in this release.",
        ],
    }
    manifest["manifest_digest"] = sha256_text(canonical_json(manifest))
    return manifest


_AGENT_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "run_id",
        "session_id",
        "status",
        "outcome",
        "started_at",
        "completed_at",
        "scenario",
        "target",
        "world",
        "attack",
        "config",
        "config_digest",
        "pre_snapshot_digest",
        "post_snapshot_digest",
        "trajectory_digest",
        "event_count",
        "oracles",
        "findings",
        "budget",
        "artifacts",
        "python",
        "packages",
        "git",
        "limitations",
        "manifest_digest",
    }
)
_REDACTED_MARKERS = frozenset({"[redacted]", "***REDACTED***"})
_ARTIFACT_KEYS = frozenset({"path", "media_type", "byte_length", "sha256"})
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _validate_agent_manifest_values(value: object, *, path: str = "manifest") -> None:
    """Reject non-JSON values and raw credential-class fields.

    Agent manifests are generated from a fixed top-level contract, but their
    redacted config and diagnostic maps are intentionally extensible.  We
    therefore validate JSON shape recursively and reject sensitive-key values
    unless they are an explicit redaction marker.  ``session_id`` and
    ``api_key_env`` are structural identifiers, not secret material, and are
    allowed by the existing manifest contract.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        # canonical_json performs the final NaN/Infinity check; keeping this
        # branch explicit makes the accepted JSON primitive contract clear.
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string key")
            if (
                key not in {"session_id", "api_key_env"}
                and SENSITIVE_KEY_RE.search(key)
                and (not isinstance(child, str) or child not in _REDACTED_MARKERS)
            ):
                raise ValueError(f"{path}.{key} contains an unredacted sensitive value")
            _validate_agent_manifest_values(child, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_agent_manifest_values(child, path=f"{path}[{index}]")
        return
    raise ValueError(f"{path} contains a non-JSON value")


def _validate_agent_manifest_artifacts(value: object) -> None:
    """Validate artifact references without requiring files to exist."""
    if not isinstance(value, (list, tuple)):
        raise ValueError("agent manifest artifacts must be a list")
    for index, artifact in enumerate(value):
        path = f"agent manifest artifacts[{index}]"
        if not isinstance(artifact, Mapping):
            raise ValueError(f"{path} must be an object")
        unknown = [key for key in artifact if key not in _ARTIFACT_KEYS]
        missing = _ARTIFACT_KEYS - set(artifact)
        if unknown:
            raise ValueError(f"{path} contains unknown fields")
        if missing:
            raise ValueError(f"{path} is missing fields: {', '.join(sorted(missing))}")

        relative_path = artifact["path"]
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError(f"{path}.path must be a non-empty relative path")
        if _CONTROL_RE.search(relative_path):
            raise ValueError(f"{path}.path contains control characters")
        posix = PurePosixPath(relative_path)
        windows = PureWindowsPath(relative_path)
        if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
            raise ValueError(f"{path}.path must be relative")
        parts = relative_path.replace("\\", "/").split("/")
        if any(part == ".." for part in parts):
            raise ValueError(f"{path}.path must not contain '..' segments")
        normalized = "/".join(part for part in parts if part not in ("", "."))
        if not normalized or normalized != relative_path:
            raise ValueError(f"{path}.path must be a canonical relative file path")

        media_type = artifact["media_type"]
        if (
            not isinstance(media_type, str)
            or not media_type
            or _CONTROL_RE.search(media_type)
            or "/" not in media_type
        ):
            raise ValueError(f"{path}.media_type must be a MIME type")
        byte_length = artifact["byte_length"]
        if isinstance(byte_length, bool) or not isinstance(byte_length, int) or byte_length < 0:
            raise ValueError(f"{path}.byte_length must be a non-negative integer")
        sha256 = artifact["sha256"]
        if not isinstance(sha256, str) or _SHA256_RE.fullmatch(sha256) is None:
            raise ValueError(f"{path}.sha256 must be a 64-character hexadecimal digest")


def validate_agent_manifest(
    manifest: Mapping[str, object],
    *,
    expected: Mapping[str, object],
) -> dict[str, JsonValue]:
    """Validate a manifest before attaching it to an agent SQLite row.

    Unknown top-level fields, raw credential-class values, mismatched run
    identity, and stale core digests are rejected.  The input is never
    rewritten or redacted, preserving provenance and its optional digest.
    """
    if not isinstance(manifest, Mapping):
        raise ValueError("agent manifest must be a mapping")
    unknown = [
        key for key in manifest if not isinstance(key, str) or key not in _AGENT_MANIFEST_KEYS
    ]
    if unknown:
        names = ", ".join(repr(key) for key in unknown)
        raise ValueError(f"agent manifest contains unknown fields: {names}")
    missing = _AGENT_MANIFEST_KEYS - set(manifest)
    if missing:
        raise ValueError(
            "agent manifest is incomplete; missing fields: " + ", ".join(sorted(missing))
        )
    _validate_agent_manifest_values(manifest)
    _validate_agent_manifest_artifacts(manifest["artifacts"])
    # Validate serializability and reject NaN/Infinity through the canonical
    # serializer without changing the caller's values.
    try:
        canonical_json(manifest)
    except (TypeError, ValueError) as exc:
        raise ValueError("agent manifest contains a non-JSON value") from exc

    run_id = manifest.get("run_id")
    expected_run_id = expected.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("agent manifest requires a non-empty run_id")
    if run_id != expected_run_id:
        raise ValueError("agent manifest run_id does not match the stored run")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("unsupported agent manifest schema version")
    for field in (
        "session_id",
        "status",
        "outcome",
        "pre_snapshot_digest",
        "post_snapshot_digest",
        "trajectory_digest",
        "scenario",
        "target",
        "world",
        "attack",
    ):
        if field in manifest and field in expected and manifest[field] != expected[field]:
            raise ValueError(f"agent manifest {field} does not match the stored run")

    if "manifest_digest" in manifest:
        digest = manifest["manifest_digest"]
        if not isinstance(digest, str):
            raise ValueError("agent manifest_digest must be a string")
        unsigned = {key: value for key, value in manifest.items() if key != "manifest_digest"}
        if digest != sha256_text(canonical_json(unsigned)):
            raise ValueError("agent manifest_digest does not match manifest content")
    return dict(manifest)
