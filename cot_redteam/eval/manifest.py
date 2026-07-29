"""Redacted reproducibility manifest generation."""

from __future__ import annotations

import platform
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

from cot_redteam.benchmark.policies import BUILTIN_POLICIES
from cot_redteam.benchmark.results import BenchmarkRunResult
from cot_redteam.benchmark.scoring import SCORER_VERSION
from cot_redteam.benchmark.techniques import TECHNIQUE_VERSION
from cot_redteam.benchmark.transforms import TRANSFORM_VERSION
from cot_redteam.core.config import AppConfig, redacted_config
from cot_redteam.core.serialization import canonical_json, sha256_text
from cot_redteam.core.types import EvaluationRun, JsonValue
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
