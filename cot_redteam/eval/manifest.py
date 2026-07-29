"""Redacted reproducibility manifest generation."""

from __future__ import annotations

import platform
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime

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
