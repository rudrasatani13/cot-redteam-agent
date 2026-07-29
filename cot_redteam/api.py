"""Supported Python API entry points for v0.2."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.core.config import AppConfig, config_digest, load_config
from cot_redteam.core.types import EvaluationRun, ModelRef
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.dataset import Dataset
from cot_redteam.eval.engine import EvaluationEngine
from cot_redteam.eval.manifest import ArtifactRecord, build_manifest
from cot_redteam.eval.planner import RunPlanner
from cot_redteam.eval.retention import sanitize_run
from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins
from cot_redteam.plugins.registry import PluginContext
from cot_redteam.providers.factory import ProviderFactory
from cot_redteam.storage.artifacts import ArtifactStore
from cot_redteam.storage.sqlite import SQLiteRunStore


async def run_evaluation(
    config: AppConfig,
    *,
    provider_factory: ProviderFactory | None = None,
    run_store: SQLiteRunStore | None = None,
    artifact_store: ArtifactStore | None = None,
    environ: Mapping[str, str] | None = None,
) -> EvaluationRun:
    """Plan and execute an evaluation run end-to-end."""
    bootstrap_plugins()
    owns_factory = provider_factory is None
    factory = provider_factory or ProviderFactory(config, environ=environ)
    context = PluginContext(
        provider_resolver=lambda name: factory.create(ModelRef(provider=name, model_id="_"))
    )
    dataset = Dataset.load_jsonl(config.evaluation.dataset_path)
    planner = RunPlanner(config, provider_factory=factory, dataset=dataset, plugin_context=context)
    plan = planner.create()
    budget = BudgetTracker(config.evaluation.budgets)
    engine = EvaluationEngine(
        factory,
        AttackRegistry,
        MonitorRegistry,
        budget,
        concurrency=config.global_.concurrency,
        config=config,
        plugin_context=context,
        close_providers=False,  # API owns factory lifecycle
    )
    try:
        run = await engine.run(plan)
    finally:
        if owns_factory:
            await factory.aclose()

    run = EvaluationRun(
        run_id=run.run_id,
        status=run.status,
        items=run.items,
        summary=run.summary,
        started_at=run.started_at,
        completed_at=run.completed_at,
        seed=run.seed,
        config_digest=config_digest(config),
        dataset_digest=run.dataset_digest or dataset.digest,
        metadata=run.metadata,
    )
    run = sanitize_run(run, config)

    plugins = list(AttackRegistry.metadata()) + list(MonitorRegistry.metadata())
    owns_store = run_store is None
    store = run_store or SQLiteRunStore(config.storage.path)
    artifacts = artifact_store or ArtifactStore(config.artifacts.root)
    try:
        # Write run JSON first so the manifest can reference real artifacts.
        run_artifact = artifacts.write_text(
            f"{run.run_id}/run.json",
            json.dumps(
                {
                    "run_id": run.run_id,
                    "status": run.status.value,
                    "summary": {
                        "planned": run.summary.planned,
                        "succeeded": run.summary.succeeded,
                        "failed": run.summary.failed,
                        "cancelled": run.summary.cancelled,
                        "monitor_excluded": run.summary.monitor_excluded,
                    },
                },
                indent=2,
                sort_keys=True,
            ),
            media_type="application/json",
        )
        artifact_records: list[ArtifactRecord] = [run_artifact.record]
        manifest = build_manifest(run, config, plugins=plugins, artifacts=artifact_records)
        manifest_write = artifacts.write_text(
            f"{run.run_id}/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True),
            media_type="application/json",
        )
        # Rebuild with the manifest artifact itself included.
        artifact_records.append(manifest_write.record)
        manifest = build_manifest(run, config, plugins=plugins, artifacts=artifact_records)
        # Overwrite manifest with final content (includes its own hash record).
        artifacts.write_text(
            f"{run.run_id}/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True),
            media_type="application/json",
        )
        store.save(run, manifest)
    finally:
        if owns_store:
            store.close()
    return run


def load_run(store: SQLiteRunStore, run_id: str) -> EvaluationRun | None:
    return store.get(run_id)


def load_app_config(
    path: str | Path,
    *,
    overrides: Mapping[str, object] | None = None,
) -> AppConfig:
    return load_config(path, overrides=overrides)
