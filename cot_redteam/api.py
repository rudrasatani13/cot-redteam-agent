"""Supported Python API entry points for legacy and v0.3 benchmark runs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.benchmark.engine import BenchmarkEngine
from cot_redteam.benchmark.planner import BenchmarkPlanner
from cot_redteam.benchmark.results import BenchmarkRunResult
from cot_redteam.benchmark.retention import sanitize_trial_result
from cot_redteam.benchmark.validation import load_configured_suites
from cot_redteam.core.config import AppConfig, config_digest, load_config
from cot_redteam.core.types import EvaluationRun, ModelRef, TargetCapabilities
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.dataset import Dataset
from cot_redteam.eval.engine import EvaluationEngine
from cot_redteam.eval.events import ProgressCallback
from cot_redteam.eval.manifest import (
    ArtifactRecord,
    build_benchmark_manifest,
    build_manifest,
)
from cot_redteam.eval.planner import RunPlanner
from cot_redteam.eval.retention import sanitize_run
from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins
from cot_redteam.plugins.registry import PluginContext
from cot_redteam.providers.factory import ProviderFactory
from cot_redteam.reporting.benchmark import (
    BenchmarkReportFormat,
    BenchmarkReportWriter,
    render_benchmark_jsonl,
)
from cot_redteam.storage.artifacts import ArtifactStore
from cot_redteam.storage.sqlite import SQLiteRunStore


async def run_evaluation(
    config: AppConfig,
    *,
    provider_factory: ProviderFactory | None = None,
    run_store: SQLiteRunStore | None = None,
    artifact_store: ArtifactStore | None = None,
    environ: Mapping[str, str] | None = None,
    progress: ProgressCallback | None = None,
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
        progress=progress,
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
        # Manifest must not include a self-checksum of its own bytes (would be stale
        # after any rewrite). Record other artifacts only; store a detached checksum.
        artifact_records: list[ArtifactRecord] = [run_artifact.record]
        manifest = build_manifest(run, config, plugins=plugins, artifacts=artifact_records)
        manifest_body = json.dumps(manifest, indent=2, sort_keys=True)
        manifest_write = artifacts.write_text(
            f"{run.run_id}/manifest.json",
            manifest_body,
            media_type="application/json",
        )
        # Detached checksum file (not embedded in the manifest body).
        artifacts.write_text(
            f"{run.run_id}/manifest.json.sha256",
            f"{manifest_write.record.sha256}  manifest.json\n",
            media_type="text/plain",
        )
        store.save(run, manifest)
    finally:
        if owns_store:
            store.close()
    return run


async def run_benchmark(
    config: AppConfig,
    *,
    provider_factory: ProviderFactory | None = None,
    run_store: SQLiteRunStore | None = None,
    artifact_store: ArtifactStore | None = None,
    environ: Mapping[str, str] | None = None,
) -> BenchmarkRunResult:
    """Plan, execute, score, sanitize, persist, and report a v0.3 benchmark."""
    owns_factory = provider_factory is None
    factory = provider_factory or ProviderFactory(config, environ=environ)
    suites = load_configured_suites(config)
    models = tuple(factory.resolve_model(value) for value in config.evaluation.models)
    capabilities = {
        name: TargetCapabilities(**settings.capabilities.model_dump())
        for name, settings in config.providers.items()
    }
    planner = BenchmarkPlanner(
        models=models,
        suites=suites,
        target_capabilities=capabilities,
        selected_policy_ids=config.evaluation.policy_ids or None,
        selected_technique_ids=config.evaluation.technique_ids or None,
        selected_transformation_ids=config.evaluation.transformation_ids or None,
        repetitions=config.evaluation.repetitions,
        max_expanded_trials=config.evaluation.max_expanded_trials,
        judge_scorer_ids=set(config.evaluation.judge_scorers),
        budgets=config.evaluation.budgets,
    )
    plan = planner.create()
    started_at = datetime.now(timezone.utc)
    try:
        execution = await BenchmarkEngine(
            config,
            factory,
            BudgetTracker(config.evaluation.budgets),
        ).run(plan)
    finally:
        if owns_factory:
            await factory.aclose()
    sanitized = tuple(
        sanitize_trial_result(result, config.evaluation) for result in execution.results
    )
    run = BenchmarkRunResult(
        run_id=plan.run_id,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
        trials=sanitized,
        metadata={
            "config_digest": config_digest(config),
            "suite_digests": {suite.id: suite.digest for suite in suites},
            "preflight": {
                "target_requests_min": plan.preflight.target_requests_min,
                "target_requests_max": plan.preflight.target_requests_max,
                "judge_requests_max": plan.preflight.judge_requests_max,
            },
        },
    )
    owns_store = run_store is None
    store = run_store or SQLiteRunStore(config.storage.path)
    artifacts = artifact_store or ArtifactStore(config.artifacts.root)
    try:
        evidence_artifact = artifacts.write_text(
            f"{run.run_id}/benchmark.jsonl",
            render_benchmark_jsonl(run),
            media_type="application/x-ndjson",
        )
        manifest = build_benchmark_manifest(
            run,
            config,
            artifacts=(evidence_artifact.record,),
        )
        run = replace(run, manifest=manifest)
        manifest_write = artifacts.write_text(
            f"{run.run_id}/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True),
            media_type="application/json",
        )
        artifacts.write_text(
            f"{run.run_id}/manifest.json.sha256",
            f"{manifest_write.record.sha256}  manifest.json\n",
            media_type="text/plain",
        )
        report_writer = BenchmarkReportWriter(config.reporting.output_dir)
        for value in config.reporting.formats:
            report_writer.write(run, BenchmarkReportFormat(value))
        store.save_benchmark(run)
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
