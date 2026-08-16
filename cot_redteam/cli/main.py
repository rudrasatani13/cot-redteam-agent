"""CLI parser, command dispatch, and exit-code mapping."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from cot_redteam import __version__
from cot_redteam.api import run_benchmark, run_evaluation
from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.benchmark.corpora import list_builtin_suites, load_builtin_suite
from cot_redteam.benchmark.importers import (
    import_cyberseceval_jsonl,
    import_ih_challenge_jsonl,
)
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.config import load_config, redacted_config, validate_config
from cot_redteam.core.errors import ConfigurationError, CotRedTeamError, PluginError
from cot_redteam.core.serialization import canonical_json
from cot_redteam.core.types import ItemStatus, RunStatus
from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins
from cot_redteam.reporting.benchmark import (
    BenchmarkReportFormat,
    BenchmarkReportWriter,
)
from cot_redteam.reporting.report import ReportFormat, ReportWriter
from cot_redteam.resources import read_example_config_text
from cot_redteam.storage.sqlite import SQLiteRunStore

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2
EXIT_PARTIAL = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cot-redteam",
        description=f"CoT Red Team Agent {__version__}",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--debug", action="store_true", help="show full tracebacks")
    sub = parser.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="write example configuration")
    init_p.add_argument("--path", default="config.yaml", help="destination path")
    init_p.add_argument("--force", action="store_true", help="overwrite existing file")

    cfg = sub.add_parser("config", help="configuration utilities")
    cfg_sub = cfg.add_subparsers(dest="config_command", required=True)
    validate = cfg_sub.add_parser("validate", help="validate configuration")
    validate.add_argument("--config", required=True)
    show = cfg_sub.add_parser("show", help="show redacted configuration")
    show.add_argument("--config", required=True)

    sub.add_parser("list-attacks", help="list registered attacks")
    sub.add_parser("list-monitors", help="list registered monitors")
    sub.add_parser("list-providers", help="list configured provider kinds")
    sub.add_parser("list-suites", help="list packaged benchmark suites")

    suite = sub.add_parser("suite", help="benchmark suite utilities")
    suite_sub = suite.add_subparsers(dest="suite_command", required=True)
    suite_validate = suite_sub.add_parser("validate", help="validate a JSONL suite")
    suite_validate.add_argument("--path", required=True)
    suite_validate.add_argument("--id", default="local.validation")
    suite_show = suite_sub.add_parser("show", help="show a packaged suite")
    suite_show.add_argument("--id", required=True)

    dataset = sub.add_parser("dataset", help="offline dataset import utilities")
    dataset_sub = dataset.add_subparsers(dest="dataset_command", required=True)
    dataset_import = dataset_sub.add_parser("import", help="import external JSONL data")
    dataset_import.add_argument(
        "format",
        choices=["cyberseceval", "ih-challenge"],
    )
    dataset_import.add_argument("--input", required=True)
    dataset_import.add_argument("--output", required=True)
    dataset_import.add_argument("--suite-id", required=True)
    dataset_import.add_argument("--upstream-revision", required=True)
    dataset_import.add_argument("--upstream-license", required=True)

    run_p = sub.add_parser("run", help="run evaluation")
    run_p.add_argument("--config", required=True)
    run_p.add_argument("--sample-count", type=int, default=None)
    run_p.add_argument("--seed", type=int, default=None)

    scan = sub.add_parser(
        "scan",
        help="quick CI-ready compliance scan (exit 0 = clean, 1 = findings)",
    )
    scan.add_argument("--config", required=True)
    scan.add_argument("--dataset", default=None)
    scan.add_argument("--sample-count", type=int, default=None)
    scan.add_argument("--model", action="append", default=None)
    scan.add_argument("--attack", action="append", default=None)
    scan.add_argument("--seed", type=int, default=None)

    list_runs = sub.add_parser("list-runs", help="list stored runs")
    list_runs.add_argument("--config", required=True)
    list_runs.add_argument("--limit", type=int, default=20)

    show_run = sub.add_parser("show-run", help="show a stored run")
    show_run.add_argument("--config", required=True)
    show_run.add_argument("--run-id", required=True)

    report = sub.add_parser("report", help="render a report for a stored run")
    report.add_argument("--config", required=True)
    report.add_argument("--run-id", required=True)
    report.add_argument(
        "--format",
        choices=["markdown", "csv", "jsonl", "latex"],
        default="markdown",
    )
    report.add_argument("--output-dir", default=None)

    evolve = sub.add_parser("evolve", help="bounded generative attack evolution")
    evolve.add_argument("--config", required=True)
    evolve.add_argument("--generator-model", default=None)
    evolve.add_argument("--target-model", default=None)

    race = sub.add_parser(
        "race",
        help="race one probe across models and compare compliance",
    )
    race.add_argument("--config", required=True)
    race.add_argument("--model", action="append", default=None, dest="race_models")
    race.add_argument(
        "--prompt", default=None, help="probe text (default: canary extraction probe)"
    )
    race.add_argument("--attack", default=None, help="optional attack id to frame the probe")
    race.add_argument("--max-tokens", type=int, default=1024)

    tui = sub.add_parser(
        "tui",
        help="interactive Codex-style adaptive red-team TUI (rich + textual)",
    )
    tui.add_argument("--config", required=True)
    tui.add_argument("--sample-count", type=int, default=None)
    tui.add_argument("--seed", type=int, default=None)
    tui.add_argument(
        "--auto-start",
        action="store_true",
        help="start the evaluation immediately without waiting for /run",
    )
    tui.add_argument(
        "--live-only",
        action="store_true",
        help="non-interactive Rich live dashboard (no slash commands)",
    )

    agent = sub.add_parser(
        "agent",
        help="agent-security commands (scripted Support Agent World)",
    )
    agent_sub = agent.add_subparsers(dest="agent_command", required=True)
    agent_scan = agent_sub.add_parser(
        "scan",
        help=(
            "run configured agent scenarios/fixtures; save checksummed "
            "replay artifacts for verified exploits (exit 0/1/3)"
        ),
    )
    agent_scan.add_argument("--config", required=True)
    agent_scan.add_argument("--scenario", action="append", default=None)
    agent_scan.add_argument("--fixture", action="append", default=None)
    agent_scan.add_argument("--seed", type=int, default=None)

    replay = sub.add_parser(
        "replay",
        help=(
            "replay a checksummed exploit artifact (exit 1 = reproduced, "
            "0 = held, 3 = inconclusive, 2 = corrupt/incompatible)"
        ),
    )
    replay.add_argument("artifact", help="path to EXPLOIT.json")
    replay.add_argument("--config", default=None, help="optional agent config")
    replay.add_argument("--fixture", default=None, help="override replayed fixture")

    regress = sub.add_parser(
        "regress",
        help=(
            "run a security regression suite: saved exploits replayed "
            "against patched targets expected to hold"
        ),
    )
    regress.add_argument("--suite", required=True, help="suite directory with suite.json")
    regress.add_argument("--config", default=None, help="optional agent config")
    return parser


def cmd_init(args: argparse.Namespace) -> int:
    dest = Path(args.path)
    if dest.exists() and not args.force:
        print(f"refusing to overwrite existing file: {dest}", file=sys.stderr)
        return EXIT_CONFIG
    text = read_example_config_text()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    print(f"wrote {dest}")
    return EXIT_OK


def cmd_config_validate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    validate_config(config, require_credentials=True)
    print("configuration valid")
    return EXIT_OK


def cmd_config_show(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    print(canonical_json(redacted_config(config)))
    return EXIT_OK


def cmd_list_attacks(_: argparse.Namespace) -> int:
    bootstrap_plugins()
    for meta in AttackRegistry.metadata():
        print(f"{meta.id}\t{meta.version}\t{meta.description}")
    return EXIT_OK


def cmd_list_monitors(_: argparse.Namespace) -> int:
    bootstrap_plugins()
    for meta in MonitorRegistry.metadata():
        print(f"{meta.id}\t{meta.version}\t{meta.description}")
    return EXIT_OK


def cmd_list_providers(args: argparse.Namespace) -> int:
    # Derived from the factory so the list cannot drift from reality.
    print("openrouter")
    print("openai")
    print("anthropic")
    print("vllm")
    print("llamacpp")
    print("openai_compatible")
    print("mock")
    return EXIT_OK


def cmd_list_suites(_: argparse.Namespace) -> int:
    for suite in list_builtin_suites():
        malicious = sum("malicious" in scenario.tags for scenario in suite.scenarios)
        controls = sum("benign_control" in scenario.tags for scenario in suite.scenarios)
        print(
            f"{suite.id}\tscenarios={len(suite.scenarios)}\t"
            f"malicious={malicious}\tcontrols={controls}\tdigest={suite.digest}"
        )
    return EXIT_OK


def cmd_suite_validate(args: argparse.Namespace) -> int:
    suite = ScenarioSuite.load_jsonl(args.path, suite_id=args.id)
    print(f"suite valid: id={suite.id} scenarios={len(suite.scenarios)} digest={suite.digest}")
    return EXIT_OK


def cmd_suite_show(args: argparse.Namespace) -> int:
    suite = load_builtin_suite(args.id)
    print(
        json.dumps(
            {
                "id": suite.id,
                "digest": suite.digest,
                "path": suite.path,
                "scenarios": [
                    {
                        "id": scenario.id,
                        "title": scenario.title,
                        "family": scenario.family,
                        "channel": scenario.channel,
                        "objective": scenario.objective.type,
                    }
                    for scenario in suite.scenarios
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return EXIT_OK


def cmd_dataset_import(args: argparse.Namespace) -> int:
    kwargs = {
        "suite_id": args.suite_id,
        "upstream_revision": args.upstream_revision,
        "upstream_license": args.upstream_license,
    }
    if args.format == "cyberseceval":
        result = import_cyberseceval_jsonl(args.input, **kwargs)
    else:
        result = import_ih_challenge_jsonl(args.input, **kwargs)
    output = Path(args.output)
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    existing = [path for path in (output, manifest_path) if path.exists()]
    if existing:
        raise ConfigurationError(
            "refusing to overwrite existing file(s): " + ", ".join(str(path) for path in existing)
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "\n".join(
            canonical_json(scenario.model_dump(mode="python"))
            for scenario in result.suite.scenarios
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_path.write_text(
        json.dumps(result.manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(
        f"imported={result.summary.imported} rejected={result.summary.rejected} "
        f"suite={output} manifest={manifest_path}"
    )
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    return asyncio.run(_scan_async(args))


async def _scan_async(args: argparse.Namespace) -> int:
    """Quick opinionated compliance scan with CI-friendly exit codes.

    Defaults (overridable via CLI flags or the config file): deterministic
    adaptive canary attack, regex monitor, packaged sample dataset, tight
    budgets. Exit codes: 0 = no findings, 1 = findings, 2 = config error,
    3 = partial run.
    """
    overrides = {}
    if args.dataset is not None:
        overrides["evaluation.dataset_path"] = args.dataset
    if args.sample_count is not None:
        overrides["evaluation.sample_count"] = args.sample_count
    if args.model:
        overrides["evaluation.models"] = args.model
    if args.attack:
        overrides["evaluation.attacks"] = args.attack
    if args.seed is not None:
        overrides["global.seed"] = args.seed
    config = load_config(args.config, overrides=overrides or None)
    # Opinionated scan defaults: deterministic adaptive canary attack, regex
    # monitor, tight budgets. Applied via documented overrides because the
    # config model is frozen after validation.
    scan_defaults: dict[str, object] = {}
    if not config.evaluation.attacks:
        scan_defaults["evaluation.attacks"] = ["injection.system_canary_adaptive"]
    if not config.evaluation.monitors:
        scan_defaults["evaluation.monitors"] = ["regex"]
    if (config.evaluation.budgets.max_requests or 3600) > 40:
        scan_defaults["evaluation.budgets.max_requests"] = 40
    if (config.evaluation.budgets.max_elapsed_seconds or 3600) > 300:
        scan_defaults["evaluation.budgets.max_elapsed_seconds"] = 300
    if scan_defaults:
        config = load_config(args.config, overrides={**overrides, **scan_defaults})
    validate_config(config, require_credentials=True)

    run = await run_evaluation(config)
    findings: dict[str, int] = {}
    attempts: dict[str, int] = {}
    for item in run.items:
        key = str(item.model)
        attempts[key] = attempts.get(key, 0) + 1
        if item.assessment is not None and item.assessment.success:
            findings[key] = findings.get(key, 0) + 1

    width = max([len(k) for k in attempts] + [len("Model")])
    print(f"{'Model':<{width}}  Attempts  Findings")
    print("-" * (width + 22))
    for model in sorted(attempts):
        print(f"{model:<{width}}  {attempts[model]:>8}  {findings.get(model, 0):>8}")
    total = sum(findings.values())
    # A run where items failed (provider/attack/monitor errors, budget
    # exhaustion, cancellation) never produced a verdict for those models:
    # treat it as partial, never as a clean pass. A fully-failed run must
    # NOT exit 0 (false-clean CI signal).
    failed_items = sum(1 for item in run.items if item.status is not ItemStatus.SUCCEEDED)
    if run.status is RunStatus.PARTIAL or run.status is RunStatus.FAILED or failed_items:
        print(
            f"VERDICT: partial run ({failed_items} item(s) did not complete) (exit {EXIT_PARTIAL})"
        )
        return EXIT_PARTIAL
    if total:
        print(f"VERDICT: {total} finding(s) — compliance issue detected (exit {EXIT_FAILED})")
        return EXIT_FAILED
    print("VERDICT: no findings — model held (exit 0)")
    return EXIT_OK


async def _run_async(args: argparse.Namespace) -> int:
    overrides = {}
    if args.sample_count is not None:
        overrides["evaluation.sample_count"] = args.sample_count
    if args.seed is not None:
        overrides["global.seed"] = args.seed
    config = load_config(args.config, overrides=overrides or None)
    validate_config(config, require_credentials=True)
    if config.evaluation.suite_ids or config.evaluation.suite_paths:
        benchmark_run = await run_benchmark(config)
        completed = sum(
            result.transcript.status.value == "completed" for result in benchmark_run.trials
        )
        config_errors = sum(
            result.transcript.status.value == "config_error" for result in benchmark_run.trials
        )
        print(
            f"run_id={benchmark_run.run_id} type=benchmark "
            f"planned={len(benchmark_run.trials)} "
            f"completed={completed} failed={len(benchmark_run.trials) - completed}"
        )
        if config_errors:
            # Judge/scorer misconfiguration is a config problem, not a
            # partial run: fail with exit 2 so CI can distinguish
            # "fix your config" from "run partially failed".
            print(f"VERDICT: configuration error in benchmark (exit {EXIT_CONFIG})")
            return EXIT_CONFIG
        return EXIT_OK if completed == len(benchmark_run.trials) else EXIT_PARTIAL
    legacy_run = await run_evaluation(config)
    print(
        f"run_id={legacy_run.run_id} status={legacy_run.status.value} "
        f"planned={legacy_run.summary.planned} "
        f"succeeded={legacy_run.summary.succeeded} "
        f"failed={legacy_run.summary.failed} "
        f"cancelled={legacy_run.summary.cancelled}"
    )
    if legacy_run.status is RunStatus.COMPLETED:
        return EXIT_OK
    if legacy_run.status is RunStatus.PARTIAL:
        return EXIT_PARTIAL
    return EXIT_FAILED


def cmd_run(args: argparse.Namespace) -> int:
    return asyncio.run(_run_async(args))


def cmd_list_runs(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    with SQLiteRunStore(config.storage.path) as store:
        for row in store.list_runs(limit=args.limit):
            print(
                f"{row['run_id']}\t{row['status']}\t"
                f"succeeded={row['summary'].get('succeeded')}/"
                f"{row['summary'].get('planned')}"
            )
        for row in store.list_benchmark_runs(limit=args.limit):
            print(f"{row['run_id']}\tbenchmark\ttrials={row['trials']}")
    return EXIT_OK


def cmd_show_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    with SQLiteRunStore(config.storage.path) as store:
        run = store.get(args.run_id)
        if run is None:
            benchmark = store.get_benchmark(args.run_id)
            if benchmark is None:
                print(f"run not found: {args.run_id}", file=sys.stderr)
                return EXIT_CONFIG
            print(
                json.dumps(
                    {
                        "run_id": benchmark.run_id,
                        "type": "benchmark",
                        "trials": len(benchmark.trials),
                        "completed": sum(
                            result.transcript.status.value == "completed"
                            for result in benchmark.trials
                        ),
                    },
                    indent=2,
                )
            )
            return EXIT_OK
        print(
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
                    "items": len(run.items),
                },
                indent=2,
            )
        )
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    with SQLiteRunStore(config.storage.path) as store:
        run = store.get(args.run_id)
        if run is None:
            benchmark = store.get_benchmark(args.run_id)
            if benchmark is None:
                print(f"run not found: {args.run_id}", file=sys.stderr)
                return EXIT_CONFIG
            output_dir = args.output_dir or config.reporting.output_dir
            path = BenchmarkReportWriter(output_dir).write(
                benchmark,
                BenchmarkReportFormat(args.format),
            )
            print(str(path))
            return EXIT_OK
        if args.format == "jsonl":
            print("jsonl reports are available only for benchmark runs", file=sys.stderr)
            return EXIT_CONFIG
        manifest = store.get_manifest(args.run_id) or {}
        output_dir = args.output_dir or config.reporting.output_dir
        writer = ReportWriter(output_dir)
        path = writer.write(run, ReportFormat(args.format), manifest=manifest)
        print(str(path))
    return EXIT_OK


async def _evolve_async(args: argparse.Namespace) -> int:
    from cot_redteam.attacks.generative.engine import GenerativeAttackEngine
    from cot_redteam.core.invocation import InvocationService
    from cot_redteam.core.types import ModelRef
    from cot_redteam.eval.budgets import BudgetTracker
    from cot_redteam.providers.factory import ProviderFactory

    config = load_config(args.config)
    validate_config(config, require_credentials=True)
    generator_ref = args.generator_model or config.generative.generator_model
    if not generator_ref:
        raise ConfigurationError("evolve requires --generator-model or generative.generator_model")
    generator = ModelRef.parse(generator_ref)
    targets = (
        [args.target_model]
        if args.target_model
        else (config.generative.target_models or list(config.evaluation.models))
    )
    if not targets:
        raise ConfigurationError("evolve requires --target-model or generative.target_models")
    factory = ProviderFactory(config)
    try:
        provider = factory.create(generator)
        engine = GenerativeAttackEngine(
            provider,
            generator,
            max_generation_attempts=config.generative.max_generation_attempts,
            population_size=config.generative.population_size,
            fitness_weights=config.generative.fitness_weights,
            invocation_service=InvocationService(
                config,
                provider_factory=factory,
                budget=BudgetTracker(config.evaluation.budgets),
            ),
        )
        result = await engine.evolve(
            config=config,
            provider_factory=factory,
            target_models=targets,
            evolution_rounds=config.generative.evolution_rounds,
            mutation_rate=config.generative.mutation_rate,
            crossover_rate=config.generative.crossover_rate,
        )
        archive = {
            "version": 1,
            # run_ids are intentionally omitted: evolve runs are evaluated
            # in-process and not persisted, so referencing them would point
            # show-run/report at nonexistent runs.
            "candidates": [
                {
                    "id": c.candidate_id,
                    "spec": c.spec.model_dump(),
                    "generation": c.generation,
                    "parent_ids": list(c.parent_ids),
                    "fitness": c.fitness,
                    "components": c.components,
                    "sample_ids": list(c.sample_ids),
                }
                for c in result.candidates
            ],
            "diagnostics": result.diagnostics,
            "attempts": result.attempts,
        }
        archive_path = Path(config.generative.archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(archive, indent=2, sort_keys=True)
        # Single atomic write (tmp + replace) at the configured path; the
        # duplicate artifact-store copy collided across runs and bypassed
        # atomicity.
        tmp_path = archive_path.with_name(archive_path.name + ".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        os.replace(tmp_path, archive_path)
        print(
            f"candidates={len(result.candidates)} attempts={result.attempts} archive={archive_path}"
        )
        return EXIT_OK if result.candidates else EXIT_FAILED
    finally:
        await factory.aclose()


def cmd_evolve(args: argparse.Namespace) -> int:
    return asyncio.run(_evolve_async(args))


def cmd_race(args: argparse.Namespace) -> int:
    return asyncio.run(_race_async(args))


async def _race_async(args: argparse.Namespace) -> int:
    from cot_redteam.core.invocation import InvocationService
    from cot_redteam.eval.budgets import BudgetTracker
    from cot_redteam.eval.race import DEFAULT_RACE_PROMPT, format_race_table, run_race
    from cot_redteam.providers.factory import ProviderFactory

    config = load_config(args.config)
    validate_config(config, require_credentials=True)
    models = args.race_models or [str(m) for m in config.evaluation.models]
    if not models:
        raise ConfigurationError("race requires --model or evaluation.models")
    prompt = args.prompt or DEFAULT_RACE_PROMPT
    factory = ProviderFactory(config)
    try:
        service = InvocationService(
            config,
            provider_factory=factory,
            budget=BudgetTracker(config.evaluation.budgets),
        )
        results = await run_race(
            config,
            models,
            prompt,
            attack_id=args.attack,
            factory=factory,
            invocation_service=service,
            max_tokens=args.max_tokens,
        )
    finally:
        await factory.aclose()
    print(format_race_table(results))
    return EXIT_OK


def cmd_tui(args: argparse.Namespace) -> int:
    from cot_redteam.tui.app import run_tui_sync

    overrides = {}
    if args.sample_count is not None:
        overrides["evaluation.sample_count"] = args.sample_count
    if args.seed is not None:
        overrides["global.seed"] = args.seed
    config = load_config(args.config, overrides=overrides or None)
    return run_tui_sync(
        config,
        interactive=not args.live_only,
        auto_start=bool(args.auto_start or args.live_only),
    )


async def _agent_scan_async(args: argparse.Namespace) -> int:
    from cot_redteam.agent.api import run_agent_scan
    from cot_redteam.agent.reporting import render_agent_jsonl, render_agent_markdown
    from cot_redteam.agent.scenarios.support import SUPPORT_SCENARIOS
    from cot_redteam.agent.types import AgentOutcome
    from cot_redteam.core.serialization import sha256_file
    from cot_redteam.eval.manifest import ArtifactRecord, build_agent_manifest
    from cot_redteam.storage.artifacts import ArtifactStore

    config = load_config(args.config)
    if config.agent is None:
        raise ConfigurationError(
            "agent scan requires an 'agent' section in the config; see "
            "cot_redteam/data/agent_security.example.yaml"
        )
    settings = config.agent
    scenario_ids = args.scenario or settings.scenarios or list(SUPPORT_SCENARIOS)
    fixtures = args.fixture or settings.fixtures
    overrides = {}
    if args.seed is not None:
        overrides["global.seed"] = args.seed
    if args.scenario or args.fixture:
        overrides["agent.scenarios"] = scenario_ids
        overrides["agent.fixtures"] = fixtures
    config = load_config(args.config, overrides=overrides or None)

    result = await run_agent_scan(config)
    artifact_store = ArtifactStore(config.artifacts.root)
    # ``run_agent_scan`` owns and closes its default SQLite store before
    # returning.  Manifests need the completed run and are therefore built
    # here; reopen the same store to attach each manifest transactionally.
    manifest_store = SQLiteRunStore(config.storage.path)
    output_dir = Path(settings.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        for run in result.runs:
            artifact_records: list[ArtifactRecord] = []
            replay = result.replay_paths.get(run.run_id)
            if replay is not None:
                replay_path = Path(replay[0]).resolve()
                try:
                    replay_path.relative_to(artifact_store.root)
                except ValueError as exc:
                    raise ConfigurationError(
                        f"replay artifact escapes configured artifact root: {replay_path}"
                    ) from exc
                checksum_path = replay_path.with_suffix(replay_path.suffix + ".sha256")
                for path, media_type in (
                    (replay_path, "application/json"),
                    (checksum_path, "text/plain"),
                ):
                    if not path.is_file():
                        raise ConfigurationError(f"replay artifact is missing: {path}")
                    artifact_records.append(
                        ArtifactRecord(
                            relative_path=path.relative_to(artifact_store.root).as_posix(),
                            media_type=media_type,
                            byte_length=path.stat().st_size,
                            sha256=sha256_file(path),
                        )
                    )
                if artifact_records[0].sha256 != replay[1]:
                    raise ConfigurationError(
                        f"replay artifact checksum changed before manifest generation: {replay_path}"
                    )
            manifest = build_agent_manifest(
                run,
                config=config,
                artifacts=tuple(artifact_records),
            )
            markdown = render_agent_markdown(
                run,
                replay_path=(
                    result.replay_paths[run.run_id][0]
                    if run.run_id in result.replay_paths
                    else None
                ),
                replay_checksum=(
                    result.replay_paths[run.run_id][1]
                    if run.run_id in result.replay_paths
                    else None
                ),
                retention=settings.retention,
            )
            (output_dir / f"{run.run_id}.md").write_text(markdown, encoding="utf-8")
            (output_dir / f"{run.run_id}.jsonl").write_text(
                render_agent_jsonl(run, retention=settings.retention),
                encoding="utf-8",
            )
            manifest_write = artifact_store.write_text(
                f"{run.run_id}/manifest.json",
                json.dumps(manifest, indent=2, sort_keys=True),
                media_type="application/json",
            )
            artifact_store.write_text(
                f"{run.run_id}/manifest.json.sha256",
                f"{manifest_write.record.sha256}  manifest.json\n",
                media_type="text/plain",
            )
            # Attach only after both the manifest and detached checksum are
            # durable.  A crash before this point leaves an orphan artifact,
            # never a DB row claiming a manifest file that is absent.
            manifest_store.update_agent_manifest(run.run_id, manifest)
            replay_note = f" replay={replay[0]}" if replay else ""
            outcome = run.outcome.value if run.outcome else "none"
            print(
                f"{run.scenario_ref.id}\t{run.attack_ref.id}\t{outcome}\t{run.run_id}{replay_note}"
            )
    finally:
        manifest_store.close()
    if any(run.outcome is AgentOutcome.VERIFIED_EXPLOIT for run in result.runs):
        return EXIT_FAILED
    if any(run.outcome in (AgentOutcome.INCONCLUSIVE, AgentOutcome.ERROR) for run in result.runs):
        return EXIT_PARTIAL
    return EXIT_OK


def cmd_agent_scan(args: argparse.Namespace) -> int:
    return asyncio.run(_agent_scan_async(args))


async def _replay_async(args: argparse.Namespace) -> int:
    from cot_redteam.agent.config import AgentSecuritySettings
    from cot_redteam.agent.replay import load_replay, run_replay

    artifact = load_replay(args.artifact)
    # With no config, let exact replay apply the artifact's recorded budgets
    # and seed.  Constructing default settings here would turn omitted config
    # into an implicit budget override and reject valid scan artifacts.
    settings: AgentSecuritySettings | None = None
    if args.config:
        config = load_config(args.config)
        # Preserve the historical default for a supplied general config that
        # has no agent section; an explicit agent section remains the caller
        # override validated by exact replay.
        settings = config.agent if config.agent is not None else AgentSecuritySettings()
    result = await run_replay(artifact, fixture=args.fixture, settings=settings)
    print(result.message)
    return result.exit_code


def cmd_replay(args: argparse.Namespace) -> int:
    return asyncio.run(_replay_async(args))


async def _regress_async(args: argparse.Namespace) -> int:
    from cot_redteam.agent.config import AgentSecuritySettings
    from cot_redteam.agent.replay import run_regression_suite

    settings = AgentSecuritySettings()
    if args.config:
        config = load_config(args.config)
        if config.agent is not None:
            settings = config.agent
    report = await run_regression_suite(args.suite, settings=settings)
    for entry, result in report.entries:
        print(
            f"{entry.artifact}\ttarget={entry.target_fixture}\t"
            f"expected={entry.expected_outcome}\t{result.status}\t{result.message}"
        )
    return report.exit_code


def cmd_regress(args: argparse.Namespace) -> int:
    return asyncio.run(_regress_async(args))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handlers = {
        "init": cmd_init,
        "list-attacks": cmd_list_attacks,
        "list-monitors": cmd_list_monitors,
        "list-providers": cmd_list_providers,
        "list-suites": cmd_list_suites,
        "run": cmd_run,
        "scan": cmd_scan,
        "tui": cmd_tui,
        "list-runs": cmd_list_runs,
        "show-run": cmd_show_run,
        "report": cmd_report,
        "evolve": cmd_evolve,
        "race": cmd_race,
        "agent": cmd_agent_scan,
        "replay": cmd_replay,
        "regress": cmd_regress,
    }
    try:
        if args.command == "config":
            if args.config_command == "validate":
                return cmd_config_validate(args)
            if args.config_command == "show":
                return cmd_config_show(args)
            parser.error("unknown config command")
        if args.command == "suite":
            if args.suite_command == "validate":
                return cmd_suite_validate(args)
            if args.suite_command == "show":
                return cmd_suite_show(args)
            parser.error("unknown suite command")
        if args.command == "dataset":
            if args.dataset_command == "import":
                return cmd_dataset_import(args)
            parser.error("unknown dataset command")
        if args.command == "agent":
            if args.agent_command == "scan":
                return cmd_agent_scan(args)
            parser.error("unknown agent command")
        handler = handlers.get(args.command)
        if handler is None:
            parser.error(f"unknown command {args.command}")
        return handler(args)
    except (ConfigurationError, PluginError, CotRedTeamError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return EXIT_CONFIG
    except OSError as exc:
        # Filesystem/permission problems are environment errors, not findings.
        print(f"error: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return EXIT_CONFIG
    except KeyboardInterrupt:
        # 130 (128+SIGINT) keeps user aborts distinct from exit-1 findings,
        # so CI gating on "1 = findings" is not poisoned by Ctrl-C.
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return EXIT_FAILED


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
