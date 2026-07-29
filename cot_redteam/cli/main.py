"""CLI parser, command dispatch, and exit-code mapping."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from cot_redteam import __version__
from cot_redteam.api import run_evaluation
from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.core.config import load_config, redacted_config, validate_config
from cot_redteam.core.errors import ConfigurationError, CotRedTeamError, PluginError
from cot_redteam.core.serialization import canonical_json
from cot_redteam.core.types import RunStatus
from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins
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
        description="CoT Red Team Agent 0.2",
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

    run_p = sub.add_parser("run", help="run evaluation")
    run_p.add_argument("--config", required=True)
    run_p.add_argument("--sample-count", type=int, default=None)
    run_p.add_argument("--seed", type=int, default=None)

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
        choices=["markdown", "csv", "latex"],
        default="markdown",
    )
    report.add_argument("--output-dir", default=None)

    evolve = sub.add_parser("evolve", help="bounded generative attack evolution")
    evolve.add_argument("--config", required=True)
    evolve.add_argument("--generator-model", default=None)
    evolve.add_argument("--target-model", default=None)
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
    print("openrouter")
    print("openai")
    print("anthropic")
    print("vllm")
    print("llamacpp")
    return EXIT_OK


async def _run_async(args: argparse.Namespace) -> int:
    overrides = {}
    if args.sample_count is not None:
        overrides["evaluation.sample_count"] = args.sample_count
    if args.seed is not None:
        overrides["global.seed"] = args.seed
    config = load_config(args.config, overrides=overrides or None)
    validate_config(config, require_credentials=True)
    run = await run_evaluation(config)
    print(
        f"run_id={run.run_id} status={run.status.value} "
        f"planned={run.summary.planned} succeeded={run.summary.succeeded} "
        f"failed={run.summary.failed} cancelled={run.summary.cancelled}"
    )
    if run.status is RunStatus.COMPLETED:
        return EXIT_OK
    if run.status is RunStatus.PARTIAL:
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
    return EXIT_OK


def cmd_show_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    with SQLiteRunStore(config.storage.path) as store:
        run = store.get(args.run_id)
        if run is None:
            print(f"run not found: {args.run_id}", file=sys.stderr)
            return EXIT_CONFIG
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
            print(f"run not found: {args.run_id}", file=sys.stderr)
            return EXIT_CONFIG
        manifest = store.get_manifest(args.run_id) or {}
        output_dir = args.output_dir or config.reporting.output_dir
        writer = ReportWriter(output_dir)
        path = writer.write(run, ReportFormat(args.format), manifest=manifest)
        print(str(path))
    return EXIT_OK


async def _evolve_async(args: argparse.Namespace) -> int:
    from cot_redteam.attacks.generative.engine import GenerativeAttackEngine
    from cot_redteam.core.types import ModelRef
    from cot_redteam.providers.factory import ProviderFactory
    from cot_redteam.storage.artifacts import ArtifactStore

    config = load_config(args.config)
    validate_config(config, require_credentials=True)
    generator = ModelRef.parse(args.generator_model or config.generative.generator_model)
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
            "candidates": [
                {
                    "id": c.candidate_id,
                    "spec": c.spec.model_dump(),
                    "generation": c.generation,
                    "parent_ids": list(c.parent_ids),
                    "fitness": c.fitness,
                    "components": c.components,
                    "run_ids": list(c.run_ids),
                    "sample_ids": list(c.sample_ids),
                }
                for c in result.candidates
            ],
            "diagnostics": result.diagnostics,
            "attempts": result.attempts,
        }
        store = ArtifactStore(config.artifacts.root)
        path = store.write_text(
            Path(config.generative.archive_path).name
            if Path(config.generative.archive_path).name
            else "generative_archive.json",
            json.dumps(archive, indent=2, sort_keys=True),
            media_type="application/json",
        ).absolute_path
        # Also write to configured archive path when absolute/relative differs
        archive_path = Path(config.generative.archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_text(json.dumps(archive, indent=2, sort_keys=True), encoding="utf-8")
        print(
            f"candidates={len(result.candidates)} attempts={result.attempts} "
            f"archive={archive_path} artifact={path}"
        )
        return EXIT_OK if result.candidates else EXIT_FAILED
    finally:
        await factory.aclose()


def cmd_evolve(args: argparse.Namespace) -> int:
    return asyncio.run(_evolve_async(args))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    handlers = {
        "init": cmd_init,
        "list-attacks": cmd_list_attacks,
        "list-monitors": cmd_list_monitors,
        "list-providers": cmd_list_providers,
        "run": cmd_run,
        "list-runs": cmd_list_runs,
        "show-run": cmd_show_run,
        "report": cmd_report,
        "evolve": cmd_evolve,
    }
    try:
        if args.command == "config":
            if args.config_command == "validate":
                return cmd_config_validate(args)
            if args.config_command == "show":
                return cmd_config_show(args)
            parser.error("unknown config command")
        handler = handlers.get(args.command)
        if handler is None:
            parser.error(f"unknown command {args.command}")
        return handler(args)
    except (ConfigurationError, PluginError, CotRedTeamError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return EXIT_CONFIG
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_FAILED
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return EXIT_FAILED


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
