"""
CLI for CoT Red Teaming Agent.
"""
from __future__ import annotations
import sys
import json
import argparse
from typing import Optional


def main():
    parser = argparse.ArgumentParser(
        prog="cot-redteam",
        description="CoT Red Teaming Agent — Automated Chain-of-Thought vulnerability testing",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # === run ===
    run_parser = subparsers.add_parser("run", help="Run evaluation")
    run_parser.add_argument("--model", "-m", action="append", required=True, help="Model ID (provider:model_id)")
    run_parser.add_argument("--dataset", "-d", required=True, help="Dataset JSONL path")
    run_parser.add_argument("--attacks", "-a", nargs="*", help="Attack categories to run")
    run_parser.add_argument("--monitors", nargs="*", default=["regex", "llm_judge"], help="Monitors to use")
    run_parser.add_argument("--num-samples", "-n", type=int, default=10, help="Number of samples per attack")
    run_parser.add_argument("--seed", type=int, default=42, help="Random seed")
    run_parser.add_argument("--config", default="config.yaml", help="Config file path")
    run_parser.add_argument("--output", "-o", default="./results", help="Output directory")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    # === list-attacks ===
    list_parser = subparsers.add_parser("list-attacks", help="List all registered attacks")
    list_parser.add_argument("--category", "-c", help="Filter by category")
    
    # === list-models ===
    subparsers.add_parser("list-monitors", help="List all registered monitors")
    
    # === list-runs ===
    runs_parser = subparsers.add_parser("list-runs", help="List recent runs")
    runs_parser.add_argument("--limit", type=int, default=20, help="Number of runs to show")
    runs_parser.add_argument("--db", default="./results/cot_redteam.db", help="Database path")
    
    # === show-run ===
    show_parser = subparsers.add_parser("show-run", help="Show details of a run")
    show_parser.add_argument("run_id", help="Run ID to show")
    show_parser.add_argument("--db", default="./results/cot_redteam.db", help="Database path")
    
    # === compare-runs ===
    compare_parser = subparsers.add_parser("compare-runs", help="Compare multiple runs")
    compare_parser.add_argument("run_ids", nargs="+", help="Run IDs to compare")
    compare_parser.add_argument("--db", default="./results/cot_redteam.db", help="Database path")
    
    # === watch-models ===
    watch_parser = subparsers.add_parser("watch-models", help="Watch for new models")
    watch_parser.add_argument("--interval", type=float, default=6, help="Check interval in hours")
    watch_parser.add_argument("--once", action="store_true", help="Check once and exit")
    
    # === evolve ===
    evolve_parser = subparsers.add_parser("evolve", help="Run generative attack evolution")
    evolve_parser.add_argument("--generator-model", "-g", required=True, help="Generator model (provider:model_id)")
    evolve_parser.add_argument("--target-model", "-t", action="append", required=True, help="Target model to evolve against")
    evolve_parser.add_argument("--rounds", "-r", type=int, default=5, help="Number of evolution rounds")
    evolve_parser.add_argument("--population", "-p", type=int, default=20, help="Population size")
    evolve_parser.add_argument("--output", "-o", default="./results/evolved_attacks.json", help="Output file")
    
    # === report ===
    report_parser = subparsers.add_parser("report", help="Generate report from a run")
    report_parser.add_argument("run_id", help="Run ID")
    report_parser.add_argument("--format", "-f", choices=["markdown", "latex", "csv"], default="markdown")
    report_parser.add_argument("--db", default="./results/cot_redteam.db", help="Database path")
    report_parser.add_argument("--output", "-o", default="./results", help="Output directory")
    
    args = parser.parse_args()
    
    if args.command == "run":
        _cmd_run(args)
    elif args.command == "list-attacks":
        _cmd_list_attacks(args)
    elif args.command == "list-monitors":
        _cmd_list_monitors(args)
    elif args.command == "list-runs":
        _cmd_list_runs(args)
    elif args.command == "show-run":
        _cmd_show_run(args)
    elif args.command == "compare-runs":
        _cmd_compare_runs(args)
    elif args.command == "watch-models":
        _cmd_watch_models(args)
    elif args.command == "evolve":
        _cmd_evolve(args)
    elif args.command == "report":
        _cmd_report(args)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_run(args):
    """Run evaluation."""
    from cot_redteam.eval.harness import EvalHarness, RunConfig, DatasetLoader
    from cot_redteam.core.types import ModelConfig, ModelProvider, AttackCategory
    
    # Parse model configs
    model_configs = []
    for model_str in args.model:
        if ":" in model_str:
            provider, model_id = model_str.split(":", 1)
        else:
            provider, model_id = "openrouter", model_str
        
        model_configs.append(ModelConfig(
            provider=ModelProvider(provider),
            model_id=model_id,
        ))
    
    # Parse attack categories
    attack_categories = None
    if args.attacks:
        attack_categories = [AttackCategory(c) for c in args.attacks]
    
    # Load dataset
    dataset = DatasetLoader.from_jsonl(args.dataset)
    
    # Create harness and run
    harness = EvalHarness({"output_dir": args.output, "artifacts_dir": "./artifacts"})
    run_config = harness.create_run(
        model_configs=model_configs,
        attack_categories=attack_categories,
        num_samples=args.num_samples,
        seed=args.seed,
        monitors=args.monitors,
    )
    
    print(f"Starting run: {run_config.run_id}")
    result = harness.run(run_config, dataset, verbose=args.verbose)
    
    print(f"\n{'='*60}")
    print(f"Run completed: {result.run_id}")
    print(f"Total attacks: {result.summary.get('total_attacks', 0)}")
    print(f"Success rate: {result.summary.get('attack_success_rate', 0.0)*100:.1f}%")
    print(f"Evasion rate: {result.summary.get('evasion_rate', 0.0)*100:.1f}%")
    
    # Save to DB
    from cot_redteam.storage.results import ResultsStore
    store = ResultsStore(f"{args.output}/cot_redteam.db")
    store.save_run(result)
    print(f"Results saved to: {args.output}/cot_redteam.db")


def _cmd_list_attacks(args):
    """List all registered attacks."""
    from cot_redteam.attacks.base import AttackRegistry, auto_discover_attacks
    auto_discover_attacks()
    
    all_attacks = AttackRegistry.get_all()
    
    if args.category:
        from cot_redteam.core.types import AttackCategory
        cat = AttackCategory(args.category)
        all_attacks = {k: v for k, v in all_attacks.items() if v.category == cat}
    
    print(f"{'Attack Name':<40} {'Category':<15} {'Description'}")
    print("-" * 90)
    for key, attack_class in sorted(all_attacks.items()):
        print(f"{key:<40} {attack_class.category.value:<15} {attack_class.description[:40]}")


def _cmd_list_monitors(args):
    """List all registered monitors."""
    from cot_redteam.monitors.base import MonitorRegistry, auto_discover_monitors
    auto_discover_monitors()
    
    all_monitors = MonitorRegistry.get_all()
    
    print(f"{'Monitor Name':<30} {'Type':<15} {'Description'}")
    print("-" * 75)
    for key, monitor_class in sorted(all_monitors.items()):
        print(f"{key:<30} {monitor_class.monitor_type.value:<15} {monitor_class.description[:40]}")


def _cmd_list_runs(args):
    """List recent runs."""
    from cot_redteam.storage.results import ResultsStore
    store = ResultsStore(args.db)
    runs = store.list_runs(args.limit)
    
    if not runs:
        print("No runs found.")
        return
    
    print(f"{'Run ID':<40} {'Started':<25} {'Attacks':<10} {'Success Rate'}")
    print("-" * 85)
    for run in runs:
        print(f"{run['run_id']:<40} {str(run['started_at']):<25} {run['total_attacks']:<10} {run['success_rate']*100:.1f}%")


def _cmd_show_run(args):
    """Show details of a run."""
    from cot_redteam.storage.results import ResultsStore
    store = ResultsStore(args.db)
    
    run = store.get_run(args.run_id)
    if not run:
        print(f"Run not found: {args.run_id}")
        return
    
    print(f"Run ID: {run['run_id']}")
    print(f"Started: {run['started_at']}")
    print(f"Completed: {run['completed_at']}")
    print(f"Artifacts hash: {run['artifacts_hash']}")
    print(f"\nSummary:")
    print(json.dumps(run['summary'], indent=2))


def _cmd_compare_runs(args):
    """Compare multiple runs."""
    from cot_redteam.storage.results import ResultsStore
    store = ResultsStore(args.db)
    comparison = store.compare_runs(args.run_ids)
    
    print(json.dumps(comparison, indent=2))


def _cmd_watch_models(args):
    """Watch for new models."""
    import asyncio
    from cot_redteam.scheduler.model_watcher import ModelWatcher
    
    watcher = ModelWatcher()
    
    if args.once:
        all_models = asyncio.run(watcher.check_all())
        new = watcher.get_new_models(all_models)
        
        for provider, models in new.items():
            print(f"\n[{provider}] New models:")
            for m in models:
                print(f"  {m.model_id} (downloads: {m.downloads})")
    else:
        asyncio.run(watcher.watch(interval_hours=args.interval))


def _cmd_evolve(args):
    """Run generative attack evolution."""
    import asyncio
    from cot_redteam.attacks.generative.engine import GenerativeAttackEngine
    from cot_redteam.core.types import ModelConfig, ModelProvider, AttackCategory
    from cot_redteam.eval.harness import DatasetLoader
    
    # Parse generator model
    if ":" in args.generator_model:
        provider, model_id = args.generator_model.split(":", 1)
    else:
        provider, model_id = "openrouter", args.generator_model
    
    generator_config = ModelConfig(provider=ModelProvider(provider), model_id=model_id)
    
    # Parse target models
    target_configs = []
    for model_str in args.target_model:
        if ":" in model_str:
            p, mid = model_str.split(":", 1)
        else:
            p, mid = "openrouter", model_str
        target_configs.append(ModelConfig(provider=ModelProvider(p), model_id=mid))
    
    async def run_evolution():
        engine = GenerativeAttackEngine(
            generator_config,
            {"attacks": {"generative": {
                "evolution_rounds": args.rounds,
                "population_size": args.population,
            }}}
        )
        await engine.initialize()
        
        print("Generating initial population...")
        await engine.generate_initial_population(list(AttackCategory))
        
        for round_num in range(args.rounds):
            print(f"\n=== Evolution Round {round_num+1}/{args.rounds} ===")
            
            # Evaluate
            # Would need dataset samples and monitors here
            # Simplified for CLI
            print(f"  Population: {len(engine.population)}")
            print(f"  Best fitness: {engine.population[0].fitness:.3f}" if engine.population else "  No candidates")
            
            # Evolve
            await engine.evolve_generation()
        
        # Export
        engine.export_attacks(args.output)
        print(f"\nEvolved attacks exported to: {args.output}")
    
    asyncio.run(run_evolution())


def _cmd_report(args):
    """Generate report from a run."""
    from cot_redteam.storage.results import ResultsStore
    from cot_redteam.reporting.report import ReportGenerator
    
    store = ResultsStore(args.db)
    run = store.get_run(args.run_id)
    
    if not run:
        print(f"Run not found: {args.run_id}")
        return
    
    class FakeEval:
        run_id = args.run_id
        summary = run["summary"]
    
    report_gen = ReportGenerator(args.output)
    path = report_gen.save_report(FakeEval(), args.format)
    print(f"Report saved to: {path}")


if __name__ == "__main__":
    main()