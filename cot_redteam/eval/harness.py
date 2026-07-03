"""
Evaluation harness with reproducibility guarantees.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, field
import json
import hashlib
import random
import os
from pathlib import Path

from cot_redteam.core.types import (
    AttackCategory, ModelConfig, AttackResult, AttackPrompt,
    ModelResponse, EvalResult, DatasetSample, AttackConfig, MonitorResult
)
from cot_redteam.attacks.base import BaseAttack, AttackRegistry, auto_discover_attacks
from cot_redteam.models.base import BaseModel, ModelRegistry, auto_discover_models
from cot_redteam.monitors.base import BaseMonitor, MonitorRegistry, auto_discover_monitors


@dataclass
class RunConfig:
    """Configuration for a single evaluation run."""
    run_id: str
    seed: int = 42
    model_configs: List[ModelConfig] = field(default_factory=list)
    attack_categories: List[AttackCategory] = field(default_factory=list)
    attack_names: List[str] = field(default_factory=list)
    num_samples: int = 10
    temperature: float = 0.7
    max_tokens: int = 4096
    monitors: List[str] = field(default_factory=list)
    save_prompts: bool = True
    save_responses: bool = True
    save_cot: bool = True
    compute_hash: bool = True
    output_dir: str = "./results"
    artifacts_dir: str = "./artifacts"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "seed": self.seed,
            "models": [m.full_id for m in self.model_configs],
            "attack_categories": [c.value for c in self.attack_categories],
            "attack_names": self.attack_names,
            "num_samples": self.num_samples,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "monitors": self.monitors,
            "save_prompts": self.save_prompts,
            "save_responses": self.save_responses,
            "save_cot": self.save_cot,
            "compute_hash": self.compute_hash,
            "timestamp": datetime.now().isoformat(),
        }


class DatasetLoader:
    """Load evaluation datasets from various formats."""
    
    @staticmethod
    def from_jsonl(path: str) -> List[DatasetSample]:
        """Load dataset from JSONL file."""
        samples = []
        with open(path, "r") as f:
            for i, line in enumerate(f):
                if not line.strip():
                    continue
                data = json.loads(line)
                samples.append(DatasetSample(
                    id=data.get("id", str(i)),
                    question=data["question"],
                    answer=data.get("answer"),
                    cot=data.get("cot"),
                    category=data.get("category"),
                    difficulty=data.get("difficulty"),
                    metadata=data.get("metadata", {}),
                ))
        return samples
    
    @staticmethod
    def from_list(items: List[Dict[str, Any]]) -> List[DatasetSample]:
        """Create dataset from list of dicts."""
        samples = []
        for i, item in enumerate(items):
            samples.append(DatasetSample(
                id=item.get("id", str(i)),
                question=item["question"],
                answer=item.get("answer"),
                cot=item.get("cot"),
                category=item.get("category"),
                difficulty=item.get("difficulty"),
                metadata=item.get("metadata", {}),
            ))
        return samples
    
    @staticmethod
    def to_jsonl(samples: List[DatasetSample], path: str) -> None:
        """Save dataset to JSONL."""
        with open(path, "w") as f:
            for s in samples:
                f.write(json.dumps({
                    "id": s.id,
                    "question": s.question,
                    "answer": s.answer,
                    "cot": s.cot,
                    "category": s.category,
                    "difficulty": s.difficulty,
                    "metadata": s.metadata,
                }) + "\n")


class MetricsCalculator:
    """Compute evaluation metrics."""
    
    @staticmethod
    def attack_success_rate(results: List[AttackResult]) -> float:
        """Fraction of attacks that succeeded."""
        if not results:
            return 0.0
        return sum(1 for r in results if r.success) / len(results)
    
    @staticmethod
    def evasion_rate(results: List[AttackResult]) -> float:
        """Fraction of attacks that evaded all monitors."""
        if not results:
            return 0.0
        evaded = sum(
            1 for r in results
            if all(not v.get("triggered", True) for v in r.monitor_results.values())
        )
        return evaded / len(results)
    
    @staticmethod
    def avg_monitor_confidence(results: List[AttackResult]) -> float:
        """Average monitor confidence across all results."""
        all_confidences = []
        for r in results:
            for v in r.monitor_results.values():
                all_confidences.append(v.get("confidence", 0.0))
        return sum(all_confidences) / len(all_confidences) if all_confidences else 0.0
    
    @staticmethod
    def per_category_breakdown(results: List[AttackResult]) -> Dict[str, Dict[str, float]]:
        """Break down metrics by attack category."""
        by_category: Dict[str, List[AttackResult]] = {}
        for r in results:
            cat = r.attack_prompt.attack_config.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(r)
        
        breakdown = {}
        for cat, cat_results in by_category.items():
            breakdown[cat] = {
                "count": len(cat_results),
                "success_rate": MetricsCalculator.attack_success_rate(cat_results),
                "evasion_rate": MetricsCalculator.evasion_rate(cat_results),
                "avg_monitor_confidence": MetricsCalculator.avg_monitor_confidence(cat_results),
            }
        return breakdown
    
    @staticmethod
    def per_model_breakdown(results: List[AttackResult]) -> Dict[str, Dict[str, float]]:
        """Break down metrics by model."""
        by_model: Dict[str, List[AttackResult]] = {}
        for r in results:
            model_id = r.model_response.model_config.full_id if r.model_response.model_config else "unknown"
            if model_id not in by_model:
                by_model[model_id] = []
            by_model[model_id].append(r)
        
        breakdown = {}
        for model_id, model_results in by_model.items():
            breakdown[model_id] = {
                "count": len(model_results),
                "success_rate": MetricsCalculator.attack_success_rate(model_results),
                "evasion_rate": MetricsCalculator.evasion_rate(model_results),
                "avg_monitor_confidence": MetricsCalculator.avg_monitor_confidence(model_results),
            }
        return breakdown
    
    @staticmethod
    def statistical_significance(
        results_a: List[AttackResult],
        results_b: List[AttackResult]
    ) -> Dict[str, Any]:
        """Compute statistical significance between two sets of results (Fisher's exact test)."""
        from scipy.stats import fisher_exact
        
        a_success = sum(1 for r in results_a if r.success)
        a_fail = len(results_a) - a_success
        b_success = sum(1 for r in results_b if r.success)
        b_fail = len(results_b) - b_success
        
        contingency = [[a_success, a_fail], [b_success, b_fail]]
        odds_ratio, p_value = fisher_exact(contingency)
        
        return {
            "odds_ratio": odds_ratio,
            "p_value": p_value,
            "significant": p_value < 0.05,
            "a_success_rate": a_success / len(results_a) if results_a else 0.0,
            "b_success_rate": b_success / len(results_b) if results_b else 0.0,
        }


class ArtifactManager:
    """Manage reproducibility artifacts."""
    
    def __init__(self, artifacts_dir: str):
        self.artifacts_dir = Path(artifacts_dir)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    def save_artifact(
        self,
        run_id: str,
        name: str,
        content: str,
        artifact_type: str = "json"
    ) -> str:
        """Save an artifact and return its path."""
        artifact_dir = self.artifacts_dir / run_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"{name}.{artifact_type}"
        path = artifact_dir / filename
        
        with open(path, "w") as f:
            if artifact_type == "json":
                json.dump(content if isinstance(content, dict) else {"data": content}, f, indent=2, default=str)
            else:
                f.write(content)
        
        return str(path)
    
    def compute_hash(self, content: str) -> str:
        """Compute SHA256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def save_run_config(self, run_config: RunConfig) -> str:
        """Save run configuration for reproducibility."""
        path = self.save_artifact(
            run_config.run_id,
            "run_config",
            json.dumps(run_config.to_dict(), indent=2),
            "json"
        )
        return path
    
    def save_results(self, run_id: str, results: List[AttackResult]) -> str:
        """Save all attack results as JSONL."""
        lines = []
        for r in results:
            lines.append(json.dumps({
                "attack_name": r.attack_prompt.attack_config.name,
                "attack_category": r.attack_prompt.attack_config.category.value,
                "model": r.model_response.model_config.full_id if r.model_response.model_config else None,
                "prompt": r.attack_prompt.prompt,
                "response": r.model_response.full_response,
                "cot": r.model_response.cot,
                "success": r.success,
                "severity": r.severity.value,
                "evidence": r.evidence,
                "metrics": r.metrics,
                "monitor_results": r.monitor_results,
                "timestamp": r.timestamp.isoformat(),
                "run_id": r.run_id,
            }, default=str))
        
        content = "\n".join(lines)
        path = self.save_artifact(run_id, "results", content, "jsonl")
        
        # Compute hash
        hash_val = self.compute_hash(content)
        self.save_artifact(run_id, "results_hash", hash_val, "txt")
        
        return path


class EvalHarness:
    """
    Main evaluation harness — runs attacks, monitors, and computes metrics.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        # Auto-discover all plugins
        auto_discover_attacks()
        auto_discover_models()
        auto_discover_monitors()
        
        self.metrics = MetricsCalculator()
        self.artifacts = ArtifactManager(
            self.config.get("artifacts_dir", "./artifacts")
        )
    
    def create_run(
        self,
        model_configs: List[ModelConfig],
        attack_categories: Optional[List[AttackCategory]] = None,
        attack_names: Optional[List[str]] = None,
        num_samples: int = 10,
        seed: int = 42,
        monitors: Optional[List[str]] = None,
    ) -> RunConfig:
        """Create a new evaluation run configuration."""
        import uuid
        
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
        
        if attack_categories is None:
            attack_categories = list(AttackCategory)
        
        if monitors is None:
            monitors = ["regex", "llm_judge", "ensemble"]
        
        return RunConfig(
            run_id=run_id,
            seed=seed,
            model_configs=model_configs,
            attack_categories=attack_categories,
            attack_names=attack_names or [],
            num_samples=num_samples,
            monitors=monitors,
        )
    
    def run(
        self,
        run_config: RunConfig,
        dataset: List[DatasetSample],
        verbose: bool = True
    ) -> EvalResult:
        """Run full evaluation."""
        
        # Set seed
        random.seed(run_config.seed)
        
        # Save run config
        self.artifacts.save_run_config(run_config)
        
        all_results: List[AttackResult] = []
        
        # Get all attacks
        attacks = self._get_attacks(run_config)
        
        # Get monitors
        monitor_instances = self._get_monitors(run_config)
        
        if verbose:
            print(f"Run {run_config.run_id}: {len(attacks)} attacks × {len(run_config.model_configs)} models × {min(run_config.num_samples, len(dataset))} samples")
        
        # Run each attack on each model
        for model_config in run_config.model_configs:
            model = ModelRegistry.create(model_config)
            
            for attack in attacks:
                # Sample dataset
                samples = random.sample(
                    dataset, min(run_config.num_samples, len(dataset))
                )
                
                for sample in samples:
                    try:
                        # Run attack
                        attack_result = self._run_single_attack(
                            attack, model, sample, run_config, monitor_instances
                        )
                        all_results.append(attack_result)
                        
                        if verbose:
                            status = "✓" if attack_result.success else "✗"
                            print(f"  {status} {attack.name} on {model_config.full_id} (sample {sample.id})")
                    except Exception as e:
                        if verbose:
                            print(f"  ✗ {attack.name} on {model_config.full_id} ERROR: {e}")
        
        # Compute summary metrics
        summary = {
            "total_attacks": len(all_results),
            "successful_attacks": sum(1 for r in all_results if r.success),
            "attack_success_rate": self.metrics.attack_success_rate(all_results),
            "evasion_rate": self.metrics.evasion_rate(all_results),
            "avg_monitor_confidence": self.metrics.avg_monitor_confidence(all_results),
            "per_category": self.metrics.per_category_breakdown(all_results),
            "per_model": self.metrics.per_model_breakdown(all_results),
        }
        
        # Save artifacts
        results_path = self.artifacts.save_results(run_config.run_id, all_results)
        artifacts_hash = self.artifacts.compute_hash(results_path)
        
        return EvalResult(
            run_id=run_config.run_id,
            model_config=run_config.model_configs[0] if run_config.model_configs else None,
            attack_results=all_results,
            summary=summary,
            completed_at=datetime.now(),
            config_snapshot=run_config.to_dict(),
            artifacts={results_path: "results_jsonl"},
            artifacts_hash=artifacts_hash,
        )
    
    def _get_attacks(self, run_config: RunConfig) -> List[BaseAttack]:
        """Get attack instances for this run."""
        all_attacks = []
        registry = AttackRegistry.get_all()
        
        for key, attack_class in registry.items():
            # Filter by category
            if run_config.attack_categories and attack_class.category not in run_config.attack_categories:
                continue
            
            # Filter by name
            if run_config.attack_names and attack_class.name not in run_config.attack_names:
                continue
            
            all_attacks.append(attack_class(self.config))
        
        return all_attacks
    
    def _get_monitors(self, run_config: RunConfig) -> Dict[str, BaseMonitor]:
        """Get monitor instances for this run."""
        monitors = {}
        for name in run_config.monitors:
            monitor = MonitorRegistry.create(name, self.config.get("monitors", {}).get(name, {}))
            if monitor:
                monitors[name] = monitor
        return monitors
    
    def _run_single_attack(
        self,
        attack: BaseAttack,
        model: BaseModel,
        sample: DatasetSample,
        run_config: RunConfig,
        monitors: Dict[str, BaseMonitor],
    ) -> AttackResult:
        """Run a single attack on a single sample."""
        
        # Generate prompt and get response
        prompt = attack.generate_prompt(sample)
        response_text = model.generate(
            prompt,
            temperature=run_config.temperature,
            max_tokens=run_config.max_tokens,
        )
        
        # Extract CoT
        cot = attack.extract_cot(response_text) if run_config.save_cot else None
        
        # Create model response object
        model_response = ModelResponse(
            full_response=response_text,
            cot=cot,
            model_config=model.config,
        )
        
        # Evaluate attack
        eval_result = attack.evaluate_response(response_text, cot, sample)
        
        # Run monitors
        monitor_results = {}
        for name, monitor in monitors.items():
            try:
                result = monitor.monitor(model_response, prompt)
                monitor_results[name] = {
                    "triggered": result.triggered,
                    "confidence": result.confidence,
                    "explanation": result.explanation,
                }
            except Exception as e:
                monitor_results[name] = {
                    "triggered": False,
                    "confidence": 0.0,
                    "error": str(e),
                }
        
        # Create attack config
        attack_config = AttackConfig(
            category=attack.category,
            name=attack.name,
            description=attack.description,
        )
        
        from cot_redteam.core.types import Severity
        return AttackResult(
            attack_prompt=AttackPrompt(prompt=prompt, attack_config=attack_config),
            model_response=model_response,
            monitor_results=monitor_results,
            success=eval_result.get("success", False),
            severity=Severity.MEDIUM,
            evidence=eval_result.get("evidence", []),
            metrics=eval_result.get("metrics", {}),
            run_id=run_config.run_id,
        )