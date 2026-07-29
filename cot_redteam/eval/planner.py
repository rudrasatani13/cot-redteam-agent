"""Plugin/model/sample resolution into immutable plans."""

from __future__ import annotations

from dataclasses import dataclass

from cot_redteam.attacks.base import AttackRegistry
from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import ConfigurationError, PluginError
from cot_redteam.core.types import DatasetSample, ModelRef
from cot_redteam.eval.dataset import Dataset
from cot_redteam.monitors.base import MonitorRegistry
from cot_redteam.plugins.bootstrap import bootstrap_plugins
from cot_redteam.plugins.registry import PluginContext
from cot_redteam.providers.factory import ProviderFactory


@dataclass(frozen=True)
class PlannedItem:
    item_id: str
    model: ModelRef
    attack_id: str
    sample: DatasetSample


@dataclass(frozen=True)
class RunPlan:
    run_id: str
    seed: int
    models: tuple[ModelRef, ...]
    attack_ids: tuple[str, ...]
    monitor_ids: tuple[str, ...]
    samples: tuple[DatasetSample, ...]
    items: tuple[PlannedItem, ...]
    dataset_digest: str
    temperature: float
    max_tokens: int
    cot_delimiters: tuple[str, ...]


class RunPlanner:
    def __init__(
        self,
        config: AppConfig,
        *,
        provider_factory: ProviderFactory,
        dataset: Dataset | None = None,
        run_id: str | None = None,
        plugin_context: PluginContext | None = None,
    ) -> None:
        self.config = config
        self.provider_factory = provider_factory
        self.dataset = dataset
        self.run_id = run_id
        self.plugin_context = plugin_context or PluginContext(
            provider_resolver=lambda name: provider_factory.create(
                ModelRef(provider=name, model_id="_")
            )
        )

    def create(self) -> RunPlan:
        bootstrap_plugins()
        evaluation = self.config.evaluation
        if not evaluation.models:
            raise ConfigurationError("models must not be empty")
        if not evaluation.attacks:
            raise ConfigurationError("attacks must not be empty")
        if not evaluation.monitors:
            raise ConfigurationError("monitors must not be empty")

        models = tuple(self.provider_factory.resolve_model(m) for m in evaluation.models)
        for attack_id in evaluation.attacks:
            if attack_id not in AttackRegistry:
                raise PluginError(
                    f"unknown attack {attack_id!r}. Available: {', '.join(AttackRegistry.ids())}"
                )
        for monitor_id in evaluation.monitors:
            if monitor_id not in MonitorRegistry:
                raise PluginError(
                    f"unknown monitor {monitor_id!r}. Available: {', '.join(MonitorRegistry.ids())}"
                )
            # Validate construction
            mon_cfg = evaluation.monitor_config.get(monitor_id, {})
            MonitorRegistry.create(monitor_id, mon_cfg, self.plugin_context)

        dataset = self.dataset or Dataset.load_jsonl(evaluation.dataset_path)
        samples = dataset.select(
            sample_ids=evaluation.sample_ids,
            sample_count=evaluation.sample_count,
            seed=self.config.global_.seed,
        )
        if not samples:
            raise ConfigurationError("samples must not be empty")

        import uuid

        run_id = self.run_id or str(uuid.uuid4())
        items: list[PlannedItem] = []
        for model in models:
            for attack_id in evaluation.attacks:
                for sample in samples:
                    item_id = f"{run_id}:{model}:{attack_id}:{sample.id}"
                    items.append(
                        PlannedItem(
                            item_id=item_id,
                            model=model,
                            attack_id=attack_id,
                            sample=sample,
                        )
                    )
        return RunPlan(
            run_id=run_id,
            seed=self.config.global_.seed,
            models=models,
            attack_ids=tuple(evaluation.attacks),
            monitor_ids=tuple(evaluation.monitors),
            samples=samples,
            items=tuple(items),
            dataset_digest=dataset.digest,
            temperature=evaluation.temperature,
            max_tokens=evaluation.max_tokens,
            cot_delimiters=tuple(evaluation.cot_delimiters),
        )
