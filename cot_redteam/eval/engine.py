"""Asynchronous item and run orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal

from cot_redteam.attacks.base import BaseAttack
from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import BudgetExceededError, ProviderError
from cot_redteam.core.reasoning import extract_visible_reasoning
from cot_redteam.core.types import (
    EvaluationItem,
    EvaluationRun,
    GenerationRequest,
    ItemStatus,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    ReasoningSource,
    RunSummary,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.planner import PlannedItem, RunPlan
from cot_redteam.monitors.base import BaseMonitor
from cot_redteam.plugins.registry import PluginContext, Registry
from cot_redteam.providers.factory import ProviderFactory


class EvaluationEngine:
    def __init__(
        self,
        provider_factory: ProviderFactory,
        attack_registry: Registry[BaseAttack],
        monitor_registry: Registry[BaseMonitor],
        budget: BudgetTracker,
        *,
        concurrency: int,
        config: AppConfig | None = None,
        plugin_context: PluginContext | None = None,
        close_providers: bool = False,
    ) -> None:
        self.provider_factory = provider_factory
        self.attack_registry = attack_registry
        self.monitor_registry = monitor_registry
        self.budget = budget
        self.concurrency = max(1, concurrency)
        self.config = config
        self.close_providers = close_providers
        self._provider_semaphores: dict[str, asyncio.Semaphore] = {}
        self.plugin_context = plugin_context or PluginContext(
            provider_resolver=lambda name: provider_factory.create(
                __import__("cot_redteam.core.types", fromlist=["ModelRef"]).ModelRef(
                    provider=name, model_id="_"
                )
            )
        )

    def _provider_semaphore(self, provider_name: str) -> asyncio.Semaphore:
        if provider_name not in self._provider_semaphores:
            limit = self.concurrency
            if self.config is not None and provider_name in self.config.providers:
                limit = min(limit, max(1, self.config.providers[provider_name].concurrency))
            self._provider_semaphores[provider_name] = asyncio.Semaphore(limit)
        return self._provider_semaphores[provider_name]

    def _estimate_cost(self, provider_name: str, usage: TokenUsage) -> Decimal | None:
        if self.config is None or provider_name not in self.config.providers:
            return None
        settings = self.config.providers[provider_name]
        if settings.input_price_per_million is None and settings.output_price_per_million is None:
            return None
        inp = Decimal(str(settings.input_price_per_million or 0))
        out = Decimal(str(settings.output_price_per_million or 0))
        cost = (Decimal(usage.input_tokens) * inp + Decimal(usage.output_tokens) * out) / Decimal(
            1_000_000
        )
        return cost

    async def run(self, plan: RunPlan) -> EvaluationRun:
        started_at = datetime.now(timezone.utc)
        semaphore = asyncio.Semaphore(self.concurrency)
        results: dict[str, EvaluationItem] = {}
        cancel_remaining = False

        async def run_one(item: PlannedItem) -> EvaluationItem:
            nonlocal cancel_remaining
            async with semaphore:
                if cancel_remaining:
                    return EvaluationItem(
                        item_id=item.item_id,
                        model=item.model,
                        attack_id=item.attack_id,
                        sample_id=item.sample.id,
                        status=ItemStatus.CANCELLED,
                        error="cancelled",
                    )
                async with self._provider_semaphore(item.model.provider):
                    return await self._execute_item(plan, item)

        tasks = [asyncio.create_task(run_one(item)) for item in plan.items]
        try:
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                except (KeyboardInterrupt, SystemExit):
                    cancel_remaining = True
                    raise
                results[result.item_id] = result
                if result.status is ItemStatus.BUDGET_EXCEEDED:
                    cancel_remaining = True
        finally:
            # Ensure unfinished tasks complete as cancelled when budget exceeded.
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if self.close_providers:
                await self.provider_factory.aclose()
            # Collect cancelled results
            for item in plan.items:
                if item.item_id not in results:
                    results[item.item_id] = EvaluationItem(
                        item_id=item.item_id,
                        model=item.model,
                        attack_id=item.attack_id,
                        sample_id=item.sample.id,
                        status=ItemStatus.CANCELLED,
                        error="cancelled",
                    )

        ordered = tuple(results[item.item_id] for item in plan.items)
        summary = RunSummary.from_items(ordered)
        completed_at = datetime.now(timezone.utc)
        return EvaluationRun(
            run_id=plan.run_id,
            status=summary.status,
            items=ordered,
            summary=summary,
            started_at=started_at,
            completed_at=completed_at,
            seed=plan.seed,
            dataset_digest=plan.dataset_digest,
        )

    async def _execute_item(self, plan: RunPlan, item: PlannedItem) -> EvaluationItem:
        started = datetime.now(timezone.utc)
        try:
            attack_cfg: Mapping = {}
            if self.config is not None:
                attack_cfg = self.config.evaluation.attack_config.get(item.attack_id, {})
            attack = self.attack_registry.create(item.attack_id, attack_cfg, self.plugin_context)
            prompt = attack.create_prompt(item.sample)
        except Exception as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.ATTACK_ERROR,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )

        try:
            await self.budget.reserve_request()
        except BudgetExceededError as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.BUDGET_EXCEEDED,
                prompt=prompt,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )

        try:
            provider = self.provider_factory.create(item.model)
            request = GenerationRequest(
                prompt=prompt.text,
                system_prompt=prompt.system_prompt,
                temperature=plan.temperature,
                max_tokens=plan.max_tokens,
            )
            raw_response = await provider.generate(item.model, request)
            reasoning, source = extract_visible_reasoning(
                raw_response.text,
                list(plan.cot_delimiters),
                provider_reasoning=raw_response.reasoning,
            )
            if (
                source is ReasoningSource.ABSENT
                and raw_response.reasoning_source is not ReasoningSource.ABSENT
            ):
                reasoning = raw_response.reasoning
                source = raw_response.reasoning_source
            response = ModelResponse(
                text=raw_response.text,
                model=raw_response.model,
                reasoning=reasoning,
                reasoning_source=source,
                latency_ms=raw_response.latency_ms,
                usage=raw_response.usage,
                provider_request_id=raw_response.provider_request_id,
                finish_reason=raw_response.finish_reason,
                model_revision=raw_response.model_revision,
                metadata=raw_response.metadata,
            )
            cost = self._estimate_cost(item.model.provider, response.usage)
            await self.budget.record_response(response.usage, estimated_cost=cost)
        except BudgetExceededError as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.BUDGET_EXCEEDED,
                prompt=prompt,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )
        except ProviderError as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.PROVIDER_ERROR,
                prompt=prompt,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )
        except Exception as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.PROVIDER_ERROR,
                prompt=prompt,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )

        try:
            assessment = attack.assess(item.sample, prompt, response)
        except Exception as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.ATTACK_ERROR,
                prompt=prompt,
                response=response,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )

        monitor_outcomes: list[MonitorOutcome] = []
        try:
            for monitor_id in plan.monitor_ids:
                mon_cfg = {}
                if self.config is not None:
                    mon_cfg = self.config.evaluation.monitor_config.get(monitor_id, {})
                monitor = self.monitor_registry.create(monitor_id, mon_cfg, self.plugin_context)
                outcome = await monitor.evaluate(prompt, response)
                monitor_outcomes.append(outcome)
        except Exception as exc:
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.MONITOR_ERROR,
                prompt=prompt,
                response=response,
                assessment=assessment,
                monitors=tuple(monitor_outcomes),
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )

        if any(o.status is MonitorStatus.ERROR for o in monitor_outcomes):
            return EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.MONITOR_ERROR,
                prompt=prompt,
                response=response,
                assessment=assessment,
                monitors=tuple(monitor_outcomes),
                error="one or more monitors returned ERROR",
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )

        return EvaluationItem(
            item_id=item.item_id,
            model=item.model,
            attack_id=item.attack_id,
            sample_id=item.sample.id,
            status=ItemStatus.SUCCEEDED,
            prompt=prompt,
            response=response,
            assessment=assessment,
            monitors=tuple(monitor_outcomes),
            started_at=started,
            completed_at=datetime.now(timezone.utc),
        )
