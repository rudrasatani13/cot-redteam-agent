"""Asynchronous item and run orchestration."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal

from cot_redteam.attacks.base import BaseAttack
from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import BudgetExceededError, ProviderError
from cot_redteam.core.reasoning import extract_visible_reasoning
from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    EvaluationItem,
    EvaluationRun,
    GenerationRequest,
    ItemStatus,
    JsonValue,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    ReasoningSource,
    RunSummary,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import ProgressCallback, RunEvent, RunEventKind, emit
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
        progress: ProgressCallback | None = None,
    ) -> None:
        self.provider_factory = provider_factory
        self.attack_registry = attack_registry
        self.monitor_registry = monitor_registry
        self.budget = budget
        self.concurrency = max(1, concurrency)
        self.config = config
        self.close_providers = close_providers
        self.progress = progress
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
        await emit(
            self.progress,
            RunEvent(
                kind=RunEventKind.RUN_STARTED,
                run_id=plan.run_id,
                message=f"planned {len(plan.items)} items",
                detail={
                    "models": [str(m) for m in plan.models],
                    "attacks": list(plan.attack_ids),
                    "planned": len(plan.items),
                },
            ),
        )

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
        run = EvaluationRun(
            run_id=plan.run_id,
            status=summary.status,
            items=ordered,
            summary=summary,
            started_at=started_at,
            completed_at=completed_at,
            seed=plan.seed,
            dataset_digest=plan.dataset_digest,
        )
        await emit(
            self.progress,
            RunEvent(
                kind=RunEventKind.RUN_FINISHED,
                run_id=plan.run_id,
                status=summary.status.value,
                message=(
                    f"planned={summary.planned} succeeded={summary.succeeded} "
                    f"failed={summary.failed} cancelled={summary.cancelled}"
                ),
                detail={
                    "planned": summary.planned,
                    "succeeded": summary.succeeded,
                    "failed": summary.failed,
                    "cancelled": summary.cancelled,
                },
            ),
        )
        return run

    async def _generate_response(
        self,
        plan: RunPlan,
        item: PlannedItem,
        prompt: AttackPrompt,
    ) -> ModelResponse:
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
        return response

    async def _run_monitors(
        self,
        plan: RunPlan,
        prompt: AttackPrompt,
        response: ModelResponse,
    ) -> list[MonitorOutcome]:
        outcomes: list[MonitorOutcome] = []
        for monitor_id in plan.monitor_ids:
            mon_cfg: Mapping = {}
            if self.config is not None:
                mon_cfg = self.config.evaluation.monitor_config.get(monitor_id, {})
            monitor = self.monitor_registry.create(monitor_id, mon_cfg, self.plugin_context)
            outcomes.append(await monitor.evaluate(prompt, response))
        return outcomes

    @staticmethod
    def _with_attempt_metadata(
        prompt: AttackPrompt,
        assessment: AttackAssessment,
        *,
        attempt: int,
        attempts_total: int,
        attempt_history: Sequence[Mapping[str, JsonValue]],
        successful_payload_id: str | None,
    ) -> tuple[AttackPrompt, AttackAssessment]:
        meta = dict(prompt.metadata)
        meta["attempt"] = attempt
        meta["attempts_total"] = attempts_total
        meta["payload_bank_size"] = attempts_total
        meta["attempt_history"] = list(attempt_history)
        if successful_payload_id is not None:
            meta["successful_payload_id"] = successful_payload_id
        enriched_prompt = AttackPrompt(
            attack_id=prompt.attack_id,
            text=prompt.text,
            sample_id=prompt.sample_id,
            system_prompt=prompt.system_prompt,
            metadata=meta,
        )
        metrics = dict(assessment.metrics)
        metrics["attempts_used"] = float(attempt)
        metrics["payload_bank_size"] = float(attempts_total)
        metrics["adaptive_success"] = 1.0 if assessment.success else 0.0
        explanation = assessment.explanation
        if attempts_total > 1:
            payload_id = str(prompt.metadata.get("payload_id") or "unknown")
            if assessment.success:
                explanation = (
                    f"{explanation} Adaptive loop succeeded on attempt {attempt}/"
                    f"{attempts_total} using payload {payload_id!r}."
                )
            else:
                explanation = (
                    f"{explanation} Adaptive loop exhausted {attempt}/{attempts_total} "
                    "payloads without real disclosure."
                )
        enriched_assessment = AttackAssessment(
            success=assessment.success,
            score=assessment.score,
            evidence=assessment.evidence,
            metrics=metrics,
            explanation=explanation,
        )
        return enriched_prompt, enriched_assessment

    async def _execute_item(self, plan: RunPlan, item: PlannedItem) -> EvaluationItem:
        started = datetime.now(timezone.utc)
        await emit(
            self.progress,
            RunEvent(
                kind=RunEventKind.ITEM_STARTED,
                run_id=plan.run_id,
                item_id=item.item_id,
                model=str(item.model),
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                message=f"starting {item.attack_id} on {item.model}",
            ),
        )
        try:
            attack_cfg: Mapping = {}
            if self.config is not None:
                attack_cfg = self.config.evaluation.attack_config.get(item.attack_id, {})
            attack = self.attack_registry.create(item.attack_id, attack_cfg, self.plugin_context)
            prompts = list(attack.create_prompts(item.sample))
            if not prompts:
                raise ValueError("attack returned zero prompts")
        except Exception as exc:
            result = EvaluationItem(
                item_id=item.item_id,
                model=item.model,
                attack_id=item.attack_id,
                sample_id=item.sample.id,
                status=ItemStatus.ATTACK_ERROR,
                error=str(exc),
                started_at=started,
                completed_at=datetime.now(timezone.utc),
            )
            await self._emit_item_finished(plan, result)
            return result

        stop_on_success = attack.stop_on_success
        attempt_history: list[dict[str, JsonValue]] = []
        last_prompt: AttackPrompt | None = None
        last_response: ModelResponse | None = None
        last_assessment: AttackAssessment | None = None
        successful_payload_id: str | None = None

        for attempt_index, prompt in enumerate(prompts, start=1):
            last_prompt = prompt
            payload_id = str(prompt.metadata.get("payload_id") or f"attempt_{attempt_index}")
            await emit(
                self.progress,
                RunEvent(
                    kind=RunEventKind.ATTEMPT_STARTED,
                    run_id=plan.run_id,
                    item_id=item.item_id,
                    model=str(item.model),
                    attack_id=item.attack_id,
                    sample_id=item.sample.id,
                    payload_id=payload_id,
                    attempt=attempt_index,
                    attempts_total=len(prompts),
                    message=f"trying payload {payload_id} ({attempt_index}/{len(prompts)})",
                ),
            )
            try:
                await self.budget.reserve_request()
            except BudgetExceededError as exc:
                result = EvaluationItem(
                    item_id=item.item_id,
                    model=item.model,
                    attack_id=item.attack_id,
                    sample_id=item.sample.id,
                    status=ItemStatus.BUDGET_EXCEEDED,
                    prompt=prompt,
                    response=last_response,
                    assessment=last_assessment,
                    error=str(exc),
                    started_at=started,
                    completed_at=datetime.now(timezone.utc),
                )
                await self._emit_item_finished(plan, result)
                return result

            try:
                response = await self._generate_response(plan, item, prompt)
            except BudgetExceededError as exc:
                result = EvaluationItem(
                    item_id=item.item_id,
                    model=item.model,
                    attack_id=item.attack_id,
                    sample_id=item.sample.id,
                    status=ItemStatus.BUDGET_EXCEEDED,
                    prompt=prompt,
                    response=last_response,
                    assessment=last_assessment,
                    error=str(exc),
                    started_at=started,
                    completed_at=datetime.now(timezone.utc),
                )
                await self._emit_item_finished(plan, result)
                return result
            except ProviderError as exc:
                result = EvaluationItem(
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
                await self._emit_item_finished(plan, result)
                return result
            except Exception as exc:
                result = EvaluationItem(
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
                await self._emit_item_finished(plan, result)
                return result

            last_response = response
            try:
                assessment = attack.assess(item.sample, prompt, response)
            except Exception as exc:
                result = EvaluationItem(
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
                await self._emit_item_finished(plan, result)
                return result

            last_assessment = assessment
            attempt_history.append(
                {
                    "attempt": attempt_index,
                    "payload_id": payload_id,
                    "success": assessment.success,
                    "score": assessment.score,
                    "evidence": list(assessment.evidence),
                    "refusal_analysis_with_canary_quote": float(
                        assessment.metrics.get("refusal_analysis_with_canary_quote", 0.0)
                    ),
                }
            )
            await emit(
                self.progress,
                RunEvent(
                    kind=RunEventKind.ATTEMPT_FINISHED,
                    run_id=plan.run_id,
                    item_id=item.item_id,
                    model=str(item.model),
                    attack_id=item.attack_id,
                    sample_id=item.sample.id,
                    payload_id=payload_id,
                    attempt=attempt_index,
                    attempts_total=len(prompts),
                    success=assessment.success,
                    message=(
                        f"payload {payload_id}: "
                        f"{'SUCCESS' if assessment.success else 'fail'}"
                    ),
                    tokens_input=response.usage.input_tokens,
                    tokens_output=response.usage.output_tokens,
                    evidence=assessment.evidence,
                    detail={
                        "score": assessment.score,
                        "explanation": assessment.explanation,
                        "response_preview": (response.text or "")[:400],
                        "reasoning_preview": (response.reasoning or "")[:400],
                        "refusal_analysis_with_canary_quote": float(
                            assessment.metrics.get("refusal_analysis_with_canary_quote", 0.0)
                        ),
                    },
                ),
            )
            if assessment.success:
                successful_payload_id = payload_id
                if stop_on_success:
                    break

        assert last_prompt is not None
        assert last_response is not None
        assert last_assessment is not None

        prompt, assessment = self._with_attempt_metadata(
            last_prompt,
            last_assessment,
            attempt=len(attempt_history),
            attempts_total=len(prompts),
            attempt_history=attempt_history,
            successful_payload_id=successful_payload_id,
        )
        response = last_response

        monitor_outcomes: list[MonitorOutcome] = []
        try:
            monitor_outcomes = await self._run_monitors(plan, prompt, response)
        except Exception as exc:
            result = EvaluationItem(
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
            await self._emit_item_finished(plan, result)
            return result

        if any(o.status is MonitorStatus.ERROR for o in monitor_outcomes):
            result = EvaluationItem(
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
            await self._emit_item_finished(plan, result)
            return result

        result = EvaluationItem(
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
        await self._emit_item_finished(plan, result)
        return result

    async def _emit_item_finished(self, plan: RunPlan, result: EvaluationItem) -> None:
        success = bool(result.assessment and result.assessment.success)
        await emit(
            self.progress,
            RunEvent(
                kind=RunEventKind.ITEM_FINISHED,
                run_id=plan.run_id,
                item_id=result.item_id,
                model=str(result.model),
                attack_id=result.attack_id,
                sample_id=result.sample_id,
                status=result.status.value,
                success=success if result.status is ItemStatus.SUCCEEDED else None,
                payload_id=(
                    str(result.prompt.metadata.get("successful_payload_id") or "")
                    if result.prompt and result.prompt.metadata.get("successful_payload_id")
                    else (
                        str(result.prompt.metadata.get("payload_id"))
                        if result.prompt
                        else None
                    )
                ),
                message=result.error or result.status.value,
                evidence=result.assessment.evidence if result.assessment else (),
                detail={
                    "attempts_used": (
                        float(result.assessment.metrics.get("attempts_used", 0))
                        if result.assessment
                        else 0.0
                    )
                },
            ),
        )
