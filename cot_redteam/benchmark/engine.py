"""End-to-end execution engine for planned benchmark trials."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal

from cot_redteam.benchmark.canary import generate_canary
from cot_redteam.benchmark.conversation import (
    ConversationRunner,
    config_error_transcript,
    internal_error_transcript,
)
from cot_redteam.benchmark.judge import JudgeRequest, run_judge
from cot_redteam.benchmark.planner import BenchmarkPlan, PlannedTrial
from cot_redteam.benchmark.preparation import prepare_trial
from cot_redteam.benchmark.results import BenchmarkTrialResult
from cot_redteam.benchmark.scoring import (
    EvidenceChannel,
    ScoringContext,
    TranscriptScoring,
    score_transcript,
)
from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.invocation import InvocationService
from cot_redteam.core.types import ModelRef, TokenUsage
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.providers.factory import ProviderFactory


@dataclass(frozen=True)
class BenchmarkExecution:
    results: tuple[BenchmarkTrialResult, ...]


class BenchmarkEngine:
    def __init__(
        self,
        config: AppConfig,
        factory: ProviderFactory,
        budget: BudgetTracker,
        *,
        invocation_service: InvocationService | None = None,
    ) -> None:
        self.config = config
        self.factory = factory
        self.budget = budget
        self.invocation_service = invocation_service or InvocationService(
            config,
            provider_factory=factory,
            budget=budget,
        )
        self._global = asyncio.Semaphore(config.global_.concurrency)
        self._provider_semaphores: dict[str, asyncio.Semaphore] = {}

    def _provider_semaphore(self, provider_name: str) -> asyncio.Semaphore:
        if provider_name not in self._provider_semaphores:
            provider_limit = self.config.providers[provider_name].concurrency
            self._provider_semaphores[provider_name] = asyncio.Semaphore(
                min(self.config.global_.concurrency, provider_limit)
            )
        return self._provider_semaphores[provider_name]

    def _estimate_cost(self, model: ModelRef, usage: TokenUsage) -> Decimal | None:
        settings = self.config.providers[model.provider]
        if settings.input_price_per_million is None or settings.output_price_per_million is None:
            return None
        million = Decimal(1_000_000)
        return (
            Decimal(usage.input_tokens) * Decimal(str(settings.input_price_per_million)) / million
            + Decimal(usage.output_tokens)
            * Decimal(str(settings.output_price_per_million))
            / million
        )

    async def _judge(
        self,
        trial: PlannedTrial,
        scoring_context: ScoringContext,
        transcript,
    ):
        del scoring_context
        if not self.config.evaluation.judge_model:
            return ()
        judge_model = self.factory.resolve_model(self.config.evaluation.judge_model)
        judge_provider = self.factory.create(judge_model)
        results = []
        configured = set(self.config.evaluation.judge_scorers)
        for spec in trial.scenario.scorers:
            if spec.id not in configured:
                continue
            rubric = spec.config.get("rubric")
            rubric_version = spec.config.get("rubric_version", "1.0.0")
            if not isinstance(rubric, str) or not rubric.strip():
                raise ConfigurationError(f"judge scorer {spec.id!r} requires a non-empty rubric")
            for channel in (EvidenceChannel.FINAL, EvidenceChannel.REASONING):
                parts = []
                for turn in transcript.turns:
                    if turn.response is None:
                        continue
                    value = (
                        turn.response.text
                        if channel is EvidenceChannel.FINAL
                        else turn.response.reasoning
                    )
                    if value is not None:
                        parts.append(value)
                if not parts:
                    continue
                async with self._global, self._provider_semaphore(judge_model.provider):
                    results.append(
                        await run_judge(
                            JudgeRequest(
                                trial_id=trial.trial_id,
                                scorer_id=spec.id,
                                rubric_id=spec.id,
                                rubric_version=str(rubric_version),
                                rubric=rubric,
                                channel=channel,
                                subject="\n\n".join(parts),
                            ),
                            judge_provider,
                            judge_model,
                            self.budget,
                            estimate_cost=self._estimate_cost,
                            invocation_service=self.invocation_service,
                        )
                    )
        return tuple(results)

    async def _run_trial(self, trial: PlannedTrial) -> BenchmarkTrialResult:
        async with self._global, self._provider_semaphore(trial.model.provider):
            canary = generate_canary()
            rogue_string = (
                trial.scenario.objective.target
                or f"COTRT3-ROGUE-{trial.trial_id.rsplit(':', 1)[-1][:12]}"
            )
            prepared = prepare_trial(
                trial,
                canary=canary,
                rogue_string=rogue_string,
                untrusted_content=trial.scenario.task.prompt,
                label=trial.scenario.channel,
            )
            provider = self.factory.create(trial.model)
            transcript = await ConversationRunner(
                self.budget,
                estimate_cost=self._estimate_cost,
                invocation_service=self.invocation_service,
            ).run(
                trial,
                provider,
                initial_messages=prepared.initial_messages,
                scripted_messages=prepared.scripted_messages,
                temperature=self.config.evaluation.temperature,
                max_tokens=self.config.evaluation.max_tokens,
            )
        context = ScoringContext(
            canary=canary,
            rogue_string=rogue_string,
            expected_output=trial.scenario.task.expected_output,
            forbidden_output=trial.scenario.objective.parameters.get("forbidden_output"),
            protected_text=trial.scenario.objective.parameters.get("protected_text"),
        )
        judge_ids = set(self.config.evaluation.judge_scorers)
        deterministic_specs = tuple(
            spec for spec in trial.scenario.scorers if spec.id not in judge_ids
        )
        scoring = score_transcript(transcript, deterministic_specs, context)
        judges = await self._judge(trial, context, transcript)
        if judges:
            scoring = TranscriptScoring(
                trial_id=trial.trial_id,
                outcomes=(
                    *scoring.outcomes,
                    *(judge.outcome for judge in judges),
                ),
            )
        return BenchmarkTrialResult(
            trial=trial,
            transcript=transcript,
            scoring=scoring,
            canary_metadata=canary.manifest_metadata(),
            transformation_digest=prepared.transformation_digest,
            judge_results=judges,
        )

    async def _run_trial_safe(self, trial: PlannedTrial) -> BenchmarkTrialResult:
        """Boundary that converts unexpected trial exceptions into typed
        internal-error evidence instead of aborting the whole run.

        Configuration errors are NOT swallowed: a judge/scorer
        misconfiguration is a user-fixable config problem, so the trial is
        typed CONFIG_ERROR (the CLI maps that to exit 2) while the rest of
        the run keeps its evidence.
        """
        try:
            return await self._run_trial(trial)
        except ConfigurationError as exc:
            return BenchmarkTrialResult(
                trial=trial,
                transcript=config_error_transcript(trial.trial_id, str(exc)[:2000]),
                scoring=TranscriptScoring(trial_id=trial.trial_id, outcomes=()),
                canary_metadata={},
                transformation_digest="",
                judge_results=(),
            )
        except Exception as exc:  # noqa: BLE001 - isolate unexpected trial failures
            return BenchmarkTrialResult(
                trial=trial,
                transcript=internal_error_transcript(trial.trial_id, str(exc)[:2000]),
                scoring=TranscriptScoring(trial_id=trial.trial_id, outcomes=()),
                canary_metadata={},
                transformation_digest="",
                judge_results=(),
            )

    async def run(self, plan: BenchmarkPlan) -> BenchmarkExecution:
        tasks = [asyncio.create_task(self._run_trial_safe(trial)) for trial in plan.trials]
        typed_results: list[BenchmarkTrialResult] = []
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, BaseException):
                # Cancellation or similar; surface it rather than dropping.
                raise result
            typed_results.append(result)
        return BenchmarkExecution(results=tuple(typed_results))
