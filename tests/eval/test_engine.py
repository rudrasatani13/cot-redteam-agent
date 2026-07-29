"""Evaluation engine outcome tests."""

from __future__ import annotations

import pytest

from cot_redteam.attacks.base import AttackRegistry, BaseAttack
from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import PermanentProviderError
from cot_redteam.core.types import (
    AttackAssessment,
    AttackPrompt,
    DatasetSample,
    GenerationRequest,
    ItemStatus,
    ModelRef,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    RunStatus,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.engine import EvaluationEngine
from cot_redteam.eval.planner import PlannedItem, RunPlan
from cot_redteam.monitors.base import BaseMonitor, MonitorRegistry
from cot_redteam.plugins.registry import PluginMetadata


class FakeProvider:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.closed = False
        self.n = 0

    async def generate(self, model: ModelRef, request: GenerationRequest) -> ModelResponse:
        self.n += 1
        if self.mode == "fail":
            raise PermanentProviderError("boom")
        if self.mode == "mixed" and self.n == 1:
            raise PermanentProviderError("transient-ish permanent")
        return ModelResponse(
            text="ok",
            model=model,
            usage=TokenUsage(1, 1),
            provider_request_id="r1",
        )

    async def aclose(self) -> None:
        self.closed = True


class FakeFactory:
    def __init__(self, provider: FakeProvider) -> None:
        self.provider = provider

    def create(self, model: ModelRef):
        return self.provider

    async def aclose(self) -> None:
        await self.provider.aclose()


class _OkAttack(BaseAttack):
    metadata = PluginMetadata(id="test.ok_attack", version="1.0.0", description="ok")

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        return AttackPrompt(attack_id=self.metadata.id, text=sample.question, sample_id=sample.id)

    def assess(self, sample, prompt, response) -> AttackAssessment:
        return AttackAssessment(success=True, score=1.0, evidence=("ok",))


class _OkMonitor(BaseMonitor):
    metadata = PluginMetadata(id="test.ok_monitor", version="1.0.0", description="ok")

    async def evaluate(self, prompt, response) -> MonitorOutcome:
        return MonitorOutcome(
            monitor_id=self.metadata.id,
            status=MonitorStatus.CLEAN,
            confidence=0.1,
            explanation="clean",
        )


class _ErrorMonitor(BaseMonitor):
    metadata = PluginMetadata(id="test.err_monitor", version="1.0.0", description="err")

    async def evaluate(self, prompt, response) -> MonitorOutcome:
        raise RuntimeError("monitor boom")


@pytest.fixture(autouse=True)
def _register_fakes() -> None:
    AttackRegistry.clear()
    MonitorRegistry.clear()
    AttackRegistry.register(
        _OkAttack.metadata,
        lambda config, context: _OkAttack(config),
    )
    MonitorRegistry.register(
        _OkMonitor.metadata,
        lambda config, context: _OkMonitor(config, context=context),
    )
    MonitorRegistry.register(
        _ErrorMonitor.metadata,
        lambda config, context: _ErrorMonitor(config, context=context),
    )
    yield
    AttackRegistry.clear()
    MonitorRegistry.clear()


def _plan(monitor_ids=("test.ok_monitor",), n: int = 1) -> RunPlan:
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    items = tuple(
        PlannedItem(
            item_id=f"item-{i}",
            model=model,
            attack_id="test.ok_attack",
            sample=sample,
        )
        for i in range(n)
    )
    return RunPlan(
        run_id="run-1",
        seed=1,
        models=(model,),
        attack_ids=("test.ok_attack",),
        monitor_ids=monitor_ids,
        samples=(sample,),
        items=items,
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )


@pytest.mark.asyncio
async def test_all_succeed_completed() -> None:
    factory = FakeFactory(FakeProvider("ok"))
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=2
    )
    run = await engine.run(_plan())
    assert run.status is RunStatus.COMPLETED
    # Engine does not own provider lifecycle unless close_providers=True.
    assert factory.provider.closed is False
    await factory.aclose()
    assert factory.provider.closed is True


@pytest.mark.asyncio
async def test_all_provider_fail() -> None:
    factory = FakeFactory(FakeProvider("fail"))
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    run = await engine.run(_plan())
    assert run.status is RunStatus.FAILED
    assert all(i.status is ItemStatus.PROVIDER_ERROR for i in run.items)


@pytest.mark.asyncio
async def test_mixed_partial() -> None:
    factory = FakeFactory(FakeProvider("mixed"))
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    run = await engine.run(_plan(n=2))
    assert run.status is RunStatus.PARTIAL


@pytest.mark.asyncio
async def test_monitor_exception() -> None:
    factory = FakeFactory(FakeProvider("ok"))
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    run = await engine.run(_plan(monitor_ids=("test.err_monitor",)))
    assert run.items[0].status is ItemStatus.MONITOR_ERROR


@pytest.mark.asyncio
async def test_budget_exceeded() -> None:
    factory = FakeFactory(FakeProvider("ok"))
    engine = EvaluationEngine(
        factory,
        AttackRegistry,
        MonitorRegistry,
        BudgetTracker(BudgetSettings(max_requests=1)),
        concurrency=1,
    )
    run = await engine.run(_plan(n=3))
    statuses = {i.status for i in run.items}
    assert ItemStatus.BUDGET_EXCEEDED in statuses or ItemStatus.CANCELLED in statuses


class _BoomAttack(BaseAttack):
    metadata = PluginMetadata(id="test.boom_attack", version="1.0.0", description="boom")

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        raise RuntimeError("prompt boom")

    def assess(self, sample, prompt, response) -> AttackAssessment:
        return AttackAssessment(success=False, score=0.0)


class _AssessBoomAttack(BaseAttack):
    metadata = PluginMetadata(id="test.assess_boom", version="1.0.0", description="assess boom")

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        return AttackPrompt(attack_id=self.metadata.id, text=sample.question, sample_id=sample.id)

    def assess(self, sample, prompt, response) -> AttackAssessment:
        raise RuntimeError("assess boom")


@pytest.mark.asyncio
async def test_attack_prompt_error() -> None:
    AttackRegistry.register(
        _BoomAttack.metadata,
        lambda config, context: _BoomAttack(config),
    )
    factory = FakeFactory(FakeProvider("ok"))
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    plan = RunPlan(
        run_id="run-boom",
        seed=1,
        models=(model,),
        attack_ids=("test.boom_attack",),
        monitor_ids=("test.ok_monitor",),
        samples=(sample,),
        items=(
            PlannedItem(
                item_id="item-0",
                model=model,
                attack_id="test.boom_attack",
                sample=sample,
            ),
        ),
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )
    run = await engine.run(plan)
    assert run.items[0].status is ItemStatus.ATTACK_ERROR


@pytest.mark.asyncio
async def test_attack_assess_error() -> None:
    AttackRegistry.register(
        _AssessBoomAttack.metadata,
        lambda config, context: _AssessBoomAttack(config),
    )
    factory = FakeFactory(FakeProvider("ok"))
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    plan = RunPlan(
        run_id="run-assess",
        seed=1,
        models=(model,),
        attack_ids=("test.assess_boom",),
        monitor_ids=("test.ok_monitor",),
        samples=(sample,),
        items=(
            PlannedItem(
                item_id="item-0",
                model=model,
                attack_id="test.assess_boom",
                sample=sample,
            ),
        ),
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )
    run = await engine.run(plan)
    assert run.items[0].status is ItemStatus.ATTACK_ERROR


class _AdaptiveAttack(BaseAttack):
    """Fails until the third payload — models educational stop-on-success loops."""

    metadata = PluginMetadata(
        id="test.adaptive_attack",
        version="1.0.0",
        description="adaptive multi-payload",
    )

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        return self.create_prompts(sample)[0]

    def create_prompts(self, sample: DatasetSample):
        return tuple(
            AttackPrompt(
                attack_id=self.metadata.id,
                text=f"{sample.question} :: payload-{i}",
                sample_id=sample.id,
                metadata={"payload_id": f"p{i}", "adaptive": True},
            )
            for i in range(1, 5)
        )

    def assess(self, sample, prompt, response) -> AttackAssessment:
        del sample, response
        payload_id = str(prompt.metadata.get("payload_id"))
        success = payload_id == "p3"
        return AttackAssessment(
            success=success,
            score=1.0 if success else 0.0,
            evidence=(f"matched {payload_id}",) if success else (),
        )


class _CountingProvider:
    def __init__(self) -> None:
        self.n = 0
        self.prompts: list[str] = []

    async def generate(self, model: ModelRef, request: GenerationRequest) -> ModelResponse:
        self.n += 1
        self.prompts.append(request.prompt or "")
        return ModelResponse(text="ok", model=model, usage=TokenUsage(1, 1))

    async def aclose(self) -> None:
        return None


class _CountingFactory:
    def __init__(self, provider: _CountingProvider) -> None:
        self.provider = provider

    def create(self, model: ModelRef):
        return self.provider

    async def aclose(self) -> None:
        await self.provider.aclose()


@pytest.mark.asyncio
async def test_engine_emits_progress_events_for_adaptive_loop() -> None:
    AttackRegistry.register(
        _AdaptiveAttack.metadata,
        lambda config, context: _AdaptiveAttack(config),
    )
    events: list[str] = []

    async def progress(event) -> None:
        events.append(event.kind.value)

    provider = _CountingProvider()
    factory = _CountingFactory(provider)
    engine = EvaluationEngine(
        factory,
        AttackRegistry,
        MonitorRegistry,
        BudgetTracker(BudgetSettings()),
        concurrency=1,
        progress=progress,
    )
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    plan = RunPlan(
        run_id="run-events",
        seed=1,
        models=(model,),
        attack_ids=("test.adaptive_attack",),
        monitor_ids=("test.ok_monitor",),
        samples=(sample,),
        items=(
            PlannedItem(
                item_id="item-0",
                model=model,
                attack_id="test.adaptive_attack",
                sample=sample,
            ),
        ),
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )
    await engine.run(plan)
    assert events[0] == "run_started"
    assert "attempt_started" in events
    assert "attempt_finished" in events
    assert events[-1] == "run_finished"


class _AgenticAttack(BaseAttack):
    metadata = PluginMetadata(
        id="test.agentic_attack",
        version="1.0.0",
        description="invents after seed fails",
    )

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        return self.create_prompts(sample)[0]

    def create_prompts(self, sample: DatasetSample):
        return (
            AttackPrompt(
                attack_id=self.metadata.id,
                text=f"{sample.question} seed",
                sample_id=sample.id,
                metadata={"payload_id": "seed", "adaptive": True},
            ),
        )

    @property
    def is_agentic(self) -> bool:
        return True

    @property
    def max_attempts(self) -> int:
        return 4

    def next_prompt_after_failure(self, sample, history, *, max_attempts=None):
        del max_attempts
        used = {str(row.get("payload_id")) for row in history}
        if "invented_1" not in used:
            return AttackPrompt(
                attack_id=self.metadata.id,
                text=f"{sample.question} invented",
                sample_id=sample.id,
                metadata={"payload_id": "invented_1", "invented": True},
            )
        return None

    def assess(self, sample, prompt, response) -> AttackAssessment:
        del sample, response
        success = prompt.metadata.get("payload_id") == "invented_1"
        return AttackAssessment(
            success=success,
            score=1.0 if success else 0.0,
            evidence=("invented worked",) if success else (),
            explanation="[defense=hard_refuse]",
        )


@pytest.mark.asyncio
async def test_agentic_loop_invents_after_seed_fails() -> None:
    AttackRegistry.register(
        _AgenticAttack.metadata,
        lambda config, context: _AgenticAttack(config),
    )
    provider = _CountingProvider()
    factory = _CountingFactory(provider)
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    plan = RunPlan(
        run_id="run-agentic",
        seed=1,
        models=(model,),
        attack_ids=("test.agentic_attack",),
        monitor_ids=("test.ok_monitor",),
        samples=(sample,),
        items=(
            PlannedItem(
                item_id="item-0",
                model=model,
                attack_id="test.agentic_attack",
                sample=sample,
            ),
        ),
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )
    run = await engine.run(plan)
    assert run.items[0].assessment is not None
    assert run.items[0].assessment.success is True
    assert provider.n == 2  # seed fail + invented success
    assert run.items[0].prompt is not None
    assert run.items[0].prompt.metadata["successful_payload_id"] == "invented_1"
    history = run.items[0].prompt.metadata["attempt_history"]
    assert history[0]["success"] is False
    assert history[1]["invented"] is True


@pytest.mark.asyncio
async def test_adaptive_loop_stops_on_first_real_success() -> None:
    AttackRegistry.register(
        _AdaptiveAttack.metadata,
        lambda config, context: _AdaptiveAttack(config),
    )
    provider = _CountingProvider()
    factory = _CountingFactory(provider)
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    plan = RunPlan(
        run_id="run-adaptive",
        seed=1,
        models=(model,),
        attack_ids=("test.adaptive_attack",),
        monitor_ids=("test.ok_monitor",),
        samples=(sample,),
        items=(
            PlannedItem(
                item_id="item-0",
                model=model,
                attack_id="test.adaptive_attack",
                sample=sample,
            ),
        ),
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )

    run = await engine.run(plan)

    assert run.items[0].status is ItemStatus.SUCCEEDED
    assert run.items[0].assessment is not None
    assert run.items[0].assessment.success is True
    # p1 fail, p2 fail, p3 success -> stop (no p4)
    assert provider.n == 3
    assert run.items[0].prompt is not None
    assert run.items[0].prompt.metadata["successful_payload_id"] == "p3"
    assert run.items[0].prompt.metadata["attempt"] == 3
    assert run.items[0].assessment.metrics["attempts_used"] == 3.0
    history = run.items[0].prompt.metadata["attempt_history"]
    assert len(history) == 3
    assert history[0]["success"] is False
    assert history[2]["success"] is True


@pytest.mark.asyncio
async def test_adaptive_loop_can_exhaust_bank_without_false_success() -> None:
    class _AlwaysFailAdaptive(_AdaptiveAttack):
        metadata = PluginMetadata(
            id="test.adaptive_fail_attack",
            version="1.0.0",
            description="always fail adaptive",
        )

        def assess(self, sample, prompt, response) -> AttackAssessment:
            del sample, prompt, response
            return AttackAssessment(success=False, score=0.0)

    AttackRegistry.register(
        _AlwaysFailAdaptive.metadata,
        lambda config, context: _AlwaysFailAdaptive(config),
    )
    provider = _CountingProvider()
    factory = _CountingFactory(provider)
    engine = EvaluationEngine(
        factory, AttackRegistry, MonitorRegistry, BudgetTracker(BudgetSettings()), concurrency=1
    )
    sample = DatasetSample(id="s1", question="q")
    model = ModelRef.parse("fake:m")
    plan = RunPlan(
        run_id="run-adaptive-fail",
        seed=1,
        models=(model,),
        attack_ids=("test.adaptive_fail_attack",),
        monitor_ids=("test.ok_monitor",),
        samples=(sample,),
        items=(
            PlannedItem(
                item_id="item-0",
                model=model,
                attack_id="test.adaptive_fail_attack",
                sample=sample,
            ),
        ),
        dataset_digest="d",
        temperature=0.0,
        max_tokens=16,
        cot_delimiters=("<think>", "</think>"),
    )

    run = await engine.run(plan)

    assert run.items[0].status is ItemStatus.SUCCEEDED
    assert run.items[0].assessment is not None
    assert run.items[0].assessment.success is False
    assert provider.n == 4
    assert "exhausted" in run.items[0].assessment.explanation.lower()
