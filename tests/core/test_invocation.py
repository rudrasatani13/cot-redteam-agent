"""InvocationService role accounting, budget, pricing, and progress tests."""

from __future__ import annotations

import asyncio
import threading
from decimal import Decimal

import pytest

from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import BudgetExceededError, UnknownPricingError
from cot_redteam.core.invocation import (
    InvocationRole,
    InvocationService,
)
from cot_redteam.core.types import (
    GenerationRequest,
    ModelRef,
    ModelResponse,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import RunEvent, RunEventKind


class RecordingProvider:
    def __init__(self, *, mode: str = "ok", usage: TokenUsage | None = None) -> None:
        self.mode = mode
        self.usage = usage or TokenUsage(input_tokens=5, output_tokens=3)
        self.calls: list[tuple[ModelRef, GenerationRequest]] = []
        self.closed = False

    async def generate(self, model: ModelRef, request: GenerationRequest) -> ModelResponse:
        self.calls.append((model, request))
        if self.mode == "fail":
            raise RuntimeError("provider boom")
        return ModelResponse(
            text="ok",
            model=model,
            usage=self.usage,
            provider_request_id=f"p-{len(self.calls)}",
        )

    async def aclose(self) -> None:
        self.closed = True


class BlockingProvider:
    """Provider that sleeps so concurrent invocation bounds can be observed."""

    def __init__(self, *, delay: float = 0.05) -> None:
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()
        self.calls = 0

    async def generate(self, model: ModelRef, request: GenerationRequest) -> ModelResponse:
        self.calls += 1
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(self.delay)
        finally:
            with self.lock:
                self.active -= 1
        return ModelResponse(text="ok", model=model, usage=TokenUsage(1, 1))

    async def aclose(self) -> None:
        return None


class FakeFactory:
    def __init__(self, provider: object) -> None:
        self.provider = provider
        self.created = 0

    def create(self, model: ModelRef):
        self.created += 1
        return self.provider

    async def aclose(self) -> None:
        provider = getattr(self.provider, "aclose", None)
        if provider is not None:
            await provider()


def _config(
    *,
    prices: dict[str, tuple[float, float]] | None = None,
    max_cost: float | None = None,
    max_requests: int | None = None,
    global_concurrency: int = 4,
    provider_concurrency: int = 4,
    provider_kind: str = "vllm",
) -> AppConfig:
    prices = prices or {}
    settings: dict = {
        "kind": provider_kind,
        "base_url": "http://localhost:9999/v1",
        "concurrency": provider_concurrency,
    }
    if provider_kind in prices:
        inp, out = prices[provider_kind]
        settings["input_price_per_million"] = inp
        settings["output_price_per_million"] = out
    budgets: dict = {}
    if max_cost is not None:
        budgets["max_estimated_cost"] = max_cost
    if max_requests is not None:
        budgets["max_requests"] = max_requests
    return AppConfig.model_validate(
        {
            "global": {"concurrency": global_concurrency},
            "providers": {provider_kind: settings},
            "evaluation": {"models": [f"{provider_kind}:m"], "budgets": budgets},
        }
    )


async def _invoke(service: InvocationService, provider: str, role: InvocationRole) -> None:
    await service.invoke(
        model=ModelRef.parse(f"{provider}:m"),
        request=GenerationRequest(prompt="probe"),
        role=role,
        correlation_id="corr-1",
    )


@pytest.mark.asyncio
async def test_role_attribution() -> None:
    config = _config()
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider()),  # type: ignore[arg-type]
    )
    await _invoke(service, "vllm", InvocationRole.TARGET)
    await _invoke(service, "vllm", InvocationRole.ATTACKER)
    await _invoke(service, "vllm", InvocationRole.JUDGE)
    await _invoke(service, "vllm", InvocationRole.MONITOR_JUDGE)
    await _invoke(service, "vllm", InvocationRole.GENERATOR)
    await _invoke(service, "vllm", InvocationRole.RACE)
    snap = service.snapshot()
    assert snap.role_record(InvocationRole.TARGET) is not None
    assert snap.role_record(InvocationRole.TARGET).requests == 1  # type: ignore[union-attr]
    assert snap.role_record(InvocationRole.ATTACKER).requests == 1  # type: ignore[union-attr]
    assert snap.role_record(InvocationRole.JUDGE).requests == 1  # type: ignore[union-attr]
    assert snap.role_record(InvocationRole.MONITOR_JUDGE).requests == 1  # type: ignore[union-attr]
    assert snap.role_record(InvocationRole.GENERATOR).requests == 1  # type: ignore[union-attr]
    assert snap.role_record(InvocationRole.RACE).requests == 1  # type: ignore[union-attr]
    assert snap.total_requests() == 6
    await service.aclose()


@pytest.mark.asyncio
async def test_request_reserved_before_provider_call_and_tokens_recorded() -> None:
    config = _config()
    provider = RecordingProvider()
    service = InvocationService(
        config,
        provider_factory=FakeFactory(provider),  # type: ignore[arg-type]
        budget=BudgetTracker(config.evaluation.budgets),
    )
    await _invoke(service, "vllm", InvocationRole.TARGET)
    assert len(provider.calls) == 1
    snap = service.budget.snapshot()
    assert snap.requests == 1
    assert snap.input_tokens == 5
    assert snap.output_tokens == 3
    await service.aclose()


@pytest.mark.asyncio
async def test_max_requests_rejected() -> None:
    config = _config(max_requests=1)
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider()),  # type: ignore[arg-type]
        budget=BudgetTracker(config.evaluation.budgets),
    )
    await _invoke(service, "vllm", InvocationRole.TARGET)
    with pytest.raises(BudgetExceededError):
        await _invoke(service, "vllm", InvocationRole.TARGET)
    snap = service.snapshot()
    assert snap.role_record(InvocationRole.TARGET).requests == 1  # type: ignore[union-attr]
    await service.aclose()


@pytest.mark.asyncio
async def test_elapsed_budget_rejected() -> None:
    clock = {"t": 0.0}

    def mono() -> float:
        return clock["t"]

    from cot_redteam.core.config import BudgetSettings

    config = _config()
    tracker = BudgetTracker(
        BudgetSettings(max_elapsed_seconds=1.0),
        clock=mono,
    )
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider()),  # type: ignore[arg-type]
        budget=tracker,
    )
    clock["t"] = 100.0
    with pytest.raises(BudgetExceededError, match="elapsed"):
        await _invoke(service, "vllm", InvocationRole.TARGET)
    await service.aclose()


@pytest.mark.asyncio
async def test_known_cost_accounting() -> None:
    config = _config(prices={"vllm": (1.0, 2.0)})
    provider = RecordingProvider(usage=TokenUsage(input_tokens=1_000_000, output_tokens=0))
    service = InvocationService(
        config,
        provider_factory=FakeFactory(provider),  # type: ignore[arg-type]
    )
    await _invoke(service, "vllm", InvocationRole.TARGET)
    record = service.snapshot().role_record(InvocationRole.TARGET)
    assert record is not None
    assert record.estimated_cost == Decimal("1.0")
    assert record.pricing_known is True
    assert service.budget.snapshot().estimated_cost == Decimal("1.0")
    await service.aclose()


@pytest.mark.asyncio
async def test_explicit_zero_pricing_accepted() -> None:
    config = _config(prices={"vllm": (0.0, 0.0)}, max_cost=10.0)
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider()),  # type: ignore[arg-type]
    )
    await _invoke(service, "vllm", InvocationRole.TARGET)
    record = service.snapshot().role_record(InvocationRole.TARGET)
    assert record is not None
    assert record.pricing_known is True
    assert service.budget.snapshot().estimated_cost == Decimal("0")
    await service.aclose()


@pytest.mark.asyncio
async def test_mock_is_known_zero_cost() -> None:
    config = _config(provider_kind="mock", max_cost=5.0)
    factory = FakeFactory(RecordingProvider())  # type: ignore[arg-type]
    service = InvocationService(config, provider_factory=factory)
    await _invoke(service, "mock", InvocationRole.TARGET)
    record = service.snapshot().role_record(InvocationRole.TARGET)
    assert record is not None
    assert record.pricing_known is True
    await service.aclose()


@pytest.mark.asyncio
async def test_unknown_price_with_cost_ceiling_rejects_before_call() -> None:
    config = _config(max_cost=10.0)  # vllm without prices -> unknown
    factory = FakeFactory(RecordingProvider())  # type: ignore[arg-type]
    service = InvocationService(config, provider_factory=factory)
    with pytest.raises(UnknownPricingError):
        await _invoke(service, "vllm", InvocationRole.TARGET)
    assert factory.created == 0
    assert service.budget.snapshot().requests == 0
    await service.aclose()


@pytest.mark.asyncio
async def test_unknown_price_without_ceiling_records_unpriced() -> None:
    config = _config()  # no max cost
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider()),  # type: ignore[arg-type]
    )
    await _invoke(service, "vllm", InvocationRole.TARGET)
    snap = service.snapshot()
    record = snap.role_record(InvocationRole.TARGET)
    assert record is not None
    assert record.pricing_known is False
    assert snap.unpriced_requests == 1
    await service.aclose()


@pytest.mark.asyncio
async def test_provider_failure_records_attempted_request() -> None:
    config = _config()
    provider = RecordingProvider(mode="fail")
    service = InvocationService(
        config,
        provider_factory=FakeFactory(provider),  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="boom"):
        await _invoke(service, "vllm", InvocationRole.TARGET)
    record = service.snapshot().role_record(InvocationRole.TARGET)
    assert record is not None
    assert record.requests == 1
    assert record.failed is True
    assert service.budget.snapshot().requests == 1
    await service.aclose()


@pytest.mark.asyncio
async def test_global_concurrency_bound() -> None:
    config = _config(global_concurrency=1)
    service = InvocationService(
        config,
        provider_factory=FakeFactory(BlockingProvider(delay=0.1)),  # type: ignore[arg-type]
    )
    await asyncio.gather(*[_invoke(service, "vllm", InvocationRole.TARGET) for _ in range(3)])
    provider = service.factory.provider
    assert isinstance(provider, BlockingProvider)
    assert provider.max_active == 1
    await service.aclose()


@pytest.mark.asyncio
async def test_per_provider_concurrency_bound() -> None:
    config = _config(global_concurrency=4, provider_concurrency=1)
    service = InvocationService(
        config,
        provider_factory=FakeFactory(BlockingProvider(delay=0.1)),  # type: ignore[arg-type]
    )
    await asyncio.gather(*[_invoke(service, "vllm", InvocationRole.TARGET) for _ in range(3)])
    provider = service.factory.provider
    assert isinstance(provider, BlockingProvider)
    assert provider.max_active == 1
    await service.aclose()


@pytest.mark.asyncio
async def test_progress_events_carry_no_prompt_text() -> None:
    events: list[RunEvent] = []

    async def collector(event: RunEvent) -> None:
        events.append(event)

    config = _config()
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider()),  # type: ignore[arg-type]
        progress=collector,
    )
    await service.invoke(
        model=ModelRef.parse("vllm:m"),
        request=GenerationRequest(prompt="TOP-SECRET-PROMPT-MARKER"),
        role=InvocationRole.TARGET,
        correlation_id="corr-9",
    )
    kinds = {event.kind for event in events}
    assert RunEventKind.INVOCATION_STARTED in kinds
    assert RunEventKind.INVOCATION_FINISHED in kinds
    serialized = "\n".join(str(event.detail) + event.message for event in events).lower()
    assert "top-secret-prompt-marker" not in serialized
    assert "corr-9" in serialized
    await service.aclose()


@pytest.mark.asyncio
async def test_failed_invocation_emits_failure_progress() -> None:
    events: list[RunEvent] = []

    async def collector(event: RunEvent) -> None:
        events.append(event)

    config = _config()
    service = InvocationService(
        config,
        provider_factory=FakeFactory(RecordingProvider(mode="fail")),  # type: ignore[arg-type]
        progress=collector,
    )
    with pytest.raises(RuntimeError):
        await _invoke(service, "vllm", InvocationRole.TARGET)
    assert any(event.kind is RunEventKind.INVOCATION_FAILED for event in events)
    await service.aclose()
