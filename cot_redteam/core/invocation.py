"""Central logical model-invocation boundary and role accounting.

``InvocationService`` is the single place every built-in logical model call
routes through. It owns provider construction, shared budget reservation,
per-provider and global concurrency, role attribution, pricing policy, and
progress events. Provider transport retries remain inside provider
implementations; each top-level ``Provider.generate`` attempt made above the
provider boundary (including semantic retries such as a judge re-request
after invalid JSON) counts as one logical invocation.

Pricing semantics:

- the ``mock`` provider is explicitly known zero-cost;
- a provider with both input and output prices explicitly configured
  (including explicit ``0.0``) has known pricing;
- a provider missing either price has unknown pricing;
- when ``max_estimated_cost`` is configured and pricing is unknown, the
  invocation is rejected before the provider call with
  ``UnknownPricingError``;
- without a cost ceiling, unknown-priced calls proceed but are recorded as
  ``pricing_known=false`` and counted in ``unpriced_requests``; they are
  never displayed as a known zero cost. Failed invocations with unknown
  pricing are counted in ``unpriced_requests`` too.

Wire-request accounting:

- provider transports retry transient HTTP failures internally, so one
  logical invocation can issue several wire requests (up to
  ``1 + max_retries``);
- providers report the per-call wire-request count via the
  ``wire_attempts`` response metadata field and the
  ``last_wire_attempts`` attribute (see ``providers.base``);
- the ledger records actual wire requests in
  ``InvocationRecord.requests`` and emits them in invocation events,
  while ``BudgetTracker`` continues to count logical requests against
  ``max_requests`` — the undercount margin is therefore bounded by
  ``max_retries`` wire requests per logical invocation;
- tokens and estimated cost come from the final successful attempt only.

Cost semantics: ``InvocationService.estimate_cost`` is the canonical
pricing path (including cache-token billing). Legacy local estimators
elsewhere (e.g. the eval engine fallback used when no service is wired)
may diverge and must not be treated as authoritative.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from cot_redteam.core.config import AppConfig
from cot_redteam.core.errors import ConfigurationError, UnknownPricingError
from cot_redteam.core.types import GenerationRequest, ModelRef, ModelResponse, TokenUsage
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.eval.events import (
    ProgressCallback,
    RunEvent,
    RunEventKind,
    emit,
)
from cot_redteam.providers.base import Provider
from cot_redteam.providers.factory import ProviderFactory

CostEstimator = Callable[[ModelRef, TokenUsage], Decimal | None]


def _wire_attempts(provider: object, response: ModelResponse | None) -> int:
    """Actual wire requests for the most recent provider call.

    Providers with transport retries report the per-call count via the
    ``wire_attempts`` response metadata field (accurate per call) and the
    ``last_wire_attempts`` attribute; the failure path only has the
    attribute. Providers without transport retries — and plugin or test
    doubles — fall back to 1, matching the single logical request.
    """
    if response is not None:
        value = response.metadata.get("wire_attempts")
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            return value
    attempts = getattr(provider, "last_wire_attempts", None)
    if isinstance(attempts, int) and not isinstance(attempts, bool) and attempts >= 1:
        return attempts
    return 1


class InvocationRole(str, Enum):
    """Attribution role for a logical model invocation."""

    TARGET = "target"
    ATTACKER = "attacker"
    JUDGE = "judge"
    MONITOR_JUDGE = "monitor_judge"
    GENERATOR = "generator"
    RACE = "race"


@dataclass(frozen=True)
class PricingPolicy:
    """Explicit provider pricing; ``None`` prices mean unknown."""

    input_price_per_million: Decimal | None
    output_price_per_million: Decimal | None

    @property
    def known(self) -> bool:
        return (
            self.input_price_per_million is not None and self.output_price_per_million is not None
        )


@dataclass(frozen=True)
class InvocationRecord:
    """Per-role aggregate accounting record."""

    role: InvocationRole
    provider: str
    model_id: str
    correlation_id: str | None
    requests: int
    input_tokens: int
    output_tokens: int
    estimated_cost: Decimal
    pricing_known: bool
    failed: bool


@dataclass(frozen=True)
class InvocationLedgerSnapshot:
    """Immutable role-attribution ledger view."""

    records: dict[str, InvocationRecord]
    unpriced_requests: int

    def role_record(self, role: InvocationRole) -> InvocationRecord | None:
        return self.records.get(role.value)

    def total_requests(self) -> int:
        return sum(record.requests for record in self.records.values())


class InvocationLedger:
    """Mutable role-attribution accumulator (single event loop only)."""

    def __init__(self) -> None:
        self._records: dict[str, InvocationRecord] = {}
        self.unpriced_requests = 0

    def record(self, record: InvocationRecord) -> None:
        key = record.role.value
        existing = self._records.get(key)
        if existing is None:
            self._records[key] = record
            return
        # Aggregation keeps the FIRST record's provider/model/correlation:
        # a role spanning multiple providers must not re-stamp the
        # aggregate with the latest attribution.
        self._records[key] = InvocationRecord(
            role=existing.role,
            provider=existing.provider,
            model_id=existing.model_id,
            correlation_id=existing.correlation_id,
            requests=existing.requests + record.requests,
            input_tokens=existing.input_tokens + record.input_tokens,
            output_tokens=existing.output_tokens + record.output_tokens,
            estimated_cost=existing.estimated_cost + record.estimated_cost,
            pricing_known=existing.pricing_known and record.pricing_known,
            failed=existing.failed or record.failed,
        )

    def snapshot(self) -> InvocationLedgerSnapshot:
        return InvocationLedgerSnapshot(
            records=dict(self._records),
            unpriced_requests=self.unpriced_requests,
        )


class InvocationService:
    def __init__(
        self,
        config: AppConfig,
        *,
        provider_factory: ProviderFactory | None = None,
        budget: BudgetTracker | None = None,
        environ: Mapping[str, str] | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.config = config
        self.factory = provider_factory or ProviderFactory(config, environ=environ)
        self.budget = budget or BudgetTracker(config.evaluation.budgets)
        self.progress = progress
        self.ledger = InvocationLedger()
        self._global = asyncio.Semaphore(max(1, config.global_.concurrency))
        self._provider_semaphores: dict[str, asyncio.Semaphore] = {}
        self._pricing_cache: dict[str, PricingPolicy] = {}
        self._owns_factory = provider_factory is None

    def _provider_semaphore(self, provider_name: str) -> asyncio.Semaphore:
        if provider_name not in self._provider_semaphores:
            limit = max(1, self.config.global_.concurrency)
            settings = self.config.providers.get(provider_name)
            if settings is not None:
                limit = min(limit, max(1, settings.concurrency))
            self._provider_semaphores[provider_name] = asyncio.Semaphore(limit)
        return self._provider_semaphores[provider_name]

    def pricing_for(self, provider_name: str) -> PricingPolicy:
        if provider_name in self._pricing_cache:
            return self._pricing_cache[provider_name]
        settings = self.config.providers.get(provider_name)
        if settings is None:
            raise ConfigurationError(
                f"unknown provider {provider_name!r}. Available: "
                f"{', '.join(sorted(self.config.providers))}"
            )
        if settings.kind == "mock":
            policy = PricingPolicy(Decimal("0"), Decimal("0"))
        else:
            policy = PricingPolicy(
                (
                    None
                    if settings.input_price_per_million is None
                    else Decimal(str(settings.input_price_per_million))
                ),
                (
                    None
                    if settings.output_price_per_million is None
                    else Decimal(str(settings.output_price_per_million))
                ),
            )
        self._pricing_cache[provider_name] = policy
        return policy

    def estimate_cost(self, model: ModelRef, usage: TokenUsage) -> Decimal | None:
        """Estimate cost for a usage record, or None when pricing is unknown.

        Anthropic-style cache tokens are billed against the input price:
        cache writes at 1.25x (the 5-minute write premium) and cache reads
        at 0.1x.
        """
        policy = self.pricing_for(model.provider)
        if not policy.known:
            return None
        million = Decimal(1_000_000)
        input_price = (
            policy.input_price_per_million
            if policy.input_price_per_million is not None
            else Decimal("0")
        )
        output_price = (
            policy.output_price_per_million
            if policy.output_price_per_million is not None
            else Decimal("0")
        )
        return (
            Decimal(usage.input_tokens) * input_price
            + Decimal(usage.output_tokens) * output_price
            + Decimal(usage.cache_read_input_tokens) * input_price * Decimal("0.1")
            + Decimal(usage.cache_creation_input_tokens) * input_price * Decimal("1.25")
        ) / million

    async def invoke(
        self,
        *,
        model: ModelRef,
        request: GenerationRequest,
        role: InvocationRole,
        correlation_id: str | None = None,
    ) -> ModelResponse:
        """Execute one logical model invocation with full accounting.

        Raises ``UnknownPricingError`` before the provider call when a cost
        ceiling is configured for a provider with unknown pricing.
        """
        if model.provider not in self.config.providers:
            raise ConfigurationError(
                f"unknown provider {model.provider!r}. Available: "
                f"{', '.join(sorted(self.config.providers))}"
            )
        policy = self.pricing_for(model.provider)
        if self.budget.settings.max_estimated_cost is not None and not policy.known:
            raise UnknownPricingError(
                f"provider {model.provider!r} has unknown pricing; configure "
                "input_price_per_million/output_price_per_million or remove "
                "max_estimated_cost from evaluation.budgets"
            )
        provider = self.factory.create(model)
        async with self._global, self._provider_semaphore(model.provider):
            await self.budget.reserve_request()
            await emit(
                self.progress,
                RunEvent(
                    kind=RunEventKind.INVOCATION_STARTED,
                    run_id=correlation_id,
                    message=f"{role.value} invocation started",
                    detail={
                        "role": role.value,
                        "provider": model.provider,
                        "model": model.model_id,
                        "correlation_id": correlation_id,
                        "budget_requests": self.budget.snapshot().requests,
                    },
                ),
            )
            try:
                response = await provider.generate(model, request)
            except Exception:
                wire_attempts = _wire_attempts(provider, None)
                self.ledger.record(
                    InvocationRecord(
                        role=role,
                        provider=model.provider,
                        model_id=model.model_id,
                        correlation_id=correlation_id,
                        requests=wire_attempts,
                        input_tokens=0,
                        output_tokens=0,
                        estimated_cost=Decimal("0"),
                        pricing_known=policy.known,
                        failed=True,
                    )
                )
                if not policy.known:
                    self.ledger.unpriced_requests += 1
                await emit(
                    self.progress,
                    RunEvent(
                        kind=RunEventKind.INVOCATION_FAILED,
                        run_id=correlation_id,
                        message=f"{role.value} invocation failed",
                        detail={
                            "role": role.value,
                            "provider": model.provider,
                            "model": model.model_id,
                            "correlation_id": correlation_id,
                            "budget_requests": self.budget.snapshot().requests,
                            "wire_attempts": wire_attempts,
                        },
                    ),
                )
                raise
            estimated_cost = self.estimate_cost(model, response.usage)
            await self.budget.record_response(
                response.usage,
                estimated_cost=estimated_cost,
            )
            wire_attempts = _wire_attempts(provider, response)
            self.ledger.record(
                InvocationRecord(
                    role=role,
                    provider=model.provider,
                    model_id=model.model_id,
                    correlation_id=correlation_id,
                    requests=wire_attempts,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    estimated_cost=estimated_cost or Decimal("0"),
                    pricing_known=policy.known,
                    failed=False,
                )
            )
            if not policy.known:
                self.ledger.unpriced_requests += 1
            await emit(
                self.progress,
                RunEvent(
                    kind=RunEventKind.INVOCATION_FINISHED,
                    run_id=correlation_id,
                    message=f"{role.value} invocation finished",
                    detail={
                        "role": role.value,
                        "provider": model.provider,
                        "model": model.model_id,
                        "correlation_id": correlation_id,
                        "budget_requests": self.budget.snapshot().requests,
                        "wire_attempts": wire_attempts,
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                    },
                ),
            )
            return response

    def snapshot(self) -> InvocationLedgerSnapshot:
        return self.ledger.snapshot()

    async def aclose(self) -> None:
        if self._owns_factory:
            await self.factory.aclose()


async def invoke_provider(
    provider: Provider,
    *,
    model: ModelRef,
    request: GenerationRequest,
    budget: BudgetTracker | None = None,
    estimate_cost: CostEstimator | None = None,
) -> ModelResponse:
    """Budgeted logical invocation against an explicitly supplied provider.

    Fallback path for plugin contexts constructed without an
    ``InvocationService`` (older callers and direct-construction tests).
    Records the logical request and tokens in ``budget`` when supplied; no
    role ledger attribution is possible without a service. New code should
    prefer ``InvocationService.invoke``.
    """
    if budget is not None:
        await budget.reserve_request()
    response = await provider.generate(model, request)
    if budget is not None:
        cost = estimate_cost(model, response.usage) if estimate_cost is not None else None
        await budget.record_response(response.usage, estimated_cost=cost)
    return response
