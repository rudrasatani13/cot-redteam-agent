"""Fixed scripted multi-turn execution with partial transcript preservation."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from cot_redteam.benchmark.planner import PlannedTrial
from cot_redteam.core.errors import BudgetExceededError, ProviderError
from cot_redteam.core.types import (
    GenerationRequest,
    Message,
    MessageRole,
    MessageTrust,
    ModelRef,
    ModelResponse,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker
from cot_redteam.providers.base import Provider

CostEstimator = Callable[[ModelRef, TokenUsage], Decimal | None]


class ConversationStatus(str, Enum):
    COMPLETED = "completed"
    PROVIDER_ERROR = "provider_error"
    BUDGET_EXCEEDED = "budget_exceeded"


@dataclass(frozen=True)
class ConversationTurn:
    turn_index: int
    request_messages: tuple[Message, ...]
    response: ModelResponse | None = None
    error: str | None = None


@dataclass(frozen=True)
class ConversationTranscript:
    trial_id: str
    status: ConversationStatus
    messages: tuple[Message, ...]
    turns: tuple[ConversationTurn, ...]
    error: str | None = None


class ConversationRunner:
    def __init__(
        self,
        budget: BudgetTracker,
        *,
        estimate_cost: CostEstimator | None = None,
    ) -> None:
        self.budget = budget
        self.estimate_cost = estimate_cost

    async def run(
        self,
        trial: PlannedTrial,
        provider: Provider,
        *,
        initial_messages: Sequence[Message],
        scripted_messages: Sequence[Message],
        temperature: float,
        max_tokens: int,
    ) -> ConversationTranscript:
        history = list(initial_messages)
        turns: list[ConversationTurn] = []

        for scripted in scripted_messages:
            history.append(scripted)
            if scripted.role not in (MessageRole.USER, MessageRole.TOOL):
                continue

            request_messages = tuple(history)
            turn_index = len(turns)
            try:
                await self.budget.reserve_request()
                response = await provider.generate(
                    trial.model,
                    GenerationRequest(
                        messages=request_messages,
                        temperature=temperature,
                        max_tokens=max_tokens,
                    ),
                )
                estimated_cost = (
                    self.estimate_cost(trial.model, response.usage)
                    if self.estimate_cost is not None
                    else None
                )
                await self.budget.record_response(
                    response.usage,
                    estimated_cost=estimated_cost,
                )
            except BudgetExceededError as exc:
                turns.append(
                    ConversationTurn(
                        turn_index=turn_index,
                        request_messages=request_messages,
                        error=str(exc),
                    )
                )
                return ConversationTranscript(
                    trial_id=trial.trial_id,
                    status=ConversationStatus.BUDGET_EXCEEDED,
                    messages=tuple(history),
                    turns=tuple(turns),
                    error=str(exc),
                )
            except ProviderError as exc:
                turns.append(
                    ConversationTurn(
                        turn_index=turn_index,
                        request_messages=request_messages,
                        error=str(exc),
                    )
                )
                return ConversationTranscript(
                    trial_id=trial.trial_id,
                    status=ConversationStatus.PROVIDER_ERROR,
                    messages=tuple(history),
                    turns=tuple(turns),
                    error=str(exc),
                )

            turns.append(
                ConversationTurn(
                    turn_index=turn_index,
                    request_messages=request_messages,
                    response=response,
                )
            )
            history.append(
                Message(
                    role=MessageRole.ASSISTANT,
                    content=response.text,
                    trust=MessageTrust.UNTRUSTED,
                    source="target_model",
                )
            )

        return ConversationTranscript(
            trial_id=trial.trial_id,
            status=ConversationStatus.COMPLETED,
            messages=tuple(history),
            turns=tuple(turns),
        )
