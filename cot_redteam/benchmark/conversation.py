"""Fixed scripted multi-turn execution with partial transcript preservation."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from cot_redteam.benchmark.planner import PlannedTrial
from cot_redteam.core.errors import BudgetExceededError, ProviderError
from cot_redteam.core.invocation import (
    InvocationRole,
    InvocationService,
    invoke_provider,
)
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
    INTERNAL_ERROR = "internal_error"


def internal_error_transcript(trial_id: str, error: str) -> ConversationTranscript:
    """Build a minimal transcript for an unexpected internal trial failure.

    Preserves the trial identity and a sanitized error so a benchmark run
    can keep typed partial/failed evidence instead of aborting unrelated
    trials. Never represents the trial as clean.
    """
    return ConversationTranscript(
        trial_id=trial_id,
        status=ConversationStatus.INTERNAL_ERROR,
        messages=(),
        turns=(),
        error=error,
    )


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
        invocation_service: InvocationService | None = None,
    ) -> None:
        self.budget = budget
        self.estimate_cost = estimate_cost
        self.invocation_service = invocation_service

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
                if self.invocation_service is not None:
                    response = await self.invocation_service.invoke(
                        model=trial.model,
                        request=GenerationRequest(
                            messages=request_messages,
                            temperature=temperature,
                            max_tokens=max_tokens,
                        ),
                        role=InvocationRole.TARGET,
                        correlation_id=trial.trial_id,
                    )
                else:
                    response = await invoke_provider(
                        provider,
                        model=trial.model,
                        request=GenerationRequest(
                            messages=request_messages,
                            temperature=temperature,
                            max_tokens=max_tokens,
                        ),
                        budget=self.budget,
                        estimate_cost=self.estimate_cost,
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
