"""Scripted multi-turn conversation runner tests."""

from __future__ import annotations

import json
from pathlib import Path

from cot_redteam.benchmark.conversation import (
    ConversationRunner,
    ConversationStatus,
)
from cot_redteam.benchmark.planner import BenchmarkPlanner
from cot_redteam.benchmark.suite import ScenarioSuite
from cot_redteam.core.config import BudgetSettings
from cot_redteam.core.errors import PermanentProviderError
from cot_redteam.core.types import (
    Message,
    MessageRole,
    MessageTrust,
    ModelRef,
    ModelResponse,
    TargetCapabilities,
    TokenUsage,
)
from cot_redteam.eval.budgets import BudgetTracker

from .test_schema import valid_scenario


class FakeProvider:
    capabilities = TargetCapabilities(system_role=True, multi_turn=True)

    def __init__(self, *, fail_at: int | None = None) -> None:
        self.requests = []
        self.fail_at = fail_at

    async def generate(self, model, request):
        self.requests.append(request)
        if self.fail_at is not None and len(self.requests) == self.fail_at:
            raise PermanentProviderError("planned failure")
        return ModelResponse(
            text=f"answer-{len(self.requests)}",
            model=model,
            usage=TokenUsage(input_tokens=2, output_tokens=1),
        )

    async def aclose(self) -> None:
        return None


def planned_trial(tmp_path: Path):
    row = valid_scenario()
    row["steps"] = [
        {
            "role": "user",
            "content": "first {task}",
            "trust": "untrusted",
        },
        {
            "role": "user",
            "content": "second {task}",
            "trust": "untrusted",
        },
    ]
    row["required_capabilities"] = ["system_role", "multi_turn"]
    path = tmp_path / "suite.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    suite = ScenarioSuite.load_jsonl(path, suite_id="suite.test")
    return (
        BenchmarkPlanner(
            models=[ModelRef.parse("gateway:model-a")],
            suites=[suite],
            target_capabilities={"gateway": FakeProvider.capabilities},
            run_id="run-123",
        )
        .create()
        .trials[0]
    )


async def run_conversation(tmp_path: Path, provider: FakeProvider):
    trial = planned_trial(tmp_path)
    steps = (
        Message(
            role=MessageRole.USER,
            content="first task",
            trust=MessageTrust.UNTRUSTED,
        ),
        Message(
            role=MessageRole.USER,
            content="second task",
            trust=MessageTrust.UNTRUSTED,
        ),
    )
    budget = BudgetTracker(BudgetSettings(max_requests=2))
    transcript = await ConversationRunner(budget).run(
        trial,
        provider,
        initial_messages=(Message(role=MessageRole.SYSTEM, content="policy"),),
        scripted_messages=steps,
        temperature=0.0,
        max_tokens=20,
    )
    return transcript, provider, budget


async def test_runner_preserves_ordered_history_and_counts_each_turn(
    tmp_path: Path,
) -> None:
    transcript, provider, budget = await run_conversation(tmp_path, FakeProvider())

    assert transcript.status is ConversationStatus.COMPLETED
    assert len(transcript.turns) == 2
    assert [message.role for message in provider.requests[0].messages] == [
        MessageRole.SYSTEM,
        MessageRole.USER,
    ]
    assert [message.role for message in provider.requests[1].messages] == [
        MessageRole.SYSTEM,
        MessageRole.USER,
        MessageRole.ASSISTANT,
        MessageRole.USER,
    ]
    assert budget.snapshot().requests == 2
    assert budget.snapshot().input_tokens == 4


async def test_runner_preserves_partial_transcript_on_later_provider_error(
    tmp_path: Path,
) -> None:
    transcript, provider, budget = await run_conversation(
        tmp_path,
        FakeProvider(fail_at=2),
    )

    assert transcript.status is ConversationStatus.PROVIDER_ERROR
    assert transcript.error == "planned failure"
    assert len(transcript.turns) == 2
    assert transcript.turns[0].response is not None
    assert transcript.turns[1].response is None
    assert transcript.turns[1].error == "planned failure"
    assert budget.snapshot().requests == 2
