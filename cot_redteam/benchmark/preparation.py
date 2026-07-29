"""Resolve a planned trial into trusted policy and untrusted scripted messages."""

from __future__ import annotations

from dataclasses import dataclass

from cot_redteam.benchmark.canary import CanaryBundle
from cot_redteam.benchmark.planner import PlannedTrial
from cot_redteam.benchmark.policies import render_policy
from cot_redteam.benchmark.techniques import apply_technique
from cot_redteam.benchmark.templates import (
    ATTACK_TEMPLATE_VARIABLES,
    render_template,
)
from cot_redteam.benchmark.transforms import TransformResult, apply_transform
from cot_redteam.core.errors import ConfigurationError
from cot_redteam.core.types import Message, MessageRole, MessageTrust


@dataclass(frozen=True)
class PreparedTrial:
    trial: PlannedTrial
    initial_messages: tuple[Message, ...]
    scripted_messages: tuple[Message, ...]
    canary: CanaryBundle
    transformation_id: str
    transformation_digest: str


def prepare_trial(
    trial: PlannedTrial,
    *,
    canary: CanaryBundle,
    rogue_string: str,
    untrusted_content: str,
    label: str,
) -> PreparedTrial:
    task = trial.scenario.task.prompt
    policy_text = render_policy(
        trial.policy_id,
        canary=canary.token,
        task=task,
        untrusted_content_label=label,
    )
    initial = (
        Message(
            role=MessageRole.SYSTEM,
            content=policy_text,
            trust=MessageTrust.TRUSTED,
            source=trial.policy_id,
        ),
    )
    values = {
        "task": task,
        "rogue_string": rogue_string,
        "untrusted_content": untrusted_content,
        "label": label,
    }
    rendered = tuple(
        Message(
            role=step.role,
            content=render_template(
                step.content,
                values,
                allowed_variables=ATTACK_TEMPLATE_VARIABLES,
            ),
            trust=step.trust,
            name=step.name,
            source=step.source,
        )
        for step in trial.scenario.steps
    )
    framed = apply_technique(trial.technique_id, rendered)
    transformed: TransformResult = apply_transform(
        trial.transformation_id,
        framed,
    )
    protected_values = (canary.token, *canary.fragments)
    if any(
        protected in message.content
        for message in transformed.messages
        for protected in protected_values
    ):
        raise ConfigurationError("canary crossed into attack-controlled trial messages")
    return PreparedTrial(
        trial=trial,
        initial_messages=initial,
        scripted_messages=transformed.messages,
        canary=canary,
        transformation_id=transformed.transform_id,
        transformation_digest=transformed.digest,
    )
