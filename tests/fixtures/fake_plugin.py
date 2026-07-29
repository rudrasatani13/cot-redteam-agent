"""Fake third-party plugin module for tests."""

from cot_redteam.attacks.base import BaseAttack, register_attack
from cot_redteam.core.types import AttackAssessment, AttackPrompt, DatasetSample, ModelResponse
from cot_redteam.plugins.registry import PluginMetadata


@register_attack
class FakePluginAttack(BaseAttack):
    metadata = PluginMetadata(
        id="custom.fake_plugin",
        version="0.0.1",
        description="fixture plugin",
        category="custom",
    )

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        return AttackPrompt(
            attack_id=self.metadata.id,
            text=sample.question,
            sample_id=sample.id,
        )

    def assess(
        self,
        sample: DatasetSample,
        prompt: AttackPrompt,
        response: ModelResponse,
    ) -> AttackAssessment:
        return AttackAssessment(success=False, score=0.0)
