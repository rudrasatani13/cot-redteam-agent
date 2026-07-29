# Plugins

Third-party plugins run **in-process** and are trusted code. 0.2 does not sandbox plugins.

## Attack contract

```python
# test: python
from cot_redteam.attacks.base import BaseAttack, register_attack
from cot_redteam.core.types import AttackAssessment, AttackPrompt, DatasetSample, ModelResponse
from cot_redteam.plugins.registry import PluginMetadata

@register_attack
class DemoAttack(BaseAttack):
    metadata = PluginMetadata(
        id="custom.demo",
        version="1.0.0",
        description="demo attack",
        category="custom",
    )

    def create_prompt(self, sample: DatasetSample) -> AttackPrompt:
        return AttackPrompt(
            attack_id=self.metadata.id,
            text=sample.question,
            sample_id=sample.id,
        )

    def assess(self, sample, prompt, response: ModelResponse) -> AttackAssessment:
        return AttackAssessment(success=False, score=0.0)
```

## Monitor contract

```python
# test: python
from cot_redteam.monitors.base import BaseMonitor, register_monitor
from cot_redteam.core.types import AttackPrompt, ModelResponse, MonitorOutcome, MonitorStatus
from cot_redteam.plugins.registry import PluginMetadata

@register_monitor
class DemoMonitor(BaseMonitor):
    metadata = PluginMetadata(
        id="custom.demo_monitor",
        version="1.0.0",
        description="demo monitor",
    )

    async def evaluate(self, prompt: AttackPrompt, response: ModelResponse) -> MonitorOutcome:
        return MonitorOutcome(
            monitor_id=self.metadata.id,
            status=MonitorStatus.CLEAN,
            confidence=0.0,
            explanation="ok",
        )
```

## Entry points

In your package `pyproject.toml`:

```toml
[project.entry-points."cot_redteam.attacks"]
demo = "mypkg.attacks:DemoAttack"

[project.entry-points."cot_redteam.monitors"]
demo = "mypkg.monitors:DemoMonitor"
```

Importing the entry point module should register the plugin (decorator or explicit `Registry.register`).
