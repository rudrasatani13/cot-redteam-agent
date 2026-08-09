"""Strict agent-security configuration (additive to the v0.5 config)."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from cot_redteam.core.config import BudgetSettings, StrictModel

DEFAULT_FIXTURES: list[Literal["vulnerable", "patched", "clean"]] = ["vulnerable"]


class AgentRetentionSettings(StrictModel):
    """Privacy-first agent retention defaults: structural data stays for
    proof, raw content is omitted unless explicitly retained."""

    retain_final_response: bool = False
    retain_tool_arguments: bool = False
    retain_tool_results: bool = False
    retain_memory_values: bool = False
    retain_world_values: bool = False
    retain_model_reasoning: bool = False


class AgentSecuritySettings(StrictModel):
    """Top-level ``agent`` section. Absent in existing v0.5 configs."""

    scenarios: list[str] = Field(default_factory=list)
    fixtures: list[Literal["vulnerable", "patched", "clean"]] = Field(
        default_factory=lambda: list(DEFAULT_FIXTURES)
    )
    target: Literal["scripted", "provider_adapter"] = "scripted"
    budgets: BudgetSettings = Field(default_factory=BudgetSettings)
    retention: AgentRetentionSettings = Field(default_factory=AgentRetentionSettings)
    max_actions: int = Field(default=100, ge=1)
    max_serialized_argument_bytes: int = Field(default=8192, ge=1)
    max_serialized_result_bytes: int = Field(default=65536, ge=1)
    tool_timeout_seconds: float = Field(default=5.0, gt=0)
    max_concurrent_tool_calls: int = Field(default=4, ge=1)
    output_dir: str = "./results/agent"
    #: Optional provider-backed model reference (e.g. for the provider
    #: adapter target or an optional remote target model).
    target_model: str | None = None
    system_prompt: str | None = None
