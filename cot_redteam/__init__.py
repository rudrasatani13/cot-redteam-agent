"""CoT Red Teaming Agent — Automated CoT Red Teaming Framework."""

__version__ = "0.2.0"

from cot_redteam.core.errors import (
    BudgetExceededError,
    ConfigurationError,
    CotRedTeamError,
    PermanentProviderError,
    PluginError,
    ProviderError,
    TransientProviderError,
)
from cot_redteam.core.types import (
    AttackAssessment,
    AttackCategory,
    AttackPrompt,
    DatasetSample,
    EvaluationItem,
    EvaluationRun,
    GenerationRequest,
    ItemStatus,
    ModelRef,
    ModelResponse,
    MonitorOutcome,
    MonitorStatus,
    ReasoningSource,
    RunStatus,
    RunSummary,
    TokenUsage,
)

__all__ = [
    "__version__",
    "AttackAssessment",
    "AttackCategory",
    "AttackPrompt",
    "BudgetExceededError",
    "ConfigurationError",
    "CotRedTeamError",
    "DatasetSample",
    "EvaluationItem",
    "EvaluationRun",
    "GenerationRequest",
    "ItemStatus",
    "ModelRef",
    "ModelResponse",
    "MonitorOutcome",
    "MonitorStatus",
    "PermanentProviderError",
    "PluginError",
    "ProviderError",
    "ReasoningSource",
    "RunStatus",
    "RunSummary",
    "TokenUsage",
    "TransientProviderError",
]
