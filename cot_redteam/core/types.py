"""
Core types and data structures for the CoT Red Teaming Agent.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Literal
from pydantic import BaseModel, Field


class ModelProvider(str, Enum):
    """Supported model providers."""
    OPENROUTER = "openrouter"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    VLLM = "vllm"
    LLAMACPP = "llamacpp"
    LOCAL = "local"


class AttackCategory(str, Enum):
    """Attack categories."""
    INJECTION = "injection"
    FAITHFULNESS = "faithfulness"
    STEGANOGRAPHY = "steganography"
    DISTILLATION = "distillation"
    MANIPULATION = "manipulation"
    SANDBAGGING = "sandbagging"
    EVASION = "evasion"
    GENERATIVE = "generative"


class MonitorType(str, Enum):
    """CoT monitor types."""
    REGEX = "regex"
    LLM_JUDGE = "llm_judge"
    ENSEMBLE = "ensemble"
    CUSTOM = "custom"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ModelConfig:
    """Configuration for a model."""
    provider: ModelProvider
    model_id: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 120
    max_retries: int = 3
    extra_params: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def full_id(self) -> str:
        return f"{self.provider.value}:{self.model_id}"


@dataclass
class AttackConfig:
    """Configuration for an attack."""
    category: AttackCategory
    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_models: List[str] = field(default_factory=list)  # Empty = all
    enabled: bool = True
    severity: Severity = Severity.MEDIUM


@dataclass
class AttackPrompt:
    """A single attack prompt with metadata."""
    prompt: str
    attack_config: AttackConfig
    metadata: Dict[str, Any] = field(default_factory=dict)
    generated_by: Optional[str] = None  # For generative attacks
    generation: int = 0  # For evolutionary attacks


@dataclass
class ModelResponse:
    """Model response with CoT extraction."""
    full_response: str
    cot: Optional[str] = None
    answer: Optional[str] = None
    model_config: Optional[ModelConfig] = None
    latency_ms: float = 0.0
    token_usage: Dict[str, int] = field(default_factory=dict)
    raw_response: Any = None


@dataclass
class AttackResult:
    """Result of running an attack against a model."""
    attack_prompt: AttackPrompt
    model_response: ModelResponse
    monitor_results: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    severity: Severity = Severity.LOW
    evidence: List[str] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    run_id: str = ""


@dataclass
class MonitorResult:
    """Result from a CoT monitor."""
    monitor_type: MonitorType
    triggered: bool
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""


@dataclass
class AttackSpec:
    """Specification for an attack (used for generative attacks)."""
    name: str
    category: AttackCategory
    description: str
    prompt_template: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_models: List[str] = field(default_factory=list)
    expected_behavior: str = ""
    tags: List[str] = field(default_factory=list)


@dataclass
class DatasetSample:
    """Single sample from an evaluation dataset."""
    id: str
    question: str
    answer: Optional[str] = None
    cot: Optional[str] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalResult:
    """Aggregated evaluation results."""
    run_id: str
    model_config: Optional[ModelConfig] = None
    attack_results: List[AttackResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)  # path -> description
    artifacts_hash: Optional[str] = None


# Pydantic models for config validation
class GlobalConfig(BaseModel):
    seed: int = 42
    log_level: str = "INFO"
    output_dir: str = "./results"
    artifacts_dir: str = "./artifacts"
    cache_dir: str = "./cache"


class ModelProviderConfig(BaseModel):
    api_key_env: Optional[str] = None
    base_url: Optional[str] = None
    timeout: int = 120
    max_retries: int = 3
    aliases: Dict[str, str] = Field(default_factory=dict)


class AttackDefaults(BaseModel):
    num_samples: int = 10
    temperature: float = 0.7
    max_tokens: int = 4096
    cot_extraction: bool = True
    cot_delimiters: List[str] = Field(default_factory=lambda: [
        "�",
        "�",
        "<reasoning>",
        "</reasoning>",
        "####",
        "Step by step:"
    ])


class GenerativeAttackConfig(BaseModel):
    generator_model: str = "openrouter:anthropic/claude-3.5-sonnet"
    evolution_rounds: int = 5
    population_size: int = 20
    mutation_rate: float = 0.3
    crossover_rate: float = 0.5
    fitness_metric: str = "evasion_rate"


class MonitorConfig(BaseModel):
    enabled: List[str] = Field(default_factory=lambda: ["regex", "llm_judge", "ensemble"])


class Config(BaseModel):
    global_: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")
    models: Dict[str, ModelProviderConfig] = Field(default_factory=dict)
    attacks: Dict[str, Any] = Field(default_factory=dict)
    monitors: MonitorConfig = Field(default_factory=MonitorConfig)


def load_config(path: str = "config.yaml") -> Config:
    """Load configuration from YAML file."""
    import yaml
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return Config(**data)