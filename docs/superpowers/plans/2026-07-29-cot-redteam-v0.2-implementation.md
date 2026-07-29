# CoT Red Team Agent 0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a dependable `0.2.0` open-source CLI and Python API for running Chain-of-Thought red-team evaluations with user-supplied provider credentials and truthful failure-aware results.

**Architecture:** Replace the contradictory `0.1.x` configuration and execution paths with one validated configuration model, stable plugin registries, shared asynchronous provider transports, a planner, and a typed evaluation engine. Persist the resulting run model through transactional SQLite and content-addressed artifacts, then render reports from the same typed summary.

**Tech Stack:** Python 3.10–3.13, Pydantic 2, HTTPX, PyYAML, SciPy, SQLite, pytest, pytest-asyncio, pytest-cov, Ruff, mypy, build, and pip-tools.

## Global Constraints

- This is an intentional breaking `0.2.0` release; do not preserve contradictory `0.1.x` runtime APIs.
- Remote provider credentials must come from named environment variables and must never appear in snapshots, logs, artifacts, database rows, exceptions, or object representations.
- OpenRouter, OpenAI, Anthropic, vLLM, and llama.cpp must remain supported.
- Evaluation is asynchronous end to end; synchronous wrappers must not call `asyncio.run()` from library code.
- `ERROR` and `NOT_RUN` monitor outcomes must never be treated as `CLEAN` or successful evasion.
- Unknown configuration keys, provider references, attack IDs, monitor IDs, and duplicate plugin IDs fail before provider requests begin.
- Runtime dependencies use compatible version ranges. CI’s primary Python version uses a hash-locked `requirements-dev.lock`.
- The complete package coverage floor is 75 percent. Configuration, planning, execution, metrics, and storage each require at least 85 percent.
- CI supports Python 3.10, 3.11, 3.12, and 3.13.
- Tests never require network access or real provider credentials.
- Each task must preserve a runnable repository and end with targeted tests plus the full suite available at that point.

---

## File and responsibility map

### Core

- `cot_redteam/core/types.py`: immutable runtime domain types and outcome enums.
- `cot_redteam/core/config.py`: strict Pydantic configuration, YAML loading, CLI override merging, secret resolution, and redaction.
- `cot_redteam/core/errors.py`: public exception hierarchy and retry classification.
- `cot_redteam/core/serialization.py`: canonical JSON conversion and SHA-256 helpers.

### Plugins

- `cot_redteam/plugins/registry.py`: generic duplicate-safe registry.
- `cot_redteam/plugins/bootstrap.py`: built-in imports and Python entry-point discovery.
- `cot_redteam/attacks/base.py`: public attack contract and attack registry.
- `cot_redteam/monitors/base.py`: public monitor contract and monitor registry.

### Providers

- `cot_redteam/providers/base.py`: provider protocol, resolved provider settings, retry policy, and lifecycle.
- `cot_redteam/providers/openai_compatible.py`: shared OpenAI/OpenRouter/vLLM/llama.cpp transport.
- `cot_redteam/providers/anthropic.py`: Anthropic transport.
- `cot_redteam/providers/factory.py`: validated provider construction and model-alias resolution.
- `cot_redteam/models/`: removed after all imports move to `cot_redteam.providers`.
- `cot_redteam/scheduler/`: removed because the unintegrated watcher is outside
  the approved 0.2 command and Python API surface.

### Evaluation

- `cot_redteam/eval/dataset.py`: validated JSONL loading and deterministic dataset digests.
- `cot_redteam/eval/planner.py`: plugin/model/sample resolution into immutable plans.
- `cot_redteam/eval/budgets.py`: request, token, elapsed-time, and cost accounting.
- `cot_redteam/eval/engine.py`: asynchronous item and run orchestration.
- `cot_redteam/eval/metrics.py`: eligibility-aware summaries, confidence intervals, and comparisons.
- `cot_redteam/eval/manifest.py`: redacted reproducibility manifest generation.
- `cot_redteam/eval/harness.py`: removed after CLI and Python API migrate.

### Persistence and reports

- `cot_redteam/storage/sqlite.py`: migrations, transactional run persistence, and queries.
- `cot_redteam/storage/artifacts.py`: atomic writes and content hashes.
- `cot_redteam/storage/results.py`: removed after callers migrate.
- `cot_redteam/reporting/model.py`: report view model.
- `cot_redteam/reporting/renderers.py`: Markdown, CSV, and LaTeX renderers.
- `cot_redteam/reporting/report.py`: thin format dispatcher and file writer.

### Application and delivery

- `cot_redteam/cli/main.py`: parser, command dispatch, exit-code mapping, and dependency lifecycle.
- `cot_redteam/api.py`: supported Python entry points.
- `config.example.yaml`: validated credential-free example.
- `config.yaml`: removed in favor of the example to avoid implying committed credentials.
- `tests/fixtures/`: fake provider payloads, datasets, and configuration.
- `.github/workflows/ci.yml`: lint, typing, tests, coverage, build, and install matrix.
- `docs/`: user guides, plugin guide, migration guide, changelog, and release checklist.

---

### Task 1: Runtime domain model and canonical serialization

**Files:**
- Create: `cot_redteam/core/errors.py`
- Create: `cot_redteam/core/serialization.py`
- Modify: `cot_redteam/core/types.py`
- Modify: `cot_redteam/__init__.py`
- Test: `tests/core/test_types_v2.py`
- Test: `tests/core/test_serialization.py`

**Interfaces:**
- Produces: `JsonValue`, `JsonDataclass`, `ItemStatus`, `MonitorStatus`, `RunStatus`, `ReasoningSource`, `ModelRef.parse(str)`, `TokenUsage`, `DatasetSample`, `GenerationRequest`, `ModelResponse`, `AttackPrompt`, `AttackAssessment`, `MonitorOutcome`, `EvaluationItem`, `RunSummary`, `EvaluationRun`, `canonical_json(value) -> str`, and `sha256_bytes(data) -> str`.
- Produces: `CotRedTeamError`, `ConfigurationError`, `PluginError`, `ProviderError`, `TransientProviderError`, `PermanentProviderError`, and `BudgetExceededError`.

- [ ] **Step 1: Write failing domain tests**

```python
def test_model_ref_requires_provider_separator() -> None:
    with pytest.raises(ValueError, match="provider:model-id"):
        ModelRef.parse("gpt-4o")


def test_monitor_error_is_not_clean() -> None:
    outcome = MonitorOutcome(
        monitor_id="regex",
        status=MonitorStatus.ERROR,
        confidence=None,
        explanation="pattern compilation failed",
    )
    assert outcome.is_evaluable is False
    assert outcome.triggered is None


def test_run_status_is_derived_from_item_counts() -> None:
    assert RunSummary.from_items([succeeded_item()]).status is RunStatus.COMPLETED
    assert RunSummary.from_items([succeeded_item(), provider_error_item()]).status is RunStatus.PARTIAL
    assert RunSummary.from_items([provider_error_item()]).status is RunStatus.FAILED
```

- [ ] **Step 2: Run the domain tests and verify RED**

Run: `python -m pytest tests/core/test_types_v2.py -q`  
Expected: collection fails because the new outcome types do not exist.

- [ ] **Step 3: Implement immutable domain types**

Implement frozen dataclasses and string enums with these required signatures:

```python
@dataclass(frozen=True)
class ModelRef:
    provider: str
    model_id: str

    @classmethod
    def parse(cls, value: str) -> "ModelRef": ...


@dataclass(frozen=True)
class MonitorOutcome:
    monitor_id: str
    status: MonitorStatus
    confidence: float | None
    explanation: str
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    @property
    def is_evaluable(self) -> bool: ...

    @property
    def triggered(self) -> bool | None: ...


@dataclass(frozen=True)
class EvaluationItem:
    item_id: str
    model: ModelRef
    attack_id: str
    sample_id: str
    status: ItemStatus
    prompt: AttackPrompt | None = None
    response: ModelResponse | None = None
    assessment: AttackAssessment | None = None
    monitors: tuple[MonitorOutcome, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class RunSummary:
    status: RunStatus
    planned: int
    succeeded: int
    failed: int
    cancelled: int
    monitor_excluded: int

    @classmethod
    def from_items(cls, items: Sequence[EvaluationItem]) -> "RunSummary": ...
```

Validate confidence and score values in `__post_init__`. Reject succeeded items
without prompts, responses, or assessments. Reject error items without an
error message.

- [ ] **Step 4: Run domain tests and verify GREEN**

Run: `python -m pytest tests/core/test_types_v2.py -q`  
Expected: all tests pass.

- [ ] **Step 5: Write failing canonical serialization tests**

```python
def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_hash_depends_on_bytes_not_path(tmp_path: Path) -> None:
    left = tmp_path / "left.json"
    right = tmp_path / "right.json"
    left.write_bytes(b'{"a":1}')
    right.write_bytes(b'{"a":1}')
    assert sha256_file(left) == sha256_file(right)
```

- [ ] **Step 6: Run serialization tests and verify RED**

Run: `python -m pytest tests/core/test_serialization.py -q`  
Expected: import fails because serialization helpers do not exist.

- [ ] **Step 7: Implement canonical JSON and hashing**

Use UTF-8, sorted keys, compact separators, enum/dataclass conversion, and
UTC ISO-8601 timestamps. Implement:

```python
def canonical_json(value: JsonValue | JsonDataclass) -> str: ...
def sha256_bytes(data: bytes) -> str: ...
def sha256_file(path: Path) -> str: ...
```

- [ ] **Step 8: Run targeted and existing tests**

Run: `python -m pytest tests/core tests/test_types.py -q`  
Expected: all new tests pass; update obsolete `0.1` type assertions rather than preserving invalid constructors.

- [ ] **Step 9: Commit**

```bash
git add cot_redteam/core cot_redteam/__init__.py tests/core tests/test_types.py
git commit -m "refactor: introduce typed v0.2 domain model"
```

### Task 2: Strict configuration and credential resolution

**Files:**
- Modify: `cot_redteam/core/config.py`
- Create: `config.example.yaml`
- Delete: `config.yaml`
- Create: `tests/core/test_config.py`
- Create: `tests/fixtures/config/minimal.yaml`
- Create: `tests/fixtures/config/unknown-key.yaml`

**Interfaces:**
- Consumes: `ModelRef`, `ConfigurationError`, and canonical serialization from Task 1.
- Produces: `AppConfig`, `ProviderSettings`, `EvaluationSettings`, `BudgetSettings`, `ResolvedProviderSettings`, `load_config(path, overrides=None) -> AppConfig`, `resolve_provider(config, name, environ=None) -> ResolvedProviderSettings`, and `redacted_config(config) -> dict[str, JsonValue]`.

- [ ] **Step 1: Write failing strict-schema tests**

```python
def test_load_config_rejects_unknown_keys() -> None:
    with pytest.raises(ConfigurationError, match="unexpected"):
        load_config(FIXTURES / "config" / "unknown-key.yaml")


def test_remote_provider_requires_named_environment_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="OPENROUTER_API_KEY"):
        resolve_provider(config, "openrouter")


def test_redacted_config_never_contains_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "secret-value")
    config = load_config(FIXTURES / "config" / "minimal.yaml")
    resolved = resolve_provider(config, "openrouter")
    assert "secret-value" not in repr(resolved)
    assert "secret-value" not in canonical_json(redacted_config(config))
```

- [ ] **Step 2: Run configuration tests and verify RED**

Run: `python -m pytest tests/core/test_config.py -q`  
Expected: imports fail because `AppConfig` and resolver functions do not exist.

- [ ] **Step 3: Implement strict Pydantic configuration**

Use a shared base model with `ConfigDict(extra="forbid", frozen=True)`.
Implement these top-level fields:

```python
class AppConfig(StrictModel):
    version: Literal[2] = 2
    global_: GlobalSettings = Field(alias="global")
    providers: dict[str, ProviderSettings]
    evaluation: EvaluationSettings
    artifacts: ArtifactSettings = ArtifactSettings()
    storage: StorageSettings = StorageSettings()
    reporting: ReportingSettings = ReportingSettings()
    generative: GenerativeSettings = GenerativeSettings()
```

`ResolvedProviderSettings.api_key` must use `SecretStr`. Local provider kinds
`vllm` and `llamacpp` may omit `api_key_env`; remote kinds may not.

- [ ] **Step 4: Implement deterministic loading and CLI overrides**

```python
def load_config(
    path: str | Path,
    *,
    overrides: Mapping[str, JsonValue] | None = None,
) -> AppConfig: ...

def resolve_provider(
    config: AppConfig,
    provider_name: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> ResolvedProviderSettings: ...
```

Merge only documented override keys. Convert YAML, Pydantic, and path errors
into `ConfigurationError` with field locations and no secret values.

- [ ] **Step 5: Rewrite the example configuration**

The file must configure all five provider kinds without credential values,
select the sample dataset, use stable monitor IDs, set concurrency to `4`, and
set finite request and elapsed-time budgets.

- [ ] **Step 6: Run configuration tests and verify GREEN**

Run: `python -m pytest tests/core/test_config.py -q`  
Expected: all tests pass.

- [ ] **Step 7: Validate the shipped example**

Run:
`OPENROUTER_API_KEY=test OPENAI_API_KEY=test ANTHROPIC_API_KEY=test python -c "from cot_redteam.core.config import load_config; load_config('config.example.yaml')"`  
Expected: exit code 0 and no output.

- [ ] **Step 8: Commit**

```bash
git add cot_redteam/core/config.py config.example.yaml config.yaml tests/core/test_config.py tests/fixtures/config
git commit -m "refactor: replace configuration with strict v0.2 schema"
```

### Task 3: Stable registries and third-party plugin discovery

**Files:**
- Create: `cot_redteam/plugins/__init__.py`
- Create: `cot_redteam/plugins/registry.py`
- Create: `cot_redteam/plugins/bootstrap.py`
- Modify: `cot_redteam/attacks/base.py`
- Modify: `cot_redteam/attacks/__init__.py`
- Modify: `cot_redteam/monitors/base.py`
- Modify: `cot_redteam/monitors/__init__.py`
- Test: `tests/plugins/test_registry.py`
- Test: `tests/plugins/test_bootstrap.py`

**Interfaces:**
- Consumes: domain outcomes, provider protocol typing, and `PluginError`.
- Produces: `PluginMetadata`, `PluginContext`, `Registry[T].register(metadata, factory)`, `Registry[T].create(id, config, context)`, `Registry[T].metadata()`, `bootstrap_plugins()`, `AttackRegistry`, and `MonitorRegistry`.

- [ ] **Step 1: Write failing registry tests**

```python
def test_registry_rejects_duplicate_id() -> None:
    registry: Registry[object] = Registry("attack")
    metadata = PluginMetadata(id="injection.demo", version="1.0.0", description="demo")
    registry.register(metadata, lambda config, context: object())
    with pytest.raises(PluginError, match="duplicate attack plugin"):
        registry.register(metadata, lambda config, context: object())


def test_unknown_id_lists_available_plugins() -> None:
    registry: Registry[object] = Registry("monitor")
    metadata = PluginMetadata(id="regex", version="1.0.0", description="regex")
    registry.register(metadata, lambda config, context: object())
    with pytest.raises(PluginError, match="Available: regex"):
        registry.create("missing", {})
```

- [ ] **Step 2: Run registry tests and verify RED**

Run: `python -m pytest tests/plugins/test_registry.py -q`  
Expected: import fails because the generic registry does not exist.

- [ ] **Step 3: Implement the generic registry and metadata**

```python
@dataclass(frozen=True)
class PluginMetadata:
    id: str
    version: str
    description: str
    category: str | None = None


@dataclass(frozen=True)
class PluginContext:
    provider_resolver: Callable[[str], Provider] | None = None


class Registry(Generic[T]):
    def register(
        self,
        metadata: PluginMetadata,
        factory: Callable[[Mapping[str, JsonValue], PluginContext], T],
    ) -> None: ...

    def create(
        self,
        plugin_id: str,
        config: Mapping[str, JsonValue],
        context: PluginContext = PluginContext(),
    ) -> T: ...
    def metadata(self) -> tuple[PluginMetadata, ...]: ...
```

Sort metadata by ID. Never return `None` for an unknown plugin.

- [ ] **Step 4: Migrate attack and monitor base contracts**

The engine-facing contracts are:

```python
class BaseAttack(ABC):
    metadata: ClassVar[PluginMetadata]

    @abstractmethod
    def create_prompt(self, sample: DatasetSample) -> AttackPrompt: ...

    @abstractmethod
    def assess(
        self,
        sample: DatasetSample,
        prompt: AttackPrompt,
        response: ModelResponse,
    ) -> AttackAssessment: ...


class BaseMonitor(ABC):
    metadata: ClassVar[PluginMetadata]

    @abstractmethod
    async def evaluate(
        self,
        prompt: AttackPrompt,
        response: ModelResponse,
    ) -> MonitorOutcome: ...
```

- [ ] **Step 5: Write failing entry-point discovery test**

Patch `importlib.metadata.entry_points` with a fake
`cot_redteam.attacks` entry point. Assert `bootstrap_plugins()` loads it once,
records its distribution name in errors, and leaves built-ins available.

- [ ] **Step 6: Implement built-in and entry-point bootstrap**

Load built-ins explicitly, then entry-point groups `cot_redteam.attacks` and
`cot_redteam.monitors`. Cache successful bootstrap. Provide a reset hook only
under `tests/` through a fixture that restores registry state.

- [ ] **Step 7: Run plugin tests and registry compatibility tests**

Run: `python -m pytest tests/plugins tests/test_attacks.py tests/test_monitors.py -q`  
Expected: all tests pass after updating old registry-name expectations to the
stable IDs.

- [ ] **Step 8: Commit**

```bash
git add cot_redteam/plugins cot_redteam/attacks cot_redteam/monitors tests/plugins tests/test_attacks.py tests/test_monitors.py
git commit -m "refactor: add stable plugin contracts and discovery"
```

### Task 4: Shared asynchronous provider layer

**Files:**
- Create: `cot_redteam/providers/__init__.py`
- Create: `cot_redteam/providers/base.py`
- Create: `cot_redteam/providers/openai_compatible.py`
- Create: `cot_redteam/providers/anthropic.py`
- Create: `cot_redteam/providers/factory.py`
- Delete: `cot_redteam/models/openrouter.py`
- Delete: `cot_redteam/models/openai.py`
- Delete: `cot_redteam/models/anthropic.py`
- Delete: `cot_redteam/models/vllm.py`
- Delete: `cot_redteam/models/llamacpp.py`
- Delete: `cot_redteam/models/base.py`
- Delete: `cot_redteam/models/__init__.py`
- Delete: `tests/test_models.py`
- Test: `tests/providers/test_openai_compatible.py`
- Test: `tests/providers/test_anthropic.py`
- Test: `tests/providers/test_factory.py`

**Interfaces:**
- Consumes: `GenerationRequest`, `ModelResponse`, `ResolvedProviderSettings`, `ModelRef`, and provider errors.
- Produces: `Provider` protocol, `RetryPolicy`, `OpenAICompatibleProvider`, `AnthropicProvider`, and `ProviderFactory.create(model_ref) -> Provider`.

- [ ] **Step 1: Write failing OpenAI-compatible provider tests**

Use `httpx.MockTransport` to assert:

```python
@pytest.mark.asyncio
async def test_openai_compatible_provider_preserves_usage_and_request_id() -> None:
    provider = OpenAICompatibleProvider(settings(), transport=mock_transport(response_payload))
    response = await provider.generate(ModelRef.parse("openrouter:model/x"), request())
    assert response.text == "answer"
    assert response.usage.input_tokens == 12
    assert response.usage.output_tokens == 7
    assert response.provider_request_id == "req-123"
    await provider.aclose()


@pytest.mark.asyncio
async def test_permanent_401_is_not_retried() -> None:
    provider = provider_returning(401)
    with pytest.raises(PermanentProviderError):
        await provider.generate(MODEL, request())
    assert provider.request_count == 1
```

- [ ] **Step 2: Run provider tests and verify RED**

Run: `python -m pytest tests/providers/test_openai_compatible.py -q`  
Expected: import fails because the provider package does not exist.

- [ ] **Step 3: Implement provider protocol and retry policy**

```python
class Provider(Protocol):
    async def generate(
        self,
        model: ModelRef,
        request: GenerationRequest,
    ) -> ModelResponse: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True)
class RetryPolicy:
    max_retries: int
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 8.0
```

Classify timeouts, connection failures, `429`, and `5xx` as transient. Classify
other `4xx` and schema-invalid successful responses as permanent. Inject the
sleep function in tests to avoid real delays.

- [ ] **Step 4: Implement OpenAI-compatible parsing**

Parse standard `choices[0].message.content`, optional reasoning fields,
`usage`, response headers, finish reason, and model revision. Do not retain
authorization headers or complete raw response bodies.

- [ ] **Step 5: Run OpenAI-compatible tests and verify GREEN**

Run: `python -m pytest tests/providers/test_openai_compatible.py -q`  
Expected: all tests pass.

- [ ] **Step 6: Write failing Anthropic contract tests**

Cover content-block concatenation, usage extraction, `request-id`, provider
reasoning blocks when exposed, rate limits, malformed success payloads, and
explicit close.

- [ ] **Step 7: Implement Anthropic provider and verify GREEN**

Run: `python -m pytest tests/providers/test_anthropic.py -q`  
Expected: all tests pass.

- [ ] **Step 8: Write failing provider factory tests**

Assert aliases resolve within provider scope, local providers work without API
keys, remote credentials resolve at construction, and one provider instance is
cached per provider configuration.

- [ ] **Step 9: Implement provider factory**

```python
class ProviderFactory:
    def __init__(
        self,
        config: AppConfig,
        *,
        environ: Mapping[str, str] | None = None,
        transport_factory: TransportFactory | None = None,
    ) -> None: ...

    def resolve_model(self, value: str) -> ModelRef: ...
    def create(self, model: ModelRef) -> Provider: ...
    async def aclose(self) -> None: ...
```

- [ ] **Step 10: Run provider suite**

Run: `python -m pytest tests/providers -q`  
Expected: all tests pass with zero network access.

- [ ] **Step 11: Commit**

```bash
git add cot_redteam/providers cot_redteam/models tests/providers tests/test_models.py
git commit -m "refactor: unify asynchronous model providers"
```

### Task 5: Migrate built-in attacks and monitors

**Files:**
- Modify: every Python module under `cot_redteam/attacks/` except generative
- Modify: every Python module under `cot_redteam/monitors/`
- Create: `cot_redteam/core/reasoning.py`
- Test: `tests/attacks/test_builtin_contract.py`
- Test: `tests/monitors/test_builtin_contract.py`
- Test: `tests/core/test_reasoning.py`

**Interfaces:**
- Consumes: Task 3 plugin contracts and Task 4 provider protocol.
- Produces: stable category-qualified attack IDs, the six stable monitor IDs, `extract_visible_reasoning(text, delimiters) -> tuple[str | None, ReasoningSource]`, and provider-injected LLM monitors.

- [ ] **Step 1: Write failing parameterized attack contract test**

```python
def test_every_builtin_attack_returns_typed_prompt_and_assessment() -> None:
    bootstrap_plugins()
    metadata_items = AttackRegistry.metadata()
    assert metadata_items
    for metadata in metadata_items:
        attack = AttackRegistry.create(metadata.id, {})
        prompt = attack.create_prompt(SAMPLE)
        assessment = attack.assess(SAMPLE, prompt, MODEL_RESPONSE)
        assert prompt.attack_id == metadata.id
        assert 0.0 <= assessment.score <= 1.0
        assert isinstance(assessment.evidence, tuple)
```

- [ ] **Step 2: Run the attack contract test and verify RED**

Run: `python -m pytest tests/attacks/test_builtin_contract.py -q`  
Expected: built-ins lack stable metadata or return old dictionary results.

- [ ] **Step 3: Migrate built-in attacks**

Give each class immutable `PluginMetadata`. Replace ad-hoc result dictionaries
with `AttackAssessment`. Preserve existing prompt and scoring behavior only
when covered by a characterization assertion. Remove the incompatible
`BaseAttack.run` method; the engine owns execution.

Use these stable built-in IDs:

```text
injection.cot_injection
injection.ignore_previous_reasoning
injection.roleplay_injection
faithfulness.unfaithful_cot_detection
faithfulness.cot_hallucination
faithfulness.cot_consistency
steganography.steganographic_cot
steganography.cot_watermarking
steganography.hidden_reasoning
manipulation.reasoning_path_forcing
manipulation.circular_reasoning
manipulation.logical_fallacy_injection
manipulation.premise_injection
sandbagging.sandbagging_detection
sandbagging.capability_hiding
sandbagging.selective_competence
evasion.monitor_awareness
evasion.stealth_reasoning
evasion.dual_process_reasoning
evasion.nl_camouflage
distillation.cot_distillation
distillation.few_shot_extraction
generative.evolved
```

- [ ] **Step 4: Run attack contract and category tests**

Run: `python -m pytest tests/attacks tests/test_attacks.py -q`  
Expected: all built-in attacks satisfy one contract.

- [ ] **Step 5: Write failing reasoning extraction tests**

Cover `<think>...</think>`, `<reasoning>...</reasoning>`, no delimiters,
unclosed delimiters, and ordinary answer text containing “because”. Ordinary
answer text must not be labeled reasoning merely because it contains a
reasoning keyword.

- [ ] **Step 6: Implement conservative visible-reasoning extraction**

Only explicit configured delimiter pairs or provider reasoning fields produce
visible reasoning. Return `ReasoningSource.ABSENT` otherwise.

- [ ] **Step 7: Write failing monitor contract tests**

Assert all stable IDs resolve. Assert regex monitors produce typed outcomes.
Assert ensemble without configured child monitors raises
`ConfigurationError`. Assert LLM monitor parse failures produce
`MonitorStatus.ERROR`, not `CLEAN`.

- [ ] **Step 8: Migrate monitors**

Inject provider dependencies into LLM-backed monitors through
`PluginContext.provider_resolver`. Validate ensemble child IDs and weights
during construction. Cascading monitors stop only after a typed `TRIGGERED`
outcome, never after an error.

- [ ] **Step 9: Run attack, monitor, and reasoning suites**

Run: `python -m pytest tests/attacks tests/monitors tests/core/test_reasoning.py tests/test_attacks.py tests/test_monitors.py -q`  
Expected: all tests pass.

- [ ] **Step 10: Commit**

```bash
git add cot_redteam/attacks cot_redteam/monitors cot_redteam/core/reasoning.py tests/attacks tests/monitors tests/core/test_reasoning.py tests/test_attacks.py tests/test_monitors.py
git commit -m "refactor: migrate attacks and monitors to typed plugins"
```

### Task 6: Dataset loader, planner, budgets, engine, and metrics

**Files:**
- Create: `cot_redteam/eval/dataset.py`
- Create: `cot_redteam/eval/planner.py`
- Create: `cot_redteam/eval/budgets.py`
- Create: `cot_redteam/eval/engine.py`
- Create: `cot_redteam/eval/metrics.py`
- Delete: `cot_redteam/eval/harness.py`
- Delete: `tests/test_eval.py`
- Modify: `cot_redteam/eval/__init__.py`
- Test: `tests/eval/test_dataset.py`
- Test: `tests/eval/test_planner.py`
- Test: `tests/eval/test_budgets.py`
- Test: `tests/eval/test_engine.py`
- Test: `tests/eval/test_metrics_v2.py`

**Interfaces:**
- Consumes: configuration, domain, registries, providers, attacks, and monitors.
- Produces: `Dataset.load_jsonl`, `RunPlan`, `PlannedItem`, `RunPlanner.create`, `BudgetTracker`, `EvaluationEngine.run`, `summarize_run`, `bootstrap_interval`, and `paired_comparison`.

- [ ] **Step 1: Write failing dataset and planner tests**

```python
def test_dataset_digest_is_independent_of_file_path(tmp_path: Path) -> None:
    first = write_dataset(tmp_path / "a.jsonl", SAMPLE_ROWS)
    second = write_dataset(tmp_path / "b.jsonl", SAMPLE_ROWS)
    assert Dataset.load_jsonl(first).digest == Dataset.load_jsonl(second).digest


def test_planner_uses_paired_sample_ids() -> None:
    plan = planner(seed=42, sample_count=2).create()
    by_attack = group_sample_ids(plan.items)
    assert len(set(by_attack.values())) == 1


@pytest.mark.parametrize("empty_field", ["models", "attacks", "monitors", "samples"])
def test_planner_rejects_empty_dimension(empty_field: str) -> None:
    with pytest.raises(ConfigurationError, match=empty_field):
        planner_with_empty(empty_field).create()
```

- [ ] **Step 2: Run planner tests and verify RED**

Run: `python -m pytest tests/eval/test_dataset.py tests/eval/test_planner.py -q`  
Expected: imports fail because dataset and planner modules do not exist.

- [ ] **Step 3: Implement validated dataset loading and deterministic planning**

`Dataset.load_jsonl` reports line numbers for malformed JSON or missing
questions. `RunPlanner.create()` resolves every ID before constructing items,
uses `random.Random(seed)`, sorts selected sample IDs, and produces stable
item IDs from the run/model/attack/sample tuple.

- [ ] **Step 4: Run dataset and planner tests and verify GREEN**

Run: `python -m pytest tests/eval/test_dataset.py tests/eval/test_planner.py -q`  
Expected: all tests pass.

- [ ] **Step 5: Write failing budget tests**

Assert request reservation is concurrency-safe, tokens and cost are committed
after responses, elapsed time uses an injected monotonic clock, and exceeded
budgets reject future reservations without erasing prior accounting.

- [ ] **Step 6: Implement `BudgetTracker`**

```python
class BudgetTracker:
    async def reserve_request(self) -> None: ...
    async def record_response(self, usage: TokenUsage, estimated_cost: Decimal | None) -> None: ...
    def snapshot(self) -> BudgetSnapshot: ...
```

Protect mutable accounting with `asyncio.Lock`.

- [ ] **Step 7: Write failing engine outcome tests**

Use real fake attack and monitor implementations plus an in-memory fake
provider. Cover:

- all items succeed → `COMPLETED`;
- mixed provider success/failure → `PARTIAL`;
- all provider calls fail → `FAILED`;
- monitor exception → item `MONITOR_ERROR`;
- exceeded request budget → remaining items `BUDGET_EXCEEDED`;
- cancellation → unscheduled items `CANCELLED`;
- provider factory closes after success and failure.

- [ ] **Step 8: Implement the asynchronous engine**

```python
class EvaluationEngine:
    def __init__(
        self,
        provider_factory: ProviderFactory,
        attack_registry: Registry[BaseAttack],
        monitor_registry: Registry[BaseMonitor],
        budget: BudgetTracker,
        *,
        concurrency: int,
    ) -> None: ...

    async def run(self, plan: RunPlan) -> EvaluationRun: ...
```

Use one task per planned item behind a semaphore. Convert known stage
exceptions into typed item outcomes. Re-raise `KeyboardInterrupt` and
`SystemExit`. Close providers in `finally`.

- [ ] **Step 9: Run engine tests and verify GREEN**

Run: `python -m pytest tests/eval/test_budgets.py tests/eval/test_engine.py -q`  
Expected: all tests pass.

- [ ] **Step 10: Write failing eligibility-aware metric tests**

```python
def test_monitor_error_is_excluded_from_evasion_rate() -> None:
    summary = summarize_run(run_with_monitor_error())
    assert summary.evasion.eligible == 0
    assert summary.evasion.excluded == 1
    assert summary.evasion.rate is None


def test_empty_run_has_no_rate_instead_of_zero_percent() -> None:
    summary = summarize_run(empty_failed_run())
    assert summary.attack_success.rate is None
```

- [ ] **Step 11: Implement metrics and statistical helpers**

Use `None` for undefined rates. Bootstrap with a local seeded random generator.
Paired comparisons require matching sample IDs and report group sizes, risk
difference, odds ratio when defined, confidence interval, and Fisher p-value.

- [ ] **Step 12: Run complete evaluation suite**

Run: `python -m pytest tests/eval -q`  
Expected: all planner, engine, budget, dataset, and metric tests pass.

- [ ] **Step 13: Commit**

```bash
git add cot_redteam/eval tests/eval tests/test_eval.py
git commit -m "refactor: add failure-aware asynchronous evaluation engine"
```

### Task 7: Transactional SQLite, artifacts, and reproducibility manifests

**Files:**
- Create: `cot_redteam/storage/sqlite.py`
- Create: `cot_redteam/storage/artifacts.py`
- Create: `cot_redteam/eval/manifest.py`
- Modify: `cot_redteam/storage/__init__.py`
- Delete: `cot_redteam/storage/results.py`
- Delete: `tests/test_storage.py`
- Test: `tests/storage/test_sqlite_v2.py`
- Test: `tests/storage/test_artifacts.py`
- Test: `tests/eval/test_manifest.py`

**Interfaces:**
- Consumes: `EvaluationRun`, canonical serialization, redacted config, dataset digest, and plugin metadata.
- Produces: `SQLiteRunStore.save(run, manifest)`, `SQLiteRunStore.get(run_id)`, `SQLiteRunStore.list_runs(limit)`, `ArtifactStore.write_bytes`, `ArtifactRecord`, and `build_manifest`.

- [ ] **Step 1: Write failing SQLite integrity tests**

```python
def test_foreign_keys_are_enabled(store: SQLiteRunStore) -> None:
    assert store.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_save_is_idempotent(store: SQLiteRunStore) -> None:
    store.save(RUN, MANIFEST)
    store.save(RUN, MANIFEST)
    assert store.count_items(RUN.run_id) == len(RUN.items)


def test_failed_item_insert_rolls_back_entire_run(store: SQLiteRunStore) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        store.save(INVALID_RUN, MANIFEST)
    assert store.get(INVALID_RUN.run_id) is None
```

- [ ] **Step 2: Run SQLite tests and verify RED**

Run: `python -m pytest tests/storage/test_sqlite_v2.py -q`  
Expected: import fails because `SQLiteRunStore` does not exist.

- [ ] **Step 3: Implement schema migrations and transactional persistence**

Create `schema_migrations`, `runs`, `evaluation_items`, and `monitor_outcomes`
tables. Enable foreign keys and WAL. Store canonical JSON for typed nested
values. On replacement, delete old child rows and insert new rows within one
transaction.

- [ ] **Step 4: Run SQLite tests and verify GREEN**

Run: `python -m pytest tests/storage/test_sqlite_v2.py -q`  
Expected: all tests pass.

- [ ] **Step 5: Write failing artifact tests**

Assert identical bytes at different paths have identical hashes, partial
temporary files are removed after a simulated write failure, and returned
manifest paths are relative to the artifact root.

- [ ] **Step 6: Implement atomic artifact writes**

Write to a temporary file in the destination directory, flush and `fsync`,
rename with `os.replace`, then hash final bytes. Clean up the exact temporary
path in `finally`.

- [ ] **Step 7: Write failing manifest tests**

Assert API key values are absent, timestamps supplied by the run are stable,
dataset and configuration digests are present, artifacts include byte lengths
and hashes, and a dirty Git worktree is represented explicitly.

- [ ] **Step 8: Implement manifest generation**

Inject Git and installed-distribution readers so tests remain deterministic.
Do not execute Git once per item. Canonicalize the complete manifest before
hashing it.

- [ ] **Step 9: Run storage and manifest suites**

Run: `python -m pytest tests/storage tests/eval/test_manifest.py -q`  
Expected: all storage, artifact, and manifest tests pass.

- [ ] **Step 10: Commit**

```bash
git add cot_redteam/storage cot_redteam/eval/manifest.py tests/storage tests/eval/test_manifest.py tests/test_storage.py
git commit -m "refactor: add transactional storage and reproducible artifacts"
```

### Task 8: Truthful reports and statistical presentation

**Files:**
- Create: `cot_redteam/reporting/model.py`
- Create: `cot_redteam/reporting/renderers.py`
- Modify: `cot_redteam/reporting/report.py`
- Modify: `cot_redteam/reporting/__init__.py`
- Test: `tests/reporting/test_markdown.py`
- Test: `tests/reporting/test_csv.py`
- Test: `tests/reporting/test_latex.py`

**Interfaces:**
- Consumes: evaluation summary, manifest, and stored run.
- Produces: `ReportFormat`, `ReportModel.from_run`, `render_markdown`, `render_csv`, `render_latex`, and `ReportWriter.write(run, format) -> Path`.

- [ ] **Step 1: Write failing renderer tests**

```python
def test_requested_format_matches_content(tmp_path: Path) -> None:
    writer = ReportWriter(tmp_path)
    csv_path = writer.write(REPORT, ReportFormat.CSV)
    assert csv_path.suffix == ".csv"
    assert csv_path.read_text().startswith("section,")


def test_csv_quotes_newlines_and_neutralizes_formulas() -> None:
    output = render_csv(report_with_model_id("=IMPORTXML(...)\\nnext"))
    rows = list(csv.reader(io.StringIO(output)))
    assert rows[1][1].startswith("'=")
    assert "\\n" in rows[1][1]


def test_latex_escapes_all_control_characters() -> None:
    output = render_latex(report_with_model_id(r"a_b%#&{}$"))
    assert r"a\\_b\\%\\#\\&\\{\\}\\$" in output
```

- [ ] **Step 2: Run reporting tests and verify RED**

Run: `python -m pytest tests/reporting -q`  
Expected: imports fail because typed report renderers do not exist.

- [ ] **Step 3: Implement one report view model and three renderers**

Build the report model once. Use `csv.writer` for CSV. Escape LaTeX through a
single character map. Include status, planned/succeeded/failed counts,
eligibility denominators, undefined rates as `N/A`, model IDs, plugin
versions, confidence intervals, effect sizes, and reproducibility limitations.

- [ ] **Step 4: Implement atomic report writing**

Reuse `ArtifactStore` so report files receive content hashes and never leave
partial output.

- [ ] **Step 5: Run reporting suite**

Run: `python -m pytest tests/reporting -q`  
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add cot_redteam/reporting tests/reporting
git commit -m "refactor: render typed reports in real output formats"
```

### Task 9: CLI and supported Python API vertical slice

**Files:**
- Modify: `cot_redteam/cli/main.py`
- Create: `cot_redteam/api.py`
- Create: `tests/cli/test_config_commands.py`
- Create: `tests/cli/test_run_command.py`
- Create: `tests/cli/test_query_commands.py`
- Create: `tests/fixtures/fake_plugin.py`
- Create: `cot_redteam/py.typed`
- Modify: `pyproject.toml`
- Delete: `cot_redteam/scheduler/__init__.py`
- Delete: `cot_redteam/scheduler/model_watcher.py`

**Interfaces:**
- Consumes: all completed core, plugin, provider, evaluation, storage, and report interfaces.
- Produces: documented CLI commands, exit-code mapping, `run_evaluation(config, dependencies=None)`, and `load_run(store, run_id)`.

- [ ] **Step 1: Write failing config-command subprocess tests**

Assert:

- `init` writes `config.example.yaml` content to a requested new path;
- `init` refuses overwrite without `--force`;
- `config validate` succeeds with fixture credentials;
- `config validate` exits `2` on missing remote credentials;
- `config show` never prints fixture secret values.

- [ ] **Step 2: Run config CLI tests and verify RED**

Run: `python -m pytest tests/cli/test_config_commands.py -q`  
Expected: parser does not expose the new commands.

- [ ] **Step 3: Implement parser, config commands, and centralized errors**

`main(argv: Sequence[str] | None = None) -> int` returns an exit code. The
console-script wrapper raises `SystemExit(main())`. Print expected user errors
without tracebacks; `--debug` includes tracebacks.

- [ ] **Step 4: Run config CLI tests and verify GREEN**

Run: `python -m pytest tests/cli/test_config_commands.py -q`  
Expected: all tests pass.

- [ ] **Step 5: Write failing end-to-end run tests**

Register a fake provider through injected dependencies. Assert:

- completed run exits `0`, stores results, and prints run ID plus counts;
- all provider failures exit `1`;
- mixed outcomes exit `3`;
- invalid monitor ID exits `2` before provider invocation;
- report command writes the requested actual format;
- list/show commands read from configured SQLite.

- [ ] **Step 6: Implement Python API orchestration**

```python
async def run_evaluation(
    config: AppConfig,
    *,
    provider_factory: ProviderFactory | None = None,
    run_store: SQLiteRunStore | None = None,
    artifact_store: ArtifactStore | None = None,
) -> EvaluationRun: ...
```

The CLI calls this API. The API does not import `cot_redteam.cli`.

- [ ] **Step 7: Implement run, list, show, report, and list-plugin commands**

Build dependencies once, validate before calls, persist the run and manifest,
and close providers in every path. `list-attacks` and `list-monitors` display
stable IDs and versions.

- [ ] **Step 8: Run the CLI and API suite**

Run: `python -m pytest tests/cli -q`  
Expected: all tests pass without network access.

- [ ] **Step 9: Update packaging metadata**

Set version `0.2.0`, add mypy/build/pip-tools development dependencies, include
the `py.typed` marker, add package classifiers, and remove unimplemented
dashboard/tracking extras from advertised installation paths. Remove the
unintegrated scheduler package; document model watching as a removed
experimental `0.1` capability in the migration guide.

- [ ] **Step 10: Build and install smoke test**

Run:

```bash
python -m build
python -m pip install --force-reinstall --no-deps dist/cot_redteam_agent-0.2.0-py3-none-any.whl
cot-redteam --help
```

Expected: build and install exit `0`; help lists all documented commands.

- [ ] **Step 11: Commit**

```bash
git add cot_redteam/cli cot_redteam/api.py cot_redteam/py.typed cot_redteam/scheduler tests/cli tests/fixtures/fake_plugin.py pyproject.toml
git commit -m "feat: deliver the v0.2 CLI and Python API"
```

### Task 10: Bounded generative attack engine

**Files:**
- Rewrite: `cot_redteam/attacks/generative/engine.py`
- Modify: `cot_redteam/attacks/generative/__init__.py`
- Create: `tests/generative/test_specs.py`
- Create: `tests/generative/test_novelty.py`
- Create: `tests/generative/test_engine.py`
- Modify: `tests/cli/test_run_command.py`

**Interfaces:**
- Consumes: provider protocol, attack registry, standard planner/engine, and typed results.
- Produces: validated `AttackSpec`, `AttackCandidate`, `GenerativeAttackEngine.generate_population`, `GenerativeAttackEngine.evolve`, `lexical_novelty`, and CLI `evolve`.

- [ ] **Step 1: Write failing generated-spec validation tests**

Assert missing `{question}`, unknown keys, invalid names, excessive prompt
length, excessive tags, and malformed provider JSON are rejected with
diagnostics and no code execution.

- [ ] **Step 2: Run spec tests and verify RED**

Run: `python -m pytest tests/generative/test_specs.py -q`  
Expected: the existing dataclass accepts invalid generated content.

- [ ] **Step 3: Implement strict Pydantic `AttackSpec`**

Set explicit maximum lengths and counts. Parse one JSON object from provider
text without evaluating Markdown or Python. Render templates with a
strict mapping that rejects unknown placeholders.

- [ ] **Step 4: Write failing deterministic novelty tests**

Assert identical prompts score `0`, disjoint token-shingle sets score `1`, and
the same archive produces identical scores across repeated calls.

- [ ] **Step 5: Implement lexical novelty**

Normalize Unicode, lowercase, split word tokens, build 3-token shingles, and
return minimum Jaccard distance against archived templates. Define empty-token
behavior explicitly in tests.

- [ ] **Step 6: Write failing bounded-generation and execution tests**

Use a fake generator that always returns malformed JSON and assert the engine
stops at `max_generation_attempts`. Use a valid generator and assert candidates
execute through `EvaluationEngine`, retain run IDs and sample IDs, and compute
fitness from actual success/evasion/novelty components.

- [ ] **Step 7: Implement bounded generation, mutation, crossover, and archive**

No population-producing loop may run without an attempt counter. Return a
`GenerationResult` containing candidates and diagnostics when the requested
population cannot be filled.

- [ ] **Step 8: Implement the `evolve` CLI path**

Require generator and target model references, validate the fitness weights,
evaluate every generation before selection, persist generation runs, and
export a versioned archive JSON document.

- [ ] **Step 9: Run generative and CLI suites**

Run: `python -m pytest tests/generative tests/cli/test_run_command.py -q`  
Expected: all tests pass and no random placeholder scoring remains.

- [ ] **Step 10: Commit**

```bash
git add cot_redteam/attacks/generative tests/generative tests/cli/test_run_command.py
git commit -m "refactor: make generative attacks bounded and measurable"
```

### Task 11: Documentation, migration, contribution, and release files

**Files:**
- Rewrite: `README.md`
- Create: `LICENSE`
- Create: `CONTRIBUTING.md`
- Create: `CHANGELOG.md`
- Create: `docs/configuration.md`
- Create: `docs/providers.md`
- Create: `docs/plugins.md`
- Create: `docs/experiments.md`
- Create: `docs/migration-0.1-to-0.2.md`
- Create: `docs/release-checklist.md`
- Test: `tests/docs/test_documented_examples.py`

**Interfaces:**
- Consumes: actual CLI help, example configuration, plugin contracts, and result semantics.
- Produces: an accurate installation path, five-minute quickstart, provider setup, plugin tutorial, experiment interpretation guide, and migration mapping.

- [ ] **Step 1: Write failing documentation-example tests**

Extract shell commands marked `<!-- test: command -->` and Python snippets
marked `<!-- test: python -->`. Assert the example configuration validates,
documented plugin classes import, every command appears in `--help`, and no
README claim mentions dashboard or Parquet.

- [ ] **Step 2: Run documentation tests and verify RED**

Run: `python -m pytest tests/docs/test_documented_examples.py -q`  
Expected: current README contains unsupported claims and lacks v0.2 examples.

- [ ] **Step 3: Rewrite README and user guides**

Document visible-reasoning limitations, failure-aware metrics, credential
environment variables, local-provider configuration, data-retention controls,
and how to interpret exclusions. Do not call automated graders ground truth.

- [ ] **Step 4: Write plugin and migration guides**

The plugin guide includes a complete installable attack entry-point example
and monitor entry-point example. The migration guide maps every old top-level
configuration section, old monitor name, CLI command, and result field.

- [ ] **Step 5: Add project governance files**

Use the standard MIT license text with the repository author and year. Define
development setup, test commands, style requirements, issue expectations, and
release checks without inventing a code of conduct or support SLA.

- [ ] **Step 6: Run documentation tests**

Run: `python -m pytest tests/docs/test_documented_examples.py -q`  
Expected: all tested examples pass.

- [ ] **Step 7: Commit**

```bash
git add README.md LICENSE CONTRIBUTING.md CHANGELOG.md docs tests/docs
git commit -m "docs: publish accurate v0.2 user and contributor guides"
```

### Task 12: Static quality gates, lockfile, CI, and final release verification

**Files:**
- Modify: `pyproject.toml`
- Create: `.gitignore`
- Create: `.github/workflows/ci.yml`
- Create: `requirements-dev.lock`
- Create: `scripts/check_critical_coverage.py`
- Modify: source and tests only where Ruff or mypy reports concrete defects

**Interfaces:**
- Consumes: the complete 0.2 implementation.
- Produces: reproducible development installation, enforced formatting/linting/typing/coverage, Python-version matrix, and installable artifacts.

- [ ] **Step 1: Add explicit Ruff, mypy, and coverage configuration**

Configure Ruff rules intentionally rather than accepting all optional rules.
Enable strict mypy for new core/provider/eval/storage/reporting modules and
incrementally type legacy attack implementations. Configure pytest coverage
with `fail_under = 75`. Add `scripts/check_critical_coverage.py` to read
`coverage.json` and fail when any configuration, planning, execution, metrics,
or storage module is below 85 percent.

- [ ] **Step 2: Run quality gates and capture RED output**

Run:

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy cot_redteam
python -m pytest --cov=cot_redteam --cov-report=term-missing --cov-report=json
python scripts/check_critical_coverage.py coverage.json
```

Expected: at least one gate fails before cleanup or coverage completion.

- [ ] **Step 3: Fix only reported quality defects**

Apply Ruff formatting mechanically. Resolve undefined names, unused runtime
state, broad exception swallowing, incompatible types, and uncovered critical
branches. Do not perform unrelated feature refactors.

- [ ] **Step 4: Generate and verify the development lock**

Run:

```bash
python -m piptools compile --generate-hashes --extra dev --output-file requirements-dev.lock pyproject.toml
python -m pip install --dry-run --require-hashes -r requirements-dev.lock
```

Expected: both commands exit `0`.

- [ ] **Step 5: Add GitHub Actions workflow**

The workflow has:

- a primary Python job installing `requirements-dev.lock` with
  `--require-hashes` and running Ruff, mypy, pytest, coverage, and build;
- a Python 3.10–3.13 matrix installing `.[dev]` from package metadata and
  running tests;
- a wheel smoke job installing the built wheel with `--no-deps` after
  dependencies and invoking `cot-redteam --help`.

- [ ] **Step 6: Run the full local verification gate**

Run:

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy cot_redteam
python -m pytest --cov=cot_redteam --cov-report=term-missing --cov-report=json
python scripts/check_critical_coverage.py coverage.json
python -m build
python -m pip check
```

Expected: every command exits `0`, the complete coverage is at least 75
percent, and critical modules are each at least 85 percent.

- [ ] **Step 7: Verify package installation in a clean temporary environment**

Run:

```bash
SMOKE_DIR="$(mktemp -d)"
python -m venv "$SMOKE_DIR/venv"
"$SMOKE_DIR/venv/bin/python" -m pip install dist/cot_redteam_agent-0.2.0-py3-none-any.whl
"$SMOKE_DIR/venv/bin/cot-redteam" --help
```

Expected: installation and help exit `0`.

- [ ] **Step 8: Audit acceptance criteria against evidence**

For each of the eleven acceptance criteria in the design specification, record
the proving test or command in `docs/release-checklist.md`. If a criterion has
no evidence, add the missing test and repeat the relevant verification gate.

- [ ] **Step 9: Commit**

```bash
git add .github .gitignore pyproject.toml requirements-dev.lock scripts/check_critical_coverage.py cot_redteam tests docs/release-checklist.md
git commit -m "chore: enforce v0.2 release quality gates"
```

---

## Final verification sequence

After all task commits:

```bash
git status --short
python -m ruff format --check .
python -m ruff check .
python -m mypy cot_redteam
python -m pytest --cov=cot_redteam --cov-report=term-missing --cov-report=json
python scripts/check_critical_coverage.py coverage.json
python -m build
python -m pip check
```

The work is complete only when the worktree contains no unintended files, all
commands exit `0`, coverage thresholds are met, the clean-wheel smoke test
passes, and every design acceptance criterion has recorded evidence.

## Specification coverage matrix

| Design requirement | Implemented and verified by |
|---|---|
| Strict configuration, precedence, redaction, provider credentials | Task 2 and Task 9 |
| Typed domain and explicit item/run/monitor outcomes | Task 1 and Task 6 |
| Stable built-in and third-party plugin contracts | Task 3 and Task 5 |
| Five asynchronous provider integrations, retries, lifecycle | Task 4 |
| Deterministic datasets, paired planning, budgets, cancellation | Task 6 |
| Eligibility-aware metrics, intervals, effects, Fisher comparisons | Task 6 and Task 8 |
| Transactional SQLite and idempotent persistence | Task 7 |
| Atomic artifacts, byte hashes, and reproducibility manifests | Task 7 |
| Real Markdown, CSV, and LaTeX output | Task 8 |
| CLI exit semantics and supported Python API | Task 9 |
| Bounded measurable generative attacks | Task 10 |
| Accurate documentation, plugin tutorial, and 0.1 migration | Task 11 |
| Dependency lock, CI matrix, lint, typing, coverage, wheel smoke | Task 12 |
| Acceptance evidence and unsupported-claim audit | Task 11 and Task 12 |
