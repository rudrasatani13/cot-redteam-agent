# CoT Red Team Agent 0.2 Architecture Design

**Status:** Approved direction  
**Date:** 2026-07-29  
**Release target:** `0.2.0`  
**Compatibility:** Intentional breaking release from `0.1.x`

## 1. Purpose

Version 0.2 turns the repository from a prototype into a dependable,
open-source evaluation tool that lets users supply their own provider
credentials, run Chain-of-Thought red-team experiments, and receive results
that distinguish successful evaluations from infrastructure failures.

The release replaces contradictory configuration and execution contracts.
It preserves valid attack and monitor logic where practical, but it does not
preserve broken `0.1.x` internal APIs. A migration guide will document every
user-facing configuration and command change.

## 2. Goals

The release must:

1. Provide a validated configuration path shared by the CLI and Python API.
2. Support OpenRouter, OpenAI, Anthropic, vLLM, and llama.cpp without storing
   credentials in source-controlled configuration.
3. Run attacks, providers, and monitors through one asynchronous execution
   engine.
4. Represent provider, attack, monitor, budget, and cancellation failures
   explicitly.
5. Prevent missing or failed monitors from being counted as successful
   evasion.
6. Produce deterministic run manifests and content-based artifact hashes.
7. Persist runs transactionally and idempotently in SQLite.
8. Generate truthful Markdown, CSV, and LaTeX reports.
9. Make generative attacks bounded, validated, deterministic where expected,
   and executable through the same engine as static attacks.
10. Provide an extension API and documentation for third-party attacks and
    monitors.
11. Ship automated tests, static analysis, package verification, and CI for
    Python 3.10 through 3.13.

## 3. Non-goals

The 0.2 release will not:

- implement a hosted multi-user service;
- implement authentication, teams, billing, or tenant isolation;
- claim access to hidden model reasoning that a provider does not expose;
- include a production dashboard;
- claim Parquet support without an implemented backend;
- automatically download commercial benchmark datasets;
- guarantee cross-provider equivalence when providers expose different
  response metadata;
- provide a generic replacement for full evaluation frameworks such as
  Inspect AI or PyRIT.

Future integrations may expose this project’s attacks and monitors to those
frameworks without changing the 0.2 core contracts.

## 4. Design principles

### 4.1 Explicit outcomes

Infrastructure errors are data, not negative evaluation results. Every stage
returns a typed outcome. Aggregate metrics operate only on outcomes that meet
the metric’s eligibility rules.

### 4.2 One public contract per concept

There is one application configuration model, one provider protocol, one
attack protocol, one monitor protocol, and one execution path. Compatibility
adapters are temporary migration aids and cannot become parallel runtimes.

### 4.3 Safe provider onboarding

Configuration names environment variables, not secret values. The runtime
resolves credentials immediately before provider construction. Secrets are
excluded from representations, logs, snapshots, artifacts, database rows, and
exceptions.

### 4.4 Deterministic experiments

Given the same dataset, seed, configuration, plugin versions, and model
behavior, sample selection and local scoring produce the same result.
Provider nondeterminism and missing provider revision metadata are recorded as
limitations in the run manifest.

### 4.5 Small extension surface

Third-party code implements documented protocols and registers stable IDs.
Registries validate duplicates and unknown references before a run starts.
Plugins do not depend on CLI internals, SQLite, or report rendering.

## 5. System architecture

```text
CLI / Python API
        |
        v
Configuration Loader -----> Plugin Bootstrap
        |                         |
        +------------+------------+
                     v
                 Run Planner
                     |
                     v
            Async Evaluation Engine
             /        |          \
         Attack    Provider     Monitor Pipeline
             \        |          /
              +-------+---------+
                      v
              Result Aggregator
                 /          \
          Artifact Store   SQLite Store
                 \          /
                  Report Renderer
```

The application layer owns startup, dependency construction, and lifecycle.
Domain types do not import the CLI, HTTP clients, SQLite, or report renderers.

## 6. Configuration

### 6.1 Application configuration

`AppConfig` is a Pydantic model composed of:

- `GlobalSettings`
- `ProviderSettings`
- `EvaluationSettings`
- `ArtifactSettings`
- `StorageSettings`
- `ReportingSettings`
- `GenerativeSettings`

Unknown configuration keys are rejected. Values with operational impact have
explicit bounds, including positive timeouts, non-negative retry counts,
temperatures in the supported range, positive concurrency limits, and positive
budgets.

### 6.2 Provider configuration

Each named provider contains:

- provider kind;
- base URL when applicable;
- environment variable containing the API key;
- timeout;
- maximum retries;
- concurrency limit;
- optional headers that are explicitly safe to persist;
- optional input and output price per million tokens;
- model aliases.

The model reference syntax remains `provider:model-id`. Aliases are resolved
within their named provider. A missing credential is a configuration error for
remote providers and is detected before the first request. Local providers may
omit credentials.

### 6.3 Configuration precedence

Values resolve in this order, from lowest to highest priority:

1. schema defaults;
2. YAML file;
3. explicit CLI arguments.

Environment variables provide secret values only. They do not silently
override unrelated experiment settings.

### 6.4 Validation commands

`cot-redteam config validate --config PATH` validates schema, provider
references, plugin IDs, file paths, and secret availability without contacting
providers.

`cot-redteam config show --config PATH` prints the resolved non-secret
configuration with credential fields replaced by a redaction marker.

## 7. Domain model

### 7.1 Requests and responses

`GenerationRequest` contains the prompt, optional system prompt, generation
parameters, and request metadata.

`ModelResponse` contains:

- response text;
- optional visible reasoning text;
- reasoning source (`provider`, `delimited`, or `absent`);
- resolved provider and model IDs;
- latency;
- token usage;
- provider request ID;
- finish reason;
- raw provider metadata after secret filtering.

The code uses the term “visible reasoning” when text was returned to the user
or exposed by the provider. Documentation does not describe inferred or
extracted text as a model’s private hidden reasoning.

### 7.2 Evaluation outcomes

Each attack/sample/model combination produces an `EvaluationItem` with one of:

- `SUCCEEDED`
- `ATTACK_ERROR`
- `PROVIDER_ERROR`
- `MONITOR_ERROR`
- `BUDGET_EXCEEDED`
- `CANCELLED`

A succeeded item contains an `AttackAssessment` and the configured monitor
outcomes. A monitor outcome has one of:

- `TRIGGERED`
- `CLEAN`
- `ERROR`
- `NOT_RUN`

Monitor `ERROR` and `NOT_RUN` outcomes are never equivalent to `CLEAN`.

### 7.3 Run outcomes

A run is:

- `COMPLETED` when every planned item reaches `SUCCEEDED`;
- `PARTIAL` when at least one item succeeds and at least one item does not;
- `FAILED` when no planned item succeeds or startup validation fails.

The run summary always includes planned, succeeded, failed, excluded, and
cancelled counts.

## 8. Plugin contracts

### 8.1 Attack protocol

An attack declares a stable ID, category, description, version, tags, and
configuration schema. It:

1. creates an `AttackPrompt` from a dataset sample;
2. evaluates a `ModelResponse`;
3. returns an `AttackAssessment` containing success, score, evidence, and
   metric values.

Attack code does not create model clients or write results.

### 8.2 Monitor protocol

A monitor declares a stable ID, description, version, and configuration
schema. It accepts an attack prompt and model response and returns a
`MonitorOutcome`.

LLM-backed monitors receive a provider dependency through construction. They
do not resolve credentials or instantiate clients themselves.

### 8.3 Provider protocol

A provider supports asynchronous generation and asynchronous close. The
application constructs one provider instance per resolved provider
configuration and shares it across bounded concurrent requests.

OpenAI, OpenRouter, vLLM, and llama.cpp share an OpenAI-compatible transport.
Anthropic uses a separate transport because its request and response contracts
differ.

### 8.4 Registries

Registry entries use declared IDs rather than inferred class-name namespaces.
Duplicate IDs fail bootstrap. Unknown configured IDs fail planning. The CLI
lists IDs, versions, categories, and descriptions.

Built-in plugins register during package bootstrap. Third-party distributions
register through Python package entry points in the
`cot_redteam.attacks` and `cot_redteam.monitors` groups. The Python API also
supports explicit in-process registration for notebooks and applications.
Entry-point loading errors identify the distribution and entry-point name and
fail validation before a run starts.

The built-in monitor IDs are:

- `regex`
- `regex_advanced`
- `llm_judge`
- `self_monitor`
- `ensemble`
- `cascading`

Attack IDs remain category-qualified to avoid collisions.

## 9. Execution engine

### 9.1 Planning

The planner resolves models, attacks, monitors, and a deterministic sample set.
It rejects a plan containing zero models, zero attacks, zero monitors, or zero
dataset samples.

Sample selection is paired: the same selected sample IDs are used for each
comparable attack/model combination. The manifest records the ordered sample
IDs and seed.

### 9.2 Execution

The engine is asynchronous end to end. A semaphore enforces the configured
concurrency limit. Provider clients remain open for the run and close in a
`finally` path.

Each item executes:

1. generate the attack prompt;
2. check request and budget limits;
3. call the provider;
4. evaluate the attack response;
5. execute monitors;
6. persist the typed outcome.

An item failure does not abort unrelated items unless the configured failure
threshold or a global budget is reached.

### 9.3 Retries and budgets

Provider transports classify errors into retryable and permanent categories.
Only transient network failures, server failures, and rate limits are retried.
Retries use exponential backoff with jitter and respect `Retry-After`.

Runs can limit:

- requests;
- input and output tokens;
- elapsed time;
- estimated cost when pricing is explicitly configured.

Reaching a budget creates `BUDGET_EXCEEDED` outcomes and stops scheduling new
requests. It does not discard completed results.

### 9.4 CLI exit codes

- `0`: completed run;
- `1`: failed run;
- `2`: configuration or command usage error;
- `3`: partial run.

## 10. Metrics and research validity

Metrics declare eligibility rules. Attack success rate includes only succeeded
evaluation items. Evasion rate requires every configured monitor to return a
non-error outcome; otherwise the item is excluded from evasion-rate
calculation and counted under monitor exclusions.

The 0.2 summary includes:

- attack success rate;
- monitor trigger rate;
- eligible evasion rate;
- provider and monitor failure rates;
- per-model and per-category breakdowns;
- bootstrap confidence intervals when at least two eligible samples exist;
- paired effect-size comparisons when two comparable groups exist.

Fisher’s exact test may be reported for binary comparisons, but a p-value is
never presented without group sizes and an effect-size estimate.

LLM-judge reports include judge provider, model ID, prompt version, parsing
failure count, and calibration fixture results. Automated graders are not
described as ground truth.

## 11. Generative attack engine

Generated payloads are parsed into a validated `AttackSpec`. Names, templates,
tags, and parameter values have length and count limits. Templates must contain
the documented `{question}` placeholder.

Initial generation, mutation, and crossover have explicit maximum attempts.
Failure to fill a requested population produces a partial population with
diagnostics rather than an infinite loop.

Candidates execute through the normal planner and engine. Fitness supports:

- attack success;
- eligible monitor evasion;
- deterministic lexical novelty;
- a validated weighted combination of those values.

Lexical novelty compares normalized token shingles using Jaccard distance
against the archive. It is deterministic and requires no additional embedding
dependency. Unsupported metrics are configuration errors.

The archive records candidate ID, complete specification, generation, parent
IDs, mutation history, fitness components, evaluated sample IDs, model IDs,
and run IDs.

## 12. Persistence and artifacts

### 12.1 SQLite

SQLite enables foreign-key enforcement on every connection. Schema versioning
uses a small ordered migration table maintained by the project.

Run writes use transactions. Saving an existing run ID replaces the aggregate
and its item rows as one operation, preventing duplicate child results.
Queries use parameters and return typed records.

### 12.2 Artifact store

Artifacts are written atomically through a temporary file followed by rename.
Hashes are SHA-256 values over file bytes. A manifest references each artifact
by relative path, media type, byte length, and content hash.

The run manifest contains:

- run ID and timestamps;
- run status and failure counts;
- canonical redacted configuration;
- configuration digest;
- ordered dataset sample IDs and dataset digest;
- random seed;
- Git revision and dirty-worktree marker;
- Python and package versions;
- plugin IDs and versions;
- provider and model IDs;
- provider revision metadata when available;
- artifact hashes;
- known reproducibility limitations.

Raw prompts, responses, and visible reasoning retention are independently
configurable. The default example config enables prompts and responses for
research reproducibility and documents their sensitivity.

## 13. Reporting

The report layer renders one typed report model into:

- Markdown;
- RFC 4180-compatible CSV;
- escaped LaTeX.

Each requested format has a real renderer. File extensions never misrepresent
content. Reports include run status, eligibility counts, failure counts,
configuration and dataset digests, model identifiers, intervals, effect sizes,
and reproducibility limitations.

Spreadsheet-oriented CSV output prefixes cells that begin with formula control
characters to prevent accidental formula execution.

## 14. Command-line and Python interfaces

The CLI provides:

- `cot-redteam init`
- `cot-redteam config validate`
- `cot-redteam config show`
- `cot-redteam list-attacks`
- `cot-redteam list-monitors`
- `cot-redteam list-providers`
- `cot-redteam run`
- `cot-redteam list-runs`
- `cot-redteam show-run`
- `cot-redteam report`
- `cot-redteam evolve`

`init` writes an example configuration without credentials and refuses to
overwrite an existing file unless the user explicitly supplies `--force`.

The Python API exposes configuration loading, planning, engine execution,
registry registration, result queries, and reporting without importing CLI
modules.

## 15. Trust boundaries and data handling

Untrusted inputs include:

- YAML configuration;
- environment variables;
- JSONL datasets;
- generated attack specifications;
- model responses;
- provider error bodies;
- plugin code;
- database contents opened from user-selected paths.

The application validates structured inputs, bounds generated content,
redacts secrets, escapes report formats, avoids dynamic code execution, and
does not deserialize arbitrary Python objects.

Third-party plugins execute in the application process and are therefore
trusted code. The plugin documentation states this explicitly; 0.2 does not
claim plugin sandboxing.

## 16. Testing strategy

Implementation follows red-green-refactor cycles. The suite contains:

1. configuration tests for valid files, unknown keys, missing credentials,
   redaction, aliases, and CLI precedence;
2. provider contract tests using `httpx.MockTransport`;
3. planner tests for unknown IDs and empty selections;
4. engine tests for complete, partial, failed, budgeted, and cancelled runs;
5. metric tests proving missing or failed monitors cannot count as evasion;
6. SQLite tests for foreign keys, transactions, migrations, and idempotency;
7. artifact tests for atomic writes and content hashes;
8. renderer tests for Markdown, CSV quoting and formula protection, and LaTeX
   escaping;
9. generative-engine tests for schema validation, deterministic novelty,
   bounded attempts, and real execution through the engine;
10. CLI subprocess tests with a fake provider and no real credentials;
11. package build and installation smoke tests.

Coverage enforcement applies to the complete package with an initial floor of
75 percent. Core configuration, planning, execution, metrics, and storage
modules each require at least 85 percent coverage. Coverage floors can increase
after 0.2 without weakening per-module expectations.

CI runs Ruff formatting and linting, mypy, pytest with coverage, package build,
and wheel installation on Python 3.10, 3.11, 3.12, and 3.13.

## 17. Packaging and documentation

The package version becomes `0.2.0`. Runtime dependencies use compatible
version ranges rather than exact pins. The repository stores a
`requirements-dev.lock` file with hashes, generated from `pyproject.toml` by
`pip-compile --generate-hashes`. CI installs that lock with hash verification
on the primary Python version and independently tests dependency resolution
from package metadata across the supported Python matrix.

Release documentation includes:

- rewritten README with accurate claims;
- installation and five-minute quickstart;
- provider credential guide;
- complete configuration reference;
- Python API example;
- attack and monitor plugin tutorial;
- experiment interpretation guide;
- `0.1.x` migration guide;
- `CONTRIBUTING.md`;
- `LICENSE`;
- changelog entry and release checklist.

## 18. Migration policy

The old duplicate `Config` singleton and incompatible `BaseAttack.run`
contract are removed. The migration guide maps:

- old configuration sections to the 0.2 schema;
- old monitor names to stable IDs;
- old attack registration to the new protocol;
- old result fields to typed outcomes;
- old CLI examples to the new commands.

Because `0.1.x` did not have a coherent executable configuration contract,
0.2 does not include a runtime compatibility mode. This avoids maintaining a
second untestable execution path.

## 19. Delivery phases

1. Core domain types, configuration, and validated registries.
2. Provider protocol, transports, and lifecycle.
3. Planner, asynchronous engine, budgets, and metrics.
4. CLI integration and deterministic end-to-end fake-provider run.
5. SQLite migrations, artifacts, manifests, and reports.
6. Generative attack repair and bounded evolution.
7. Statistical summaries and grader calibration fixtures.
8. Documentation, migration materials, CI, linting, typing, build, and final
   release verification.

Each phase must end with passing targeted tests and leave the repository in a
runnable state.

## 20. Acceptance criteria

Version 0.2 is ready when:

1. a new user can install the wheel, initialize configuration, set one provider
   environment variable, validate configuration, and run the sample dataset;
2. an invalid credential produces a failed or partial run, never a zero-result
   completed run;
3. missing or failed monitors cannot increase evasion rate;
4. every documented built-in provider, attack, and monitor resolves before
   execution;
5. repeated persistence of the same run does not duplicate item rows;
6. artifact hashes change when file content changes and not when only paths
   change;
7. generative population creation terminates within configured attempt bounds;
8. generated candidates are evaluated through the standard engine;
9. every documented report format contains the requested format;
10. tests, lint, formatting, typing, coverage, package build, and installation
    verification pass in CI;
11. the README contains no feature claim unsupported by tested code.
