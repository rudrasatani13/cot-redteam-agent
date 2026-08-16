# Providers

Supported kinds:

| Kind | Transport | Credential |
|---|---|---|
| `openrouter` | OpenAI-compatible | `api_key_env` required |
| `openai` | OpenAI-compatible | `api_key_env` required |
| `anthropic` | Anthropic Messages API | `api_key_env` required |
| `vllm` | OpenAI-compatible | optional |
| `llamacpp` | OpenAI-compatible | optional |
| `openai_compatible` | Explicit `base_url` | optional |
| `mock` | None (in-process) | none |

## Retries, rate limits, and cost accounting

Both HTTP transports retry transient failures (429 and 5xx) with capped
exponential backoff and jitter. A server-supplied `Retry-After` header is
honored but clamped to at most 60 seconds, so a hostile endpoint cannot
stall a run indefinitely. Redirects (3xx) are treated as permanent
configuration errors and are not retried. The Anthropic transport clamps
`temperature` to its supported 0–1 range.

One logical invocation may issue several wire HTTP requests (up to
`1 + max_retries`); wire attempts are recorded in the invocation ledger and
emitted in invocation events. Anthropic prompt-cache usage is billed in cost
estimates: cache writes at 1.25× and cache reads at 0.1× of the input price.

## Mock provider

The `mock` provider is a deterministic, keyless stand-in that never touches
the network. It exists so demos, tests, and CI can exercise the full pipeline
without any API budget:

```yaml
providers:
  mock:
    kind: mock
    mock_mode: auto   # auto | refuse | disclose | error
```

- `auto` (default): discloses a synthetic canary (`COT-REDTEAM-CANARY-*` or
  benchmark `COTRT3-*`) when one appears in the request, otherwise refuses.
- `disclose`: always discloses (falls back to a fixed mock canary).
- `refuse`: always refuses extraction and answers the utility question.
- `error`: raises a provider error to exercise failure paths.

The generative `evolve` pipeline also works against the mock provider (it
returns a valid attack spec JSON for generation prompts), so the whole
feature surface is testable offline.

Model references use `provider:model-id` (aliases resolve within the named provider).

Retries apply to timeouts, connection errors, HTTP 429, and 5xx. Other 4xx
responses are permanent failures.

Providers close in a `finally` path after each run.

Benchmark requests preserve ordered role messages. A provider capability must
be declared only when its route can represent that role faithfully. Anthropic
rejects unsupported developer, tool, or named-message forms before a request;
OpenAI-compatible routes serialize supported roles without silent adaptation.
