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

Model references use `provider:model-id` (aliases resolve within the named provider).

Retries apply to timeouts, connection errors, HTTP 429, and 5xx. Other 4xx
responses are permanent failures.

Providers close in a `finally` path after each run.

Benchmark requests preserve ordered role messages. A provider capability must
be declared only when its route can represent that role faithfully. Anthropic
rejects unsupported developer, tool, or named-message forms before a request;
OpenAI-compatible routes serialize supported roles without silent adaptation.
