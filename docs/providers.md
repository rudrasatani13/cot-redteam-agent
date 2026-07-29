# Providers

Supported kinds:

| Kind | Transport | Credential |
|---|---|---|
| `openrouter` | OpenAI-compatible | `api_key_env` required |
| `openai` | OpenAI-compatible | `api_key_env` required |
| `anthropic` | Anthropic Messages API | `api_key_env` required |
| `vllm` | OpenAI-compatible | optional |
| `llamacpp` | OpenAI-compatible | optional |

Model references use `provider:model-id` (aliases resolve within the named provider).

Retries apply to timeouts, connection errors, HTTP 429, and 5xx. Other 4xx
responses are permanent failures.

Providers close in a `finally` path after each run.
