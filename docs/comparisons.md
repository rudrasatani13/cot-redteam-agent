# How this project compares to garak, PyRIT, and promptfoo

Pick the tool that matches the job. CoT Red Team Agent is an MIT-licensed
Python CLI (`cot-redteam`) for scoring visible chain-of-thought and proving
simulated-agent impact. It does **not** replace a broad vulnerability scanner,
an orchestration SDK, or a YAML eval harness.

The short table in the [README](../README.md#why-this-vs-garak-pyrit-and-promptfoo)
is first-screen length only. This page expands it without inventing
capabilities or ranking projects by popularity.

## What each project is

Descriptions below follow each project's own README.

### [garak](https://github.com/NVIDIA/garak)

NVIDIA's *Generative AI Red-teaming & Assessment Kit*. Its README describes it
as an LLM vulnerability scanner: it "checks if an LLM can be made to fail in a
way we don't want" and "probes for hallucination, data leakage, prompt
injection, misinformation, toxicity generation, jailbreaks, and many other
weaknesses." Static, dynamic, and adaptive probes plus detectors cover a wide
failure surface. Typical start: a target generator and `garak` on the CLI.

### [PyRIT](https://github.com/Azure/PyRIT)

Microsoft's *Python Risk Identification Tool for generative AI*. Its README
calls it "an open source framework built to empower security professionals and
engineers to proactively identify risks in generative AI systems." You compose
red-team workflows in Python: targets, prompt converters, scorers, and
orchestrators. Typical start: a notebook or script against a chosen target.

The Azure GitHub URL still redirects; the project also lives at
[microsoft/PyRIT](https://github.com/microsoft/PyRIT).

### [promptfoo](https://github.com/promptfoo/promptfoo)

A CLI and library "for evaluating and red-teaming LLM apps" with declarative
YAML configs, a local web viewer, and CI/CD hooks. Its README highlights
prompt/model evals, red teaming and vulnerability scanning, side-by-side
provider comparison, and automating checks in CI. Typical start: a YAML eval
file and `promptfoo eval` / `promptfoo redteam`.

### CoT Red Team Agent

This repository: a local CLI and Python API that runs reproducible model
attacks and offline simulated-agent scenarios, records failure-aware evidence,
and writes auditable reports. Scoring treats assistant prose and LLM-judge
opinion as evidence, not proof. A refusal that only re-quotes a canary is
**not** success. Agent-lane impact is proven only by observed simulated tool
actions and pre/post world-state diffs.

## Where they overlap

All four can be used to:

- exercise prompt injection or jailbreak-style prompts against a model;
- record outputs and produce some form of report;
- run from a developer machine or a CI job once a target is configured.

They are complementary, not mutually exclusive. A team might scan broadly with
garak, orchestrate a custom multi-turn campaign in PyRIT, keep prompt
regression YAML in promptfoo, and use this CLI when the question is "did
visible reasoning leak the canary?" or "did the simulated agent actually
mutate protected state?"

## Where this repository is different

Claims below are already true in this tree:

| Topic | What this repo does |
|---|---|
| Visible CoT | Scores exact and partial canary disclosure in final text **and** provider-exposed reasoning. Ordinary answer prose is not relabeled as hidden thought. |
| Honest success | A refusal that only quotes a canary (own-line dumps, `TOKEN=` / JSON-style fields, reasoning analysis) is not compliant disclosure. |
| Adaptive TUI | `cot-redteam tui` is a live multi-model board and payload attempt log. Refusal re-quotes are not counted as the last successful disclosure. |
| `scan` exit codes | `0` clean, `1` findings, `2` config/env, `3` partial. Gate CI on `1`. Errors are excluded, not silently counted as clean. |
| OWASP tags | Report items and SARIF rules carry OWASP GenAI LLM Top 10 (2026) tags, with the mapping version cited so citations cannot silently drift. |
| Keyless start | Packaged `mock` provider (`mock_mode: auto\|refuse\|disclose\|error`) never touches the network. |
| Local/hosted routes | OpenRouter, OpenAI, Anthropic, vLLM, llama.cpp, generic OpenAI-compatible, plus mock. Keys come from named environment variables only. |
| Agent proof (v0.6) | Simulated Support Agent World, deny-by-default `ToolGateway`, deterministic oracles, checksummed replay JSON with detached `.sha256` sidecars, patched-target regression suites. Model text is never proof of impact. |

## What this repository is not

- A hosted service or a SaaS dashboard.
- A universal model-security score. Results apply to the tested route, policy,
  suite, and repetition — see [benchmarking](benchmarking.md).
- A replacement for garak's probe breadth (toxicity, hallucination, leakage
  across many probe families).
- A replacement for PyRIT's Python orchestration SDK (converters, memory,
  multi-orchestrator campaigns you assemble yourself).
- A replacement for promptfoo's YAML eval UX, web viewer, or prompt-regression
  workflow.

Import/export with those tools is not implemented here. Treat that as
ecosystem follow-up, not a current capability.

## Related docs

- [README comparison table](../README.md#why-this-vs-garak-pyrit-and-promptfoo)
- [Consumer CI scan snippet](ci-scan.md)
- [Attack catalog](attacks.md)
- [Agent security (README)](../README.md#agent-security-v06-proof-of-action)
