# Roadmap

Direction for the next releases. Items are ordered by impact; Phase 0 items
are small, self-contained hardening steps, Phases 1-2 are the product's
next major capabilities, Phases 3-4 scale and grow the ecosystem. Research
references point at the state of the art each item builds on.

## Phase 0 — Hardening and alignment (mostly done)

- [x] **OWASP GenAI LLM Top 10 (2026) migration** — report tags now cite
  the 2026 list with the mapping version annotated (`reporting/owasp.py`,
  `reporting/renderers.py`).
- [x] **`AGENTS.md`** — on-boarding contract for AI contributors.
- [x] **`docs/roadmap.md`** — this file.
- [x] **`pytest-timeout`** in dev extras and `requirements-dev.lock`.
- [x] **CI OS matrix** — tests now run on Ubuntu, macOS, and Windows;
  symlink-dependent tests skip on Windows.
- [ ] **SARIF export** — `scan`/`agent scan` findings as SARIF JSON so
  GitHub code scanning and other tools can ingest them.
- [ ] **Scheduled CI scanning** — a cron workflow running an offline scan
  (mock provider + packaged suites) that fails the branch on findings.

## Phase 1 — v0.7: a team of red-team agents

Generalize the single-attacker loops (`injection.agent_llm` PAIR loop,
crescendo, deterministic catalog) into an attack-team engine with role
specialization, under the existing budgets/retention/oracles:

- **Planner** agent — picks techniques from a growing, memory-guided
  attack library (AutoRedTeamer: [arXiv:2503.15754](https://arxiv.org/abs/2503.15754)).
- **Attacker** agents — parallel PAIR/TAP branches with per-agent context
  windows; subagents act as compression and separation of concerns
  (Anthropic multi-agent research system:
  [engineering blog](https://www.anthropic.com/engineering/built-multi-agent-research-system)).
- **Critic/Judge** agent — validates candidates before dispatch and
  explains verdicts (JAILJUDGE: [arXiv:2410.12855](https://arxiv.org/abs/2410.12855)).
- **Team session artifacts** — replayable, checksummed attack-team
  trajectories with per-role attribution, so a team finding stays
  reproducible under the v0.6 proof-of-action rules.
- Memory-guided attack selection across runs (persisted attack library,
  lifelong integration) so each campaign is stronger than the last.

## Phase 2 — v0.8: agent-lane expansion (multi-agent targets)

The proof-of-action lane currently has one world and three scenarios.
Extend it toward the agentic attack surface the industry now ranks
top-tier (Excessive Agency, Hidden Context Exposure):

- **More worlds** — filesystem-sim, API/web-sim, browser-sim in addition
  to the Support world.
- **MCP as a target surface** — evaluate agents that consume Model
  Context Protocol tools.
- **Multi-agent target scenarios** — collusion, privilege escalation,
  cross-agent message injection (MAStrike:
  [arXiv:2606.12918](https://arxiv.org/abs/2606.12918)).
- **AgentDojo-style task library** — import and run
  [AgentDojo](https://arxiv.org/abs/2406.13352) tasks against the
  deterministic worlds.
- **New oracles** — excessive-agency detection (LLM03) and hidden-context
  exposure (LLM08) proofs over world state.
- **Production-agent red-teaming** — scan-style evaluation of agents that
  operate over untrusted files/commands, following
  [Agent Hacks Agent](https://arxiv.org/abs/2607.11698).

## Phase 3 — Scale

- **Distributed runner** — queue + worker pool across providers with
  resumable runs and crash-safe checkpoints.
- **Model-sweep fleets** — extend `race` to full cross-model campaigns
  with cost-aware scheduling and response caching.
- **Regression dashboards** — a small leaderboard over stored SQLite runs
  (honest eligibility, Wilson intervals — no universal score).
- **SARIF + scheduled scanning** (from Phase 0) wired into GitHub code
  scanning and Dependabot-style alerts.

## Phase 4 — Ecosystem

- Dataset hub: importers beyond cyberseceval/ih-challenge (AgentDojo
  tasks, CyberSecEval 3, MITRE ATLAS mapping).
- Third-party attack/monitor plugin marketplace via the existing entry
  points.
- Docs site (mkdocs) and GitHub Discussions.
- Release automation (PyPI publish on tag, attestation, SBOM).

## Guiding principles

- Deterministic oracles, not LLM-judge opinion, prove impact — always.
- Every new path honors budgets, retention, manifests, and checksums.
- Multi-agent only where it provably beats a single agent (breadth-first
  parallel work); never add agents for their own sake.
- Reports stay honest: no universal scores, no overclaiming.
