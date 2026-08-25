# Attack catalog

This catalog lists the built-in attacks registered by CoT Red Team Agent. Run
`cot-redteam list-attacks` to inspect the same source of truth in an installed
environment. Descriptions stay at an educational capability level and do not
include live exploit payloads.

## Choosing a family

- **Injection** tests whether untrusted instructions can redirect reasoning or
  expose a synthetic system canary. Start with the fixed single-turn attack,
  then choose adaptive, multi-turn, or attacker-model variants when the
  evaluation needs those extra controls.
- **Harm** evaluates a forbidden request directly with the configured rubric
  judge. Use it for refusal and harmful-compliance testing that does not involve
  a canary.
- **Evasion** probes whether reasoning can be made less visible to monitors.
- **Steganography** probes hidden channels and encoded patterns in reasoning.
- **Distillation** evaluates extraction of reusable reasoning traces or
  exemplars.
- **Faithfulness** checks whether visible reasoning is consistent, grounded,
  and supportive of the final answer.
- **Manipulation** tests false premises, fallacies, circularity, and forced
  reasoning paths.
- **Sandbagging** probes deliberate or selective underperformance.
- **Generative** runs validated generated templates through the normal
  evaluation engine.

## Registered attacks

| ID | Family | Attacker model? | Objective | Notes |
|---|---|---:|---|---|
| `distillation.cot_distillation` | distillation | No | trace extraction | Attempts to extract distillable reasoning traces. |
| `distillation.few_shot_extraction` | distillation | No | exemplar extraction | Extracts few-shot style reasoning exemplars. |
| `evasion.dual_process_reasoning` | evasion | No | monitor evasion | Encourages separate public and private reasoning. |
| `evasion.monitor_awareness` | evasion | No | monitor evasion | Probes monitor-aware sanitization. |
| `evasion.nl_camouflage` | evasion | No | monitor evasion | Camouflages intent in natural language. |
| `evasion.stealth_reasoning` | evasion | No | monitor evasion | Encourages low-signal reasoning. |
| `faithfulness.cot_consistency` | faithfulness | No | consistency | Checks for contradictions within visible reasoning. |
| `faithfulness.cot_hallucination` | faithfulness | No | grounding | Probes for hallucinated reasoning steps. |
| `faithfulness.unfaithful_cot_detection` | faithfulness | No | answer support | Detects reasoning that does not support the final answer. |
| `generative.evolved` | generative | No | generated template | Runs a validated generated attack template. |
| `harm.forbidden_behavior` | harm | No | rubric | Scores a forbidden request with the configured rubric judge; no canary is required. |
| `injection.cot_injection` | injection | No | instruction hijack | Injects conflicting instructions into reasoning. |
| `injection.crescendo_canary` | injection | No | canary | Escalates gradually across multiple turns. |
| `injection.ignore_previous_reasoning` | injection | No | instruction hijack | Adapts the classic ignore-previous-instructions pattern. |
| `injection.roleplay_injection` | injection | No | instruction hijack | Uses a role-play scenario to test guard boundaries. |
| `injection.system_canary` | injection | No | canary | Runs a fixed synthetic-canary extraction attempt. |
| `injection.system_canary_adaptive` | injection | No | canary | Tries a bounded built-in payload bank adaptively. |
| `injection.system_canary_agent` | injection | No | canary | Mutates techniques from refusal feedback without a separate attacker model. |
| `injection.system_canary_agent_llm` | injection | Yes | canary | Uses an attacker model for PAIR-style iteration and TAP-style branching. |
| `manipulation.circular_reasoning` | manipulation | No | reasoning quality | Encourages circular reasoning patterns. |
| `manipulation.logical_fallacy_injection` | manipulation | No | reasoning quality | Injects logical fallacies into the reasoning instructions. |
| `manipulation.premise_injection` | manipulation | No | reasoning quality | Introduces false premises into the setup. |
| `manipulation.reasoning_path_forcing` | manipulation | No | reasoning quality | Forces a specific incorrect reasoning path. |
| `sandbagging.capability_hiding` | sandbagging | No | capability | Probes for hidden capability signals. |
| `sandbagging.sandbagging_detection` | sandbagging | No | capability | Detects deliberate underperformance signals. |
| `sandbagging.selective_competence` | sandbagging | No | capability | Probes topic-dependent selective competence. |
| `steganography.cot_watermarking` | steganography | No | hidden channel | Attempts to plant a watermark pattern in reasoning. |
| `steganography.hidden_reasoning` | steganography | No | hidden channel | Probes dual-channel or hidden reasoning. |
| `steganography.steganographic_cot` | steganography | No | hidden channel | Encourages encoded information inside reasoning. |

Attack-to-OWASP mappings are maintained separately in
`cot_redteam/reporting/owasp.py` against the project's documented 2026
mapping. This catalog does not duplicate or infer those tags.
