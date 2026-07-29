# Security Policy

## Supported versions

Security fixes are provided for the latest `0.3.x` release and may be applied
to the unreleased default branch before the next patch release. Version
`0.1.x` is unsupported.

| Version | Supported |
|---|---|
| Latest `0.3.x` | Yes |
| `0.2.x` | No |
| `0.1.x` | No |

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/rudrasatani13/cot-redteam-agent/security/advisories/new).
Do not disclose suspected vulnerabilities, secrets, or exploit details in
public issues, discussions, or pull requests.

Include:

- the affected version and component;
- impact and a realistic attack path;
- a minimal reproduction or proof of concept;
- suggested remediation, when available;
- confirmation that you tested only systems and credentials you were
  authorized to use.

The project aims to acknowledge reports within seven calendar days and provide
status updates when practical. This is a best-effort open-source response
target, not a service-level agreement.

## System and scope

CoT Red Team Agent is a local CLI and Python library that loads configuration
and datasets, contacts user-selected LLM providers, executes attacks and
monitors, persists evaluation results, and renders reports.

Potentially hostile inputs include configuration files, datasets, generated
attack specifications, provider responses, plugin metadata, report content,
and filesystem paths derived from configuration.

Third-party Python plugins execute in the host process and become trusted code
once installed. LLM providers, local inference servers, operating systems,
GitHub, and user-controlled deployment environments are external trust
boundaries.

## Security invariants

- API keys and authorization headers must not be persisted in configuration
  output, logs, SQLite records, reports, manifests, or artifacts.
- Dataset and artifact paths must not escape intended user-selected locations
  through unsafe path interpretation.
- Generated attack specifications are data and must never be evaluated as
  Python or shell code.
- Imported benchmark rows are untrusted data. Importers must never execute
  dataset-provided graders, templates, plugins, or scripts.
- Provider requests must use explicitly configured endpoints with bounded
  retries, timeouts, concurrency, request counts, token limits, and estimated
  cost controls.
- Retention settings must be applied before prompts, responses, or visible
  reasoning are persisted.
- Monitor failures must fail closed for evaluation accounting and must never be
  counted as successful evasion.
- Artifact and manifest integrity data must match the bytes written.

## Reportable findings and severity

Reportable software vulnerabilities include realistic:

- secret or authorization-header disclosure;
- unsafe file access or path traversal;
- unintended command or code execution;
- injection across a local execution boundary;
- SSRF beyond an explicitly configured provider endpoint;
- insecure deserialization;
- retention-policy bypass;
- material artifact-integrity failures;
- reachable dependency vulnerabilities;
- authentication or authorization defects in future networked components.

Severity depends on realistic reachability, required interaction, privilege,
data sensitivity, and impact. A vulnerability isolated to an optional
third-party plugin should normally be reported to that plugin unless the core
plugin boundary causes or amplifies it.

## Out of scope

The following are not core software vulnerabilities by themselves:

- an evaluated model producing unsafe, incorrect, deceptive, or jailbreakable
  output during an intentional red-team run;
- prompt-injection or monitor-evasion results that remain within the evaluated
  model interaction and do not cross a software trust boundary;
- provider outages, model nondeterminism, pricing changes, or policy decisions;
- testing against credentials or systems the reporter was not authorized to
  use;
- resource exhaustion caused only by a user deliberately choosing unbounded or
  unaffordable settings after explicit configuration.

These exclusions do not cover defects that expose secrets, bypass configured
budgets or retention, access unintended resources, or execute unintended code.

## Safe research

Use only accounts, models, endpoints, and datasets you are authorized to test.
Avoid privacy violations, service disruption, persistence, or access to
third-party data. Stop testing and report privately if you encounter sensitive
information or an unintended execution boundary.
