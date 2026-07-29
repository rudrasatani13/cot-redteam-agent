# Open-Source Release Design

## 1. Objective

Prepare CoT Red Team Agent `0.2.0` for its first public GitHub release. The
release will make `rudrasatani13/cot-redteam-agent` public, merge the existing
`codex/production-refactor-v0.2` branch into `main`, and publish GitHub Release
`v0.2.0`. Publishing to PyPI is explicitly out of scope.

## 2. Release Principles

- Public documentation must describe implemented behavior only.
- Installation instructions must work without PyPI.
- Provider secrets remain in environment variables and must not appear in
  source, configuration examples, logs, reports, or generated artifacts.
- Security reports must use GitHub private vulnerability reporting rather than
  public issues.
- The repository will use a small, maintainable community-file set rather than
  speculative governance or roadmap documents.
- Publication must not bypass branch review or CI.

## 3. Public Documentation

### 3.1 README

`README.md` will become the public entry point and will contain:

- project purpose and explicit research/evaluation positioning;
- implemented capabilities and supported providers;
- installation from a GitHub checkout or GitHub Release wheel;
- a verified five-minute quickstart;
- visible-reasoning and automated-monitor limitations;
- responsible-use and data-retention warnings;
- links to configuration, provider, plugin, experiment, migration, security,
  support, contribution, and release documentation;
- development and license information.

The README will not claim PyPI availability, a hosted service, a dashboard,
model-safety guarantees, or control over provider nondeterminism.

### 3.2 Existing documentation

- `CONTRIBUTING.md` will define setup, quality gates, test isolation, plugin
  contribution rules, pull-request expectations, and handling of security
  reports.
- `CHANGELOG.md` will describe the complete `0.2.0` release and its breaking
  migration boundary.
- `docs/release-checklist.md` will include package inspection, clean-wheel
  validation, GitHub CI, repository visibility, tagging, and release checks.
- Existing technical guides remain focused on their current responsibilities.

## 4. Community Files

The release will add:

- `CODE_OF_CONDUCT.md`, using Contributor Covenant 2.1 language;
- `SUPPORT.md`, directing usage questions and reproducible bugs to GitHub
  Discussions or Issues and vulnerabilities to private reporting;
- `.github/ISSUE_TEMPLATE/bug_report.yml`;
- `.github/ISSUE_TEMPLATE/feature_request.yml`;
- `.github/ISSUE_TEMPLATE/config.yml`, disabling blank issues and linking
  security reports to the repository security advisory flow;
- `.github/PULL_REQUEST_TEMPLATE.md`.

Governance, funding, maintainer succession, and project-roadmap files are out
of scope for `0.2.0`.

## 5. Security Policy

The repository-wide policy target is `/SECURITY.md`. No existing root or nested
security policy currently applies.

### 5.1 Supported versions

Only the latest `0.2.x` release receives security fixes. The unreleased branch
may receive fixes before the next patch release. Version `0.1.x` is unsupported.

### 5.2 Reporting channel

Researchers must use GitHub private vulnerability reporting through the
repository Security tab. Public issues, discussions, and pull requests must
not contain vulnerability details or secrets.

The policy will request:

- affected version and component;
- impact and realistic attack path;
- minimal reproduction or proof of concept;
- suggested remediation when available;
- confirmation that testing used systems and credentials the reporter was
  authorized to access.

The project will acknowledge reports within seven calendar days and provide
status updates when practical. This is a best-effort open-source response
target, not a service-level agreement.

### 5.3 Threat model and trust boundaries

Potentially hostile inputs include configuration files, datasets, generated
attack specifications, provider responses, plugin metadata, report content,
and filesystem paths derived from configuration.

Third-party Python plugins execute in the host process and are trusted code
once installed. LLM providers, local inference servers, operating systems,
GitHub, and user-controlled deployment environments remain external trust
boundaries.

### 5.4 Security invariants

- API keys and authorization headers must remain server-side and must not be
  persisted in configuration output, logs, SQLite records, reports, manifests,
  or artifacts.
- Dataset and artifact paths must not escape intended user-selected locations
  through unsafe path interpretation.
- Generated attack specifications are data and must never be evaluated as
  Python or shell code.
- Provider requests must use explicitly configured endpoints and bounded
  retries, timeouts, concurrency, token limits, request counts, and estimated
  cost controls.
- Retention settings must be applied before sensitive prompts, responses, or
  visible reasoning are persisted.
- Monitor failures must fail closed for evaluation accounting and must never be
  counted as successful evasion.
- Artifact and manifest integrity data must match the bytes written.

### 5.5 Reportable findings

Reportable software vulnerabilities include realistic secret disclosure,
unsafe file access or path traversal, command or code execution, injection into
local execution boundaries, SSRF beyond an explicitly configured provider
endpoint, insecure deserialization, authentication or authorization defects in
future networked components, retention-policy bypass, material artifact
integrity failures, and dependency issues reachable through normal use.

Severity depends on realistic reachability, required user interaction,
privilege, data sensitivity, and impact. A vulnerability in an optional
third-party plugin is normally reported to that plugin unless the core plugin
boundary causes or amplifies it.

### 5.6 Out of scope

The following are not core software vulnerabilities by themselves:

- an evaluated model producing unsafe, incorrect, deceptive, or jailbreakable
  output during an intentional red-team run;
- prompt-injection or monitor-evasion results that remain inside the evaluated
  model interaction and do not cross a software trust boundary;
- provider outages, model nondeterminism, pricing changes, or policy decisions;
- attacks requiring credentials or systems the reporter was not authorized to
  use;
- denial of service caused only by a user intentionally choosing unbounded or
  unaffordable evaluation settings after explicit configuration.

These exclusions do not suppress bugs that expose secrets, bypass configured
budgets or retention, access unintended resources, or execute unintended code.

## 6. Package Metadata

`pyproject.toml` will:

- use the SPDX license expression `MIT`;
- remove the deprecated MIT license classifier;
- add project URLs for homepage, source, issues, changelog, documentation, and
  security policy.

The version remains `0.2.0`. No package dependency or supported Python version
changes are planned.

## 7. Validation

Before publication:

1. `ruff format --check .`
2. `ruff check .`
3. `mypy cot_redteam`
4. full pytest suite with coverage JSON
5. critical-module coverage gate
6. hash-locked dependency installation
7. sdist and wheel build
8. wheel metadata and archive-content inspection
9. clean-wheel `init`, OpenRouter-only `config validate`, packaged dataset load,
   and `pip check`
10. documentation example tests
11. security-policy resolver check
12. clean Git worktree and diff review

GitHub Actions on Python 3.10 through 3.13 is the external release gate.

## 8. Publication Flow

1. Implement documentation, community files, policy, and metadata on
   `codex/production-refactor-v0.2`.
2. Verify locally and commit only intended files.
3. Push the branch to `origin`.
4. Open a draft pull request into `main` with the complete `0.2.0` change
   summary and validation evidence.
5. Wait for required GitHub Actions checks.
6. Review the final PR diff and convert it to ready for review.
7. Merge into `main` without force-pushing.
8. Change repository visibility from private to public.
9. Create annotated tag `v0.2.0` from the merged `main` commit.
10. Publish GitHub Release `v0.2.0` with changelog-derived notes and attach the
    verified wheel and sdist.
11. Recheck public repository links, release assets, installation instructions,
    private vulnerability reporting, and default-branch CI.

Visibility change, merge, tag creation, and GitHub Release publication are
separate externally visible checkpoints. Their targets must be revalidated
immediately before execution.

## 9. Success Criteria

- A new contributor can install, validate configuration, run tests, and open a
  compliant pull request using repository documentation alone.
- A security researcher can privately report a vulnerability without exposing
  it in a public issue.
- GitHub CI and all local release gates pass.
- The public repository contains no committed secrets or generated local
  artifacts.
- GitHub Release `v0.2.0` contains the verified wheel and sdist from the merged
  commit.
- Documentation does not claim PyPI publication.
