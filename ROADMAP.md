# AgentBOM Roadmap

AgentBOM v0.5.0 has the core public adoption surface in place: PyPI package,
HTML reports, Mermaid export, SARIF integration, CycloneDX export, GitHub
Action, realistic examples, and onboarding documentation.

The roadmap below is intentionally conservative. AgentBOM should remain
offline-first, deterministic, dependency-light, and safe to run on untrusted
repositories.

## Current Focus

- Improve detector accuracy without executing scanned code.
- Improve explanations for mixed engineering, security, and governance reviews.
- Keep report outputs stable and easy to diff.
- Make CI adoption simple without requiring hosted services.

## Near-Term Candidates

- More package and configuration parsing with standard-library parsers where
  possible.
- Better MCP transport and command classification.
- More precise framework-to-tool registration patterns.
- Policy allowlists for expected capabilities.
- Baseline comparison for existing repositories.
- Additional SARIF rule help and remediation text.
- More demo repositories that mirror real agent architectures.

## Not Yet Planned

- SPDX export.
- Dynamic analysis.
- Runtime tracing.
- Telemetry.
- Hosted scanning.
- LLM-generated findings.

## Release Principles

- New findings should include source paths and confidence.
- New outputs should be deterministic.
- New dependencies should be avoided unless they are clearly justified.
- Secret values must never be stored or printed.
