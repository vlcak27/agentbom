# Changelog

All notable changes to AgentBOM are documented here.

## v0.5.0

### Added

- HTML reports for offline human review.
- Mermaid capability graph export.
- SARIF export for GitHub code scanning.
- CycloneDX JSON export.
- Repository risk scoring with rationale.
- Reachable capability confidence scoring.
- GitHub Action for CI scanning.

### Improved

- README onboarding, demo workflow, screenshots, and architecture diagrams.
- Report explanations for non-security reviewers.
- Realistic demo repositories for support and research agents.
- Issue templates, release notes templates, and contribution docs.

### Security Model

- Scanner remains offline-first and deterministic.
- Scanner does not execute or import scanned code.
- Secret findings record names only, never values.

## v0.1.0

### Added

- Initial CLI scanner.
- JSON and Markdown reports.
- Provider, model, framework, prompt, MCP, capability, policy, and secret-name
  detection.
- Basic repository risk signals.
