# Changelog

All notable changes to AgentBOM are documented here.

## v0.5.2

### Improved

- Expanded static model detection coverage for modern OpenAI, Anthropic,
  Google, DeepSeek, local/open, and coding-oriented model identifiers.
- Added support for provider-prefixed and OpenRouter-style model strings such as
  `openrouter/openai/gpt-5.5`, `anthropic/claude-opus-4.7`, and
  `google/gemini-2.5-pro`.
- Updated README and report-guide examples to reflect current static model
  detection coverage.

### Compatibility

- No output schema changes.
- No runtime dependency changes.
- No scanner network behavior changes; scanning remains deterministic and
  offline.

Why this matters: Agent repositories increasingly mix cloud, local, and
router-based model identifiers; this release improves static visibility across
that ecosystem.

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
