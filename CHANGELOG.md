# Changelog

All notable changes to AgentBOM are documented here.

## v0.6.0

### Added

- First-class MCP Security Analysis for AI agent attack-surface review.
- Safe JSON-only MCP config parsing for common files such as `mcp.json`,
  `.mcp.json`, `claude_desktop_config.json`, and nested Cursor/Claude paths.
- MCP server metadata extraction for server name, command, args, package or
  binary, transport, source file, confidence, risk categories, and rationale.
- MCP env handling that records variable names only, never values.
- MCP risk categories for filesystem access, shell/process execution,
  browser/network access, database access, cloud access, secrets/env access, and
  unknown/custom servers.
- MCP reachability integration for agent framework or prompt context connected
  to parsed MCP server configuration.
- MCP report coverage across JSON, Markdown, HTML, Mermaid, and SARIF.
- MCP policy support for denied server names and denied risk categories.
- MCP demo repositories for controlled and risky MCP configurations.
- Dedicated MCP Security Analysis documentation guide.

### Security Model

- MCP analysis remains offline and deterministic.
- AgentBOM does not execute MCP servers or scanned code.
- AgentBOM does not contact networks during scanning.
- Secret values and MCP env values are not stored or printed.

### Improved

- Reduced MCP false positives during the pre-release audit, including tighter
  shell/process classification and parsed-server-only MCP reachability.

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
