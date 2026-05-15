# Public Launch Guide

Use this checklist when preparing AgentBOM for a public announcement, repository
share, or external demo.

## GitHub About

Description:

> Offline bill of materials and attack surface analysis for AI agent
> repositories.

Website:

> https://pypi.org/project/ai-agentbom/

## GitHub Topics

Recommended topics:

- ai-security
- ai-agents
- agent-security
- mcp
- model-context-protocol
- sbom
- security-tools
- static-analysis
- github-actions
- sarif
- python
- cli

## Screenshot Checklist

Store launch screenshots under `docs/images/`:

- `terminal-quickstart.png`: install and scan commands with concise output.
- `html-report-summary.png`: HTML report summary with risk, providers,
  frameworks, and reachable capabilities.
- `mcp-security-analysis.png`: MCP servers, risk categories, source paths, and
  env variable names only.
- `github-action-artifact-mode.png`: passing GitHub Action with report
  artifacts and no code scanning upload.

Use demo repositories from `examples/`. Do not capture private repository names,
private paths, customer data, tokens, or secret values.

## Demo Commands

Install:

```bash
pip install ai-agentbom
```

Quick scan:

```bash
agentbom scan . --pretty
```

Generate shareable reports:

```bash
agentbom scan . --output-dir agentbom-report --html --mermaid --sarif --pretty
```

MCP safe demo:

```bash
agentbom scan examples/mcp-safe-agent --output-dir agentbom-report/mcp-safe --html --mermaid --sarif --pretty
```

MCP risky demo:

```bash
agentbom scan examples/mcp-risky-agent --output-dir agentbom-report/mcp-risky --html --mermaid --sarif --pretty
```

MCP policy demo:

```bash
agentbom scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir agentbom-report/mcp-policy --html --mermaid --sarif --pretty
```

GitHub Action first-run mode:

```yaml
with:
  path: .
  fail-on: none
  sarif-upload: false
  html: true
  output-dir: agentbom-report
```

## Release Notes Template

````markdown
# AgentBOM vX.Y.Z

AgentBOM is an offline CLI for AI agent bill of materials and attack surface
review.

## Highlights

- 

## MCP Security Analysis

- 

## Reports and Integrations

- JSON:
- Markdown:
- HTML:
- Mermaid:
- SARIF:
- GitHub Action:

## Security Model

- Runs offline.
- Does not execute scanned code or MCP servers.
- Records secret names only, never values.
- Findings are review signals, not exploit proof.

## Upgrade

```bash
pip install --upgrade ai-agentbom
```
````

## Launch Copy

X/Twitter:

> AgentBOM is an open-source CLI for reviewing AI agent repositories. It
> generates an offline bill of materials for providers, models, frameworks,
> prompts, MCP servers, reachable capabilities, and policy gaps. Findings are
> review signals, not exploit proof.

Hacker News:

> AgentBOM is a small open-source CLI that scans AI agent repositories offline
> and produces JSON, Markdown, HTML, Mermaid, and SARIF reports. v0.6.0 adds MCP
> Security Analysis: it parses MCP config safely, records env variable names
> only, categorizes server risk, and highlights reachable MCP tool exposure for
> review.

Reddit:

> I built AgentBOM, an open-source offline CLI for AI agent repository review.
> It reports providers, model identifiers, frameworks, prompts, MCP
> configuration, reachable capabilities, and policy gaps without executing code
> or reading secret values. v0.6.0 focuses on MCP Security Analysis and GitHub
> Action/SARIF workflows.

LinkedIn:

> AgentBOM helps teams review AI agent repositories with an offline bill of
> materials and attack surface report. It identifies AI providers, model
> identifiers, frameworks, prompts, MCP configuration, reachable capabilities,
> and policy gaps, with JSON, Markdown, HTML, Mermaid, SARIF, and GitHub Action
> outputs. Findings are designed as review signals for human assessment.

## What To Show

- A simple `pip install ai-agentbom` and `agentbom scan . --pretty` flow.
- The HTML report summary.
- MCP server findings with risk categories and source paths.
- Env variable names only, with no secret values.
- Informational GitHub Action mode using `fail-on: none` and
  `sarif-upload: false`.
- SARIF/code scanning as optional, not required for first use.

## What Not To Overclaim

- Do not claim exploit proof or runtime validation.
- Do not claim package authenticity verification.
- Do not claim deep language-specific SAST coverage.
- Do not claim CycloneDX or SPDX replacement.
- Do not claim secret discovery or secret value inspection.
- Do not imply AgentBOM executes MCP servers or contacts networks.
- Do not present deterministic pattern matching as complete vulnerability
  analysis.
