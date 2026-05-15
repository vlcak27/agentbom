# Report Guide

AgentBOM reports are designed for mixed engineering, security, and governance
reviews. The scanner does not execute code and does not claim exploitability.
It records static evidence, source paths, confidence, and rationale.

## Read order

1. Repository risk: a compact severity and score with rationale.
2. Review priorities: the shortest queue of findings to triage first.
3. Reachable capabilities: AI actors connected to sensitive actions.
4. Policy findings: controls that appear missing or violated.
5. Component sections: providers, models, frameworks, MCP security analysis,
   prompts, dependencies, and secret references.

## Terms

- Provider: AI service or runtime vendor such as OpenAI, Anthropic, or Gemini.
- Model: concrete model identifier found by static pattern matching, such as
  `gpt-5.5`, `claude-opus-4.7`, `gemini-2.5-pro`, or
  `openrouter/openai/gpt-5.5`.
- Framework: agent orchestration library such as LangChain or CrewAI.
- MCP server: a Model Context Protocol server definition found in JSON config.
  AgentBOM records server metadata and env variable names only.
- MCP risk category: deterministic classification for server definitions that
  appear to expose filesystem, shell/process, browser/network, database, cloud,
  secrets/env, or unknown/custom capabilities.
- Capability: static evidence of a sensitive action, such as shell or network.
- Reachable capability: an inferred relationship from an AI actor to a
  capability.
- Policy finding: a missing control or custom policy violation.

## Model evidence

Model findings separate the normalized model name from the source evidence. For
example, `openrouter/openai/gpt-5.5` is stored as the model name `gpt-5.5`, while
the evidence field keeps the provider-prefixed string seen in the scanned file.
This keeps graphs and summaries grouped by model while preserving the exact text
reviewers need to inspect.

Provider-prefixed strings are common in router and proxy configurations. A value
such as `openrouter/anthropic/claude-opus-4.7` is static evidence of the model
identifier and route style; it is not proof that the repository can reach that
provider at runtime.

## MCP security analysis

The MCP Security Analysis section lists each detected MCP config file or parsed
server definition. AgentBOM currently parses JSON only, including `mcp.json`,
`.mcp.json`, `claude_desktop_config.json`, and common nested Cursor or Claude
paths. Invalid JSON is reported as a low-confidence review signal instead of
failing the scan.

For parsed servers, review:

- `command`, `args`, `transport`, and `package`: how the MCP server appears to
  launch or connect.
- `env`: variable names only. Values are not stored or printed.
- `risk_categories`: why the server may matter for attack-surface review.
- `rationale`: the simple pattern match that caused the category.

If an agent framework or prompt configuration exists with an MCP config,
AgentBOM adds reachable `mcp_tool_invocation` entries. Those entries identify
the MCP server, risk categories, and rationale so reviewers can decide whether
the tool exposure is expected, sandboxed, or policy-approved.

Custom policy can deny MCP server names or MCP risk categories:

```yaml
deny_mcp_servers:
  - filesystem

deny_mcp_risk_categories:
  - shell_process_execution
  - secrets_env_access
```

## What to do with findings

For expected capabilities, document the control in policy files and keep the
source path easy to review. For unexpected capabilities, remove the code path,
isolate it behind a sandbox or approval boundary, or make the repository policy
explicit about why it exists.

Secret reference findings require credential hygiene review only. AgentBOM
records names such as `OPENAI_API_KEY`; it must not store or print secret values.
