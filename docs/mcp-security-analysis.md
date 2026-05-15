# MCP Security Analysis

Model Context Protocol servers can connect an agent runtime to tools outside the
model: local files, shell commands, browsers, databases, cloud APIs, or services
that need credentials. AgentBOM treats MCP configuration as part of the agent
attack surface so reviewers can see which tools are configured and whether they
appear reachable from agent code or prompt context.

Findings are review signals, not proof of exploitability.

## What AgentBOM Detects

AgentBOM detects common JSON MCP configuration files:

- `mcp.json`
- `.mcp.json`
- `claude_desktop_config.json`
- nested Cursor or Claude MCP config paths such as `.cursor/mcp.json`

For parsed MCP servers, AgentBOM records:

- server name
- source file and confidence
- command
- args
- package or binary name
- transport when visible
- env variable names only, never values
- risk categories
- rationale for the risk category

## Safe Parsing Model

AgentBOM parses MCP configuration as JSON only. It does not execute MCP servers,
does not run configured commands, does not import scanned code, and does not
contact networks. Invalid JSON is handled as a report finding instead of
failing the scan.

The scanner keeps the same repository safety rules used elsewhere in AgentBOM:
large files are skipped, binary-looking files are skipped, and symlink loops are
not followed.

## Secret Handling

AgentBOM records env variable names only. For example, an MCP config containing
`BRAVE_SEARCH_API_KEY` is reported as that name, but the value is not stored or
printed. Secret-looking args such as `--token value` are redacted in output.

## Risk Categories

MCP server risk is assigned with deterministic pattern matching. Categories are
intended to help reviewers prioritize, not to claim that a server is exploitable.

| Category | Review question |
| --- | --- |
| `filesystem_access` | Can the server read or write local files or directories? |
| `shell_process_execution` | Can the server run commands or spawn processes? |
| `browser_network_access` | Can the server browse, fetch URLs, or search the web? |
| `database_access` | Can the server query databases or data stores? |
| `cloud_access` | Can the server interact with cloud APIs or admin surfaces? |
| `secrets_env_access` | Does the server depend on env-provided credentials? |
| `unknown_custom_server` | Is the server custom or not recognized by simple patterns? |

## Reachability

AgentBOM marks MCP tool invocation as reachable when parsed MCP server config
exists alongside an agent framework or prompt configuration. The reachable
finding includes the MCP server name, source file, risk categories, and
rationale. This is an inferred static relationship, not runtime proof.

## Policy Controls

Custom policy files can deny specific MCP server names or MCP risk categories.
They can also require controls such as human approval when supported by the
policy parser.

```yaml
deny_mcp_servers:
  - shell-runner

deny_mcp_risk_categories:
  - filesystem_access
  - shell_process_execution
  - secrets_env_access

require:
  human_approval: true
```

Run the policy demo:

```bash
agentbom scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir agentbom-report/mcp-policy --html --mermaid --sarif --pretty
```

## Reviewing Findings

Start with high-risk MCP servers, reachable `mcp_tool_invocation`, and policy
findings. Then inspect the config source file to confirm whether the server is
expected and whether policy controls, sandboxing, read-only modes, or human
approval are documented.

## What AgentBOM Does Not Do

AgentBOM does not:

- execute MCP servers
- validate server package authenticity
- contact package registries or remote services
- prove exploitability
- inspect runtime permissions
- verify that an env variable exists
- store or print secret values
