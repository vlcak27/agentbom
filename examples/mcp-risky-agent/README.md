# MCP Risky Agent Demo

This static demo shows why MCP configuration deserves review. The agent has a
framework and prompt context, plus MCP servers that appear to expose filesystem,
shell/process, browser/network, database, cloud, and env-backed access. The env
entries are variable names with placeholder values only.

Expected AgentBOM result:

- OpenAI provider and `gpt-4o`
- LangGraph framework
- parsed MCP server metadata from `mcp.json`
- high-risk MCP server categories
- reachable `mcp_tool_invocation` findings from the framework context
- policy findings because no local policy documentation is present

Run:

```bash
agentbom scan examples/mcp-risky-agent --output-dir agentbom-report/mcp-risky --html --mermaid --sarif --pretty
```

Policy example:

```bash
agentbom scan examples/mcp-risky-agent --policy examples/policies/mcp-policy.yaml --output-dir agentbom-report/mcp-policy --html --mermaid --sarif --pretty
```
