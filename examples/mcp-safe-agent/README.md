# MCP Safe Agent Demo

This static demo shows a controlled MCP setup. The agent has a prompt, a simple
LangChain model call, a low-risk local memory MCP server, and policy text that
requires human approval before tool output is used.

Expected AgentBOM result:

- OpenAI provider and `gpt-4o`
- LangChain framework
- parsed MCP server metadata from `.mcp.json`
- low-risk `unknown_custom_server` MCP category for the local memory server
- reachable `mcp_tool_invocation` with documented controls

Run:

```bash
agentbom scan examples/mcp-safe-agent --output-dir agentbom-report/mcp-safe --html --mermaid --sarif --pretty
```
