# Customer Support Agent Demo

This static demo repository models a customer support agent that can summarize
tickets, read customer context, and draft responses for human approval.

AgentBOM should detect:

- OpenAI provider and `gpt-4o`
- LangChain framework usage
- network and database capabilities
- MCP configuration
- prompt surface
- secret references by name only
- policy documentation for controls

Run:

```bash
agentbom scan examples/customer-support-agent --output-dir agentbom-report/support --html --mermaid --sarif --pretty
```
