# AgentBOM Examples

These directories are static demo repositories for trying AgentBOM. They are not
intended to be executed.

## customer-support-agent

A controlled support automation example with an OpenAI/LangChain agent, a CRM
API call, local ticket lookup, MCP configuration, prompt instructions, and a
policy file. This is useful for demonstrating expected findings with documented
controls.

```bash
agentbom scan examples/customer-support-agent --output-dir agentbom-report/support --html --mermaid --sarif --pretty
```

## research-agent

An intentionally riskier research automation example with a CrewAI/Anthropic
agent, prompt instructions, network access, and shell execution without policy
documentation. This is useful for demonstrating review priorities and SARIF
findings.

```bash
agentbom scan examples/research-agent --output-dir agentbom-report/research --html --mermaid --sarif --pretty
```
