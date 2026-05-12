# Research Agent Demo

This static demo repository models an intentionally risky research agent. It is
designed to show how AgentBOM explains reachable capabilities and missing
controls.

AgentBOM should detect:

- Anthropic provider and `claude-3-sonnet`
- CrewAI framework usage
- network, shell, and autonomous execution capabilities
- prompt surface without policy documentation
- secret references by name only

Run:

```bash
agentbom scan examples/research-agent --output-dir agentbom-report/research --html --mermaid --sarif --pretty
```
