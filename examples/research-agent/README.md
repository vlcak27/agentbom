# Research Agent Demo

This static demo repository models an intentionally risky research agent. It has
reachable capabilities and missing controls.

AgentBOM scans this directory as text. Do not run the demo agent for the scan.

AgentBOM should detect:

- Anthropic provider and `claude-3-sonnet`
- CrewAI framework usage
- network, shell, and autonomous execution capabilities
- prompt surface without policy documentation
- secret references by name only

Run:

```bash
agentbom scan examples/research-agent \
  --output-dir agentbom-report/research \
  --html --mermaid --sarif --pretty
```
