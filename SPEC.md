# AgentBOM v0.1 Specification

## Goal

AgentBOM is an open-source CLI tool that creates a bill of materials for AI agents.

It scans a repository and identifies:
- AI model providers
- Agent frameworks
- Prompt and instruction files
- MCP configuration files
- Risky tool capabilities
- Basic risk findings

The output is:
- machine-readable JSON
- human-readable Markdown

## MVP command

```bash
agentbom scan PATH
