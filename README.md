# AgentBOM

AgentBOM is a minimal CLI that generates a bill of materials for AI agents.

## Install

```sh
pip install -e ".[dev]"
```

## Usage

```sh
agentbom scan examples/simple_agent --pretty
```

By default, AgentBOM writes `agentbom.json` and `agentbom.md` to the current working directory. Use `--output-dir DIR` to write reports somewhere else.

## What v0.1 Detects

- Providers: `openai`, `anthropic`, `gemini`
- Frameworks: `langchain`, `llamaindex`, `crewai`, `autogen`, `semantic_kernel`
- MCP config files: `mcp.json`, `claude_desktop_config.json`
- Prompt files: `AGENTS.md`, `CLAUDE.md`, `*.prompt.yaml`, `*.prompt.yml`, `prompts/*.md`
- Risky capabilities: shell, code execution, network, database, cloud
- Secret references by name without storing secret values

AgentBOM does not execute or import scanned code. It skips ignored directories, symlinks, binary-looking files, and files larger than 1 MB.
