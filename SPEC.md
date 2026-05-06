# AgentBOM v0.1 Specification

AgentBOM is an open-source CLI tool that creates a bill of materials for AI agents.

## Command

agentbom scan PATH

## Output

The command creates:
- agentbom.json
- agentbom.md

## Requirements

- Python 3.11+
- No external runtime dependencies
- pytest allowed for tests
- Recursively scan a repository
- Ignore .git, node_modules, venv, .venv, dist, build, __pycache__
- Do not read files larger than 1 MB
- Do not execute scanned code
- Do not import scanned code
- Never store secret values

## Detect

AI providers:
- openai
- anthropic
- gemini

Agent frameworks:
- langchain
- llamaindex
- crewai
- autogen
- semantic_kernel

MCP config files:
- mcp.json
- claude_desktop_config.json

Prompt files:
- AGENTS.md
- CLAUDE.md
- *.prompt.yaml
- *.prompt.yml
- prompts/*.md

Risky capabilities:
- shell: subprocess, os.system, shell=True
- code_execution: eval(, exec(
- network: requests., httpx., aiohttp, urllib.request
- database: sqlite3, psycopg, sqlalchemy, pymongo
- cloud: boto3, google.cloud, azure.

## JSON shape

{
  "schema_version": "0.1.0",
  "repository": "examples/simple_agent",
  "generated_by": "agentbom",
  "models": [],
  "frameworks": [],
  "mcp_servers": [],
  "prompts": [],
  "capabilities": [],
  "secret_references": [],
  "risks": []
}

## Tests

Add tests for:
- CLI works
- JSON is generated
- Markdown is generated
- OpenAI is detected
- LangChain is detected
- MCP config is detected
- prompt file is detected
- shell capability is detected
- secret values are not stored
