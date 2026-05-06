"""Simple text detectors for AgentBOM v0.1."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


PROVIDERS = {
    "openai": ("openai", "OPENAI_API_KEY"),
    "anthropic": ("anthropic", "ANTHROPIC_API_KEY"),
    "gemini": ("gemini", "google.generativeai", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

FRAMEWORKS = {
    "langchain": ("langchain",),
    "llamaindex": ("llama_index", "llamaindex"),
    "crewai": ("crewai",),
    "autogen": ("autogen", "pyautogen"),
    "semantic_kernel": ("semantic_kernel", "semantic-kernel"),
}

CAPABILITIES = {
    "shell": ("subprocess", "os.system", "shell=True"),
    "code_execution": ("eval(", "exec("),
    "network": ("requests.", "httpx.", "aiohttp", "urllib.request"),
    "database": ("sqlite3", "psycopg", "sqlalchemy", "pymongo"),
    "cloud": ("boto3", "google.cloud", "azure."),
}

MCP_CONFIG_NAMES = {"mcp.json", "claude_desktop_config.json"}
PROMPT_NAMES = {"AGENTS.md", "CLAUDE.md"}
SECRET_NAME_RE = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|token|secret|password|credential|private[_-]?key)[A-Z0-9_]*)\b\s*[:=]"
)


def detect_in_text(text: str, relpath: str) -> dict[str, list[dict[str, str]]]:
    """Return all text-based detections for a file."""
    lower = text.lower()
    return {
        "providers": _detect_patterns(PROVIDERS, lower, relpath),
        "frameworks": _detect_patterns(FRAMEWORKS, lower, relpath),
        "capabilities": _detect_patterns(CAPABILITIES, lower, relpath),
        "secret_references": detect_secret_references(text, relpath),
    }


def detect_mcp_config(relpath: str) -> dict[str, str] | None:
    name = PurePosixPath(relpath).name
    if name in MCP_CONFIG_NAMES:
        return {"name": name, "path": relpath}
    return None


def detect_prompt_file(relpath: str) -> dict[str, str] | None:
    path = PurePosixPath(relpath)
    name = path.name
    if name in PROMPT_NAMES:
        return {"path": relpath, "type": "prompt"}
    if name.endswith((".prompt.yaml", ".prompt.yml")):
        return {"path": relpath, "type": "prompt"}
    if len(path.parts) >= 2 and path.parts[-2] == "prompts" and name.endswith(".md"):
        return {"path": relpath, "type": "prompt"}
    return None


def is_policy_file(relpath: str) -> bool:
    name = PurePosixPath(relpath).name.lower()
    return name in {"policy.md", "policies.md", "security.md", "permissions.md"}


def detect_secret_references(text: str, relpath: str) -> list[dict[str, str]]:
    """Detect secret names without storing values."""
    names = set(SECRET_NAME_RE.findall(text))
    names.update(match.group(1) for match in SECRET_ASSIGNMENT_RE.finditer(text))
    return [{"name": name, "path": relpath} for name in sorted(names)]


def _detect_patterns(
    definitions: dict[str, tuple[str, ...]], lower_text: str, relpath: str
) -> list[dict[str, str]]:
    findings = []
    for name, patterns in definitions.items():
        for pattern in patterns:
            if pattern.lower() in lower_text:
                findings.append({"name": name, "path": relpath})
                break
    return findings
