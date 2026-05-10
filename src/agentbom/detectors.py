"""Simple text detectors for AgentBOM v0.1."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


PROVIDERS = {
    "openai": ("openai", "OPENAI_API_KEY"),
    "anthropic": ("anthropic", "ANTHROPIC_API_KEY"),
    "gemini": ("gemini", "google.generativeai", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

MODELS = (
    "gemini-2.0-flash",
    "gemini-1.5-pro",
    "claude-3-sonnet",
    "claude-3-haiku",
    "claude-3-opus",
    "mistral-large",
    "gemini-pro",
    "claude-3",
    "gpt-4.1",
    "gpt-4o",
    "gpt-4",
    "gpt-5",
    "llama3",
)

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
GENERIC_SECRET_NAMES = {"API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY"}
SECRET_NAME_RE = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*\b"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|token|secret|password|credential|private[_-]?key)[A-Z0-9_]*)\b\s*[:=]"
)


def detect_in_text(text: str, relpath: str) -> dict[str, list[dict[str, str]]]:
    """Return all text-based detections for a file."""
    lower = text.lower()
    detections = {
        "models": [],
        "providers": [],
        "frameworks": [],
        "capabilities": _detect_patterns(CAPABILITIES, lower, relpath),
        "secret_references": detect_secret_references(text, relpath),
    }
    if can_detect_model(relpath):
        detections["models"] = detect_models(text, relpath)
    if can_detect_provider_or_framework(relpath):
        detections["providers"] = _detect_patterns(PROVIDERS, lower, relpath)
        detections["frameworks"] = _detect_patterns(FRAMEWORKS, lower, relpath)
    return detections


def detect_mcp_config(relpath: str) -> dict[str, str] | None:
    name = PurePosixPath(relpath).name
    if name in MCP_CONFIG_NAMES:
        return {"name": name, "path": relpath, "confidence": confidence_for_path(relpath)}
    return None


def detect_prompt_file(relpath: str) -> dict[str, str] | None:
    path = PurePosixPath(relpath)
    name = path.name
    if name in PROMPT_NAMES:
        return {"path": relpath, "type": "prompt", "confidence": confidence_for_path(relpath)}
    if name.endswith((".prompt.yaml", ".prompt.yml")):
        return {"path": relpath, "type": "prompt", "confidence": confidence_for_path(relpath)}
    if len(path.parts) >= 2 and path.parts[-2] == "prompts" and name.endswith(".md"):
        return {"path": relpath, "type": "prompt", "confidence": confidence_for_path(relpath)}
    return None


def is_policy_file(relpath: str) -> bool:
    name = PurePosixPath(relpath).name.lower()
    return name in {"policy.md", "policies.md", "security.md", "permissions.md"}


def detect_secret_references(text: str, relpath: str) -> list[dict[str, str]]:
    """Detect secret names without storing values."""
    raw_names = set(SECRET_NAME_RE.findall(text))
    raw_names.update(match.group(1) for match in SECRET_ASSIGNMENT_RE.finditer(text))
    names = {
        name
        for raw_name in raw_names
        if (name := normalize_secret_name(raw_name, text)) is not None
    }
    confidence = confidence_for_path(relpath)
    return [{"name": name, "path": relpath, "confidence": confidence} for name in sorted(names)]


def detect_models(text: str, relpath: str) -> list[dict[str, str]]:
    findings = []
    confidence = confidence_for_path(relpath)
    for model in MODELS:
        pattern = re.compile(
            rf"(?<![A-Za-z0-9_.-]){re.escape(model)}(?![A-Za-z0-9_.-])",
            re.IGNORECASE,
        )
        match = pattern.search(text)
        if match:
            findings.append(
                {
                    "type": "model",
                    "name": model,
                    "source_file": relpath,
                    "confidence": confidence,
                    "evidence": match.group(0),
                }
            )
    return findings


def normalize_secret_name(name: str, text: str) -> str | None:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if normalized in GENERIC_SECRET_NAMES:
        provider = provider_context(text)
        if provider is None:
            return None
        return f"{provider}_{normalized}"
    return normalized


def provider_context(text: str) -> str | None:
    lower = text.lower()
    providers = {
        name.upper()
        for name, patterns in PROVIDERS.items()
        if any(pattern.lower() in lower for pattern in patterns)
    }
    if len(providers) == 1:
        return next(iter(providers))
    return None


def can_detect_model(relpath: str) -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    return suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}


def can_detect_provider_or_framework(relpath: str) -> bool:
    suffix = PurePosixPath(relpath).suffix.lower()
    return suffix in {".py", ".ts", ".js", ".json", ".yaml", ".yml", ".toml"}


def confidence_for_path(relpath: str) -> str:
    suffix = PurePosixPath(relpath).suffix.lower()
    if suffix in {".py", ".ts", ".js"}:
        return "high"
    if suffix in {".json", ".yaml", ".yml", ".toml"}:
        return "medium"
    return "low"


def _detect_patterns(
    definitions: dict[str, tuple[str, ...]], lower_text: str, relpath: str
) -> list[dict[str, str]]:
    findings = []
    confidence = confidence_for_path(relpath)
    for name, patterns in definitions.items():
        for pattern in patterns:
            if pattern.lower() in lower_text:
                findings.append({"name": name, "path": relpath, "confidence": confidence})
                break
    return findings
