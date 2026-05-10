"""Policy validation for AgentBOM findings."""

from __future__ import annotations

from pathlib import Path
import re


CAPABILITY_ALIASES = {
    "autonomous-execution": "autonomous_execution",
    "autonomous_execution": "autonomous_execution",
    "code-execution": "code_execution",
    "code_execution": "code_execution",
    "cloud": "cloud",
    "cloud-access": "cloud",
    "cloud_access": "cloud",
    "database": "database",
    "database-access": "database",
    "database_access": "database",
    "mcp-tool-invocation": "mcp_tool_invocation",
    "mcp_tool_invocation": "mcp_tool_invocation",
    "network": "network",
    "network-access": "network",
    "network_access": "network",
    "shell": "shell",
    "shell-execution": "shell",
    "shell_execution": "shell",
}
HUMAN_APPROVAL_RE = re.compile(
    r"\b(human approval|human[- ]in[- ]the[- ]loop|approval required|manual approval)\b",
    re.IGNORECASE,
)


class PolicyError(ValueError):
    """Raised when a custom policy file cannot be parsed."""


def validate_policies(
    prompts: list[dict[str, str]],
    capabilities: list[dict[str, str]],
    mcp_servers: list[dict[str, str]],
    has_policy: bool,
) -> list[dict[str, str]]:
    if has_policy:
        return []

    findings: list[dict[str, str]] = []
    for prompt in prompts:
        _append_unique(
            findings,
            {
                "severity": "low",
                "message": "prompt file detected without security policy",
                "source_file": prompt["path"],
            },
        )

    for capability in capabilities:
        if capability["name"] == "shell":
            _append_unique(
                findings,
                {
                    "severity": "high",
                    "message": "shell execution detected without restrictions",
                    "source_file": capability["path"],
                },
            )
        if capability["name"] == "cloud":
            _append_unique(
                findings,
                {
                    "severity": "medium",
                    "message": "cloud access detected without policy file",
                    "source_file": capability["path"],
                },
            )

    for server in mcp_servers:
        _append_unique(
            findings,
            {
                "severity": "medium",
                "message": "MCP config detected without policy documentation",
                "source_file": server["path"],
            },
        )

    return findings


def validate_custom_policy(
    policy_path: str | Path,
    bom: dict[str, object],
    has_human_approval: bool = False,
) -> list[dict[str, str]]:
    policy_file = Path(policy_path)
    policy = load_policy(policy_file)
    findings: list[dict[str, str]] = []

    denied_capabilities = {
        normalized
        for item in policy.get("deny_capabilities", [])
        if (normalized := normalize_capability(str(item))) is not None
    }
    for capability in bom.get("capabilities", []):
        if not isinstance(capability, dict):
            continue
        name = normalize_capability(str(capability.get("name", "")))
        if name in denied_capabilities:
            _append_unique(
                findings,
                {
                    "severity": "high",
                    "message": f"custom policy violation: denied capability {name}",
                    "source_file": str(capability.get("path", policy_file)),
                    "policy_id": "deny_capabilities",
                },
            )

    requirements = policy.get("require", {})
    if requirements.get("sandboxing") and not _has_sandboxing_dependency(bom):
        _append_unique(
            findings,
            {
                "severity": "high",
                "message": "custom policy violation: sandboxing is required",
                "source_file": str(policy_file),
                "policy_id": "require_sandboxing",
            },
        )
    if requirements.get("human_approval") and not has_human_approval:
        _append_unique(
            findings,
            {
                "severity": "high",
                "message": "custom policy violation: human approval is required",
                "source_file": str(policy_file),
                "policy_id": "require_human_approval",
            },
        )

    return findings


def load_policy(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"policy file does not exist: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"policy path is not a file: {path}")
    text = path.read_text(encoding="utf-8")
    return parse_policy_yaml(text)


def parse_policy_yaml(text: str) -> dict[str, object]:
    policy: dict[str, object] = {"deny_capabilities": [], "require": {}}
    section: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if not raw_line.startswith((" ", "\t")) and stripped.endswith(":"):
            section = stripped[:-1].strip()
            if section == "deny":
                section = "deny_capabilities"
            if section == "deny_capabilities":
                policy.setdefault("deny_capabilities", [])
            elif section == "require":
                policy.setdefault("require", {})
            else:
                section = None
            continue
        if section == "deny_capabilities" and stripped.startswith("- "):
            value = stripped[2:].strip()
            if value:
                policy["deny_capabilities"].append(value)  # type: ignore[union-attr]
            continue
        if section == "require" and ":" in stripped:
            key, value = stripped.split(":", 1)
            policy["require"][key.strip()] = _yaml_bool(value.strip())  # type: ignore[index]
            continue
        raise PolicyError(f"unsupported policy YAML line: {raw_line}")
    return policy


def normalize_capability(value: str) -> str | None:
    return CAPABILITY_ALIASES.get(value.strip().lower().replace(" ", "_"))


def has_human_approval_text(text: str) -> bool:
    return HUMAN_APPROVAL_RE.search(text) is not None


def _yaml_bool(value: str) -> bool:
    lowered = value.lower()
    if lowered in {"true", "yes", "on", "required"}:
        return True
    if lowered in {"false", "no", "off", "optional"}:
        return False
    raise PolicyError(f"unsupported boolean value: {value}")


def _has_sandboxing_dependency(bom: dict[str, object]) -> bool:
    dependencies = bom.get("dependencies", [])
    if not isinstance(dependencies, list):
        return False
    return any(
        isinstance(item, dict) and item.get("category") == "sandbox_runtime"
        for item in dependencies
    )


def _append_unique(items: list[dict[str, str]], item: dict[str, str]) -> None:
    if item not in items:
        items.append(item)
