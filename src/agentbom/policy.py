"""Basic policy validation for AgentBOM findings."""

from __future__ import annotations


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


def _append_unique(items: list[dict[str, str]], item: dict[str, str]) -> None:
    if item not in items:
        items.append(item)
