"""Rule-based reachable capability inference."""

from __future__ import annotations

import re
from typing import Any

from .detectors import confidence_for_path


REACHABILITY_RULES = (
    {
        "capability": "shell_execution",
        "patterns": ("shelltool", "shell tool", "shell=True", "bash -c", "sh -c"),
        "risk": "high",
    },
    {
        "capability": "network_access",
        "patterns": ("requests.", "httpx.", "aiohttp", "urllib.request"),
        "risk": "medium",
    },
    {
        "capability": "code_execution",
        "patterns": ("subprocess", "os.system", "eval(", "exec("),
        "risk": "high",
    },
    {
        "capability": "cloud_access",
        "patterns": ("boto3", "google.cloud", "google-cloud-", "azure."),
        "risk": "medium",
    },
    {
        "capability": "autonomous_execution",
        "patterns": (
            r"\bwhile\s+true\s*:",
            r"\bwhile\s*\(\s*true\s*\)",
            r"\bfor\s*\(\s*;\s*;\s*\)",
            r"\bmax_iterations\b",
            r"\bauto_run\b",
            r"\bcontinuous_mode\b",
            r"\bself\.(?:run|execute)\s*\(",
            r"\bagent\.(?:run|execute)\s*\(",
        ),
        "risk": "high",
        "regex": "true",
    },
)

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
CONFIDENCE_BY_RANK = {rank: confidence for confidence, rank in CONFIDENCE_RANK.items()}
PATH_RULES = (
    {
        "path": "prompt_input",
        "patterns": (
            "input(",
            "prompt =",
            "prompt:",
            "PromptTemplate",
            "ChatPromptTemplate",
            "HumanMessage",
            "SystemMessage",
        ),
    },
    {
        "path": "tool_invocation",
        "patterns": (
            ".call_tool(",
            ".invoke_tool(",
            ".invoke(",
            "agent.run(",
            "Tool(",
            "@tool",
        ),
    },
)
CAPABILITY_PATHS = {
    "autonomous_execution": "tool_invocation",
    "cloud_access": "network_execution",
    "code_execution": "shell_execution",
    "network_access": "network_execution",
    "shell_execution": "shell_execution",
}


def detect_reachable_capability_hits(text: str, relpath: str) -> list[dict[str, str]]:
    """Detect capability facts used for reachability inference."""
    lower = text.lower()
    confidence = confidence_for_path(relpath)
    static_paths = _detect_static_paths(text, lower)
    hits = []
    for rule in REACHABILITY_RULES:
        if _matches_rule(text, lower, rule):
            capability = str(rule["capability"])
            paths = _paths_for_capability(capability, static_paths)
            hits.append(
                {
                    "capability": capability,
                    "source_file": relpath,
                    "risk": str(rule["risk"]),
                    "confidence": confidence,
                    "paths": paths,
                }
            )
    return hits


def _matches_rule(text: str, lower_text: str, rule: dict[str, object]) -> bool:
    patterns = rule["patterns"]
    if rule.get("regex") == "true":
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)  # type: ignore[arg-type]
    return any(pattern.lower() in lower_text for pattern in patterns)  # type: ignore[union-attr]


def infer_reachable_capabilities(
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    mcp_servers: list[dict[str, Any]],
    prompts: list[dict[str, str]],
    capability_hits: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Connect model/framework/tool findings to capability hits."""
    actors = _actors(models, frameworks, mcp_servers, prompts)
    reachable = []
    for hit in capability_hits:
        for actor in _reachable_actors(hit, actors):
            _append_unique(
                reachable,
                {
                    "capability": hit["capability"],
                    "reachable_from": actor["name"],
                    "source_file": hit["source_file"],
                    "risk": hit["risk"],
                    "confidence": _combined_confidence(actor, hit),
                    "confidence_score": _confidence_score(actor, hit),
                    "paths": hit.get("paths", []),
                },
            )
    for item in _mcp_reachable_capabilities(frameworks, prompts, mcp_servers):
        _append_unique(reachable, item)
    return reachable


def _actors(
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    mcp_servers: list[dict[str, Any]],
    prompts: list[dict[str, str]],
) -> list[dict[str, str]]:
    actors = []
    for model in models:
        actors.append(
            {
                "type": "model",
                "name": model["name"],
                "source_file": model["source_file"],
                "confidence": model["confidence"],
            }
        )
    for framework in frameworks:
        actors.append(
            {
                "type": "framework",
                "name": framework["name"],
                "source_file": framework["path"],
                "confidence": framework["confidence"],
            }
        )
    for server in mcp_servers:
        actors.append(
            {
                "type": "tool",
                "name": str(server["name"]),
                "source_file": str(server["path"]),
                "confidence": str(server["confidence"]),
            }
        )
    for prompt in prompts:
        actors.append(
            {
                "type": "prompt",
                "name": "prompt configuration",
                "source_file": prompt["path"],
                "confidence": prompt["confidence"],
            }
        )
    return actors


def _reachable_actors(
    hit: dict[str, str], actors: list[dict[str, str]]
) -> list[dict[str, str]]:
    same_file = [actor for actor in actors if actor["source_file"] == hit["source_file"]]
    if same_file:
        return same_file
    for actor_type in ("model", "framework", "tool"):
        typed = [actor for actor in actors if actor["type"] == actor_type]
        if typed:
            return typed
    return []


def _combined_confidence(actor: dict[str, str], hit: dict[str, str]) -> str:
    rank = min(CONFIDENCE_RANK[actor["confidence"]], CONFIDENCE_RANK[hit["confidence"]])
    if actor["source_file"] != hit["source_file"]:
        rank = max(1, rank - 1)
    return CONFIDENCE_BY_RANK[rank]


def _confidence_score(actor: dict[str, str], hit: dict[str, str]) -> int:
    score = 40
    if actor["source_file"] == hit["source_file"]:
        score += 25
    else:
        score += 10
    score += CONFIDENCE_RANK[actor["confidence"]] * 5
    score += CONFIDENCE_RANK[hit["confidence"]] * 5
    paths = hit.get("paths", [])
    if not isinstance(paths, list):
        paths = []
    if "prompt_input" in paths:
        score += 5
    if "tool_invocation" in paths:
        score += 5
    if {"shell_execution", "network_execution"} & set(paths):
        score += 5
    return min(score, 100)


def _detect_static_paths(text: str, lower_text: str) -> list[str]:
    paths = []
    for rule in PATH_RULES:
        if any(pattern.lower() in lower_text for pattern in rule["patterns"]):
            paths.append(rule["path"])
    return paths


def _paths_for_capability(capability: str, static_paths: list[str]) -> list[str]:
    paths = list(static_paths)
    capability_path = CAPABILITY_PATHS.get(capability)
    if capability_path is not None and capability_path not in paths:
        paths.append(capability_path)
    return paths


def _mcp_reachable_capabilities(
    frameworks: list[dict[str, str]],
    prompts: list[dict[str, str]],
    mcp_servers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    servers = [
        server
        for server in mcp_servers
        if server.get("kind") == "server" or server.get("risk_categories")
    ]
    if not servers or not (frameworks or prompts):
        return []

    actors: list[dict[str, str]] = []
    for framework in frameworks:
        actors.append(
            {
                "name": framework["name"],
                "source_file": framework["path"],
                "confidence": framework["confidence"],
            }
        )
    if not actors:
        for prompt in prompts:
            actors.append(
                {
                    "name": "prompt configuration",
                    "source_file": prompt["path"],
                    "confidence": prompt["confidence"],
                }
            )

    reachable = []
    for server in sorted(
        servers,
        key=lambda item: (str(item.get("path", "")), str(item.get("name", ""))),
    ):
        hit = {
            "confidence": str(server.get("confidence", "low")),
            "source_file": str(server.get("path", "")),
        }
        for actor in actors:
            categories = server.get("risk_categories", [])
            if not isinstance(categories, list):
                categories = []
            rationale = server.get("rationale", [])
            if not isinstance(rationale, list):
                rationale = []
            reachable.append(
                {
                    "capability": "mcp_tool_invocation",
                    "reachable_from": actor["name"],
                    "source_file": str(server.get("path", "")),
                    "risk": str(server.get("risk", "low")),
                    "confidence": _combined_confidence(actor, hit),
                    "confidence_score": _confidence_score(
                        actor,
                        {
                            "confidence": hit["confidence"],
                            "source_file": hit["source_file"],
                            "paths": ["tool_invocation"],
                        },
                    ),
                    "paths": ["tool_invocation"],
                    "mcp_server": str(server.get("name", "")),
                    "risk_categories": [str(category) for category in categories],
                    "rationale": [str(reason) for reason in rationale],
                }
            )
    return reachable


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if item not in items:
        items.append(item)
