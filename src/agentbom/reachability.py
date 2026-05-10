"""Rule-based reachable capability inference."""

from __future__ import annotations

import re

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


def detect_reachable_capability_hits(text: str, relpath: str) -> list[dict[str, str]]:
    """Detect capability facts used for reachability inference."""
    lower = text.lower()
    confidence = confidence_for_path(relpath)
    hits = []
    for rule in REACHABILITY_RULES:
        if _matches_rule(text, lower, rule):
            hits.append(
                {
                    "capability": rule["capability"],
                    "source_file": relpath,
                    "risk": rule["risk"],
                    "confidence": confidence,
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
    mcp_servers: list[dict[str, str]],
    capability_hits: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Connect model/framework/tool findings to capability hits."""
    actors = _actors(models, frameworks, mcp_servers)
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
                },
            )
    return reachable


def _actors(
    models: list[dict[str, str]],
    frameworks: list[dict[str, str]],
    mcp_servers: list[dict[str, str]],
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
                "name": server["name"],
                "source_file": server["path"],
                "confidence": server["confidence"],
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


def _append_unique(items: list[dict[str, str]], item: dict[str, str]) -> None:
    if item not in items:
        items.append(item)
