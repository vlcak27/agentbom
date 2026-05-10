"""Risk scoring for AgentBOM findings."""

from __future__ import annotations


def score_risks(capabilities: list[dict[str, str]], prompts: list[dict[str, str]], has_policy: bool) -> list[dict[str, str]]:
    risks: list[dict[str, str]] = []
    capability_names = {item["name"] for item in capabilities}

    if capability_names & {"shell", "code_execution", "autonomous_execution"}:
        risks.append(
            {
                "severity": "high",
                "reason": "shell, code execution, or autonomous execution capability detected",
            }
        )

    medium = capability_names & {"network", "database", "cloud"}
    if medium:
        risks.append(
            {
                "severity": "medium",
                "reason": "network, database, or cloud capability detected",
            }
        )

    if prompts and not has_policy:
        risks.append(
            {
                "severity": "low",
                "reason": "prompt files detected without a policy file",
            }
        )

    return risks
