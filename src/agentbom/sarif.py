"""SARIF export for AgentBOM."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}


def write_sarif_report(bom: dict[str, Any], output_dir: str | Path, pretty: bool = False) -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    sarif_path = out / "agentbom.sarif"
    indent = 2 if pretty else None
    sarif_path.write_text(
        json.dumps(render_sarif(bom), indent=indent, sort_keys=pretty) + "\n",
        encoding="utf-8",
    )
    return sarif_path


def render_sarif(bom: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    grouped_results: dict[str, dict[str, Any]] = {}

    for risk in bom.get("risks", []):
        severity = risk["severity"]
        rule_id = f"risk.{severity}"
        _register_rule(
            rules,
            rule_id,
            name=f"{severity.title()} aggregate risk",
            severity=severity,
            summary=risk["reason"],
            help_text=(
                "AgentBOM emits aggregate risk findings when static analysis detects "
                "repository-level patterns that require security review."
            ),
            remediation=(
                "Review the detailed AgentBOM JSON and Markdown output, then reduce exposed "
                "agent capabilities or document compensating controls."
            ),
        )
        _add_result(grouped_results, rule_id, severity, risk["reason"])

    for item in bom.get("reachable_capabilities", []):
        severity = item["risk"]
        capability = item["capability"]
        rule_id = f"reachable.{capability}"
        message = f"{item['reachable_from']} reaches {capability} with {severity} risk"
        _register_rule(
            rules,
            rule_id,
            name=f"Reachable capability: {capability}",
            severity=severity,
            summary=f"An agent actor appears able to reach {capability}.",
            help_text=(
                "Reachability findings connect detected models, frameworks, or tool "
                "configuration to sensitive capabilities using deterministic static evidence."
            ),
            remediation=(
                "Constrain or remove the reachable capability, isolate it behind an explicit "
                "approval or sandbox boundary, and document expected use in repository policy."
            ),
        )
        _add_result(
            grouped_results,
            rule_id,
            severity,
            message,
            source_file=item["source_file"],
        )

    for finding in bom.get("policy_findings", []):
        severity = finding["severity"]
        rule_id = f"policy.{_slug(finding['message'])}"
        _register_rule(
            rules,
            rule_id,
            name=finding["message"],
            severity=severity,
            summary="Policy finding detected by AgentBOM.",
            help_text=(
                "Policy findings indicate missing controls or custom policy violations "
                "for AI agent behavior."
            ),
            remediation=(
                "Update repository policy, add required controls, or reduce the capability "
                "that triggered the policy finding."
            ),
        )
        _add_result(
            grouped_results,
            rule_id,
            severity,
            finding["message"],
            source_file=finding["source_file"],
        )

    sorted_rules = sorted(rules.values(), key=lambda item: item["id"])
    rule_indexes = {rule["id"]: index for index, rule in enumerate(sorted_rules)}
    results = [
        _with_rule_index(result, rule_indexes)
        for result in sorted(grouped_results.values(), key=lambda item: item["ruleId"])
    ]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentBOM",
                        "informationUri": "https://github.com/agentbom/agentbom",
                        "semanticVersion": str(bom.get("schema_version", "0.1.0")),
                        "rules": sorted_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _register_rule(
    rules: dict[str, dict[str, Any]],
    rule_id: str,
    name: str,
    severity: str,
    summary: str,
    help_text: str,
    remediation: str,
) -> None:
    if rule_id in rules:
        return
    rules[rule_id] = {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": summary},
        "fullDescription": {"text": help_text},
        "help": {"text": f"{help_text}\n\nRemediation: {remediation}"},
        "defaultConfiguration": {"level": _level(severity)},
        "properties": {
            "precision": "medium",
            "problem.severity": severity,
            "security-severity": SECURITY_SEVERITY.get(severity, SECURITY_SEVERITY["low"]),
            "tags": ["security", "ai-agent", "attack-surface"],
        },
    }


def _add_result(
    results: dict[str, dict[str, Any]],
    rule_id: str,
    severity: str,
    message: str,
    source_file: str | None = None,
) -> None:
    result = results.setdefault(
        rule_id,
        {
            "ruleId": rule_id,
            "level": _level(severity),
            "message": {"text": message},
            "properties": {
                "problem.severity": severity,
                "security-severity": SECURITY_SEVERITY.get(severity, SECURITY_SEVERITY["low"]),
            },
        },
    )
    locations = result.setdefault("locations", [])
    _append_unique(locations, _location(source_file))


def _with_rule_index(result: dict[str, Any], rule_indexes: dict[str, int]) -> dict[str, Any]:
    copied = dict(result)
    copied["ruleIndex"] = rule_indexes[copied["ruleId"]]
    return copied


def _location(source_file: str | None) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": source_file or "repository",
                "uriBaseId": "%SRCROOT%",
            },
            "region": {"startLine": 1},
        }
    }


def _level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if item not in items:
        items.append(item)
