"""Minimal SARIF export for AgentBOM."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


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
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for risk in bom.get("risks", []):
        rule_id = f"risk.{risk['severity']}"
        _append_rule(rules, rule_id, risk["reason"])
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(risk["severity"]),
                "message": {"text": risk["reason"]},
            }
        )

    for item in bom.get("reachable_capabilities", []):
        rule_id = f"reachable.{item['capability']}"
        message = (
            f"{item['reachable_from']} reaches {item['capability']} "
            f"with {item['risk']} risk"
        )
        _append_rule(rules, rule_id, f"Reachable capability: {item['capability']}")
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(item["risk"]),
                "message": {"text": message},
                "locations": [_location(item["source_file"])],
            }
        )

    for finding in bom.get("policy_findings", []):
        rule_id = f"policy.{_slug(finding['message'])}"
        _append_rule(rules, rule_id, finding["message"])
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(finding["severity"]),
                "message": {"text": finding["message"]},
                "locations": [_location(finding["source_file"])],
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentBOM",
                        "informationUri": "https://github.com/agentbom/agentbom",
                        "rules": sorted(rules, key=lambda item: item["id"]),
                    }
                },
                "results": results,
            }
        ],
    }


def _append_rule(rules: list[dict[str, Any]], rule_id: str, name: str) -> None:
    rule = {"id": rule_id, "name": name}
    if rule not in rules:
        rules.append(rule)


def _location(source_file: str) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": source_file,
            }
        }
    }


def _level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _slug(value: str) -> str:
    return "_".join(value.lower().split())
