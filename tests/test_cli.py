from __future__ import annotations

import json

from agentbom.cli import main


def test_cli_generates_json_and_markdown(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "import subprocess\nfrom langchain.chat_models import ChatOpenAI\nOPENAI_API_KEY = 'do-not-store'\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text("{}", encoding="utf-8")
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")

    output_dir = tmp_path / "out"
    result = main(["scan", str(project), "--output-dir", str(output_dir), "--pretty"])

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert not (output_dir / "agentbom.sarif").exists()

    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    markdown = (output_dir / "agentbom.md").read_text(encoding="utf-8")

    assert "capability_graph" in data
    assert "Capability Graph" not in markdown
    assert {"name": "openai", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert {"name": "langchain", "path": "agent.py", "confidence": "high"} in data["frameworks"]
    assert {"name": "mcp.json", "path": "mcp.json", "confidence": "medium"} in data["mcp_servers"]
    assert {"path": "AGENTS.md", "type": "prompt", "confidence": "low"} in data["prompts"]
    assert {"name": "shell", "path": "agent.py", "confidence": "high"} in data["capabilities"]
    assert any(item["name"] == "OPENAI_API_KEY" for item in data["secret_references"])
    assert not any(item["name"] == "api_key" for item in data["secret_references"])
    assert not any(item["name"] == "openai_api_key" for item in data["secret_references"])
    assert "do-not-store" not in json.dumps(data)


def test_cli_generates_sarif_when_requested(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "model = 'gpt-4o'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")

    output_dir = tmp_path / "out"
    result = main(["scan", str(project), "--output-dir", str(output_dir), "--sarif", "--pretty"])

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert (output_dir / "agentbom.sarif").exists()

    sarif = json.loads((output_dir / "agentbom.sarif").read_text(encoding="utf-8"))
    run = sarif["runs"][0]
    results = run["results"]
    rule_ids = {result["ruleId"] for result in results}
    rules = run["tool"]["driver"]["rules"]
    rules_by_id = {rule["id"]: rule for rule in rules}

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "AgentBOM"
    assert run["tool"]["driver"]["semanticVersion"] == "0.1.0"
    assert "risk.high" in rule_ids
    assert "risk.low" in rule_ids
    assert "reachable.code_execution" in rule_ids
    assert "policy.prompt_file_detected_without_security_policy" in rule_ids
    assert "policy.shell_execution_detected_without_restrictions" in rule_ids
    assert rules_by_id["reachable.code_execution"]["shortDescription"]["text"]
    assert "Remediation:" in rules_by_id["reachable.code_execution"]["help"]["text"]
    assert rules_by_id["reachable.code_execution"]["defaultConfiguration"]["level"] == "error"
    assert rules_by_id["reachable.code_execution"]["properties"]["security-severity"] == "8.0"
    assert all(result["ruleIndex"] == rules.index(rules_by_id[result["ruleId"]]) for result in results)
    assert len(rule_ids) == len(results)
    assert {
    "physicalLocation": {
        "artifactLocation": {
            "uri": "agent.py",
            "uriBaseId": "%SRCROOT%"
        },
        "region": {
            "startLine": 1
        }
    }
} in locations


def test_cli_applies_custom_policy_to_sarif(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "import subprocess\nsubprocess.run(['echo', 'hello'])\n",
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "deny_capabilities:",
                "  - shell_execution",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--policy",
            str(policy),
            "--output-dir",
            str(output_dir),
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    sarif = json.loads((output_dir / "agentbom.sarif").read_text(encoding="utf-8"))

    assert {
        "severity": "high",
        "message": "custom policy violation: denied capability shell",
        "source_file": "agent.py",
        "policy_id": "deny_capabilities",
    } in data["policy_findings"]
    run = sarif["runs"][0]
    rule_id = "policy.custom_policy_violation_denied_capability_shell"
    rules_by_id = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    results_by_id = {result["ruleId"]: result for result in run["results"]}

    assert rule_id in results_by_id
    assert "Remediation:" in rules_by_id[rule_id]["help"]["text"]
    assert results_by_id[rule_id]["level"] == "error"
    assert results_by_id[rule_id]["properties"]["security-severity"] == "8.0"


def test_cli_generates_cyclonedx_when_requested(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    (project / "requirements.txt").write_text("langchain>=0.2\nmcp\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--cyclonedx",
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.cdx.json").exists()
    cyclonedx = json.loads((output_dir / "agentbom.cdx.json").read_text(encoding="utf-8"))
    native = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    components = cyclonedx["components"]
    refs = {component["bom-ref"] for component in components}

    assert "components" not in native
    assert cyclonedx["bomFormat"] == "CycloneDX"
    assert cyclonedx["specVersion"] == "1.5"
    assert "agentbom:provider:openai" in refs
    assert "agentbom:model:gpt-4o" in refs
    assert "agentbom:framework:langchain" in refs
    assert "agentbom:capability:shell" in refs
    assert "agentbom:dependency:langchain" in refs
    assert "agentbom:dependency:mcp" in refs
    assert any(
        component["type"] == "machine-learning-model" and component["name"] == "gpt-4o"
        for component in components
    )
    assert any(
        {"name": "agentbom:dependency_category", "value": "mcp"} in component["properties"]
        for component in components
        if component["bom-ref"] == "agentbom:dependency:mcp"
    )
