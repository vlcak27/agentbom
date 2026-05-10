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

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "AgentBOM"
    assert "risk.high" in rule_ids
    assert "risk.low" in rule_ids
    assert "reachable.code_execution" in rule_ids
    assert "policy.prompt_file_detected_without_security_policy" in rule_ids
    assert "policy.shell_execution_detected_without_restrictions" in rule_ids
    assert {
        "physicalLocation": {"artifactLocation": {"uri": "agent.py"}}
    } in [
        location
        for result in results
        for location in result.get("locations", [])
    ]
