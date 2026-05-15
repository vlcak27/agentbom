from __future__ import annotations

import json

import pytest

from agentbom.cli import main
from agentbom.html_report import render_html


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert "agentbom 0.5.1" in capsys.readouterr().out


def test_cli_help_mentions_core_workflows(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "offline" in help_text
    assert "--html" in help_text
    assert "--mermaid" in help_text
    assert "--sarif" in help_text
    assert "--baseline" in help_text
    assert "--fail-on-new" in help_text
    assert "Common workflows" in help_text


def test_cli_generates_json_and_markdown(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()

    (project / "agent.py").write_text(
        "import subprocess\nfrom langchain.chat_models import ChatOpenAI\nOPENAI_API_KEY = 'do-not-store'\n",
        encoding="utf-8",
    )

    (project / "mcp.json").write_text(
        "{}",
        encoding="utf-8",
    )

    (project / "AGENTS.md").write_text(
        "prompt",
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert not (output_dir / "agentbom.html").exists()
    assert not (output_dir / "agentbom.sarif").exists()

    data = json.loads(
        (output_dir / "agentbom.json").read_text(encoding="utf-8")
    )

    markdown = (output_dir / "agentbom.md").read_text(
        encoding="utf-8"
    )

    assert "capability_graph" in data
    assert "Capability Graph" not in markdown

    assert {
        "name": "openai",
        "path": "agent.py",
        "confidence": "high",
    } in data["providers"]

    assert {
        "name": "langchain",
        "path": "agent.py",
        "confidence": "high",
    } in data["frameworks"]

    assert data["mcp_servers"] == [
        {
            "name": "mcp.json",
            "path": "mcp.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "no_servers",
        }
    ]

    assert {
        "path": "AGENTS.md",
        "type": "prompt",
        "confidence": "low",
    } in data["prompts"]

    assert {
        "name": "shell",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]

    assert any(
        item["name"] == "OPENAI_API_KEY"
        for item in data["secret_references"]
    )

    assert not any(
        item["name"] == "api_key"
        for item in data["secret_references"]
    )

    assert not any(
        item["name"] == "openai_api_key"
        for item in data["secret_references"]
    )

    assert "do-not-store" not in json.dumps(data)


def test_cli_generates_html_when_requested(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()

    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    (project / "AGENTS.md").write_text(
        "system prompt",
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--html",
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert (output_dir / "agentbom.html").exists()

    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")

    assert "<style>" in html
    assert "<script" not in html.lower()
    assert "<link" not in html.lower()
    assert "AgentBOM Security Report" in html
    assert "Overview" in html
    assert "Review Priorities" in html
    assert "How to read this report" in html
    assert "Providers &amp; Models" in html
    assert "MCP Security Analysis" in html
    assert "Reachable Capabilities" in html
    assert "Policy Findings" in html
    assert "Prompt Injection Surfaces" in html
    assert "Capability Graph" in html
    assert "score-ring" in html
    assert "severity-" in html
    assert "do-not-store" not in html


def test_html_report_escapes_bom_values():
    html = render_html(
        {
            "schema_version": "0.1.0",
            "repository": "<unsafe>",
            "generated_by": "agentbom",
            "providers": [
                {"name": "<openai>", "path": "agent.py", "confidence": "high"}
            ],
            "models": [],
            "frameworks": [],
            "mcp_servers": [
                {
                    "name": "<filesystem>",
                    "path": "mcp.json",
                    "confidence": "medium",
                    "kind": "server",
                    "parse_status": "parsed",
                    "risk": "high",
                    "risk_categories": ["filesystem_access"],
                    "rationale": ["review <filesystem> access"],
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "package": "@modelcontextprotocol/server-filesystem",
                    "transport": "stdio",
                }
            ],
            "capabilities": [],
            "dependencies": [],
            "reachable_capabilities": [],
            "capability_graph": {"nodes": [], "edges": []},
            "policy_findings": [],
            "repository_risk": {
                "score": 0,
                "severity": "low",
                "rationale": ["review <prompt> handling"],
            },
            "secret_references": [],
            "risks": [],
        }
    )

    assert "&lt;unsafe&gt;" in html
    assert "&lt;openai&gt;" in html
    assert "&lt;filesystem&gt;" in html
    assert "@modelcontextprotocol/server-filesystem" in html
    assert "review &lt;prompt&gt; handling" in html
    assert "review &lt;filesystem&gt; access" in html
    assert "<unsafe>" not in html


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

    (project / "AGENTS.md").write_text(
        "prompt",
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    assert (output_dir / "agentbom.json").exists()
    assert (output_dir / "agentbom.md").exists()
    assert (output_dir / "agentbom.sarif").exists()

    sarif = json.loads(
        (output_dir / "agentbom.sarif").read_text(encoding="utf-8")
    )

    run = sarif["runs"][0]
    results = run["results"]

    rule_ids = {
        result["ruleId"]
        for result in results
    }

    rules = run["tool"]["driver"]["rules"]

    rules_by_id = {
        rule["id"]: rule
        for rule in rules
    }

    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "AgentBOM"
    assert run["tool"]["driver"]["semanticVersion"] == "0.5.1"

    assert "risk.high" in rule_ids
    assert "risk.low" in rule_ids
    assert "reachable.code_execution" in rule_ids
    assert "policy.prompt_file_detected_without_security_policy" in rule_ids
    assert "policy.shell_execution_detected_without_restrictions" in rule_ids

    assert rules_by_id["reachable.code_execution"]["shortDescription"]["text"]

    assert (
        "Remediation:"
        in rules_by_id["reachable.code_execution"]["help"]["text"]
    )

    assert (
        rules_by_id["reachable.code_execution"]["defaultConfiguration"]["level"]
        == "error"
    )

    assert (
        rules_by_id["reachable.code_execution"]["properties"]["security-severity"]
        == "8.0"
    )

    assert all(
        result["ruleIndex"]
        == rules.index(rules_by_id[result["ruleId"]])
        for result in results
    )

    assert len(rule_ids) == len(results)

    locations = [
        location
        for result in results
        for location in result.get("locations", [])
    ]

    assert {
        "physicalLocation": {
            "artifactLocation": {
                "uri": "agent.py",
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": 1,
            },
        }
    } in locations
    assert all(
        result.get("locations")
        and all(
            location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            for location in result["locations"]
        )
        for result in results
    )


def test_sarif_emits_high_risk_mcp_server_findings(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "shell-runner": {
              "command": "python",
              "args": ["-m", "local_shell_server"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 0
    sarif = json.loads((output_dir / "agentbom.sarif").read_text(encoding="utf-8"))
    rule_ids = {result["ruleId"] for result in sarif["runs"][0]["results"]}

    assert "mcp.high_risk_server.shell_runner" in rule_ids


def test_cli_generates_diff_outputs_and_fails_on_new_threshold(tmp_path, capsys):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "repository": "baseline",
                "providers": [],
                "capabilities": [],
                "secret_references": [],
                "policy_findings": [],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(output_dir),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "high",
            "--html",
            "--sarif",
            "--pretty",
        ]
    )

    assert result == 1
    captured = capsys.readouterr()
    assert "New findings at or above high severity were introduced." in captured.err

    data = json.loads((output_dir / "agentbom.json").read_text(encoding="utf-8"))
    markdown = (output_dir / "agentbom.md").read_text(encoding="utf-8")
    html = (output_dir / "agentbom.html").read_text(encoding="utf-8")
    sarif = json.loads((output_dir / "agentbom.sarif").read_text(encoding="utf-8"))

    introduced = {
        (item["category"], item["title"], item["severity"])
        for item in data["diff"]["introduced"]
    }
    assert ("providers", "openai", "low") in introduced
    assert ("capabilities", "shell", "high") in introduced
    assert ("secret_references", "OPENAI_API_KEY", "high") in introduced
    assert "Introduced Findings" in markdown
    assert "diff" in html
    assert "Introduced Findings" in html
    assert any(
        result["ruleId"].startswith("diff.introduced.capabilities.")
        for result in sarif["runs"][0]["results"]
    )


def test_cli_fail_on_new_allows_lower_severity_introductions(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("from openai import OpenAI\n", encoding="utf-8")

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "repository": "baseline",
                "providers": [],
                "capabilities": [],
                "secret_references": [],
                "policy_findings": [],
            }
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "scan",
            str(project),
            "--output-dir",
            str(tmp_path / "out"),
            "--baseline",
            str(baseline),
            "--fail-on-new",
            "medium",
        ]
    )

    assert result == 0
