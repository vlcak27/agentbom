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
    assert run["tool"]["driver"]["semanticVersion"] == "0.1.0"

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
