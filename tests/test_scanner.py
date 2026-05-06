from __future__ import annotations

from agentbom.scanner import MAX_FILE_SIZE, scan_path


def test_scanner_ignores_large_files_and_detects_prompt_policy_risk(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "large.py").write_bytes(b"openai" * (MAX_FILE_SIZE // 6 + 1))

    data = scan_path(project)

    assert data["prompts"] == [{"path": "AGENTS.md", "type": "prompt"}]
    assert data["providers"] == []
    assert {"severity": "low", "reason": "prompt files detected without a policy file"} in data["risks"]


def test_scanner_detects_medium_capabilities_and_policy_file(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("import sqlite3\nimport boto3\nrequests.get('https://example.com')\n", encoding="utf-8")
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "SECURITY.md").write_text("policy", encoding="utf-8")

    data = scan_path(project)

    capability_names = {item["name"] for item in data["capabilities"]}
    assert {"network", "database", "cloud"} <= capability_names
    assert {"severity": "medium", "reason": "network, database, or cloud capability detected"} in data["risks"]
    assert not any(risk["severity"] == "low" for risk in data["risks"])
