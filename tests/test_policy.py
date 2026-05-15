from __future__ import annotations

from agentbom.policy import parse_policy_yaml
from agentbom.scanner import scan_path


def test_custom_policy_reports_denies_and_required_controls(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "model = 'gpt-4o'",
                "while True:",
                "    agent.run()",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "deny_capabilities:",
                "  - shell_execution",
                "  - autonomous_execution",
                "require:",
                "  sandboxing: true",
                "  human_approval: true",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    messages = {finding["message"] for finding in data["policy_findings"]}

    assert "custom policy violation: denied capability shell" in messages
    assert "custom policy violation: denied capability autonomous_execution" in messages
    assert "custom policy violation: sandboxing is required" in messages
    assert "custom policy violation: human approval is required" in messages


def test_custom_policy_required_controls_can_pass(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "SECURITY.md").write_text("Human approval required for tool use.\n", encoding="utf-8")
    (project / "requirements.txt").write_text("docker>=7\n", encoding="utf-8")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "require:",
                "  sandboxing: true",
                "  human_approval: true",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)

    assert not any(
        finding["message"].startswith("custom policy violation")
        for finding in data["policy_findings"]
    )


def test_custom_policy_can_deny_mcp_servers_and_risk_categories(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            }
          }
        }
        """,
        encoding="utf-8",
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "\n".join(
            [
                "deny_mcp_servers:",
                "  - filesystem",
                "deny_mcp_risk_categories:",
                "  - filesystem_access",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project, policy_path=policy)
    messages = {finding["message"] for finding in data["policy_findings"]}

    assert "custom policy violation: denied MCP server filesystem" in messages
    assert (
        "custom policy violation: denied MCP risk category filesystem_access"
        in messages
    )


def test_documented_policy_allows_high_risk_mcp_without_default_policy_gap(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "SECURITY.md").write_text(
        "Human approval required for filesystem MCP tools.\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["policy_findings"] == []


def test_policy_yaml_supports_deny_alias():
    policy = parse_policy_yaml(
        "\n".join(
            [
                "deny:",
                "  - shell",
                "require:",
                "  sandboxing: yes",
                "  human_approval: required",
            ]
        )
    )

    assert policy == {
        "deny_capabilities": ["shell"],
        "require": {"sandboxing": True, "human_approval": True},
    }
