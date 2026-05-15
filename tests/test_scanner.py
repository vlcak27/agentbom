from __future__ import annotations

from pathlib import Path

from agentbom.scanner import MAX_FILE_SIZE, scan_path


def assert_reachable_contains(items, expected):
    assert any(
        all(item.get(key) == value for key, value in expected.items())
        for item in items
    )


def test_scanner_ignores_large_files_and_detects_prompt_policy_risk(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "large.py").write_bytes(b"openai" * (MAX_FILE_SIZE // 6 + 1))

    data = scan_path(project)

    assert data["prompts"] == [{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}]
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


def test_provider_framework_detection_skips_docs(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "README.md").write_text("openai langchain", encoding="utf-8")
    (project / "AGENTS.md").write_text("openai langchain", encoding="utf-8")
    (project / "agent.yaml").write_text("provider: anthropic\nframework: crewai\n", encoding="utf-8")
    (project / "agent.ts").write_text("import OpenAI from 'openai';\n", encoding="utf-8")

    data = scan_path(project)

    assert {"name": "openai", "path": "README.md", "confidence": "low"} not in data["providers"]
    assert {"name": "langchain", "path": "AGENTS.md", "confidence": "low"} not in data["frameworks"]
    assert {"name": "anthropic", "path": "agent.yaml", "confidence": "medium"} in data["providers"]
    assert {"name": "crewai", "path": "agent.yaml", "confidence": "medium"} in data["frameworks"]
    assert {"name": "openai", "path": "agent.ts", "confidence": "high"} in data["providers"]


def test_provider_framework_fixture_covers_new_sdk_and_env_patterns():
    project = Path(__file__).parent / "fixtures" / "provider_framework_agent"

    data = scan_path(project)

    providers = {(item["name"], item["path"], item["confidence"]) for item in data["providers"]}
    frameworks = {(item["name"], item["path"], item["confidence"]) for item in data["frameworks"]}
    models = {(item["name"], item["source_file"], item["confidence"]) for item in data["models"]}
    dependencies = {
        (item["name"], item["category"], item["path"], item["confidence"])
        for item in data["dependencies"]
    }
    secrets = {(item["name"], item["path"], item["confidence"]) for item in data["secret_references"]}

    assert ("ollama", "ollama_agent.py", "high") in providers
    assert ("deepseek", "deepseek_agent.py", "high") in providers
    assert ("gemini", "gemini_langgraph_agent.py", "high") in providers
    assert ("openrouter", "openrouter_agent.ts", "high") in providers
    assert ("openrouter", "agent.yaml", "medium") in providers
    assert ("langgraph", "gemini_langgraph_agent.py", "high") in frameworks
    assert ("langgraph", "agent.yaml", "medium") in frameworks
    assert ("llama3.1", "ollama_agent.py", "high") in models
    assert ("deepseek-chat", "deepseek_agent.py", "high") in models
    assert ("gemini-2.0-flash", "gemini_langgraph_agent.py", "high") in models
    assert ("gpt-4o", "openrouter_agent.ts", "high") in models
    assert ("google-genai", "provider_sdk", "requirements.txt", "low") in dependencies
    assert ("ollama", "provider_sdk", "requirements.txt", "low") in dependencies
    assert ("openrouter", "provider_sdk", "requirements.txt", "low") in dependencies
    assert ("langgraph", "ai_framework", "requirements.txt", "low") in dependencies
    assert ("DEEPSEEK_API_KEY", "deepseek_agent.py", "high") in secrets
    assert (
        "GOOGLE_GENERATIVE_AI_API_KEY",
        "gemini_langgraph_agent.py",
        "high",
    ) in secrets
    assert ("OPENROUTER_API_KEY", "openrouter_agent.ts", "high") in secrets


def test_agents_md_is_prompt_only_for_ai_terms(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("openai langchain gpt-4o", encoding="utf-8")

    data = scan_path(project)

    assert data["prompts"] == [{"path": "AGENTS.md", "type": "prompt", "confidence": "low"}]
    assert data["providers"] == []
    assert data["frameworks"] == []
    assert data["models"] == []


def test_scanner_detects_concrete_models_in_code_and_config_files(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text("model = 'gpt-4o'\nfallback = 'gpt-5'\n", encoding="utf-8")
    (project / "models.js").write_text("const models = ['gpt-4', 'gpt-4.1', 'llama3'];\n", encoding="utf-8")
    (project / "config.ts").write_text("const model = 'mistral-large';\n", encoding="utf-8")
    (project / "agent.json").write_text('{"model": "claude-3-opus"}\n', encoding="utf-8")
    (project / "agent.yaml").write_text(
        "models:\n- claude-3\n- claude-3-sonnet\n- claude-3-haiku\n- gemini-pro\n- gemini-1.5-pro\n- gemini-2.0-flash\n",
        encoding="utf-8",
    )
    (project / "settings.toml").write_text(
        'provider = "gemini"\nframework = "semantic-kernel"\nmodel = "gemini-pro"\n',
        encoding="utf-8",
    )

    data = scan_path(project)
    models = {(item["name"], item["source_file"], item["confidence"]) for item in data["models"]}

    assert ("gpt-4o", "agent.py", "high") in models
    assert ("gpt-5", "agent.py", "high") in models
    assert ("gpt-4", "models.js", "high") in models
    assert ("gpt-4.1", "models.js", "high") in models
    assert ("llama3", "models.js", "high") in models
    assert ("mistral-large", "config.ts", "high") in models
    assert ("claude-3-opus", "agent.json", "medium") in models
    assert ("claude-3", "agent.yaml", "medium") in models
    assert ("claude-3-sonnet", "agent.yaml", "medium") in models
    assert ("claude-3-haiku", "agent.yaml", "medium") in models
    assert ("gemini-pro", "agent.yaml", "medium") in models
    assert ("gemini-1.5-pro", "agent.yaml", "medium") in models
    assert ("gemini-2.0-flash", "agent.yaml", "medium") in models
    assert ("gemini-pro", "settings.toml", "medium") in models
    assert {"name": "gemini", "path": "settings.toml", "confidence": "medium"} in data["providers"]
    assert {"name": "semantic_kernel", "path": "settings.toml", "confidence": "medium"} in data["frameworks"]
    assert all(item["type"] == "model" for item in data["models"])
    assert all(item["evidence"] == item["name"] for item in data["models"])


def test_model_detection_skips_markdown_docs_and_keeps_providers_separate(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "README.md").write_text("gpt-4o openai", encoding="utf-8")
    (project / "AGENTS.md").write_text("claude-3-opus anthropic", encoding="utf-8")
    (project / "agent.py").write_text(
        "from openai import OpenAI\nmodel = 'gpt-4o'\napi_key = 'do-not-store'\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "type": "model",
        "name": "gpt-4o",
        "source_file": "agent.py",
        "confidence": "high",
        "evidence": "gpt-4o",
    } in data["models"]
    assert not any(item["source_file"].endswith(".md") for item in data["models"])
    assert {"name": "openai", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert "do-not-store" not in str(data)


def test_secret_references_are_normalized_and_deduplicated(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from openai import OpenAI",
                "api_key = 'do-not-store'",
                "openai_api_key = api_key",
                "OPENAI_API_KEY = openai_api_key",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_references"] == [
        {"name": "OPENAI_API_KEY", "path": "agent.py", "confidence": "high"}
    ]
    assert "do-not-store" not in str(data)


def test_repository_risk_score_uses_reachability_secrets_and_missing_policy(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess",
                "from openai import OpenAI",
                "model = 'gpt-4o'",
                "OPENAI_API_KEY = 'do-not-store'",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")

    data = scan_path(project)

    assert data["repository_risk"] == {
        "score": 90,
        "severity": "critical",
        "rationale": [
            "high-risk reachable capability detected: code_execution",
            "shell or code execution is present or reachable",
            "secret references were detected",
            "policy controls are missing or incomplete",
        ],
    }
    assert "do-not-store" not in str(data["repository_risk"])


def test_repository_risk_score_is_low_without_risk_factors(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "README.md").write_text("documentation only\n", encoding="utf-8")

    data = scan_path(project)

    assert data["repository_risk"] == {
        "score": 0,
        "severity": "low",
        "rationale": ["no repository-level risk factors detected"],
    }


def test_python_ast_detection_finds_security_relevant_constructs(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import subprocess as sp",
                "import httpx as client",
                "from anthropic import Anthropic",
                "from mcp import ClientSession",
                "from openai import OpenAI",
                "",
                "def run(session: ClientSession):",
                "    OpenAI()",
                "    Anthropic()",
                "    sp.run(['echo', 'hello'])",
                "    eval('1 + 1')",
                "    client.get('https://example.com')",
                "    session.call_tool('search', {'query': 'agent'})",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {"name": "openai", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert {"name": "anthropic", "path": "agent.py", "confidence": "high"} in data["providers"]
    assert {"name": "shell", "path": "agent.py", "confidence": "high"} in data["capabilities"]
    assert {
        "name": "code_execution",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]
    assert {"name": "network", "path": "agent.py", "confidence": "high"} in data["capabilities"]
    assert {
        "name": "mcp_tool_invocation",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]


def test_dependency_analysis_parses_pyproject_and_requirements(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "\n".join(
            [
                "[project]",
                'dependencies = ["langchain>=0.2", "mcp", "requests"]',
                "",
                "[project.optional-dependencies]",
                'sandbox = ["e2b>=1"]',
            ]
        ),
        encoding="utf-8",
    )
    (project / "requirements.txt").write_text(
        "\n".join(
            [
                "crewai==0.80.0",
                "fastmcp>=2",
                "docker[ssh]>=7",
                "pytest",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "langchain",
        "category": "ai_framework",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "mcp",
        "category": "mcp",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "e2b",
        "category": "sandbox_runtime",
        "path": "pyproject.toml",
        "confidence": "medium",
    } in data["dependencies"]
    assert {
        "name": "crewai",
        "category": "ai_framework",
        "path": "requirements.txt",
        "confidence": "low",
    } in data["dependencies"]
    assert {
        "name": "fastmcp",
        "category": "mcp",
        "path": "requirements.txt",
        "confidence": "low",
    } in data["dependencies"]
    assert {
        "name": "docker",
        "category": "sandbox_runtime",
        "path": "requirements.txt",
        "confidence": "low",
    } in data["dependencies"]
    assert not any(item["name"] == "pytest" for item in data["dependencies"])


def test_generic_secret_names_without_provider_context_are_ignored(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "api_key = 'do-not-store'\ntoken = 'do-not-store'\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_references"] == []


def test_reachable_capabilities_connect_model_to_risky_capabilities(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import boto3",
                "import httpx",
                "import subprocess",
                "model = 'gpt-4o'",
                "httpx.get('https://example.com')",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "network_access",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["network_execution"],
    })
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "code_execution",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "high",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["shell_execution"],
    })
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "cloud_access",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["network_execution"],
    })


def test_reachable_capabilities_use_framework_when_no_model_is_detected(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from langchain.chat_models import ChatOpenAI",
                "requests.get('https://example.com')",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert len(data["reachable_capabilities"]) == 1
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "network_access",
        "reachable_from": "langchain",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["network_execution"],
    })


def test_reachability_tracks_prompt_tool_and_network_paths(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "import requests",
                "from mcp import ClientSession",
                "model = 'gpt-4o'",
                "prompt = input('task: ')",
                "session = ClientSession()",
                "session.call_tool('search', {'query': prompt})",
                "requests.get('https://example.com')",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "network_access",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "medium",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["prompt_input", "tool_invocation", "network_execution"],
    })


def test_reachable_capabilities_can_cross_files_with_lower_confidence(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "config.py").write_text("model = 'gpt-4o'\n", encoding="utf-8")
    (project / "tools.py").write_text(
        "import os\nos.system('echo hello')\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert len(data["reachable_capabilities"]) == 1
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "code_execution",
        "reachable_from": "gpt-4o",
        "source_file": "tools.py",
        "risk": "high",
        "confidence": "medium",
        "confidence_score": 85,
        "paths": ["shell_execution"],
    })


def test_scanner_detects_autonomous_execution_capability(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "model = 'gpt-4o'",
                "while True:",
                "    agent.run()",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)

    assert {
        "name": "autonomous_execution",
        "path": "agent.py",
        "confidence": "high",
    } in data["capabilities"]
    assert {
        "severity": "high",
        "reason": "shell, code execution, or autonomous execution capability detected",
    } in data["risks"]
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "autonomous_execution",
        "reachable_from": "gpt-4o",
        "source_file": "agent.py",
        "risk": "high",
        "confidence": "high",
        "confidence_score": 100,
        "paths": ["tool_invocation"],
    })


def test_scanner_detects_autonomous_execution_config_flags(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.yaml").write_text(
        "model: gpt-4o\nauto_run: true\ncontinuous_mode: true\nmax_iterations: 100\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["capabilities"] == [
        {"name": "autonomous_execution", "path": "agent.yaml", "confidence": "medium"}
    ]
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "autonomous_execution",
        "reachable_from": "gpt-4o",
        "source_file": "agent.yaml",
        "risk": "high",
        "confidence": "medium",
        "confidence_score": 90,
        "paths": ["tool_invocation"],
    })


def test_policy_findings_report_missing_policy_controls(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "agent.py").write_text(
        "import subprocess\nimport boto3\nsubprocess.run(['echo', 'hello'])\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text("{}", encoding="utf-8")

    data = scan_path(project)

    assert {
        "severity": "low",
        "message": "prompt file detected without security policy",
        "source_file": "AGENTS.md",
    } in data["policy_findings"]
    assert {
        "severity": "high",
        "message": "shell execution detected without restrictions",
        "source_file": "agent.py",
    } in data["policy_findings"]
    assert {
        "severity": "medium",
        "message": "cloud access detected without policy file",
        "source_file": "agent.py",
    } in data["policy_findings"]
    assert {
        "severity": "medium",
        "message": "MCP config detected without policy documentation",
        "source_file": "mcp.json",
    } in data["policy_findings"]


def test_policy_findings_are_empty_when_policy_file_exists(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / "agent.py").write_text(
        "import subprocess\nimport boto3\nsubprocess.run(['echo', 'hello'])\n",
        encoding="utf-8",
    )
    (project / "mcp.json").write_text("{}", encoding="utf-8")
    (project / "SECURITY.md").write_text("policy", encoding="utf-8")

    data = scan_path(project)

    assert data["policy_findings"] == []


def test_mcp_security_analysis_extracts_safe_server_metadata(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "AGENTS.md").write_text("prompt", encoding="utf-8")
    (project / ".mcp.json").write_text(
        """
        {
          "mcpServers": {
            "safe-docs": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-memory", "--api-key", "do-not-store"],
              "env": {
                "DOCS_API_KEY": "do-not-store"
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "safe-docs",
            "path": ".mcp.json",
            "confidence": "medium",
            "kind": "server",
            "parse_status": "parsed",
            "risk": "high",
            "risk_categories": ["secrets_env_access"],
            "rationale": ["server declares environment variables: DOCS_API_KEY"],
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory", "--api-key", "[redacted]"],
            "env": ["DOCS_API_KEY"],
            "transport": "stdio",
            "package": "@modelcontextprotocol/server-memory",
        }
    ]
    assert "do-not-store" not in str(data)
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "mcp_tool_invocation",
        "reachable_from": "prompt configuration",
        "source_file": ".mcp.json",
        "risk": "high",
        "confidence": "low",
        "confidence_score": 70,
        "paths": ["tool_invocation"],
        "mcp_server": "safe-docs",
    })


def test_mcp_security_analysis_classifies_filesystem_and_shell_servers(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "from langchain.chat_models import ChatOpenAI\n",
        encoding="utf-8",
    )
    (project / ".cursor").mkdir()
    (project / ".cursor" / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            },
            "shell-runner": {
              "command": "python",
              "args": ["-m", "local_shell_server"]
            }
          }
        }
        """,
        encoding="utf-8",
    )

    data = scan_path(project)

    servers = {item["name"]: item for item in data["mcp_servers"]}
    assert servers["filesystem"]["risk"] == "high"
    assert "filesystem_access" in servers["filesystem"]["risk_categories"]
    assert servers["filesystem"]["package"] == "@modelcontextprotocol/server-filesystem"
    assert servers["shell-runner"]["risk"] == "high"
    assert "shell_process_execution" in servers["shell-runner"]["risk_categories"]
    assert servers["shell-runner"]["package"] == "local_shell_server"
    assert any(
        item.get("mcp_server") == "filesystem"
        and item.get("reachable_from") == "langchain"
        for item in data["reachable_capabilities"]
    )


def test_invalid_mcp_json_is_reported_without_crashing(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "claude_desktop_config.json").write_text("{not-json", encoding="utf-8")

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "claude_desktop_config.json",
            "path": "claude_desktop_config.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "invalid_json",
            "risk": "low",
            "risk_categories": ["unknown_custom_server"],
            "rationale": ["MCP config could not be parsed as JSON"],
        }
    ]


def test_mcp_output_order_is_deterministic(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        """
        {
          "mcpServers": {
            "z-server": {"command": "node", "args": ["z.js"]},
            "a-server": {"command": "node", "args": ["a.js"]}
          }
        }
        """,
        encoding="utf-8",
    )

    first = scan_path(project)
    second = scan_path(project)

    assert [item["name"] for item in first["mcp_servers"]] == ["a-server", "z-server"]
    assert first["mcp_servers"] == second["mcp_servers"]


def test_mcp_security_fixture_covers_safe_server_env_redaction_and_reachability():
    project = Path(__file__).parent / "fixtures" / "mcp_safe_agent"

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "docs-search",
            "path": ".mcp.json",
            "confidence": "medium",
            "kind": "server",
            "parse_status": "parsed",
            "risk": "high",
            "risk_categories": ["browser_network_access", "secrets_env_access"],
            "rationale": [
                "server name or config suggests browser or network access",
                "server declares environment variables: DOCS_API_KEY",
            ],
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory", "--token", "[redacted]"],
            "env": ["DOCS_API_KEY"],
            "transport": "stdio",
            "package": "@modelcontextprotocol/server-memory",
        },
        {
            "name": "memory-cache",
            "path": ".mcp.json",
            "confidence": "medium",
            "kind": "server",
            "parse_status": "parsed",
            "risk": "low",
            "risk_categories": ["unknown_custom_server"],
            "rationale": ["custom or unknown MCP server: @modelcontextprotocol/server-memory"],
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-memory"],
            "transport": "stdio",
            "package": "@modelcontextprotocol/server-memory",
        },
    ]
    assert "sk-do-not-store" not in str(data)
    assert_reachable_contains(data["reachable_capabilities"], {
        "capability": "mcp_tool_invocation",
        "reachable_from": "prompt configuration",
        "source_file": ".mcp.json",
        "risk": "high",
        "mcp_server": "docs-search",
        "paths": ["tool_invocation"],
    })


def test_mcp_security_fixture_covers_nested_filesystem_shell_and_ordering():
    project = Path(__file__).parent / "fixtures" / "mcp_risky_agent"

    first = scan_path(project)
    second = scan_path(project)
    servers = {item["name"]: item for item in first["mcp_servers"]}

    assert first["mcp_servers"] == second["mcp_servers"]
    assert [item["name"] for item in first["mcp_servers"]] == [
        "brave-search",
        "filesystem",
        "shell-runner",
    ]
    assert servers["brave-search"]["path"] == ".cursor/mcp.json"
    assert servers["brave-search"]["risk"] == "medium"
    assert servers["brave-search"]["risk_categories"] == ["browser_network_access"]
    assert "shell_process_execution" not in servers["brave-search"]["risk_categories"]
    assert servers["filesystem"]["risk_categories"] == ["filesystem_access"]
    assert servers["shell-runner"]["risk_categories"] == ["shell_process_execution"]
    assert {
        "id": "mcp_server:filesystem",
        "type": "mcp_server",
        "name": "filesystem",
    } in first["capability_graph"]["nodes"]
    assert {
        "source": "mcp_server:filesystem",
        "target": "mcp_risk:filesystem_access",
        "type": "risk",
    } in first["capability_graph"]["edges"]


def test_invalid_mcp_fixture_does_not_create_reachable_tool_invocation():
    project = Path(__file__).parent / "fixtures" / "mcp_invalid_agent"

    data = scan_path(project)

    assert data["mcp_servers"] == [
        {
            "name": "claude_desktop_config.json",
            "path": "claude_desktop_config.json",
            "confidence": "medium",
            "kind": "config_file",
            "parse_status": "invalid_json",
            "risk": "low",
            "risk_categories": ["unknown_custom_server"],
            "rationale": ["MCP config could not be parsed as JSON"],
        }
    ]
    assert not any(
        item.get("capability") == "mcp_tool_invocation"
        for item in data["reachable_capabilities"]
    )
    assert not any(
        item.get("type") == "mcp_server"
        for item in data["capability_graph"]["nodes"]
    )


def test_mcp_config_alone_does_not_make_unrelated_code_reachable(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "mcp.json").write_text(
        '{"mcpServers": {"filesystem": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]}}}',
        encoding="utf-8",
    )
    (project / "tool.py").write_text("import subprocess\nsubprocess.run(['echo', 'hello'])\n", encoding="utf-8")

    data = scan_path(project)

    assert not any(
        item.get("reachable_from") == "filesystem"
        for item in data["reachable_capabilities"]
    )


def test_capability_graph_contains_nodes_and_edges(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "\n".join(
            [
                "from openai import OpenAI",
                "from langchain.chat_models import ChatOpenAI",
                "model = 'gpt-4o'",
                "requests.get('https://example.com')",
                "subprocess.run(['echo', 'hello'])",
            ]
        ),
        encoding="utf-8",
    )

    data = scan_path(project)
    graph = data["capability_graph"]

    assert {
        "id": "provider:openai",
        "type": "provider",
        "name": "openai",
    } in graph["nodes"]
    assert {
        "id": "model:gpt-4o",
        "type": "model",
        "name": "gpt-4o",
    } in graph["nodes"]
    assert {
        "id": "framework:langchain",
        "type": "framework",
        "name": "langchain",
    } in graph["nodes"]
    assert {
        "id": "capability:network_access",
        "type": "capability",
        "name": "network_access",
    } in graph["nodes"]
    assert {
        "source": "model:gpt-4o",
        "target": "provider:openai",
        "type": "uses",
    } in graph["edges"]
    assert {
        "source": "model:gpt-4o",
        "target": "capability:code_execution",
        "type": "reaches",
    } in graph["edges"]
    assert {
        "source": "framework:langchain",
        "target": "capability:network_access",
        "type": "enables",
    } in graph["edges"]
    assert graph["nodes"] == sorted(graph["nodes"], key=lambda item: (item["type"], item["id"]))
    assert graph["edges"] == sorted(
        graph["edges"], key=lambda item: (item["source"], item["target"], item["type"])
    )
