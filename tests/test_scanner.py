from __future__ import annotations

from agentbom.scanner import MAX_FILE_SIZE, scan_path


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
    (project / "settings.toml").write_text('model = "gemini-pro"\n', encoding="utf-8")

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


def test_generic_secret_names_without_provider_context_are_ignored(tmp_path):
    project = tmp_path / "agent"
    project.mkdir()
    (project / "agent.py").write_text(
        "api_key = 'do-not-store'\ntoken = 'do-not-store'\n",
        encoding="utf-8",
    )

    data = scan_path(project)

    assert data["secret_references"] == []
