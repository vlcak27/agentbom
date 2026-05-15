from __future__ import annotations

import pytest

from agentbom.detectors import DetectionContext, DetectionResult, detect_in_file


class CustomDetector:
    name = "custom"

    def detect(self, context: DetectionContext) -> DetectionResult:
        return DetectionResult(
            {
                "providers": [
                    {"name": "custom", "path": context.relpath, "confidence": "low"}
                ]
            }
        )


def test_detect_in_file_accepts_custom_detectors():
    result = detect_in_file("agent.py", "ignored", (CustomDetector(),))

    assert result.findings == {
        "providers": [{"name": "custom", "path": "agent.py", "confidence": "low"}]
    }


def test_policy_detector_marks_policy_files_without_text():
    result = detect_in_file("SECURITY.md", None)

    assert result.has_policy is True


@pytest.mark.parametrize(
    ("relpath", "text", "provider"),
    [
        ("agent.py", "import ollama\n", "ollama"),
        ("agent.py", 'base_url = "http://localhost:11434"\n', "ollama"),
        ("agent.py", 'api_key = os.environ["DEEPSEEK_API_KEY"]\n', "deepseek"),
        ("agent.py", 'base_url = "https://api.deepseek.com"\n', "deepseek"),
        ("agent.py", 'api_key = os.environ["OPENROUTER_API_KEY"]\n', "openrouter"),
        ("agent.ts", 'baseURL: "https://openrouter.ai/api/v1"\n', "openrouter"),
        ("agent.py", "import google.generativeai as genai\n", "gemini"),
        ("agent.py", "from google import genai\n", "gemini"),
        ("agent.py", "from vertexai.generative_models import GenerativeModel\n", "gemini"),
        ("agent.ts", 'import { GoogleGenAI } from "@google/genai";\n', "gemini"),
        ("agent.ts", 'import { GoogleGenerativeAI } from "@google/generative-ai";\n', "gemini"),
        ("agent.yaml", "api_key: GOOGLE_GENERATIVE_AI_API_KEY\n", "gemini"),
    ],
)
def test_provider_detector_covers_common_sdk_and_env_patterns(relpath, text, provider):
    result = detect_in_file(relpath, text)

    assert {
        "name": provider,
        "path": relpath,
        "confidence": "high" if relpath.endswith((".py", ".ts")) else "medium",
    } in result.findings["providers"]


@pytest.mark.parametrize(
    ("relpath", "text"),
    [
        ("agent.py", "from langgraph.graph import StateGraph\n"),
        ("agent.ts", 'import { StateGraph } from "@langchain/langgraph";\n'),
        ("agent.yaml", "framework: langgraph\n"),
    ],
)
def test_framework_detector_covers_langgraph_patterns(relpath, text):
    result = detect_in_file(relpath, text)

    assert {
        "name": "langgraph",
        "path": relpath,
        "confidence": "high" if relpath.endswith((".py", ".ts")) else "medium",
    } in result.findings["frameworks"]


@pytest.mark.parametrize(
    ("model", "expected_name"),
    [
        ("gpt-5.5", "gpt-5.5"),
        ("gpt-5.5-pro", "gpt-5.5-pro"),
        ("gpt-5.4", "gpt-5.4"),
        ("gpt-5.4-pro", "gpt-5.4-pro"),
        ("gpt-5.4-mini", "gpt-5.4-mini"),
        ("gpt-5.4-nano", "gpt-5.4-nano"),
        ("gpt-5", "gpt-5"),
        ("gpt-5-mini", "gpt-5-mini"),
        ("gpt-5-nano", "gpt-5-nano"),
        ("gpt-4.1", "gpt-4.1"),
        ("gpt-4.1-mini", "gpt-4.1-mini"),
        ("gpt-4.1-nano", "gpt-4.1-nano"),
        ("gpt-4o", "gpt-4o"),
        ("gpt-4o-mini", "gpt-4o-mini"),
        ("o3", "o3"),
        ("o4-mini", "o4-mini"),
        ("claude-opus-4-7", "claude-opus-4-7"),
        ("claude-opus-4.7", "claude-opus-4.7"),
        ("claude-opus-4-6", "claude-opus-4-6"),
        ("claude-opus-4.6", "claude-opus-4.6"),
        ("claude-sonnet-4-6", "claude-sonnet-4-6"),
        ("claude-sonnet-4.6", "claude-sonnet-4.6"),
        ("claude-haiku-4-5", "claude-haiku-4-5"),
        ("claude-3.7-sonnet", "claude-3.7-sonnet"),
        ("claude-3.5-sonnet", "claude-3.5-sonnet"),
        ("gemini-2.5-pro", "gemini-2.5-pro"),
        ("gemini-2.5-flash", "gemini-2.5-flash"),
        ("gemini-2.0-flash", "gemini-2.0-flash"),
        ("deepseek-chat", "deepseek-chat"),
        ("deepseek-reasoner", "deepseek-reasoner"),
        ("llama3.1", "llama3.1"),
        ("llama3.2", "llama3.2"),
        ("llama3.3", "llama3.3"),
        ("llama4", "llama4"),
        ("qwen2.5", "qwen2.5"),
        ("qwen3", "qwen3"),
        ("mistral-large", "mistral-large"),
        ("codestral", "codestral"),
        ("grok", "grok"),
        ("openrouter/openai/gpt-5.5", "gpt-5.5"),
        ("openrouter/openai/gpt-5.5-pro", "gpt-5.5-pro"),
        ("openrouter/anthropic/claude-opus-4.7", "claude-opus-4.7"),
        ("openrouter/anthropic/claude-opus-4-7", "claude-opus-4-7"),
        ("openrouter/deepseek/deepseek-reasoner", "deepseek-reasoner"),
        ("openrouter/google/gemini-2.5-pro", "gemini-2.5-pro"),
        ("anthropic/claude-opus-4.7", "claude-opus-4.7"),
        ("openai/gpt-5.5", "gpt-5.5"),
        ("google/gemini-2.5-pro", "gemini-2.5-pro"),
    ],
)
def test_model_detector_covers_modern_model_patterns(model, expected_name):
    result = detect_in_file("agent.py", f'model = "{model}"\n')

    assert {
        "type": "model",
        "name": expected_name,
        "source_file": "agent.py",
        "confidence": "high",
        "evidence": model,
    } in result.findings["models"]
