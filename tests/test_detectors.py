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
