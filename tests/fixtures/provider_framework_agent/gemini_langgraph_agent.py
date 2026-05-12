"""Static Gemini and LangGraph fixture."""

from __future__ import annotations

import os

from google import genai
from langgraph.graph import StateGraph
from vertexai.generative_models import GenerativeModel


GOOGLE_GENERATIVE_AI_API_KEY = os.environ["GOOGLE_GENERATIVE_AI_API_KEY"]


def build_graph() -> StateGraph:
    _client = genai.Client(api_key=GOOGLE_GENERATIVE_AI_API_KEY)
    _fallback = GenerativeModel("gemini-2.0-flash")
    graph = StateGraph(dict)
    return graph
