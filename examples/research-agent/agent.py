"""Static demo research agent with intentionally risky capabilities."""

from __future__ import annotations

import os
import subprocess

from anthropic import Anthropic
from crewai import Agent
import requests


ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]


def search_web(query: str) -> str:
    response = requests.get("https://example.com/search", params={"q": query}, timeout=10)
    return response.text


def summarize_with_local_tool(markdown_path: str) -> str:
    result = subprocess.run(
        ["python", "-m", "tools.summarize", markdown_path],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_research_loop(topic: str) -> str:
    _researcher = Agent(role="researcher", goal="collect sources and draft a summary")
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    model = "claude-3-sonnet"
    max_iterations = 5
    notes = []
    for _ in range(max_iterations):
        notes.append(search_web(topic))
    draft = summarize_with_local_tool("notes.md")
    return client.messages.create(
        model=model,
        max_tokens=400,
        messages=[{"role": "user", "content": draft}],
    ).content[0].text
