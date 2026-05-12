"""Static DeepSeek fixture using the OpenAI-compatible SDK shape."""

from __future__ import annotations

import os

from openai import OpenAI


DEEPSEEK_API_KEY = os.environ["DEEPSEEK_API_KEY"]


def plan(task: str) -> str:
    client = OpenAI(
        api_key=DEEPSEEK_API_KEY,
        base_url="https://api.deepseek.com",
    )
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": task}],
    )
    return response.choices[0].message.content
