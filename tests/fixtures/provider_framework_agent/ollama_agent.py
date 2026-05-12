"""Static local model agent fixture; scanners must not execute this file."""

from __future__ import annotations

import os

import ollama


OLLAMA_HOST = os.environ["OLLAMA_HOST"]


def summarize(prompt: str) -> str:
    response = ollama.chat(
        model="llama3.1",
        messages=[{"role": "user", "content": prompt}],
    )
    return response["message"]["content"]
