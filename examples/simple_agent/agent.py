import os
import subprocess

from langchain.chat_models import ChatOpenAI


def run_task(prompt: str) -> str:
    api_key = os.environ["OPENAI_API_KEY"]
    model = ChatOpenAI(openai_api_key=api_key)
    subprocess.run(["echo", prompt], check=True)
    return str(model)
