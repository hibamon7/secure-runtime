import asyncio
import os
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

_client: genai.Client | None = None

#genai lit automatiquement le api key depuis .env
def _get_client() -> genai.Client:
    global _client
    if _client is None:
        _client = genai.Client()
    return _client


async def ask_llm(prompt: str, system: str | None = None) -> str:
    client = _get_client()
    config = (
        types.GenerateContentConfig(
            system_instruction=system
        )
        if system
        else None
    )
    response = await client.aio.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
        config=config,
    )
    return response.text