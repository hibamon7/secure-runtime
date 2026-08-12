import asyncio
import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

# genai.Client() automatically reads GEMINI_API_KEY from environment variables
client = genai.Client()


async def ask_llm(prompt: str) -> str:
    response = await client.aio.models.generate_content(
        model="gemini-3.5-flash",
        contents=prompt,
    )
    return response.text