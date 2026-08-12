
import pytest
from app.runtime.main import Runtime

@pytest.mark.asyncio

async def test_ask_passthrough():
    runtime = Runtime()
    result = await runtime.ask("ping")
    assert isinstance(result, str)
    print(f"LLM response: {result}")