import pytest
import json
from pathlib import Path
from app.runtime.rag_layer.classification import get_classification

@pytest.mark.asyncio
async def test_confidential_document_blocked_for_user_allowed_for_admin(runtime, make_user, monkeypatch):
    from app.runtime import main as runtime_main
    monkeypatch.setattr(runtime_main, "rag_search", lambda q, n_results=3: [
        {"text": "Contenu confidentiel.", "source": "internal_docs", "document_id": "secret1", "signature": "valid"},
    ])
    monkeypatch.setattr(runtime_main.IntegrityVerifier, "verify", lambda self, doc: True)
    runtime.rag_classification = {"secret1": "confidential"}

    captured = {}
    async def fake_call_llm(self, prompt, system=None):
        captured["prompt"] = prompt
        return "réponse"
    monkeypatch.setattr(runtime_main.Runtime, "_call_llm", fake_call_llm)

    await runtime.ask_with_context("question", current_user=make_user(role="user"))
    assert "confidentiel" not in captured["prompt"]

    await runtime.ask_with_context("question", current_user=make_user(role="admin"))
    assert "confidentiel" in captured["prompt"]