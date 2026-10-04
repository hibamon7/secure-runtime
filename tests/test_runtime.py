import pytest
from app.runtime import main as runtime_main
from app.runtime.main import Runtime


@pytest.fixture
def fake_llm(monkeypatch):
    """Remplace l'appel au fournisseur : ces tests vérifient le Runtime, pas le réseau."""
    async def fake_call_llm(self, prompt, system=None):
        return "réponse factice"
    monkeypatch.setattr(runtime_main.Runtime, "_call_llm", fake_call_llm)


@pytest.mark.asyncio
async def test_ask_passthrough(make_user, fake_llm):
    result = await Runtime().ask("ping", current_user=make_user())
    assert result == "réponse factice"


@pytest.mark.asyncio
async def test_ask_allowed_for_valid_role(make_user, fake_llm):
    result = await Runtime().ask("hello", current_user=make_user(role="admin"))
    assert isinstance(result, str)


@pytest.mark.asyncio
async def test_ask_denied_for_unlisted_role(make_user):
    with pytest.raises(PermissionError):
        await Runtime().ask("hello", current_user=make_user(role="banned"))


@pytest.mark.asyncio
async def test_ask_with_context_requires_llm_authorization(tmp_path, make_user, fake_llm, monkeypatch):
    """Droit d'interroger la base documentaire sans droit d'interroger le modèle : refusé."""
    import json
    rules = {"version": "t", "rules": [
        {"id": "r-rag", "resource": "rag", "action": "query", "effect": "allow", "conditions": {"role": ["user"]}},
    ]}
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(json.dumps(rules))
    monkeypatch.setattr(runtime_main, "check_prompt", lambda prompt: None)
    with pytest.raises(PermissionError):
        await Runtime(policy_rules_path=str(rules_file)).ask_with_context("question", current_user=make_user())
