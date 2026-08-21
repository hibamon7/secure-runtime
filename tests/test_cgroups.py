import pytest


@pytest.mark.asyncio
async def test_timeout_exceeded(runtime, make_user, monkeypatch):
    from app.runtime.sandbox_manager import wiring
    monkeypatch.setattr(wiring, "SANDBOX_WORKER", "app/scripts/fake_slow_worker.py")  # dort 30s
    with pytest.raises(PermissionError, match="délai"):
        await runtime.execute_tool("calculator", current_user=make_user(), expression="1")


@pytest.mark.asyncio
async def test_memory_exceeded(runtime, make_user):
    #Vérifie que le cgroup empêche un outil de dépasser la limite mémoire configurée.
    current_user = make_user()
    with pytest.raises(PermissionError):
        await runtime.ask(
            prompt="run memory test",
            current_user=current_user,
        )

    
def test_identity_manager_rejects_unlisted_tool():
    from app.runtime.tool_manager.identity_manager import verify_tool_identity
    with pytest.raises(PermissionError, match="non whitelisté"):
        verify_tool_identity("app/runtime/tool_manager/tools/inconnu.py")

def test_identity_manager_rejects_modified_hash(tmp_path, monkeypatch):
    from app.runtime.tool_manager import identity_manager
    fake_script = tmp_path / "fake.py"
    fake_script.write_text("def run(): return 1")
    monkeypatch.setitem(identity_manager.TOOL_HASHES, str(fake_script), "0" * 64)  # faux hash
    with pytest.raises(PermissionError, match="Intégrité compromise"):
        identity_manager.verify_tool_identity(str(fake_script))