import pytest


@pytest.mark.asyncio
async def test_timeout_exceeded(runtime, make_user, monkeypatch):
    from app.runtime.sandbox_manager import wiring
    monkeypatch.setattr(wiring, "SANDBOX_WORKER", "app/scripts/fake_slow_worker.py")  # dort 30s
    with pytest.raises(PermissionError, match="délai"):
        await runtime.execute_tool("calculator", current_user=make_user(), expression="1")


@pytest.mark.asyncio
async def test_memory_exceeded(monkeypatch):
    from app.runtime.sandbox_manager import wiring
    from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt
    monkeypatch.setattr(wiring, "SANDBOX_WORKER", "app/scripts/fake_memory_hog_worker.py") 
    receipt = AuthorizationReceipt(resource_type="tool", action="execute", identifier="calculator")
    with pytest.raises(PermissionError):
        await wiring._run_sandboxed(receipt, "tool_exec", identifier="calculator",
                                     worker_kwargs={"script_path": "x", "kwargs": {}})

    
def test_identity_manager_accepts_real_calculator():
    from app.runtime.tool_manager.identity_manager import verify_tool_identity
    verify_tool_identity("app/runtime/tool_manager/tools/calculator.py")

def test_prepare_cgroup_tree_builds_leaf_then_enables_controllers(tmp_path, monkeypatch):
    """Vérifie la séquence (feuille -> déplacement du processus -> contrôleurs sur le parent).
    Le comportement noyau réel de cette séquence est validé par app/scripts/diagnose_cgroup.py."""
    import os
    from app.runtime.sandbox_manager import wiring
    monkeypatch.delenv("SANDBOX_CGROUP_BASE", raising=False)
    monkeypatch.setattr(wiring, "CGROUP_BASE", wiring.CGROUP_BASE)  # restauré en fin de test
    base = wiring.prepare_cgroup_tree(base=tmp_path)
    assert base == tmp_path
    assert (tmp_path / "main" / "cgroup.procs").read_text() == str(os.getpid())
    assert (tmp_path / "cgroup.subtree_control").read_text() == "+memory +pids +cpu"
    assert wiring.CGROUP_BASE == tmp_path


def test_prepare_cgroup_tree_fails_loudly_when_not_writable(tmp_path, monkeypatch):
    from app.runtime.sandbox_manager import wiring
    monkeypatch.setattr(wiring, "CGROUP_BASE", wiring.CGROUP_BASE)
    with pytest.raises(RuntimeError, match="Delegate=yes"):
        wiring.prepare_cgroup_tree(base=tmp_path / "inexistant" / "profond")
