import json
import logging
import subprocess
import sys

import pytest

SANDBOX_WORKER = "app/runtime/sandbox_manager/landlock_worker.py"

from app.runtime.sandbox_manager.wiring import _run_sandboxed
from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt



@pytest.mark.asyncio
async def test_read_file_authorized_succeeds_through_landlock(runtime, make_user, tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("bonjour")
    result = await runtime.read_file(str(f), current_user=make_user(scopes=["file:read"]))
    assert result == "bonjour"


@pytest.mark.asyncio
async def test_policy_denial_logged_without_reaching_landlock(runtime, make_user, caplog):
    with caplog.at_level(logging.INFO):
        with pytest.raises(PermissionError):
            await runtime.read_file("/etc/passwd", current_user=make_user(scopes=["file:read"]))
    messages = [r.message for r in caplog.records]
    assert any("policy_decision" in m and "allowed=False" in m for m in messages)
    assert not any("landlock_denied" in m for m in messages)  # jamais atteint, refusé avant


@pytest.mark.asyncio
async def test_landlock_denial_logged_distinctly(tmp_path, caplog):
    (tmp_path / "allowed").mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    escape = tmp_path / "allowed" / "escape"
    escape.symlink_to(outside)

    with caplog.at_level(logging.WARNING):
        with pytest.raises(PermissionError):
            receipt = AuthorizationReceipt(resource_type="file", action="read", path=str(escape))
            await _run_sandboxed(receipt,"read", str(escape))
    assert any("landlock_denied" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_read_file_always_authorizes_before_sandboxing(runtime, make_user, tmp_path, monkeypatch):
    call_order = []

    original_authorize = runtime._authorize
    async def tracking_authorize(*a, **kw):
        call_order.append("authorize")
        return await original_authorize(*a, **kw)
    monkeypatch.setattr(runtime, "_authorize", tracking_authorize)

    async def tracking_sandbox(*a, **kw):
        call_order.append("sandbox")
        return "contenu"
    monkeypatch.setattr("app.runtime.main._run_sandboxed", tracking_sandbox)
    f = tmp_path / "x.txt"
    f.write_text("y")
    await runtime.read_file(str(f), current_user=make_user(scopes=["file:read"]))
    assert call_order == ["authorize", "sandbox"]



@pytest.mark.asyncio
async def test_run_sandboxed_requires_a_receipt():
    with pytest.raises(TypeError):
        await _run_sandboxed("read", "/tmp/whatever")  # pas de reçu : erreur avant tout accès


@pytest.mark.asyncio
async def test_run_sandboxed_rejects_receipt_for_wrong_action(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("y")
    receipt = AuthorizationReceipt(resource_type="file", action="write", path=str(f))
    with pytest.raises(PermissionError):
        await _run_sandboxed(receipt, "read", str(f))


@pytest.mark.asyncio
async def test_run_sandboxed_rejects_receipt_for_wrong_path(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("y")
    other = tmp_path / "y.txt"
    receipt = AuthorizationReceipt(resource_type="file", action="read", path=str(other))
    with pytest.raises(PermissionError):
        await _run_sandboxed(receipt, "read", str(f))


@pytest.mark.asyncio
async def test_landlock_denies_symlink_escape_even_with_valid_receipt(tmp_path, caplog):
    """Un reçu valide prouve qu'une autorisation a eu lieu — pas que le chemin réel
    est sûr. Le lien symbolique reste le cas où Landlock agit en dernière ligne,
    indépendamment de ce que le reçu affirme."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    escape = allowed / "escape"
    escape.symlink_to(outside)

    receipt = AuthorizationReceipt(resource_type="file", action="read", path=str(escape))
    with caplog.at_level(logging.WARNING):
        with pytest.raises(PermissionError):
            await _run_sandboxed(receipt, "read", str(escape))
    assert any("landlock_denied" in r.message for r in caplog.records)


