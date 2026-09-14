import json
import logging
import subprocess
import sys

import pytest

from app.runtime.sandbox_manager.wiring import _run_sandboxed
from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt

LANDLOCK_WORKER = "app/runtime/sandbox_manager/landlock_worker.py"


def test_landlock_allows_authorized_read(tmp_path):
    d = tmp_path / "allowed"
    d.mkdir()
    (d / "ok.txt").write_text("visible")
    result = subprocess.run(
        [sys.executable, LANDLOCK_WORKER, json.dumps({"operation": "file_read", "path": str(d / "ok.txt"), "dangerous_syscalls": []})],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert result.stdout == "visible"


def test_landlock_helper_denies_when_run_against_a_symlink_escape(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    escape = allowed / "escape"
    escape.symlink_to(outside)
    result = subprocess.run(
        [sys.executable, LANDLOCK_WORKER, json.dumps({"operation": "file_read", "path": str(escape), "dangerous_syscalls": []})],
        capture_output=True, text=True,
    )
    assert result.returncode != 0


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


@pytest.mark.asyncio
async def test_run_sandboxed_requires_a_receipt():
    with pytest.raises(TypeError):
        await _run_sandboxed("file_read", "/tmp/whatever")


@pytest.mark.asyncio
async def test_run_sandboxed_rejects_receipt_for_wrong_action(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("y")
    receipt = AuthorizationReceipt(resource_type="file", action="write", identifier=str(f))
    with pytest.raises(PermissionError):
        await _run_sandboxed(receipt, "file_read", identifier=str(f), worker_kwargs={"path": str(f)})


@pytest.mark.asyncio
async def test_run_sandboxed_rejects_receipt_for_wrong_path(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("y")
    other = tmp_path / "y.txt"
    receipt = AuthorizationReceipt(resource_type="file", action="read", identifier=str(other))
    with pytest.raises(PermissionError):
        await _run_sandboxed(receipt, "file_read", identifier=str(f), worker_kwargs={"path": str(f)})


@pytest.mark.asyncio
async def test_landlock_denies_symlink_escape_even_with_valid_receipt(tmp_path, caplog):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    escape = allowed / "escape"
    escape.symlink_to(outside)

    receipt = AuthorizationReceipt(resource_type="file", action="read", identifier=str(escape))
    with caplog.at_level(logging.WARNING):
        with pytest.raises(PermissionError):
            await _run_sandboxed(receipt, "file_read", identifier=str(escape), worker_kwargs={"path": str(escape)})
    assert any('"landlock_denial"' in r.message for r in caplog.records)