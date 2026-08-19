import pytest



@pytest.mark.asyncio
async def test_read_file_allowed(runtime, make_user, tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("bonjour")
    result = await runtime.read_file(str(f), current_user=make_user(scopes=["file:read"]))
    assert result == "bonjour"


@pytest.mark.asyncio
async def test_read_file_denied_outside_prefix(runtime, make_user):
    with pytest.raises(PermissionError):
        await runtime.read_file("/etc/passwd", current_user=make_user(scopes=["file:read"]))


@pytest.mark.asyncio
async def test_write_file_denied_without_scope(runtime, make_user, tmp_path):
    with pytest.raises(PermissionError):
        await runtime.write_file(str(tmp_path / "x.txt"), "data", current_user=make_user(scopes=[]))


@pytest.mark.asyncio
async def test_execute_tool_calculator(runtime, make_user):
    result = await runtime.execute_tool("calculator", current_user=make_user(), expression="2 + 3 * 4")
    assert result == 14


@pytest.mark.asyncio
async def test_execute_tool_shell_exec_denied_no_rule(runtime, make_user):
    with pytest.raises(PermissionError):
        await runtime.execute_tool("shell_exec", current_user=make_user(), command="ls")


@pytest.mark.asyncio
async def test_call_api_allowed_domain(runtime, make_user, monkeypatch):
    async def fake_request(method, url, **kwargs):
        return {"temperature": 21}
    monkeypatch.setattr(runtime, "_http_request", fake_request)
    result = await runtime.call_api("https://api.open-meteo.com/v1/forecast", current_user=make_user())
    assert result == {"temperature": 21}


@pytest.mark.asyncio
async def test_call_api_denied_domain_not_allowlisted(runtime, make_user):
    with pytest.raises(PermissionError):
        await runtime.call_api("https://evil.example.com/data", current_user=make_user())



@pytest.mark.asyncio
async def test_execute_tool_calculator_via_sandbox(runtime, make_user):
    result = await runtime.execute_tool("calculator", current_user=make_user(), expression="2 + 3 * 4")
    assert result == 14

@pytest.mark.asyncio
async def test_receipt_identifier_mismatch_for_wrong_tool(runtime, make_user):
    from app.runtime.sandbox_manager.wiring import _run_sandboxed
    from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt
    receipt = AuthorizationReceipt(resource_type="tool", action="execute", identifier="calculator")
    with pytest.raises(PermissionError):
        await _run_sandboxed(receipt, "tool_exec", identifier="autre_outil",
                              worker_kwargs={"script_path": "app/runtime/tool_manager/tools/calculator.py", "kwargs": {}})

@pytest.mark.asyncio
async def test_call_api_network_denied_wrong_port(runtime, make_user, monkeypatch):
    with pytest.raises(PermissionError):
        await runtime.call_api("https://api.open-meteo.com:9999/v1/forecast", current_user=make_user())