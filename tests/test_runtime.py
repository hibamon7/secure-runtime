
import pytest
from app.runtime.main import Runtime
from app.auth.schemas import TokenPayload

@pytest.mark.asyncio

@pytest.mark.asyncio
async def test_ask_passthrough(make_user):
    runtime = Runtime()
    result = await runtime.ask("ping", current_user=make_user())
    assert isinstance(result, str)


@pytest.fixture
def make_user():
    def _make(sub="alice", role="user", scopes=None):
        return TokenPayload(sub=sub, role=role, scopes=scopes or [])
    return _make

@pytest.mark.asyncio
async def test_ask_allowed_for_valid_role(make_user):
    runtime = Runtime()
    result = await runtime.ask("hello", current_user=make_user(role="user"))
    assert isinstance(result, str)

@pytest.mark.asyncio
async def test_ask_denied_for_unlisted_role(make_user):
    runtime = Runtime()
    with pytest.raises(PermissionError):
        await runtime.ask("hello", current_user=make_user(role="banned"))