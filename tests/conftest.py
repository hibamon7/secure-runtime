import json
import pytest
from app.runtime.main import Runtime
from app.runtime.sandbox_manager.wiring import _run_sandboxed
from app.auth.schemas import TokenPayload


@pytest.fixture
def test_rules_file(tmp_path):
    rules = {
        "version": "test",
        "rules": [
            {"id": "r-read", "resource": "file", "action": "read", "path_prefix": str(tmp_path),
             "effect": "allow", "conditions": {"role": ["user", "admin"], "required_scopes": ["file:read"], "max_file_size_mb": 20}},
            {"id": "r-write", "resource": "file", "action": "write", "path_prefix": str(tmp_path),
             "effect": "allow", "conditions": {"role": ["user", "admin"], "required_scopes": ["file:write"]}},
            {"id": "r-calc", "resource": "tool", "action": "execute", "tool_name": "calculator",
             "effect": "allow", "conditions": {"role": ["user", "admin"]}},
            {"id": "r-api", "resource": "api", "action": "call", "effect": "allow", "conditions": {"role": ["user", "admin"]}},
            {"id": "r-net", "resource": "network", "action": "connect", "domain": "api.open-meteo.com",
             "effect": "allow", "conditions": {}},{"id": "r-rag", "resource": "rag", "action": "query", "effect": "allow", "conditions": {"role": ["user", "admin"]}},
            {"id": "r-llm", "resource": "llm", "action": "ask", "effect": "allow", "conditions": {"role": ["user", "admin"]}},
            {"id": "r-rag", "resource": "rag", "action": "query", "effect": "allow", "conditions": {"role": ["user", "admin"]}},
        ],
    }
    f = tmp_path / "rules.json"
    f.write_text(json.dumps(rules))
    return str(f)


@pytest.fixture
def runtime(test_rules_file):
    return Runtime(policy_rules_path=test_rules_file)


@pytest.fixture
def make_user():
    def _make(sub="alice", role="user", scopes=None):
        return TokenPayload(sub=sub, role=role, scopes=scopes or [])
    return _make
