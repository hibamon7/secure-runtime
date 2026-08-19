import pytest
from app.runtime.policy_engine.main import PolicyEngine
from app.auth.schemas import TokenPayload
import json


@pytest.fixture 
def engine(): #fixture to create a PolicyEngine instance for testing
    return PolicyEngine("app/runtime/policy_engine/rules.json")

@pytest.fixture
def make_user(): #fixture to create a TokenPayload instance for testing
    def _make(sub="alice", role="user", scopes=None):
        return TokenPayload(sub=sub, role=role, scopes=scopes or [])
    return _make

def test_allow_matching_rule(engine):
    d = engine.evaluate({"role": "user", "scopes": ["file:read"], "file_size_mb": 5},
                         {"type": "file", "path": "/data/user_uploads/photo.png"}, "read")
    assert d.allowed is True

def test_fail_closed_no_matching_rule(engine):
    d = engine.evaluate({"role": "user"}, {"type": "file", "path": "/tmp/x.txt"}, "read")
    assert d.allowed is False

def test_deny_wins_on_system_write(engine):
    d = engine.evaluate({"role": "admin"}, {"type": "file", "path": "/etc/passwd"}, "write")
    assert d.allowed is False

def test_path_traversal_blocked(engine):
    d = engine.evaluate({"role": "user", "scopes": ["file:read"], "file_size_mb": 1},
                         {"type": "file", "path": "/data/user_uploads/../../etc/passwd"}, "read")
    assert d.allowed is False

def test_missing_scope_denied(engine):
    d = engine.evaluate({"role": "user", "scopes": [], "file_size_mb": 1},
                         {"type": "file", "path": "/data/user_uploads/x.png"}, "read")
    assert d.allowed is False

def test_unknown_condition_key_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": "0.0.1", "rules": [
        {"id": "r1", "resource": "file", "action": "read", "effect": "allow",
         "conditions": {"requiredScopes": ["x"]}}
    ]}))
    with pytest.raises(ValueError, match="condition"):
        PolicyEngine(str(bad))

def test_invalid_effect_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": "0.0.1", "rules": [
        {"id": "r1", "resource": "file", "action": "read", "effect": "denny", "conditions": {}}
    ]}))
    with pytest.raises(ValueError, match="effect invalide"):
        PolicyEngine(str(bad))