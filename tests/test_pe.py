import pytest
from app.runtime.policy_engine.main import PolicyEngine

@pytest.fixture
def engine():
    return PolicyEngine("app/runtime/policy_engine/rules.json")

def test_allow_matching_rule(engine):
    d = engine.evaluate(
        subject={"role": "user", "file_size_mb": 5},
        resource={"type": "file", "path": "/data/user_uploads/photo.png"},
        action="read",
    )
    assert d.allowed is True
    assert d.matched_rule_id == "allow-read-user-uploads"

def test_fail_closed_no_matching_rule(engine):
    d = engine.evaluate(
        subject={"role": "user"},
        resource={"type": "file", "path": "/tmp/random.txt"},
        action="read",
    )
    assert d.allowed is False

def test_deny_wins_on_system_write(engine):
    d = engine.evaluate(
        subject={"role": "admin"},
        resource={"type": "file", "path": "/etc/passwd"},
        action="write",
    )
    assert d.allowed is False
    assert d.matched_rule_id == "deny-write-system-files"

def test_path_traversal_blocked_by_normalization(engine):
    d = engine.evaluate(
        subject={"role": "user", "file_size_mb": 1},
        resource={"type": "file", "path": "/data/user_uploads/../../etc/passwd"},
        action="read",
    )
    assert d.allowed is False  # le chemin normalisé ne matche plus le prefix autorisé

def test_condition_role_rejected(engine):
    d = engine.evaluate(
        subject={"role": "guest"},
        resource={"type": "tool", "tool_name": "calculator"},
        action="execute",
    )
    assert d.allowed is False