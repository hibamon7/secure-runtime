import json
import pytest

def test_sandbox_config_loads_defaults(tmp_path):
    from app.runtime.sandbox_manager.config import load_sandbox_config
    good = tmp_path / "sandbox.json"
    good.write_text(json.dumps({
        "version": "1.0.0",
        "dangerous_syscalls": ["execve", "fork"],
        "cgroup_defaults": {"memory_max_mb": 256, "pids_max": 32, "cpu_percent": 50},
        "subprocess_timeout_seconds": 10,
    }))
    result = load_sandbox_config(str(good))
    assert result["subprocess_timeout_seconds"] == 10
    assert "execve" in result["dangerous_syscalls"]


def test_sandbox_config_rejects_unknown_top_level_key(tmp_path):
    from app.runtime.sandbox_manager.config import load_sandbox_config
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": "1.0.0", "dangerous_syscalls": [], "cgroup_defaults": {},
        "subprocess_timeout_seconds": 10, "typo_field": True,
    }))
    with pytest.raises(ValueError, match="inconnue"):
        load_sandbox_config(str(bad))


def test_sandbox_config_rejects_unknown_cgroup_key(tmp_path):
    from app.runtime.sandbox_manager.config import load_sandbox_config
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": "1.0.0", "dangerous_syscalls": [],
        "cgroup_defaults": {"memory_max_mb": 256, "disk_quota_gb": 5},  # clé inventée
        "subprocess_timeout_seconds": 10,
    }))
    with pytest.raises(ValueError, match="inconnue"):
        load_sandbox_config(str(bad))


def test_real_sandbox_config_loads_without_error():
    """Le vrai policies/sandbox.json, tel qu'il doit exister chez toi maintenant."""
    from app.runtime.sandbox_manager.config import load_sandbox_config
    config = load_sandbox_config()
    assert "execve" in config["dangerous_syscalls"]
    assert config["cgroup_defaults"]["memory_max_mb"] > 0