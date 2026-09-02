import json
import pytest

def test_tools_config_loads_calculator(tmp_path):
    from app.runtime.tool_manager.config import load_tools_config
    good = tmp_path / "tools.json"
    good.write_text(json.dumps({
        "version": "1.0.0",
        "tools": {"calculator": {
            "script_path": "app/runtime/tool_manager/tools/calculator.py",
            "sha256": "5c9aa7bdcb933d87f420b0343f4d9717dddc9f8dcb8ee69c2cede1385f03ff9c",
        }},
    }))
    result = load_tools_config(str(good))
    assert "calculator" in result
    assert result["calculator"]["script_path"] == "app/runtime/tool_manager/tools/calculator.py"


def test_tools_config_rejects_unknown_top_level_key(tmp_path):
    from app.runtime.tool_manager.config import load_tools_config
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": "1.0.0", "tools": {}, "typo_field": True}))
    with pytest.raises(ValueError, match="inconnue"):
        load_tools_config(str(bad))


def test_tools_config_rejects_missing_sha256(tmp_path):
    from app.runtime.tool_manager.config import load_tools_config
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "version": "1.0.0",
        "tools": {"calculator": {"script_path": "x.py"}},  # sha256 manquant
    }))
    with pytest.raises(ValueError, match="requis"):
        load_tools_config(str(bad))


def test_identity_manager_accepts_real_calculator_with_real_config():
    """Charge le vrai policies/tools.json, vérifie le vrai calculator.py sur disque —
    le test le plus proche de ce qui se passe réellement au démarrage de l'app."""
    from app.runtime.tool_manager.identity_manager import verify_tool_identity
    verify_tool_identity("app/runtime/tool_manager/tools/calculator.py")  # ne doit rien lever