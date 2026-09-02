import json
from pathlib import Path

_KNOWN_KEYS = {"version", "tools"}
_KNOWN_TOOL_KEYS = {"script_path", "sha256"}
# #par compute-tool

def load_tools_config(path: str = "app/runtime/policy_engine/tools.json") -> dict:
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"tools.json: clé(s) inconnue(s) {unknown}")
    for name, entry in data.get("tools", {}).items():
        bad = set(entry.keys()) - _KNOWN_TOOL_KEYS
        if bad:
            raise ValueError(f"tools.json: outil '{name}': clé(s) inconnue(s) {bad}")
        if "script_path" not in entry or "sha256" not in entry:
            raise ValueError(f"tools.json: outil '{name}': script_path et sha256 requis")
    return data["tools"]