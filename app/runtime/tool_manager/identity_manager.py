import hashlib
from pathlib import Path
from app.runtime.tool_manager.config import load_tools_config

_TOOLS_CONFIG = load_tools_config()


def verify_tool_identity(script_path: str) -> None:
    matching = [e for e in _TOOLS_CONFIG.values() if e["script_path"] == script_path]
    if not matching:
        raise PermissionError(f"Outil non whitelisté: {script_path}")
    expected = matching[0]["sha256"]
    actual = hashlib.sha256(Path(script_path).read_bytes()).hexdigest()
    if actual != expected:
        raise PermissionError(f"Intégrité compromise pour {script_path}")