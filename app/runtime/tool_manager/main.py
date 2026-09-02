import ast
import operator
from app.runtime.tool_manager.config import load_tools_config

TOOLS_CONFIG = load_tools_config()

def get_tool_script(name: str) -> str | None:
    entry = TOOLS_CONFIG.get(name)
    return entry["script_path"] if entry else None