import ast
import operator

# Registre des outils réellement implémentés — "shell_exec" n'y figure pas volontairement.
TOOL_SCRIPTS = {
    "calculator": "app/runtime/tool_manager/tools/calculator.py",
}

def get_tool_script(name: str) -> str | None:
    return TOOL_SCRIPTS.get(name)