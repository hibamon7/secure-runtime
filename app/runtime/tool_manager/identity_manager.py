import hashlib
from pathlib import Path

TOOL_HASHES = {
    "app/runtime/tool_manager/tools/calculator.py": "5c9aa7bdcb933d87f420b0343f4d9717dddc9f8dcb8ee69c2cede1385f03ff9c",
}
#hash de calculator par ex genere par: python3 app/scripts/compute_tool-hash.py app/runtime/tool_manager/tools/calculator.py


def verify_tool_identity(script_path: str) -> None:
    expected = TOOL_HASHES.get(script_path)
    if expected is None:
        raise PermissionError(f"Outil non whitelisté: {script_path}")
    actual = hashlib.sha256(Path(script_path).read_bytes()).hexdigest() 
    if actual != expected:
        raise PermissionError(f"Intégrité compromise pour {script_path}")