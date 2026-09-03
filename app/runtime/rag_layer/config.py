import json
from pathlib import Path


def load_rag_integrity_config(path: str = "app/runtime/policy_engine/rag_layer.json") -> dict: #loads the public key in our rag json 
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - {"version", "indexation_public_key"}
    if unknown:
        raise ValueError(f"rag_integrity.json: clé(s) inconnue(s) {unknown}")
    if "indexation_public_key" not in data:
        raise ValueError("rag_integrity.json: champ 'indexation_public_key' manquant")
    return data["indexation_public_key"]
