import json
from pathlib import Path

_KNOWN_KEYS = {"version", "trusted_sources"}


def load_rag_sources_config(path: str = "policies/rag_sources.json") -> dict:
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"rag_sources.json: clé(s) inconnue(s) {unknown}")
    if "trusted_sources" not in data:
        raise ValueError("rag_sources.json: champ 'trusted_sources' manquant")
    return data["trusted_sources"]