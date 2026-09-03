import json
from pathlib import Path

_KNOWN_KEYS = {"version", "classified_documents"}

#ce document servira a filtrer l acces par role&scopes au documents confidentiels


def load_classification_registry(path: str = "app/runtime/policy_engine/rag_classification.json") -> dict:
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"rag_classification.json: clé(s) inconnue(s) {unknown}")
    return data.get("classified_documents", {})


def get_classification(document_id: str, registry: dict) -> str | None:
    """None = document non classifié -> pas de vérification supplémentaire."""
    return registry.get(document_id)