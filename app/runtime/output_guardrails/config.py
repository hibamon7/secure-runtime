import json
from pathlib import Path

_KNOWN_KEYS = {"version", "grounding_threshold"}


def load_output_guardrails_config(path: str = "app/runtime/policy_engine/output_guardrails.json") -> dict:
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"output_guardrails.json: clé(s) inconnue(s) {unknown}")
    if "grounding_threshold" not in data:
        raise ValueError("output_guardrails.json: champ 'grounding_threshold' manquant")
    return data