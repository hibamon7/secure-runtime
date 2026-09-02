import json
from pathlib import Path

_KNOWN_KEYS = {"version", "max_prompt_length", "model_threshold", "jailbreak_patterns"}
_REQUIRED = {"max_prompt_length", "model_threshold", "jailbreak_patterns"}


def load_guardrails_config(path: str = "app/runtime/policy_engine/guardrails.json") -> dict:
    data = json.loads(Path(path).read_text())
    unknown = set(data.keys()) - _KNOWN_KEYS
    if unknown:
        raise ValueError(f"guardrails.json: clé(s) inconnue(s) {unknown}")
    missing = _REQUIRED - set(data.keys())
    if missing:
        raise ValueError(f"guardrails.json: champ(s) manquant(s) {missing}")
    return data