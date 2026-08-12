import json
from pathlib import Path
from dataclasses import dataclass

@dataclass #pour la construction automatique de la classe Decision sans __init__ et __repr__
class Decision:
    allowed: bool
    reason: str
    matched_rule_id: str | None = None

RESERVED_KEYS = {"id", "resource", "action", "effect", "conditions"}

class PolicyEngine:
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self._load() #methode privée pour charger les règles depuis le fichier JSON

    def _load(self):
        data = json.loads(self.rules_path.read_text())
        self.version = data["version"]
        self.rules = data["rules"]

    def evaluate(self, subject: dict, resource: dict, action: str) -> Decision:
        matched_deny = None
        matched_allow = None
        for rule in self.rules:
            if not self._rule_matches(rule, subject, resource, action):
                continue
            if rule["effect"] == "deny":
                matched_deny = rule
                break  # deny-overrides : inutile de continuer, deny gagne toujours
            elif matched_allow is None:
                matched_allow = rule

        if matched_deny:
            return Decision(False, f"Refusé par '{matched_deny['id']}'", matched_deny["id"])
        if matched_allow:
            return Decision(True, f"Autorisé par '{matched_allow['id']}'", matched_allow["id"])
        return Decision(False, "Aucune règle applicable (fail-closed)", None)

    def _rule_matches(self, rule: dict, subject: dict, resource: dict, action: str) -> bool: #why subject is a dict? because it can contain any information about the user, like role, file size, etc.
    #what is the syntax of rule? it is a dict with keys: id, resource, action, effect, conditions (optional)
        if rule["resource"] != resource.get("type"):
            return False
        if rule["action"] != action:
            return False
        for key, expected in rule.items():
            if key in RESERVED_KEYS:
                continue
            if key == "path_prefix":
                actual = str(Path(resource.get("path", "")).resolve()) #to get the exact path with no ../../
                if not actual.startswith(expected):
                    return False
            elif resource.get(key) != expected:
                return False
        return self._conditions_match(rule.get("conditions", {}), subject)

    def _conditions_match(self, conditions: dict, subject: dict) -> bool:
        if "role" in conditions and subject.get("role") not in conditions["role"]:
            return False
        if "max_file_size_mb" in conditions:
            if subject.get("file_size_mb", 0) > conditions["max_file_size_mb"]:
                return False
        return True