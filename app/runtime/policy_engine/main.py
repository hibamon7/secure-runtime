import json
from pathlib import Path #to access the file system and read the rules from a JSON file
from dataclasses import dataclass

@dataclass #pour la construction automatique de la classe Decision sans __init__ et __repr__
class Decision:
    allowed: bool
    reason: str
    matched_rule_id: str | None = None

'''this can be modified to add more features like logging, caching, etc. but for now it is a simple implementation of a policy engine that evaluates rules based on subject, resource and action. The rules are loaded from a JSON file and the evaluate method returns a Decision object indicating whether the action is allowed or denied based on the rules.'''
RESERVED_KEYS = {"id", "resource", "action", "effect", "conditions"}
KNOWN_MATCH_KEYS = {"path_prefix", "tool_name", "domain", "port"}
KNOWN_CONDITION_KEYS = {"role", "required_scopes", "max_file_size_mb"}


'''N.B'''
#in this file, we define a PolicyEngine class that loads rules from a JSON file and evaluates them based on the 
#subject, resource, and action. The rules are defined in a specific format, and the engine checks for matches and
#conditions to determine if an action is allowed or denied. The Decision class is used to encapsulate the result
# of the evaluation.


class PolicyEngine:
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self._load() #methode privée pour charger les règles depuis le fichier JSON
        self._validate_rules() #fail early if the rules are invalid

    def _load(self):
        data = json.loads(self.rules_path.read_text())
        self.version = data["version"]
        self.rules = data["rules"]

    def _validate_rules(self):
        for rule in self.rules:
            rid = rule.get("id", "<sans id>")

            if rule.get("effect") not in ("allow", "deny"):
                raise ValueError(f"Règle '{rid}': effect invalide '{rule.get('effect')}' (doit être 'allow' ou 'deny')")

            unknown_match = set(rule.keys()) - RESERVED_KEYS - KNOWN_MATCH_KEYS
            if unknown_match:
                raise ValueError(f"Règle '{rid}': champ(s) de correspondance inconnu(s) {unknown_match}")

            unknown_cond = set(rule.get("conditions", {}).keys()) - KNOWN_CONDITION_KEYS
            if unknown_cond:
                raise ValueError(f"Règle '{rid}': condition(s) inconnue(s) {unknown_cond} — vérifie l'orthographe")

    def evaluate(self, subject: dict, resource: dict, action: str) -> Decision:   #the core function of the POLICY ENGINE
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
        return self._conditions_match(rule.get("conditions", {}), subject, resource) #for keys like role, max_file_size_mb)

    def _conditions_match(self, conditions: dict, subject: dict, resource: dict) -> bool:
        #exemple of a rule with conditions:
        #"id": "allow-read-user-uploads", "resource": "file", "action": "read",
        #"path_prefix": "/data/user_uploads/", "effect": "allow",
        #"conditions": {"role": ["user", "admin"], "required_scopes": ["file:read"], "max_file_size_mb": 20}
    
        if "role" in conditions and subject.get("role") not in conditions["role"]:
            return False
        if "required_scopes" in conditions:
            subject_scopes = set(subject.get("scopes", []))
            if not set(conditions["required_scopes"]).issubset(set(subject.get("scopes", []))):
                return False
        if "max_file_size_mb" in conditions:
            if subject.get("file_size_mb", 0) > conditions["max_file_size_mb"]:
                return False
        return True