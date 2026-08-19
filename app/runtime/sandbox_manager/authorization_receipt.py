from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationReceipt:
    """Preuve qu'une autorisation Policy Engine a été rendue pour une ressource précise.
    Ne peut être produite que par Runtime._authorize() — c'est le seul appelant qui la
    construit à partir d'une décision réellement évaluée.
    _run_sandboxed() exige ce reçu et vérifie qu'il correspond exactement à l'opération
    demandée (action + chemin) avant d'exécuter quoi que ce soit."""
    """resource_type: 'file' | 'tool' | 'network'
    action: 'read' | 'write' | 'execute' | 'connect'
    identifier: le chemin (file), le nom d'outil (tool), ou 'domaine:port' (network)."""
    resource_type: str
    action: str
    identifier: str