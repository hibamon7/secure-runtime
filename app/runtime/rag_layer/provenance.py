import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature


#Sans elle, si on signait seulement doc["text"], la signature ne protège que le texte — source et document_id restent des métadonnées libres, jamais couvertes par la signature. Un attaquant qui a un accès en écriture à Chroma (même sans la clé privée) pourrait alors :
'''Prendre un chunk légitimement signé, avec une signature valide
Réécrire son document_id, ou changer son source déclaré vers une autre entrée de known_sources
La signature reste valide — puisqu'elle ne couvrait jamais ces deux champs — alors que le document a été altéré'''


def canonical_payload(document_id: str, text: str) -> bytes:
    """Plus de 'source' dans la signature — elle ne représente plus une
    déclaration d'origine, seulement l'intégrité depuis l'indexation."""
    return json.dumps(
        {"document_id": document_id, "text": text},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


class IndexationSigner:
    """Utilisée UNIQUEMENT par le pipeline d'indexation (scripts/), jamais par
    le Runtime qui sert les requêtes. Une seule clé privée interne — pas une
    clé par source déclarée."""
    def __init__(self, private_key_b64: str):
        self._key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))

    def sign(self, document_id: str, text: str) -> str:
        return base64.b64encode(self._key.sign(canonical_payload(document_id, text))).decode()


class IntegrityVerifier:
    """Vérifie qu'un document n'a pas été modifié depuis son indexation.
    Ne dit rien sur qui l'a écrit ni sur sa fiabilité — juste son intégrité."""
    def __init__(self, public_key_b64: str):
        self._key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))

    def verify(self, doc: dict) -> bool:
        signature_b64 = doc.get("signature")
        document_id = doc.get("document_id")
        if not signature_b64 or document_id is None:
            return False
        payload = canonical_payload(str(document_id), doc["text"])
        try:
            self._key.verify(base64.b64decode(signature_b64), payload)
            return True
        except (InvalidSignature, ValueError):
            return False