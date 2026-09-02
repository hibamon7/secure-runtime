import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def canonical_payload(source: str, document_id: str, text: str) -> bytes:
    """Sérialisation déterministe — utilisée à la fois pour signer (indexation)
    et pour vérifier (ici). Une seule fonction partagée entre les deux étapes,
    pour qu'elles ne puissent jamais diverger silencieusement."""
    return json.dumps(
        {"source": source, "document_id": document_id, "text": text},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


class ProvenanceVerifier:
    """Ne détient jamais de clé privée — seulement les clés publiques des sources
    déclarées de confiance. La signature couvre source + document_id + texte :
    modifier n'importe lequel des trois après signature casse la vérification."""

    def __init__(self, trusted_public_keys: dict[str, str]):
        self._keys = {
            source: Ed25519PublicKey.from_public_bytes(base64.b64decode(key_b64))
            for source, key_b64 in trusted_public_keys.items()
        }

    def verify(self, doc: dict) -> bool:
        source = doc.get("source")
        signature_b64 = doc.get("signature")
        document_id = doc.get("document_id")
        if source not in self._keys or not signature_b64 or document_id is None:
            return False
        payload = canonical_payload(source, str(document_id), doc["text"])
        try:
            self._keys[source].verify(base64.b64decode(signature_b64), payload)
            return True
        except (InvalidSignature, ValueError):
            return False