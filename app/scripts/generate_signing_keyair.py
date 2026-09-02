from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import base64

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

priv_b64 = base64.b64encode(private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
pub_b64 = base64.b64encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

print("Clé PRIVÉE (garde-la hors du repo, jamais commit) :", priv_b64)
print("Clé PUBLIQUE (colle-la dans policies/rag_sources.json) :", pub_b64)