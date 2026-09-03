import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import pytest

from app.runtime.rag_layer.provenance import IndexationSigner, IntegrityVerifier


def _make_pair():
    priv = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return IndexationSigner(priv_b64), IntegrityVerifier(pub_b64)


def test_integrity_verifier_accepts_unmodified_document():
    signer, verifier = _make_pair()
    sig = signer.sign("doc1", "contenu original")
    assert verifier.verify({"document_id": "doc1", "text": "contenu original", "signature": sig}) is True


def test_integrity_verifier_rejects_modified_text():
    signer, verifier = _make_pair()
    sig = signer.sign("doc1", "contenu original")
    assert verifier.verify({"document_id": "doc1", "text": "contenu modifié après coup", "signature": sig}) is False


def test_integrity_verifier_rejects_tampered_document_id():
    signer, verifier = _make_pair()
    sig = signer.sign("doc1", "contenu")
    assert verifier.verify({"document_id": "doc2", "text": "contenu", "signature": sig}) is False


def test_integrity_verifier_ignores_source_label_entirely():
    signer, verifier = _make_pair()
    sig = signer.sign("doc1", "contenu")
    assert verifier.verify({"document_id": "doc1", "text": "contenu", "source": "n'importe quoi", "signature": sig}) is True


def test_integrity_verifier_rejects_missing_signature():
    _, verifier = _make_pair()
    assert verifier.verify({"document_id": "doc1", "text": "contenu"}) is False