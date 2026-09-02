import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.runtime.rag_layer.main import index_documents, chunk_text
from app.runtime.rag_layer.provenance import canonical_payload

PRIVATE_KEY_B64 = "<colle ici la clé privée générée>"
private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(PRIVATE_KEY_B64))

docs = [
    "Le Policy Engine applique fail-closed : toute action sans règle explicite est refusée.",
    "Landlock restreint l'accès filesystem au niveau noyau, via un sous-processus jetable.",
    "Le Sandbox Manager unifie Landlock, seccomp et cgroups pour fichiers, outils et réseau.",
]

all_chunks, all_ids, all_sources, all_signatures = [], [], [], []
for i, doc in enumerate(docs):
    for j, chunk in enumerate(chunk_text(doc)):
        doc_id = f"doc{i}_chunk{j}"
        source = "internal_docs"
        payload = canonical_payload(source, doc_id, chunk)
        signature = base64.b64encode(private_key.sign(payload)).decode()
        all_chunks.append(chunk)
        all_ids.append(doc_id)
        all_sources.append(source)
        all_signatures.append(signature)

index_documents(all_chunks, ids=all_ids, sources=all_sources, signatures=all_signatures)
print(f"{len(all_chunks)} chunks signés (source+id+texte) et indexés depuis {len(docs)} documents.")