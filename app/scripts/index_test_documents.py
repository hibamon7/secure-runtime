import json
from pathlib import Path
from app.runtime.rag_layer.main import index_documents, chunk_text
from app.runtime.rag_layer.provenance import IndexationSigner

PRIVATE_KEY_B64 = "upfBEgrnc+4nKWk40nKb7RDxa4Do1Og3Zdm/qpuAA44="
signer = IndexationSigner(PRIVATE_KEY_B64)

docs = [
    {"text": "Le Policy Engine applique fail-closed : toute action sans règle explicite est refusée.", "classification": None},
    {"text": "Landlock restreint l'accès filesystem au niveau noyau, via un sous-processus jetable.", "classification": None},
    {"text": "Budget interne confidentiel : détail des coûts d'infrastructure du projet.", "classification": "confidential"},
]

all_chunks, all_ids, all_sources, all_signatures = [], [], [], []
classification_registry = {}

for i, doc in enumerate(docs):
    for j, chunk in enumerate(chunk_text(doc["text"])):
        doc_id = f"doc{i}_chunk{j}"
        all_chunks.append(chunk)
        all_ids.append(doc_id)
        all_sources.append("internal_docs")
        all_signatures.append(signer.sign(doc_id, chunk))
        if doc["classification"] is not None:
            classification_registry[doc_id] = doc["classification"]  # chaque chunk hérite du document

index_documents(all_chunks, ids=all_ids, sources=all_sources, signatures=all_signatures)

registry_path = Path("app/runtime/policy_engine/rag_classification.json")
registry_path.write_text(json.dumps({"version": "1.0.0", "classified_documents": classification_registry}, indent=2))

print(f"{len(all_chunks)} chunks indexés, {len(classification_registry)} classifiés confidentiels.")