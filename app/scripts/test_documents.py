from app.runtime.rag_layer.main import index_documents, chunk_text

docs = [
    "Le Policy Engine applique fail-closed : toute action sans règle explicite est refusée.",
    "Landlock restreint l'accès filesystem au niveau noyau, via un sous-processus jetable.",
    "Le Sandbox Manager unifie Landlock, seccomp et cgroups pour fichiers, outils et réseau.",
]

all_chunks, all_ids = [], []
for i, doc in enumerate(docs):
    for j, chunk in enumerate(chunk_text(doc)):
        all_chunks.append(chunk)
        all_ids.append(f"doc{i}_chunk{j}")

index_documents(all_chunks, ids=all_ids)
print(f"{len(all_chunks)} chunks indexés depuis {len(docs)} documents.")