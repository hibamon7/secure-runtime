import chromadb
import logging

logger = logging.getLogger("rag_layer")


_client = None
_collection = None


def _get_collection():
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path="data/rag_index") #ceci sert a conserver l'index de recherche de documents de manière persistante sur le disque, dans le répertoire "data/rag_index". 
        _collection = _client.get_or_create_collection("test_docs") #cette collection est pour stocker et interroger les documents
    return _collection


def index_documents(documents: list[str], ids: list[str], sources: list[str], signatures: list[str]) -> None:
    metadatas = [{"source": s, "signature": sig} for s, sig in zip(sources, signatures)]
    _get_collection().add(documents=documents, ids=ids, metadatas=metadatas)


def search(query: str, n_results: int = 3) -> list[dict]: #returns the 3 documents of chroma the nearerst to the sense of the question asked (kNN search)
    results = _get_collection().query(query_texts=[query], n_results=n_results)
    docs = results["documents"][0] if results["documents"] else []
    metas = results["metadatas"][0] if results["metadatas"] else [{}] * len(docs)
    metas = [m if isinstance(m, dict) else {} for m in metas]
    ids = results["ids"][0] if results["ids"] else [""] * len(docs)
    return [
        {"text": d, "source": m.get("source", "inconnu"), "signature": m.get("signature", ""), "document_id": i}
        for d, m, i in zip(docs, metas, ids)
    ]


def chunk_text(text: str, max_chars: int = 500, overlap: int = 50) -> list[str]:
    """Découpe un texte en passages courts, avec un léger chevauchement pour
    ne pas couper une idée en plein milieu à la frontière entre deux chunks."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + max_chars
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def spotlight(text: str, marker: str = "^") -> str: #ignore all ... ==> ignore^all^... makes it harder for the ai to take it as an instruction
    return marker.join(text.split())