import chromadb

_client = None
_collection = None


def _get_collection():
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path="data/rag_index") #ceci sert a conserver l'index de recherche de documents de manière persistante sur le disque, dans le répertoire "data/rag_index". 
        _collection = _client.get_or_create_collection("test_docs") #cette collection est pour stocker et interroger les documents
    return _collection


def index_documents(documents: list[str], ids: list[str]) -> None:
    _get_collection().add(documents=documents, ids=ids)


def search(query: str, n_results: int = 3) -> list[str]: #this function will return the 3 documents of chroma the nearest to the query
    results = _get_collection().query(query_texts=[query], n_results=n_results)
    return results["documents"][0] if results["documents"] else []

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