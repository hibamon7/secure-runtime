import pytest


def test_rag_search_returns_relevant_document():
    from app.runtime.rag_layer.main import index_documents, search
    index_documents(
        ["Le ciel est bleu.", "Python est un langage de programmation."],
        ids=["t1", "t2"], sources=["internal_docs", "internal_docs"], signatures=["", ""],
    )
    results = search("langage de programmation", n_results=1)
    assert "Python" in results[0]["text"]


@pytest.mark.asyncio
async def test_query_rag_denied_without_authorized_role(runtime, make_user):
    with pytest.raises(PermissionError):
        await runtime.query_rag("test", current_user=make_user(role="banned"))