"""Faz 4: chunk'lama ve kosinüs benzerliği (Ollama gerektirmez)."""
from app.ai.rag import chunk_text, cosine_similarity


def test_chunking_respects_paragraphs():
    text = "\n\n".join(f"Paragraf {i}: " + "x" * 300 for i in range(8))
    chunks = chunk_text(text, max_chars=1000)
    assert len(chunks) > 1
    assert all(len(c) <= 1000 for c in chunks)


def test_oversized_paragraph_hard_split():
    chunks = chunk_text("y" * 5000, max_chars=1200)
    assert all(len(c) <= 1200 for c in chunks)
    assert sum(len(c) for c in chunks) >= 5000  # overlap ile kayıpsız


def test_empty_text():
    assert chunk_text("") == []


def test_cosine_similarity():
    assert cosine_similarity([1, 0], [1, 0]) == 1.0
    assert cosine_similarity([1, 0], [0, 1]) == 0.0
    assert cosine_similarity([1, 1], [0, 0]) == 0.0  # sıfır vektör güvenli
