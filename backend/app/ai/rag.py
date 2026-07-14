"""Faz 4 Sprint 29-30: RAG — CIS benchmark chunk'lama, embedding ve
benzerlik araması.

Embedding'ler Ollama /api/embeddings ile üretilir. Postgres'te pgvector
önerilir; taşınabilirlik için embedding JSON olarak saklanır ve kosinüs
benzerliği uygulama katmanında hesaplanır (küçük/orta korpus için
yeterli; pgvector migration'ı üretim notu olarak README'de).
"""
import json
import math
import os

import httpx

from app.core.database import SessionLocal
from app.models.models import RagChunk

EMBED_ENDPOINT = os.getenv("OLLAMA_EMBED_ENDPOINT", "http://localhost:11434/api/embeddings")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")


def chunk_text(text: str, max_chars: int = 1200, overlap: int = 150) -> list[str]:
    """Paragraf sınırlarına saygılı kayan pencere chunk'lama."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 <= max_chars:
            current = f"{current}\n\n{para}".strip()
        else:
            if current:
                chunks.append(current)
            # tek paragraf limitten büyükse sert böl
            while len(para) > max_chars:
                chunks.append(para[:max_chars])
                para = para[max_chars - overlap:]
            current = para
    if current:
        chunks.append(current)
    return chunks


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return dot / norm if norm else 0.0


async def embed(text: str) -> list[float]:
    async with httpx.AsyncClient(timeout=60.0, trust_env=False) as client:
        resp = await client.post(EMBED_ENDPOINT, json={"model": EMBED_MODEL, "prompt": text})
        resp.raise_for_status()
        return resp.json()["embedding"]


async def index_document(source: str, text: str) -> int:
    """Bir dokümanı (örn. CIS benchmark) chunk'layıp embedding'leriyle saklar."""
    chunks = chunk_text(text)
    db = SessionLocal()
    try:
        for chunk in chunks:
            vector = await embed(chunk)
            db.add(RagChunk(source=source, chunk_text=chunk,
                            embedding_json=json.dumps(vector)))
        db.commit()
        return len(chunks)
    finally:
        db.close()


async def retrieve(query: str, top_k: int = 4) -> list[dict]:
    """Sorguya en benzer chunk'ları döndürür."""
    query_vec = await embed(query)
    db = SessionLocal()
    try:
        scored = []
        for row in db.query(RagChunk).all():
            sim = cosine_similarity(query_vec, json.loads(row.embedding_json))
            scored.append({"source": row.source, "text": row.chunk_text, "score": sim})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]
    finally:
        db.close()
