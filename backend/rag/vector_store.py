"""ChromaDB vector store wrapper — deterministic, local, no external deps."""

from __future__ import annotations

import chromadb
from chromadb.config import Settings

from app.config import settings
from rag.schemas import IncidentResponsePair, pair_to_text
from rag.embeddings import embed_text, embed_texts, _stable_id


COLLECTION_NAME = "incident_response_pairs"
META_FIELDS = (
    "mitre_tactic",
    "mitre_technique_id",
    "severity",
    "attack_pattern",
    "source",
)


class VectorStore:
    """Thin wrapper around a persistent Chroma collection."""

    def __init__(self, path: str | None = None):
        self._client = chromadb.PersistentClient(
            path=path or str(settings.vector_store_path),
            settings=Settings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    def count(self) -> int:
        return self._collection.count()

    def reset(self) -> None:
        """Drop and recreate the collection; used by tests."""
        self._client.delete_collection(name=COLLECTION_NAME)
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    def index_pair(self, pair: IncidentResponsePair) -> None:
        """Upsert one incident/response pair (idempotent via content hash)."""
        text = pair_to_text(pair)
        vec = embed_text(text)
        _id = _stable_id(text)
        meta = {k: getattr(pair, k) for k in META_FIELDS}
        meta.update(
            {
                "incident_id": pair.incident_id,
                "title": pair.title,
                "source": pair.source,
            }
        )
        self._collection.upsert(
            ids=[_id],
            embeddings=[vec],
            metadatas=[meta],
            documents=[text],
        )

    def index_pairs(self, pairs: list[IncidentResponsePair]) -> None:
        """Batch index; dedups by content hash automatically."""
        texts = [pair_to_text(p) for p in pairs]
        vecs = embed_texts(texts)
        ids = [_stable_id(t) for t in texts]
        metadatas = []
        for p in pairs:
            meta = {k: getattr(p, k) for k in META_FIELDS}
            meta.update(
                {
                    "incident_id": p.incident_id,
                    "title": p.title,
                    "source": p.source,
                }
            )
            metadatas.append(meta)
        self._collection.upsert(
            ids=ids,
            embeddings=vecs,
            metadatas=metadatas,
            documents=texts,
        )

    def query(
        self,
        query_text: str,
        k: int = 3,
        where: dict | None = None,
    ) -> list[dict]:
        """Semantic search; returns list of {id, document, metadata, distance}."""
        q_vec = embed_text(query_text)
        res = self._collection.query(
            query_embeddings=[q_vec],
            n_results=k,
            where=where,
            include=["documents", "metadatas", "distances"],
        )
        out = []
        for i in range(len(res["ids"][0])):
            out.append(
                {
                    "id": res["ids"][0][i],
                    "document": res["documents"][0][i],
                    "metadata": res["metadatas"][0][i],
                    "distance": res["distances"][0][i],
                }
            )
        return out