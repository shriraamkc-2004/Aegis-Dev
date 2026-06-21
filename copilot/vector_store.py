"""
Aegis Copilot — Qdrant Vector Store Manager
Manages 4 enterprise collections: knowledge_base, alert_rules, incidents, logs.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Dict, Any, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels
from qdrant_client.http.exceptions import UnexpectedResponse

from copilot.config import (
    QDRANT_HOST,
    QDRANT_PORT,
    QDRANT_URL,
    QDRANT_API_KEY,
    QDRANT_USE_HTTPS,
    QDRANT_COLLECTION_KNOWLEDGE,
    QDRANT_COLLECTION_ALERTS,
    QDRANT_COLLECTION_INCIDENTS,
    QDRANT_COLLECTION_LOGS,
    EMBEDDING_DIM,
)

logger = logging.getLogger(__name__)

# Distance metric: cosine similarity best for semantic search
DISTANCE = qmodels.Distance.COSINE

ALL_COLLECTIONS = [
    QDRANT_COLLECTION_KNOWLEDGE,
    QDRANT_COLLECTION_ALERTS,
    QDRANT_COLLECTION_INCIDENTS,
    QDRANT_COLLECTION_LOGS,
]


class VectorStore:
    """
    Manages Qdrant collections, upsert, search, and deletion operations.
    Thread-safe singleton — create once at service startup.
    """

    def __init__(
        self,
        host: str = QDRANT_HOST,
        port: int = QDRANT_PORT,
        url: str = QDRANT_URL,
        api_key: str = QDRANT_API_KEY,
        use_https: bool = QDRANT_USE_HTTPS,
        embedding_dim: int = EMBEDDING_DIM,
    ):
        if url:
            # Use QDRANT_URL (e.g. http://qdrant:6333 or https://...)
            self._client = QdrantClient(
                url=url,
                api_key=api_key if api_key else None,
                timeout=30,
            )
        else:
            self._client = QdrantClient(
                host=host,
                port=port,
                api_key=api_key if api_key else None,
                https=use_https,
                timeout=30,
            )
        self._dim = embedding_dim

    # ─── Collection Lifecycle ──────────────────────────────────────────────────

    def ensure_collections(self) -> None:
        """
        Create all 4 enterprise collections if they don't exist.
        Idempotent — safe to call on every startup.
        """
        for name in ALL_COLLECTIONS:
            try:
                self._client.get_collection(name)
                logger.info("Collection '%s' already exists.", name)
            except (UnexpectedResponse, Exception):
                logger.info("Creating collection '%s' (dim=%d)…", name, self._dim)
                self._client.create_collection(
                    collection_name=name,
                    vectors_config=qmodels.VectorParams(
                        size=self._dim,
                        distance=DISTANCE,
                    ),
                    optimizers_config=qmodels.OptimizersConfigDiff(
                        indexing_threshold=100,
                    ),
                )
                logger.info("Collection '%s' created.", name)

    def delete_collection(self, name: str) -> None:
        self._client.delete_collection(name)

    # ─── Upsert ─────────────────────────────────────────────────────────────────

    def upsert_points(
        self,
        collection: str,
        embeddings: List[List[float]],
        payloads: List[Dict[str, Any]],
        ids: Optional[List[str]] = None,
    ) -> int:
        """
        Insert or update vectors.
        Returns number of points upserted.
        """
        if ids is None:
            ids = [str(uuid.uuid4()) for _ in embeddings]

        points = [
            qmodels.PointStruct(
                id=point_id,
                vector=vec,
                payload=payload,
            )
            for point_id, vec, payload in zip(ids, embeddings, payloads)
        ]

        # Batch upsert in chunks of 100 to avoid gRPC size limits
        batch_size = 100
        total = 0
        for i in range(0, len(points), batch_size):
            batch = points[i : i + batch_size]
            self._client.upsert(collection_name=collection, points=batch)
            total += len(batch)

        logger.info(
            "Upserted %d points into '%s'.", total, collection
        )
        return total

    # ─── Semantic Search ────────────────────────────────────────────────────────

    def search(
        self,
        collection: str,
        query_vector: List[float],
        top_k: int = 5,
        score_threshold: float = 0.0,
        filter_payload: Optional[Dict] = None,
        tenant_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run a nearest-neighbour semantic search.
        Supports tenant-isolated filtering via tenant_id in payload metadata.
        Returns list of {id, score, payload}.
        """
        search_filter = None
        conditions = []

        # Tenant isolation: always filter by tenant_id when provided
        if tenant_id is not None:
            conditions.append(
                qmodels.FieldCondition(key="tenant_id", match=qmodels.MatchValue(value=tenant_id))
            )

        if filter_payload:
            conditions.extend([
                qmodels.FieldCondition(key=k, match=qmodels.MatchValue(value=v))
                for k, v in filter_payload.items()
            ])

        if conditions:
            search_filter = qmodels.Filter(must=conditions)

        hits = self._client.search(
            collection_name=collection,
            query_vector=query_vector,
            limit=top_k,
            score_threshold=score_threshold if score_threshold > 0 else None,
            query_filter=search_filter,
        )

        return [
            {
                "id": str(h.id),
                "score": h.score,
                "payload": h.payload or {},
            }
            for h in hits
        ]

    def search_multi(
        self,
        collections: List[str],
        query_vector: List[float],
        top_k: int = 5,
        tenant_id: Optional[int] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Search across multiple collections and return per-collection results."""
        results: Dict[str, List[Dict[str, Any]]] = {}
        for col in collections:
            try:
                results[col] = self.search(col, query_vector, top_k, tenant_id=tenant_id)
            except Exception as exc:
                logger.warning("Search on '%s' failed: %s", col, exc)
                results[col] = []
        return results

    # ─── Deletion ───────────────────────────────────────────────────────────────

    def delete_by_payload(
        self, collection: str, key: str, value: Any
    ) -> None:
        """Delete all points matching a payload field."""
        self._client.delete(
            collection_name=collection,
            points_selector=qmodels.FilterSelector(
                filter=qmodels.Filter(
                    must=[
                        qmodels.FieldCondition(
                            key=key, match=qmodels.MatchValue(value=value)
                        )
                    ]
                )
            ),
        )

    def get_collection_info(self, name: str) -> Dict[str, Any]:
        """Return collection metadata (points count, status, etc.)."""
        info = self._client.get_collection(name)
        return {
            "name": name,
            "points_count": info.points_count,
            "status": str(info.status),
            "vectors_count": info.vectors_count,
        }

    def list_all_collections_info(self) -> List[Dict[str, Any]]:
        return [self.get_collection_info(c) for c in ALL_COLLECTIONS]

    # ─── Health ──────────────────────────────────────────────────────────────────

    def is_healthy(self) -> bool:
        try:
            self._client.get_collections()
            return True
        except Exception:
            return False
