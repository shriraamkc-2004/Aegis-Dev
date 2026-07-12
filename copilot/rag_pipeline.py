"""
Aegis Copilot — LangChain RAG Pipeline
Handles: document ingestion, chunking, embedding, vector indexing,
semantic retrieval, and context injection into Gemini.
"""

from __future__ import annotations

import logging
import os
import hashlib
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from copilot.config import (
    GEMINI_API_KEY,
    GEMINI_EMBEDDING_MODEL,
    RAG_CHUNK_SIZE,
    RAG_CHUNK_OVERLAP,
    RAG_TOP_K,
    RAG_CONFIDENCE_THRESHOLD,
    QDRANT_COLLECTION_KNOWLEDGE,
    QDRANT_COLLECTION_ALERTS,
    QDRANT_COLLECTION_INCIDENTS,
    QDRANT_COLLECTION_LOGS,
    KNOWLEDGE_BASE_DIR,
    ALERT_RULES_DIR,
    INCIDENTS_DIR,
    LOGS_DIR,
    EMBEDDING_DIM,
    DEFAULT_TENANT_ID,
)
from copilot.vector_store import VectorStore

logger = logging.getLogger(__name__)


# ─── Embedding Providers ───────────────────────────────────────────────────────


class GeminiEmbedder:
    """
    Generates embeddings via Google Gemini text-embedding-004.
    Falls back to local sentence-transformers if API is unavailable.
    """

    def __init__(self, api_key: str = GEMINI_API_KEY, model: str = GEMINI_EMBEDDING_MODEL):
        self._api_key = api_key
        self._model = model
        self._fallback = None

    def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Embed a list of texts. Returns list of vectors."""
        if not self._api_key or self._api_key in ("MY_GEMINI_API_KEY", ""):
            return self._embed_fallback(texts)
        try:
            from google import genai
            client = genai.Client(api_key=self._api_key)
            result = client.models.embed_content(
                model=self._model,
                contents=texts,
            )
            return [emb.values for emb in result.embeddings]
        except Exception as exc:
            logger.warning("Gemini embedding failed (%s). Using fallback.", exc)
            return self._embed_fallback(texts)

    def embed_query(self, text: str) -> List[float]:
        return self.embed_texts([text])[0]

    def _embed_fallback(self, texts: List[str]) -> List[List[float]]:
        """Local sentence-transformers fallback (all-MiniLM-L6-v2 → 384 dim)."""
        if self._fallback is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._fallback = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("Loaded fallback embedding model: all-MiniLM-L6-v2")
            except Exception as exc:
                logger.error("Fallback embedding unavailable: %s", exc)
                # Return zero vectors as last resort
                return [[0.0] * EMBEDDING_DIM for _ in texts]
        vecs = self._fallback.encode(texts, show_progress_bar=False).tolist()
        # Pad/truncate to EMBEDDING_DIM
        return [
            (v + [0.0] * EMBEDDING_DIM)[:EMBEDDING_DIM] for v in vecs
        ]


# ─── Document Loaders ───────────────────────────────────────────────────────────


def load_documents_from_directory(
    directory: str,
    extensions: Tuple[str, ...] = (".md", ".txt", ".json", ".pdf", ".rst", ".docx"),
) -> List[Document]:
    """
    Recursively load text documents from a directory.
    Supports: .md, .txt, .json, .pdf, .rst, .docx
    """
    docs: List[Document] = []
    try:
        base_path = Path(KNOWLEDGE_BASE_DIR).resolve()
        dir_path = Path(directory).resolve()
        try:
            dir_path.relative_to(base_path)
        except ValueError:
            logger.warning("Path traversal attempt blocked: '%s' is not relative to base '%s'", directory, base_path)
            return docs
    except Exception as exc:
        logger.error("Error resolving ingestion directory: %s", exc)
        return docs

    if not dir_path.exists():
        logger.warning("Knowledge directory does not exist: %s", directory)
        return docs

    for file_path in dir_path.rglob("*"):
        if not file_path.is_file():
            continue
        if not file_path.suffix.lower().endswith(extensions):
            continue

        try:
            if file_path.suffix.lower() == ".pdf":
                text = _load_pdf(file_path)
            elif file_path.suffix.lower() == ".docx":
                text = _load_docx(file_path)
            elif file_path.suffix.lower() == ".json":
                text = file_path.read_text(encoding="utf-8", errors="replace")
            else:
                text = file_path.read_text(encoding="utf-8", errors="replace")

            if text.strip():
                docs.append(
                    Document(
                        page_content=text,
                        metadata={
                            "source": str(file_path),
                            "filename": file_path.name,
                            "directory": str(file_path.parent),
                        },
                    )
                )
        except Exception as exc:
            logger.warning("Failed loading %s: %s", file_path, exc)

    logger.info("Loaded %d documents from '%s'.", len(docs), directory)
    return docs


def _load_pdf(file_path: Path) -> str:
    """Minimal PDF text extraction without heavy deps."""
    try:
        from langchain_community.document_loaders import PyPDFLoader
        loader = PyPDFLoader(str(file_path))
        pages = loader.load()
        return "\n\n".join(p.page_content for p in pages)
    except Exception:
        # If PyPDF not available, return empty
        logger.warning("PDF extraction unavailable for %s", file_path)
        return ""


def _load_docx(file_path: Path) -> str:
    """Extract text from DOCX files using python-docx."""
    try:
        from docx import Document as DocxDocument
        doc = DocxDocument(str(file_path))
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        # Also extract text from tables
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if row_text:
                    paragraphs.append(row_text)
        return "\n\n".join(paragraphs)
    except ImportError:
        logger.warning("DOCX extraction unavailable for %s (install python-docx)", file_path)
        return ""
    except Exception as exc:
        logger.warning("DOCX extraction failed for %s: %s", file_path, exc)
        return ""


# ─── RAG Pipeline ───────────────────────────────────────────────────────────────


class RAGPipeline:
    """
    End-to-end Retrieval-Augmented Generation pipeline.

    1. Ingest documents from directories
    2. Chunk with RecursiveCharacterTextSplitter
    3. Embed via Gemini text-embedding-004 (fallback: sentence-transformers)
    4. Index into Qdrant collections
    5. Retrieve semantically at query time
    6. Build context-injected prompt for Gemini
    7. Return response + source attribution
    """

    def __init__(self, vector_store: VectorStore, embedder: Optional[GeminiEmbedder] = None):
        self._vs = vector_store
        self._embedder = embedder or GeminiEmbedder()
        self._splitter = RecursiveCharacterTextSplitter(
            chunk_size=RAG_CHUNK_SIZE,
            chunk_overlap=RAG_CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
            length_function=len,
        )

    # ─── Ingestion ──────────────────────────────────────────────────────────────

    def ingest_directory(
        self,
        directory: str,
        collection: str,
        tag: str = "",
        tenant_id: int = DEFAULT_TENANT_ID,
    ) -> int:
        """
        Load, chunk, embed, and index all documents from a directory.
        Returns total chunks indexed.
        """
        docs = load_documents_from_directory(directory)
        if not docs:
            logger.info("No documents found in '%s'.", directory)
            return 0
        return self.ingest_documents(docs, collection, tag, tenant_id)

    def ingest_documents(
        self,
        documents: List[Document],
        collection: str,
        tag: str = "",
        tenant_id: int = DEFAULT_TENANT_ID,
    ) -> int:
        """Chunk, embed, and index a list of LangChain Documents with tenant isolation."""
        all_chunks: List[Document] = []
        for doc in documents:
            chunks = self._splitter.split_documents([doc])
            all_chunks.extend(chunks)

        if not all_chunks:
            return 0

        texts = [c.page_content for c in all_chunks]
        embeddings = self._embedder.embed_texts(texts)

        payloads = []
        ids = []
        for i, chunk in enumerate(all_chunks):
            content_hash = hashlib.md5(chunk.page_content.encode()).hexdigest()
            ids.append(content_hash)
            payloads.append({
                "text": chunk.page_content,
                "source": chunk.metadata.get("source", ""),
                "filename": chunk.metadata.get("filename", ""),
                "chunk_index": i,
                "tag": tag,
                "tenant_id": tenant_id,
                "document_id": chunk.metadata.get("document_id", ""),
                "page_number": chunk.metadata.get("page_number", 0),
                "category": chunk.metadata.get("category", ""),
                "uploaded_by": chunk.metadata.get("uploaded_by", ""),
                "classification": chunk.metadata.get("classification", "internal"),
                "indexed_at": time.time(),
            })

        return self._vs.upsert_points(collection, embeddings, payloads, ids)

    def ingest_text(
        self,
        text: str,
        collection: str,
        source: str = "user_input",
        tag: str = "",
        tenant_id: int = DEFAULT_TENANT_ID,
    ) -> int:
        """Ingest raw text directly (for API uploads or incident notes)."""
        doc = Document(page_content=text, metadata={"source": source, "filename": source})
        return self.ingest_documents([doc], collection, tag, tenant_id)

    # ─── Ingest all default knowledge sources ────────────────────────────────────

    def ingest_all_default_sources(self) -> Dict[str, int]:
        """Ingest all default knowledge directories into their respective collections."""
        results: Dict[str, int] = {}

        # Knowledge base
        if os.path.exists(KNOWLEDGE_BASE_DIR):
            results["knowledge_base"] = self.ingest_directory(
                KNOWLEDGE_BASE_DIR, QDRANT_COLLECTION_KNOWLEDGE, "knowledge"
            )

        # Alert rules
        if os.path.exists(ALERT_RULES_DIR):
            results["alert_rules"] = self.ingest_directory(
                ALERT_RULES_DIR, QDRANT_COLLECTION_ALERTS, "alert_rules"
            )

        # Incidents
        if os.path.exists(INCIDENTS_DIR):
            results["incidents"] = self.ingest_directory(
                INCIDENTS_DIR, QDRANT_COLLECTION_INCIDENTS, "incidents"
            )

        # Logs
        if os.path.exists(LOGS_DIR):
            results["logs"] = self.ingest_directory(
                LOGS_DIR, QDRANT_COLLECTION_LOGS, "logs"
            )

        return results

    # ─── Retrieval ───────────────────────────────────────────────────────────────

    def retrieve(
        self,
        query: str,
        collections: Optional[List[str]] = None,
        top_k: int = RAG_TOP_K,
        tenant_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Semantic retrieval across specified collections (or all by default).
        Supports tenant-isolated retrieval via tenant_id payload filtering.
        Returns ranked list of {text, source, score, collection}.
        """
        if collections is None:
            collections = [
                QDRANT_COLLECTION_KNOWLEDGE,
                QDRANT_COLLECTION_ALERTS,
                QDRANT_COLLECTION_INCIDENTS,
                QDRANT_COLLECTION_LOGS,
            ]

        query_vec = self._embedder.embed_query(query)
        multi_results = self._vs.search_multi(collections, query_vec, top_k, tenant_id=tenant_id)

        all_hits: List[Dict[str, Any]] = []
        for col, hits in multi_results.items():
            for h in hits:
                all_hits.append({
                    "text": h["payload"].get("text", ""),
                    "source": h["payload"].get("source", ""),
                    "filename": h["payload"].get("filename", ""),
                    "score": h["score"],
                    "collection": col,
                    "tag": h["payload"].get("tag", ""),
                })

        # Sort by relevance score descending
        all_hits.sort(key=lambda x: x["score"], reverse=True)
        return all_hits[:top_k]

    # ─── Context Builder ─────────────────────────────────────────────────────────

    def build_context(
        self,
        query: str,
        collections: Optional[List[str]] = None,
        top_k: int = RAG_TOP_K,
        tenant_id: Optional[int] = None,
    ) -> Tuple[str, List[Dict[str, Any]], float]:
        """
        Retrieve relevant documents and build a context string for Gemini.
        Supports tenant-isolated retrieval.

        Returns:
          - context_text: formatted context block
          - sources: list of source dicts (for attribution)
          - max_confidence: highest retrieval score
        """
        hits = self.retrieve(query, collections, top_k, tenant_id=tenant_id)

        if not hits:
            return "", [], 0.0

        max_confidence = hits[0]["score"] if hits else 0.0

        context_parts = []
        sources = []
        for i, hit in enumerate(hits, 1):
            source_label = hit["filename"] or hit["source"] or "Unknown"
            context_parts.append(
                f"[Source {i}: {source_label} (relevance: {hit['score']:.2f})]\n{hit['text']}"
            )
            sources.append({
                "index": i,
                "source": source_label,
                "filename": hit["filename"],
                "collection": hit["collection"],
                "score": round(hit["score"], 4),
            })

        context_text = "\n\n---\n\n".join(context_parts)
        return context_text, sources, max_confidence
