"""
Aegis Copilot — FastAPI Server
Exposes chat, document management, RAG ingestion, and health endpoints.
Runs as a separate service on port 8100 alongside the main Express server.
"""

from __future__ import annotations

import logging
import time
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from copilot.config import COPILOT_PORT, COPILOT_HOST, GEMINI_MODEL, get_postgres_dsn
from copilot.vector_store import VectorStore
from copilot.rag_pipeline import RAGPipeline, GeminiEmbedder
from copilot.responsible_ai import ResponsibleAIEngine, AuditLogger, SourceAttribution
from copilot.storage_service import StorageService
from copilot.chat_engine import ChatEngine, ASSISTANT_PERSONAS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ─── FastAPI App ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis Enterprise Security Copilot",
    version="2.0.0",
    description="RAG-powered security copilot with Responsible AI guardrails",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Service Singletons (initialized at startup) ─────────────────────────────────

_vector_store: Optional[VectorStore] = None
_rag_pipeline: Optional[RAGPipeline] = None
_rai_engine: Optional[ResponsibleAIEngine] = None
_audit_logger: Optional[AuditLogger] = None
_storage_service: Optional[StorageService] = None
_chat_engine: Optional[ChatEngine] = None


def _init_services():
    global _vector_store, _rag_pipeline, _rai_engine, _audit_logger, _storage_service, _chat_engine
    try:
        _vector_store = VectorStore()
        _vector_store.ensure_collections()
    except Exception as exc:
        logger.warning("Qdrant init deferred: %s", exc)
        _vector_store = VectorStore.__new__(VectorStore)

    embedder = GeminiEmbedder()
    _rag_pipeline = RAGPipeline(_vector_store, embedder) if _vector_store else None
    _rai_engine = ResponsibleAIEngine()

    # Wire audit logger with PostgreSQL persistence
    pg_dsn = None
    try:
        pg_dsn = get_postgres_dsn()
        logger.info("AuditLogger will persist to PostgreSQL.")
    except Exception:
        logger.warning("PostgreSQL DSN unavailable; audit logs will be in-memory only.")
    _audit_logger = AuditLogger(pg_connection=pg_dsn)

    # MinIO Storage Service (skip blocking connection attempts if running in cloud without local MinIO)
    if os.getenv("MINIO_ENDPOINT") and os.getenv("MINIO_ENDPOINT") not in ("localhost:9000", "127.0.0.1:9000"):
        try:
            _storage_service = StorageService()
            _storage_service.ensure_bucket()
        except Exception as exc:
            logger.warning("MinIO init deferred: %s", exc)
            _storage_service = None
    else:
        _storage_service = None

    if _vector_store and _rag_pipeline:
        _chat_engine = ChatEngine(_vector_store, _rag_pipeline, _rai_engine, _audit_logger)
    else:
        _chat_engine = None


@app.on_event("startup")
async def startup():
    _init_services()


# ─── Auth Header Extraction ────────────────────────────────────────────────────────

def extract_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Extract user info from Bearer token (JWT validation delegated to Express proxy)."""
    # In production, validate JWT here or trust the Express proxy header
    return {"user_id": None, "role": "anonymous"}


# ─── Request / Response Models ─────────────────────────────────────────────────────


class ChatRequest(BaseModel):
    message: str
    assistant: str = "analyst"
    session_id: Optional[int] = None
    chat_history: Optional[List[Dict[str, str]]] = None
    tenant_id: Optional[int] = None


class ChatResponse(BaseModel):
    response_id: str
    answer: str
    confidence: float
    confidence_level: str = "low"
    sources: List[Dict[str, Any]]
    evidence_sufficient: bool
    requires_approval: bool
    pending_action: Optional[str]
    model_used: str
    reasoning: str


class IngestRequest(BaseModel):
    text: str
    collection: str = "knowledge_base"
    source: str = "api_upload"
    tag: str = ""


class ApprovalRequest(BaseModel):
    response_id: str
    approved: bool
    approver_id: int
    notes: str = ""


# ─── Chat Endpoints ──────────────────────────────────────────────────────────────

@app.post("/api/copilot/chat", response_model=ChatResponse)
async def copilot_chat(req: ChatRequest, authorization: Optional[str] = Header(None)):
    """
    Main copilot chat endpoint.
    Supports 4 assistant personas: analyst, audit, documentation, incident.
    """
    if not _chat_engine:
        raise HTTPException(status_code=503, detail="Copilot service not initialized")

    if req.assistant not in ASSISTANT_PERSONAS:
        raise HTTPException(status_code=400, detail=f"Unknown assistant: {req.assistant}. Valid: {list(ASSISTANT_PERSONAS.keys())}")

    user_info = extract_user(authorization)
    response = _chat_engine.chat(
        user_message=req.message,
        assistant=req.assistant,
        user_id=user_info.get("user_id"),
        session_id=req.session_id,
        chat_history=req.chat_history,
        tenant_id=req.tenant_id,
    )

    return ChatResponse(
        response_id=response.response_id,
        answer=response.answer,
        confidence=response.confidence,
        confidence_level=response.confidence_level,
        sources=[
            {"index": s.index, "source": s.source, "filename": s.filename, "collection": s.collection, "score": s.score}
            for s in response.sources
        ],
        evidence_sufficient=response.evidence_sufficient,
        requires_approval=response.requires_approval,
        pending_action=response.pending_action,
        model_used=response.model_used,
        reasoning=response.reasoning,
    )


@app.post("/api/copilot/approve")
async def approve_action(req: ApprovalRequest):
    """Approve or deny a high-impact action suggested by the copilot."""
    if not _chat_engine:
        raise HTTPException(status_code=503, detail="Copilot service not initialized")
    result = _chat_engine.approve_action(req.response_id, req.approved, req.approver_id, req.notes)
    return result


@app.get("/api/copilot/assistants")
async def list_assistants():
    """List available copilot assistant personas."""
    return {
        name: {"name": p["name"], "description": p["description"]}
        for name, p in ASSISTANT_PERSONAS.items()
    }


# ─── RAG Ingestion Endpoints ─────────────────────────────────────────────────────

@app.post("/api/copilot/ingest/text")
async def ingest_text(req: IngestRequest):
    """Ingest raw text directly into a Qdrant collection."""
    if not _rag_pipeline:
        raise HTTPException(status_code=503, detail="RAG pipeline not initialized")
    count = _rag_pipeline.ingest_text(req.text, req.collection, req.source, req.tag)
    return {"chunks_indexed": count, "collection": req.collection}


@app.post("/api/copilot/ingest/directory")
async def ingest_directory(
    directory: str = Form("knowledge_base"),
    collection: str = Form("knowledge_base"),
    tag: str = Form(""),
    tenant_id: int = Form(1),
):
    """Ingest all documents from a server-side directory (tenant-aware)."""
    if not _rag_pipeline:
        raise HTTPException(status_code=503, detail="RAG pipeline not initialized")
    
    clean_dir = os.path.basename(directory).strip().lower()
    allowed_dirs = {"knowledge_base", "alert_rules", "incidents", "logs"}
    if clean_dir not in allowed_dirs:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid directory '{clean_dir}'. Allowed directories: {', '.join(sorted(allowed_dirs))}",
        )

    count = _rag_pipeline.ingest_directory(clean_dir, collection, tag, tenant_id)
    return {"chunks_indexed": count, "collection": collection, "directory": clean_dir}


@app.post("/api/copilot/ingest/upload")
async def ingest_uploaded_file(
    file: UploadFile = File(...),
    collection: str = Form("knowledge_base"),
    tag: str = Form(""),
    tenant_id: int = Form(1),
    trust_level: str = Form("MEDIUM"),
    provenance: str = Form("api_upload"),
):
    """Upload a file, store in MinIO, and ingest into RAG. Supports PDF, TXT, MD, DOCX."""
    if not _rag_pipeline:
        raise HTTPException(status_code=503, detail="RAG pipeline not initialized")

    # Enforce maximum file size limit (5MB) to prevent memory exhaustion DoS
    MAX_FILE_SIZE = 5 * 1024 * 1024
    file.file.seek(0, 2)
    file_size = file.file.tell()
    file.file.seek(0)
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds maximum limit of 5MB")

    content = await file.read()
    filename = file.filename or "unknown"

    # Store in MinIO if available
    storage_info = None
    if _storage_service:
        try:
            storage_info = _storage_service.upload_file(content, filename, file.content_type or "application/octet-stream")
        except Exception as exc:
            logger.warning("MinIO upload failed: %s", exc)

    # Extract text based on file type
    from langchain_core.documents import Document
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if suffix == "docx":
        from copilot.rag_pipeline import _load_docx
        from pathlib import Path
        import tempfile
        # Write to temp file for python-docx (needs file path)
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
        try:
            text = _load_docx(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    elif suffix == "pdf":
        from copilot.rag_pipeline import _load_pdf
        from pathlib import Path
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(content)
            tmp_path = Path(tmp.name)
        try:
            text = _load_pdf(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    else:
        text = content.decode("utf-8", errors="replace")

    if not text.strip():
        return {"chunks_indexed": 0, "collection": collection, "filename": filename, "warning": "No text extracted from file."}

    doc = Document(
        page_content=text,
        metadata={
            "source": filename,
            "filename": filename,
            "uploaded_by": "api",
            "trust_level": trust_level,
            "provenance": provenance,
        }
    )
    count = _rag_pipeline.ingest_documents([doc], collection, tag, tenant_id)

    return {
        "chunks_indexed": count,
        "collection": collection,
        "filename": filename,
        "storage": storage_info,
    }


@app.post("/api/copilot/ingest/all")
async def ingest_all_default():
    """Ingest all default knowledge base directories."""
    if not _rag_pipeline:
        raise HTTPException(status_code=503, detail="RAG pipeline not initialized")
    results = _rag_pipeline.ingest_all_default_sources()
    return results


# ─── Document Management ─────────────────────────────────────────────────────────

@app.get("/api/copilot/documents")
async def list_documents(prefix: str = ""):
    """List documents stored in MinIO."""
    if not _storage_service:
        raise HTTPException(status_code=503, detail="MinIO storage not available")
    objects = _storage_service.list_objects(prefix)
    return {"objects": objects}


@app.get("/api/copilot/documents/{object_name:path}/url")
async def get_document_url(object_name: str):
    """Get a presigned download URL for a document."""
    if not _storage_service:
        raise HTTPException(status_code=503, detail="MinIO storage not available")
    url = _storage_service.get_presigned_url(object_name)
    return {"url": url}


@app.delete("/api/copilot/documents/{object_name:path}")
async def delete_document(object_name: str):
    """Delete a document from MinIO."""
    if not _storage_service:
        raise HTTPException(status_code=503, detail="MinIO storage not available")
    _storage_service.delete_object(object_name)
    return {"deleted": object_name}


# ─── Vector Store Management ─────────────────────────────────────────────────────

@app.get("/api/copilot/collections")
async def list_collections():
    """List all Qdrant collections with metadata."""
    if not _vector_store:
        raise HTTPException(status_code=503, detail="Vector store not available")
    try:
        return {"collections": _vector_store.list_all_collections_info()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@app.post("/api/copilot/collections/{name}/recreate")
async def recreate_collection(name: str):
    """Delete and recreate a Qdrant collection (clears all data)."""
    if not _vector_store:
        raise HTTPException(status_code=503, detail="Vector store not available")
    try:
        _vector_store.delete_collection(name)
        _vector_store.ensure_collections()
        return {"recreated": name}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ─── Audit Endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/copilot/audit")
async def get_audit_logs(limit: int = 50):
    """Retrieve recent AI interaction audit logs."""
    if not _audit_logger:
        return {"logs": []}
    return {"logs": _audit_logger.get_recent(limit)}


# ─── Chat History (PostgreSQL) ──────────────────────────────────────────────────

def _get_pg_conn():
    """Get a psycopg2 connection for chat history persistence."""
    try:
        import psycopg2
        return psycopg2.connect(get_postgres_dsn())
    except Exception as exc:
        logger.warning("PostgreSQL connection failed: %s", exc)
        return None


@app.post("/api/copilot/sessions")
async def create_session(tenant_id: Optional[int] = None, user_id: Optional[int] = None, assistant: str = "analyst", title: str = ""):
    """Create a new chat session."""
    conn = _get_pg_conn()
    if not conn:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO chat_sessions (organization_id, user_id, assistant, title)
                   VALUES (%s, %s, %s, %s) RETURNING id, created_at""",
                (tenant_id, user_id, assistant, title or f"New {assistant} session"),
            )
            row = cur.fetchone()
            conn.commit()
            return {"id": row[0], "created_at": str(row[1]), "assistant": assistant}
    finally:
        conn.close()


@app.get("/api/copilot/sessions")
async def list_sessions(tenant_id: Optional[int] = None, user_id: Optional[int] = None, limit: int = 50):
    """List chat sessions for a tenant/user."""
    conn = _get_pg_conn()
    if not conn:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        with conn.cursor() as cur:
            query = "SELECT id, assistant, title, created_at, updated_at FROM chat_sessions WHERE 1=1"
            params: List[Any] = []
            if tenant_id is not None:
                query += " AND organization_id = %s"
                params.append(tenant_id)
            if user_id is not None:
                query += " AND user_id = %s"
                params.append(user_id)
            query += " ORDER BY updated_at DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, params)
            rows = cur.fetchall()
            return {
                "sessions": [
                    {"id": r[0], "assistant": r[1], "title": r[2], "created_at": str(r[3]), "updated_at": str(r[4])}
                    for r in rows
                ]
            }
    finally:
        conn.close()


@app.get("/api/copilot/history/{session_id}")
async def get_chat_history(session_id: int):
    """Retrieve all messages for a chat session."""
    conn = _get_pg_conn()
    if not conn:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, role, content, sources, confidence, model_used,
                          reasoning, requires_approval, pending_action, created_at
                   FROM chat_messages WHERE session_id = %s ORDER BY created_at ASC""",
                (session_id,),
            )
            rows = cur.fetchall()
            return {
                "session_id": session_id,
                "messages": [
                    {
                        "id": r[0],
                        "role": r[1],
                        "content": r[2],
                        "sources": r[3],
                        "confidence": r[4],
                        "model_used": r[5],
                        "reasoning": r[6],
                        "requires_approval": r[7],
                        "pending_action": r[8],
                        "created_at": str(r[9]),
                    }
                    for r in rows
                ],
            }
    finally:
        conn.close()


@app.delete("/api/copilot/history/{session_id}")
async def delete_chat_history(session_id: int):
    """Delete a chat session and all its messages."""
    conn = _get_pg_conn()
    if not conn:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM chat_sessions WHERE id = %s", (session_id,))
            conn.commit()
            return {"deleted": session_id}
    finally:
        conn.close()


@app.post("/api/copilot/history/{session_id}/messages")
async def save_chat_message(
    session_id: int,
    role: str = Form(...),
    content: str = Form(...),
    sources: Optional[str] = Form(None),
    confidence: Optional[float] = Form(None),
    model_used: str = Form(""),
    reasoning: str = Form(""),
    requires_approval: bool = Form(False),
    pending_action: Optional[str] = Form(None),
):
    """Save a chat message to a session (called after each copilot exchange)."""
    import json
    conn = _get_pg_conn()
    if not conn:
        raise HTTPException(status_code=503, detail="Database unavailable")
    try:
        sources_json = json.loads(sources) if sources else None
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO chat_messages
                   (session_id, role, content, sources, confidence, model_used,
                    reasoning, requires_approval, pending_action)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (session_id, role, content, json.dumps(sources_json) if sources_json else None,
                 confidence, model_used, reasoning, requires_approval, pending_action),
            )
            # Update session updated_at and auto-title
            cur.execute(
                "UPDATE chat_sessions SET updated_at = NOW() WHERE id = %s",
                (session_id,),
            )
            # Auto-set title from first user message
            cur.execute(
                "SELECT title FROM chat_sessions WHERE id = %s", (session_id,)
            )
            row = cur.fetchone()
            if row and (not row[0] or row[0].startswith("New ")):
                if role == "user" and content:
                    title = content[:100]
                    cur.execute(
                        "UPDATE chat_sessions SET title = %s WHERE id = %s",
                        (title, session_id),
                    )
            conn.commit()
            return {"saved": True, "session_id": session_id}
    finally:
        conn.close()


# ─── Health ──────────────────────────────────────────────────────────────────────

@app.get("/health")
@app.get("/api/copilot/health")
async def health_check():
    """Service health endpoint."""
    status = {
        "service": "aegis-copilot",
        "version": "2.0.0",
        "timestamp": time.time(),
        "components": {},
    }

    if _chat_engine:
        status["components"]["chat_engine"] = _chat_engine.is_healthy()
    else:
        status["components"]["chat_engine"] = {"gemini": False, "qdrant": False, "rag": False}

    status["components"]["minio"] = _storage_service.is_healthy() if _storage_service else False
    status["components"]["qdrant"] = _vector_store.is_healthy() if _vector_store else False

    status["status"] = "healthy"
    return status


# ─── Entry Point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "copilot.server:app",
        host=COPILOT_HOST,
        port=COPILOT_PORT,
        reload=False,
        log_level="info",
    )
