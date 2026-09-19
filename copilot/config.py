"""
Aegis Enterprise Copilot — Centralized Configuration
Reads from environment variables (injected via .env or Docker Compose).
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ──────────────────────────────────────────────────────────────
# Gemini (existing — DO NOT replace)
# ──────────────────────────────────────────────────────────────
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_EMBEDDING_MODEL: str = os.getenv("GEMINI_EMBEDDING_MODEL", "text-embedding-004")

# ──────────────────────────────────────────────────────────────
# Qdrant Vector Database
# ──────────────────────────────────────────────────────────────
QDRANT_HOST: str = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT: int = int(os.getenv("QDRANT_PORT", "6333"))
QDRANT_URL: str = os.getenv("QDRANT_URL", "")  # Overrides HOST:PORT if set
QDRANT_API_KEY: str = os.getenv("QDRANT_API_KEY", "")
QDRANT_USE_HTTPS: bool = os.getenv("QDRANT_USE_HTTPS", "false").lower() == "true"

# Collection names
QDRANT_COLLECTION_KNOWLEDGE: str = "knowledge_base"
QDRANT_COLLECTION_ALERTS: str = "alert_rules"
QDRANT_COLLECTION_INCIDENTS: str = "incidents"
QDRANT_COLLECTION_LOGS: str = "logs"

# Embedding dimension (text-embedding-004 → 768, sentence-transformers → 384)
EMBEDDING_DIM: int = int(os.getenv("EMBEDDING_DIM", "768"))

# ──────────────────────────────────────────────────────────────
# PostgreSQL (enterprise metadata)
# ──────────────────────────────────────────────────────────────
POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB: str = os.getenv("POSTGRES_DB", "aegis_enterprise")
POSTGRES_USER: str = os.getenv("POSTGRES_USER", "aegis")
POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "aegis_secret")

def get_postgres_dsn() -> str:
    return (
        f"host={POSTGRES_HOST} port={POSTGRES_PORT} "
        f"dbname={POSTGRES_DB} user={POSTGRES_USER} password={POSTGRES_PASSWORD}"
    )

# ──────────────────────────────────────────────────────────────
# MinIO Object Storage
# ──────────────────────────────────────────────────────────────
MINIO_ENDPOINT: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_USE_SSL: bool = os.getenv("MINIO_USE_SSL", "false").lower() == "true"
MINIO_BUCKET: str = os.getenv("MINIO_BUCKET", "aegis-documents")

# ──────────────────────────────────────────────────────────────
# Copilot Service
# ──────────────────────────────────────────────────────────────
COPILOT_PORT: int = int(os.getenv("PORT", os.getenv("COPILOT_PORT", "8110")))
COPILOT_HOST: str = os.getenv("COPILOT_HOST", "0.0.0.0")

# ──────────────────────────────────────────────────────────────
# RAG Settings
# ──────────────────────────────────────────────────────────────
RAG_CHUNK_SIZE: int = int(os.getenv("RAG_CHUNK_SIZE", "1000"))
RAG_CHUNK_OVERLAP: int = int(os.getenv("RAG_CHUNK_OVERLAP", "200"))
RAG_TOP_K: int = int(os.getenv("RAG_TOP_K", os.getenv("COPILOT_TOP_K", "3")))
RAG_CONFIDENCE_THRESHOLD: float = float(os.getenv("RAG_CONFIDENCE_THRESHOLD", "0.50"))
RAG_CONFIDENCE_HIGH: float = float(os.getenv("RAG_CONFIDENCE_HIGH", "0.80"))
RAG_CONFIDENCE_MODERATE: float = float(os.getenv("RAG_CONFIDENCE_MODERATE", "0.50"))
EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", GEMINI_EMBEDDING_MODEL)

# ──────────────────────────────────────────────────────────────
# Responsible AI
# ──────────────────────────────────────────────────────────────
RAI_MAX_RESPONSE_TOKENS: int = int(os.getenv("RAI_MAX_RESPONSE_TOKENS", "2048"))
RAI_TEMPERATURE: float = float(os.getenv("RAI_TEMPERATURE", "0.15"))

# High-impact actions that require human approval
HIGH_IMPACT_ACTIONS = [
    "isolate_endpoint",
    "block_user",
    "disable_account",
    "modify_security_controls",
    "block_ip",
    "revoke_credentials",
    "shutdown_service",
]

# ──────────────────────────────────────────────────────────────
# Knowledge Base Paths
# ──────────────────────────────────────────────────────────────
KNOWLEDGE_BASE_DIR: str = os.getenv("KNOWLEDGE_BASE_DIR", "knowledge_base")
ALERT_RULES_DIR: str = os.getenv("ALERT_RULES_DIR", "knowledge_base/alert_rules")
INCIDENTS_DIR: str = os.getenv("INCIDENTS_DIR", "knowledge_base/incidents")
LOGS_DIR: str = os.getenv("LOGS_DIR", "knowledge_base/logs")

# ──────────────────────────────────────────────────────────────
# Multi-Tenant
# ──────────────────────────────────────────────────────────────
DEFAULT_TENANT_ID: int = int(os.getenv("DEFAULT_TENANT_ID", "1"))

# ──────────────────────────────────────────────────────────────
# Observability & Cost Tracking
# ──────────────────────────────────────────────────────────────
OBSERVABILITY_ENABLED: bool = os.getenv("OBSERVABILITY_ENABLED", "true").lower() == "true"
GEMINI_INPUT_COST_PER_1K: float = float(os.getenv("GEMINI_INPUT_COST_PER_1K", "0.000125"))
GEMINI_OUTPUT_COST_PER_1K: float = float(os.getenv("GEMINI_OUTPUT_COST_PER_1K", "0.000375"))

# ──────────────────────────────────────────────────────────────
# MITRE ATT&CK
# ──────────────────────────────────────────────────────────────
MITRE_ATTACK_ENABLED: bool = os.getenv("MITRE_ATTACK_ENABLED", "true").lower() == "true"
MITRE_ATTACK_DATA_PATH: str = os.getenv("MITRE_ATTACK_DATA_PATH", "knowledge_base/mitre_attack")
