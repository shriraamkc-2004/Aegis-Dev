-- ============================================================
-- Aegis Enterprise — PostgreSQL Migration 001
-- Initial Schema: users, chat_sessions, chat_messages,
--                 documents, alerts, audit_logs
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Users Table ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            VARCHAR(50) NOT NULL DEFAULT 'viewer'
                    CHECK (role IN ('admin', 'soc_analyst', 'auditor', 'viewer')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Chat Sessions Table ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_sessions (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title           VARCHAR(500) DEFAULT 'New Chat',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id);

-- ─── Chat Messages Table ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_messages (
    id              SERIAL PRIMARY KEY,
    session_id      INTEGER NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    role            VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    message         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);

-- ─── Documents Table ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS documents (
    id              SERIAL PRIMARY KEY,
    filename        VARCHAR(500) NOT NULL,
    storage_path    TEXT NOT NULL,
    uploaded_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          VARCHAR(50) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'indexed', 'failed', 'archived'))
);

CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);

-- ─── Alerts Table ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id              SERIAL PRIMARY KEY,
    severity        VARCHAR(20) NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source          VARCHAR(255),
    description     TEXT,
    status          VARCHAR(50) NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'acknowledged', 'mitigated', 'closed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

-- ─── Audit Logs Table ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource        VARCHAR(255),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      VARCHAR(45),
    details         TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- ─── Copilot Interaction Log (AI-specific audit) ────────────────────────────────
CREATE TABLE IF NOT EXISTS copilot_interactions (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    session_id      INTEGER REFERENCES chat_sessions(id) ON DELETE SET NULL,
    prompt          TEXT NOT NULL,
    response        TEXT,
    confidence      REAL DEFAULT 0,
    sources_count   INTEGER DEFAULT 0,
    evidence_sufficient BOOLEAN DEFAULT false,
    requires_approval   BOOLEAN DEFAULT false,
    approved_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at     TIMESTAMPTZ,
    model_used      VARCHAR(100) DEFAULT 'gemini-2.5-flash',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_interactions_user ON copilot_interactions(user_id);
