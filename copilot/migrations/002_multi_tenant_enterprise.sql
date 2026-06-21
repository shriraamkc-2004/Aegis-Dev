-- ============================================================
-- Aegis Enterprise — PostgreSQL Migration 002
-- Multi-Tenant Schema, Case Management, Prompt Registry,
-- AI Evaluation, Observability, Threat Intelligence
-- ============================================================

-- ─── Multi-Tenant: Add tenant_id to existing tables ──────────────────────────────

-- Tenants (organizations) table
CREATE TABLE IF NOT EXISTS tenants (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE,
    description     TEXT DEFAULT '',
    status          VARCHAR(50) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Departments within tenants
CREATE TABLE IF NOT EXISTS departments (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_departments_tenant ON departments(tenant_id);

-- Add tenant_id to users
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS department_id INTEGER REFERENCES departments(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(255) DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);

-- Add tenant_id to chat_sessions
ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS assistant_type VARCHAR(50) DEFAULT 'analyst';
ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS summary TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_chat_sessions_tenant ON chat_sessions(tenant_id);

-- Add tenant_id and RAG metadata to chat_messages
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS retrieved_sources JSONB DEFAULT '[]';
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS confidence_score REAL DEFAULT 0;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS model_used VARCHAR(100) DEFAULT 'gemini-2.5-flash';
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS reasoning TEXT DEFAULT '';
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN DEFAULT false;
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS pending_action VARCHAR(100);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created ON chat_messages(created_at);

-- Add tenant_id to documents
ALTER TABLE documents ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS classification VARCHAR(50) DEFAULT 'internal';
ALTER TABLE documents ADD COLUMN IF NOT EXISTS collection VARCHAR(100) DEFAULT 'knowledge_base';
ALTER TABLE documents ADD COLUMN IF NOT EXISTS chunks_indexed INTEGER DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_documents_tenant ON documents(tenant_id);

-- Add tenant_id and approval workflow to alerts
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN DEFAULT false;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS pending_action TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_techniques JSONB DEFAULT '[]';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactics JSONB DEFAULT '[]';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sla_deadline TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_assigned ON alerts(assigned_to);

-- Add tenant_id to audit_logs
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prompt TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS retrieved_documents JSONB DEFAULT '[]';
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS llm_response TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS approval_granted BOOLEAN;
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant ON audit_logs(tenant_id);

-- Add tenant_id to copilot_interactions
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS assistant_type VARCHAR(50) DEFAULT 'analyst';
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS retrieved_sources JSONB DEFAULT '[]';
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS confidence REAL DEFAULT 0;
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS reasoning TEXT DEFAULT '';
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS token_usage_input INTEGER DEFAULT 0;
ALTER TABLE copilot_interactions ADD COLUMN IF NOT EXISTS token_usage_output INTEGER DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_copilot_interactions_tenant ON copilot_interactions(tenant_id);

-- ─── Case Management ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cases (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title           VARCHAR(500) NOT NULL,
    description     TEXT DEFAULT '',
    severity        VARCHAR(20) NOT NULL DEFAULT 'MEDIUM'
                    CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status          VARCHAR(50) NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'assigned', 'investigating', 'pending_approval', 'mitigating', 'resolved', 'closed')),
    assigned_to     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    alert_id        INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
    incident_id     INTEGER,
    mitre_techniques JSONB DEFAULT '[]',
    mitre_tactics   JSONB DEFAULT '[]',
    root_cause      TEXT DEFAULT '',
    resolution      TEXT DEFAULT '',
    lessons_learned TEXT DEFAULT '',
    sla_deadline    TIMESTAMPTZ,
    sla_breached    BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cases_tenant ON cases(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
CREATE INDEX IF NOT EXISTS idx_cases_assigned ON cases(assigned_to);
CREATE INDEX IF NOT EXISTS idx_cases_sla ON cases(sla_deadline);

-- Case timeline events
CREATE TABLE IF NOT EXISTS case_timeline (
    id              SERIAL PRIMARY KEY,
    case_id         INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL
                    CHECK (event_type IN ('alert', 'investigation', 'ai_recommendation', 'approval', 'mitigation', 'closure', 'note', 'status_change')),
    description     TEXT NOT NULL,
    metadata        JSONB DEFAULT '{}',
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_case_timeline_case ON case_timeline(case_id);
CREATE INDEX IF NOT EXISTS idx_case_timeline_type ON case_timeline(event_type);

-- ─── Prompt Registry ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS prompt_registry (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    category        VARCHAR(100) NOT NULL DEFAULT 'general'
                    CHECK (category IN ('general', 'analyst', 'audit', 'documentation', 'incident', 'system')),
    prompt_template TEXT NOT NULL,
    system_hint     TEXT DEFAULT '',
    variables       JSONB DEFAULT '{}',
    is_active       BOOLEAN DEFAULT true,
    governance_reviewed BOOLEAN DEFAULT false,
    reviewed_by     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at     TIMESTAMPTZ,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_prompts_tenant ON prompt_registry(tenant_id);
CREATE INDEX IF NOT EXISTS idx_prompts_active ON prompt_registry(is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_prompts_category ON prompt_registry(category);

-- ─── AI Evaluation Metrics ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_evaluations (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    interaction_id  INTEGER REFERENCES copilot_interactions(id) ON DELETE SET NULL,
    citation_quality    REAL DEFAULT 0,
    hallucination_score REAL DEFAULT 0,
    consistency_score   REAL DEFAULT 0,
    accuracy_score      REAL DEFAULT 0,
    retrieval_score     REAL DEFAULT 0,
    overall_score       REAL DEFAULT 0,
    evaluator_notes     TEXT DEFAULT '',
    evaluated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_eval_tenant ON ai_evaluations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_eval_time ON ai_evaluations(evaluated_at);

-- ─── Observability Metrics ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS observability_metrics (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    metric_type     VARCHAR(100) NOT NULL
                    CHECK (metric_type IN ('gemini_latency', 'qdrant_latency', 'rag_success', 'api_performance', 'error_rate', 'token_usage')),
    metric_value    REAL NOT NULL,
    metadata        JSONB DEFAULT '{}',
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_obs_tenant ON observability_metrics(tenant_id);
CREATE INDEX IF NOT EXISTS idx_obs_type ON observability_metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_obs_time ON observability_metrics(recorded_at);

-- ─── Cost Tracking ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cost_tracking (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    date            DATE NOT NULL DEFAULT CURRENT_DATE,
    model           VARCHAR(100) NOT NULL DEFAULT 'gemini-2.5-flash',
    input_tokens    INTEGER DEFAULT 0,
    output_tokens   INTEGER DEFAULT 0,
    total_tokens    INTEGER DEFAULT 0,
    estimated_cost_usd REAL DEFAULT 0,
    request_count   INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, user_id, date, model)
);

CREATE INDEX IF NOT EXISTS idx_cost_tenant ON cost_tracking(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cost_date ON cost_tracking(date);

-- ─── Threat Intelligence Cache ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    source          VARCHAR(100) NOT NULL
                    CHECK (source IN ('mitre_attack', 'virustotal', 'abuseipdb', 'alienvault_otx', 'custom')),
    indicator_type  VARCHAR(50) NOT NULL
                    CHECK (indicator_type IN ('ip', 'domain', 'hash', 'technique', 'tactic', 'cve')),
    indicator_value VARCHAR(500) NOT NULL,
    confidence      REAL DEFAULT 0,
    severity        VARCHAR(20) DEFAULT 'MEDIUM',
    metadata        JSONB DEFAULT '{}',
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    cached_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_threat_tenant ON threat_intel_cache(tenant_id);
CREATE INDEX IF NOT EXISTS idx_threat_source ON threat_intel_cache(source);
CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_intel_cache(indicator_type, indicator_value);

-- ─── AI Memory (Investigation Context) ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_memory (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    session_id      INTEGER REFERENCES chat_sessions(id) ON DELETE SET NULL,
    case_id         INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    memory_type     VARCHAR(50) NOT NULL
                    CHECK (memory_type IN ('investigation', 'session_summary', 'analyst_note', 'lesson_learned', 'context')),
    title           VARCHAR(500) DEFAULT '',
    content         TEXT NOT NULL,
    metadata        JSONB DEFAULT '{}',
    is_pinned       BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_memory_tenant ON ai_memory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_memory_user ON ai_memory(user_id);
CREATE INDEX IF NOT EXISTS idx_memory_case ON ai_memory(case_id);
CREATE INDEX IF NOT EXISTS idx_memory_type ON ai_memory(memory_type);

-- ─── Seed default tenant ─────────────────────────────────────────────────────────

INSERT INTO tenants (id, name, slug, description)
VALUES (1, 'Default Organization', 'default', 'Primary tenant organization')
ON CONFLICT DO NOTHING;

-- Backfill tenant_id for existing users
UPDATE users SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE chat_sessions SET tenant_id = (SELECT tenant_id FROM users WHERE users.id = chat_sessions.user_id) WHERE tenant_id IS NULL;
UPDATE documents SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE alerts SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE audit_logs SET tenant_id = 1 WHERE tenant_id IS NULL;
UPDATE copilot_interactions SET tenant_id = 1 WHERE tenant_id IS NULL;
