-- ============================================================
-- Aegis Phase 3A — PostgreSQL Migration
-- SaaS Foundation: extends existing schema with multi-tenant
-- organizations, enhanced users, refresh tokens, audit logs
-- ============================================================

-- ─── Organizations ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS organizations (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

-- ─── Extend existing users table (from 001) with Phase 3A fields ─────────────────

-- Add new columns if they don't exist
ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name VARCHAR(100) DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name VARCHAR(100) DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

-- Create new role type and migrate existing roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'saas_role') THEN
        CREATE TYPE saas_role AS ENUM ('SuperAdmin', 'OrganizationAdmin', 'SOCAnalyst', 'Auditor', 'Viewer');
    END IF;
END $$;

-- Add saas_role column (parallel to existing varchar role for backward compat)
ALTER TABLE users ADD COLUMN IF NOT EXISTS saas_role saas_role DEFAULT 'Viewer';

-- Migrate existing role values to saas_role
UPDATE users SET saas_role = CASE role
    WHEN 'admin' THEN 'OrganizationAdmin'::saas_role
    WHEN 'soc_analyst' THEN 'SOCAnalyst'::saas_role
    WHEN 'auditor' THEN 'Auditor'::saas_role
    WHEN 'viewer' THEN 'Viewer'::saas_role
    ELSE 'Viewer'::saas_role
END WHERE saas_role = 'Viewer'::saas_role;

CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_saas_role ON users(saas_role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- Backfill organization_id for existing users
UPDATE users SET organization_id = 1 WHERE organization_id IS NULL
    AND EXISTS (SELECT 1 FROM organizations WHERE id = 1);

-- ─── Refresh Tokens (hashed, with rotation) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- ─── Extend existing audit_logs table with Phase 3A fields ───────────────────────

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(organization_id);

-- ─── Password Reset Tokens ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pwd_reset_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_expires ON password_reset_tokens(expires_at);

-- ─── Email Verification Tokens ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_verify_user ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verify_expires ON email_verification_tokens(expires_at);

-- ─── Seed default organization ───────────────────────────────────────────────────

INSERT INTO organizations (name, slug) VALUES ('Default Organization', 'default')
ON CONFLICT (slug) DO NOTHING;

-- Backfill tenant_id for existing records
UPDATE users SET organization_id = 1 WHERE organization_id IS NULL
    AND EXISTS (SELECT 1 FROM organizations WHERE id = 1);
