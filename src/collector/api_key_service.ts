/**
 * Aegis SaaS — API Key Service
 *
 * Manages tenant-scoped API Keys for machine-to-machine log ingestion.
 * Keys are designed for use by the Aegis Log Forwarder agent and any
 * external system pushing events to POST /api/ingest/events.
 *
 * Security design:
 *  - Keys are generated as 32-byte cryptographically random secrets
 *  - Only the hashed value (SHA-256) is stored in the database
 *  - The raw key is shown ONCE on creation and never again
 *  - Keys are scoped to a single organization
 *  - Keys can be named, rotated, and revoked by org_admin
 */

import crypto from "crypto";
import { getPrismaClient, isPostgresConnected } from "../saas/prisma_client.js";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface ApiKey {
  id: number;
  organization_id: number;
  name: string;
  key_prefix: string; // First 8 chars for display (e.g. "aegis_ab")
  key_hash: string;
  created_by: number;
  last_used_at: Date | null;
  expires_at: Date | null;
  is_active: boolean;
  created_at: Date;
}

export interface CreateApiKeyResult {
  success: boolean;
  key?: ApiKey;
  rawKey?: string; // Shown ONCE — never stored
  error?: string;
}

// ─── Key Generator ──────────────────────────────────────────────────────────────

const PREFIX = "aegis_";

function generateRawKey(): string {
  const secret = crypto.randomBytes(32).toString("hex");
  return `${PREFIX}${secret}`;
}

function hashKey(rawKey: string): string {
  return crypto.scryptSync(rawKey, "aegis_api_key_salt_v1", 64).toString("hex");
}

function extractPrefix(rawKey: string): string {
  return rawKey.substring(0, PREFIX.length + 8); // "aegis_" + 8 chars
}

// ─── Database Helpers ───────────────────────────────────────────────────────────

/**
 * Returns the Prisma delegate for the ApiKey model.
 * We use a raw table name since this is added via Prisma migration.
 */
function getApiKeyTable() {
  const prisma = getPrismaClient();
  return (prisma as any).apiKey;
}

// ─── Service Functions ──────────────────────────────────────────────────────────

/**
 * Create a new API key for an organization.
 * Returns the key object + the raw key (show once, then discard).
 */
export async function createApiKey(opts: {
  organizationId: number;
  name: string;
  createdBy: number;
  expiresInDays?: number;
}): Promise<CreateApiKeyResult> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const rawKey = generateRawKey();
  const keyHash = hashKey(rawKey);
  const keyPrefix = extractPrefix(rawKey);

  const expiresAt = opts.expiresInDays
    ? new Date(Date.now() + opts.expiresInDays * 24 * 60 * 60 * 1000)
    : null;

  try {
    const table = getApiKeyTable();
    const key = await table.create({
      data: {
        organization_id: opts.organizationId,
        name: opts.name,
        key_prefix: keyPrefix,
        key_hash: keyHash,
        created_by: opts.createdBy,
        expires_at: expiresAt,
        is_active: true,
      },
    });

    return { success: true, key, rawKey };
  } catch (err: any) {
    console.error("[ApiKeyService] Error creating API key:", err.message);
    return { success: false, error: "Failed to create API key." };
  }
}

/**
 * Validate an incoming API key from the Authorization header.
 * Returns the associated organization_id if valid, null otherwise.
 * Updates last_used_at on successful validation.
 */
export async function validateApiKey(rawKey: string): Promise<{
  valid: boolean;
  organizationId?: number;
  keyId?: number;
  error?: string;
}> {
  if (!rawKey || !rawKey.startsWith(PREFIX)) {
    return { valid: false, error: "Invalid API key format." };
  }

  const connected = await isPostgresConnected();
  if (!connected) return { valid: false, error: "Database unavailable." };

  const keyHash = hashKey(rawKey);

  try {
    const table = getApiKeyTable();
    const key = await table.findUnique({ where: { key_hash: keyHash } });

    if (!key) return { valid: false, error: "API key not found." };
    if (!key.is_active) return { valid: false, error: "API key is revoked." };
    if (key.expires_at && key.expires_at < new Date()) {
      return { valid: false, error: "API key has expired." };
    }

    // Non-blocking update of last_used_at
    table
      .update({ where: { id: key.id }, data: { last_used_at: new Date() } })
      .catch(() => {});

    return { valid: true, organizationId: key.organization_id, keyId: key.id };
  } catch (err: any) {
    console.error("[ApiKeyService] Validation error:", err.message);
    return { valid: false, error: "Validation failed." };
  }
}

/**
 * List all API keys for an organization (hashes and raw keys are never returned).
 */
export async function listApiKeys(organizationId: number): Promise<ApiKey[]> {
  const connected = await isPostgresConnected();
  if (!connected) return [];

  try {
    const table = getApiKeyTable();
    return table.findMany({
      where: { organization_id: organizationId },
      select: {
        id: true,
        organization_id: true,
        name: true,
        key_prefix: true,
        created_by: true,
        last_used_at: true,
        expires_at: true,
        is_active: true,
        created_at: true,
        // key_hash is intentionally excluded
      },
      orderBy: { created_at: "desc" },
    });
  } catch {
    return [];
  }
}

/**
 * Revoke an API key by ID (soft-delete via is_active flag).
 */
export async function revokeApiKey(
  keyId: number,
  organizationId: number,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  try {
    const table = getApiKeyTable();
    const key = await table.findFirst({
      where: { id: keyId, organization_id: organizationId },
    });

    if (!key) return { success: false, error: "API key not found." };

    await table.update({ where: { id: keyId }, data: { is_active: false } });
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/**
 * Rotate an API key: revoke the old one and create a new one with the same name.
 * Returns the new raw key (show once).
 */
export async function rotateApiKey(
  keyId: number,
  organizationId: number,
  rotatedBy: number,
): Promise<CreateApiKeyResult> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  try {
    const table = getApiKeyTable();
    const oldKey = await table.findFirst({
      where: { id: keyId, organization_id: organizationId, is_active: true },
    });

    if (!oldKey) return { success: false, error: "Active API key not found." };

    // Revoke the old key
    await table.update({ where: { id: keyId }, data: { is_active: false } });

    // Create a new key with the same name
    return createApiKey({
      organizationId,
      name: oldKey.name,
      createdBy: rotatedBy,
      expiresInDays: oldKey.expires_at
        ? Math.ceil((oldKey.expires_at.getTime() - Date.now()) / 86400000)
        : undefined,
    });
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}
