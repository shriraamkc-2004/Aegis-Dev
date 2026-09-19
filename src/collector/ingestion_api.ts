/**
 * Aegis SaaS — Universal Log Ingestion API
 *
 * Secure endpoint for organizations to push security events into Aegis
 * from any source: firewalls, servers, cloud providers, or the Aegis forwarder agent.
 *
 * Authentication:
 *   Header: Authorization: Bearer aegis_<raw_key>
 *   The key is validated against the api_keys table (SHA-256 hash comparison).
 *
 * Endpoint: POST /api/ingest/events
 *
 * Supported formats (set Content-Type or ?format= query param):
 *   application/json          → JSON / NDJSON / AWS CloudTrail
 *   application/cef           → CEF (ArcSight / Cisco)
 *   text/plain                → Syslog / key-value / raw
 *
 * Response: { received: N, queued: N, errors: [] }
 */

import { Router } from "express";
import rateLimit from "express-rate-limit";
import { validateApiKey } from "./api_key_service.js";
import { normalizeLog, type LogFormat } from "./log_normalizer.js";
import { getPrismaClient, isPostgresConnected } from "../saas/prisma_client.js";

export const ingestionRouter = Router();

// ─── Rate Limiter (per IP — coarse protection) ─────────────────────────────────
const ingestionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 500, // 500 requests/min per IP — high for log shippers
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Ingestion rate limit exceeded. Back off and retry." },
});

import { checkAndIncrementEventQuota } from "../saas/tenant_quota.js";

// ─── POST /api/ingest/events ───────────────────────────────────────────────────

ingestionRouter.post("/events", ingestionLimiter, async (req, res) => {
  // ── 1. Authenticate via API Key ──────────────────────────────────────────
  const authHeader = req.headers.authorization || "";
  const rawKey = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : (req.headers["x-api-key"] as string) || "";

  if (!rawKey) {
    res.status(401).json({
      error: "Missing API key. Provide: Authorization: Bearer <aegis_key>",
    });
    return;
  }

  const keyResult = await validateApiKey(rawKey);
  if (!keyResult.valid || !keyResult.organizationId) {
    res.status(401).json({ error: keyResult.error || "Invalid API key." });
    return;
  }

  const orgId = keyResult.organizationId;

  // ── 2. Detect Format ─────────────────────────────────────────────────────
  const formatParam = (req.query.format as string) || "";
  let format: LogFormat = "auto";

  const contentType = (req.headers["content-type"] || "").toLowerCase();
  if (formatParam === "cef" || contentType.includes("cef")) format = "cef";
  else if (formatParam === "syslog") format = "syslog";
  else if (formatParam === "kv") format = "kv";
  else if (contentType.includes("json") || formatParam === "json")
    format = "json";
  else if (formatParam === "ndjson") format = "ndjson";

  // ── 3. Get Raw Body ──────────────────────────────────────────────────────
  let rawBody: string;
  if (typeof req.body === "string") {
    rawBody = req.body;
  } else if (Buffer.isBuffer(req.body)) {
    rawBody = req.body.toString("utf8");
  } else if (req.body && typeof req.body === "object") {
    rawBody = JSON.stringify(req.body);
  } else {
    res.status(400).json({ error: "Empty or unreadable request body." });
    return;
  }

  if (!rawBody.trim()) {
    res.status(400).json({ error: "Empty payload." });
    return;
  }

  // ── 4. Normalize Events ──────────────────────────────────────────────────
  let normalizedEvents;
  try {
    normalizedEvents = normalizeLog(rawBody, format);
  } catch (err: any) {
    res.status(400).json({ error: `Log parsing failed: ${err.message}` });
    return;
  }

  if (normalizedEvents.length === 0) {
    res.status(400).json({ error: "No parseable events found in payload." });
    return;
  }

  // ── 5. Quota Check (Redis-backed) ────────────────────────────────────────
  const quotaResult = await checkAndIncrementEventQuota(
    orgId,
    "pro",
    normalizedEvents.length,
  );
  if (!quotaResult.allowed) {
    res.status(429).json({
      error: `Daily event quota exceeded (${quotaResult.currentUsage}/${quotaResult.limit}). Upgrade your plan at https://aegis.yourdomain.com/billing`,
      received: normalizedEvents.length,
      queued: 0,
    });
    return;
  }

  // ── 6. Persist to PostgreSQL ─────────────────────────────────────────────
  const connected = await isPostgresConnected();
  const errors: string[] = [];
  let queued = 0;

  if (connected) {
    const prisma = getPrismaClient();

    // Batch insert for performance
    const batchSize = 250;
    for (let i = 0; i < normalizedEvents.length; i += batchSize) {
      const batch = normalizedEvents.slice(i, i + batchSize);
      try {
        await prisma.telemetryEvent.createMany({
          data: batch.map((e) => ({
            organization_id: orgId,
            event_type: e.event_type.slice(0, 100),
            source: e.source.slice(0, 255),
            timestamp: new Date(e.timestamp),
            raw_data: e.raw_data,
          })),
          skipDuplicates: false,
        });
        queued += batch.length;
      } catch (err: any) {
        errors.push(`Batch ${i / batchSize + 1} failed: ${err.message}`);
      }
    }
  } else {
    // Graceful degradation: accept but note the storage failure
    errors.push(
      "PostgreSQL unavailable — events were accepted but not persisted.",
    );
    queued = 0;
  }

  // ── 7. Respond ───────────────────────────────────────────────────────────
  res.status(errors.length > 0 && queued === 0 ? 503 : 200).json({
    received: normalizedEvents.length,
    queued,
    errors: errors.length > 0 ? errors : undefined,
    formats_detected: [...new Set(normalizedEvents.map((e) => e._parser))],
  });
});

// ─── GET /api/ingest/health ────────────────────────────────────────────────────
// Simple ping for forwarder agents to verify connectivity + key validity.

ingestionRouter.get("/health", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const rawKey = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : "";

  if (!rawKey) {
    res.json({ status: "ok", authenticated: false });
    return;
  }

  const keyResult = await validateApiKey(rawKey);
  res.json({
    status: "ok",
    authenticated: keyResult.valid,
    organization_id: keyResult.organizationId,
  });
});
