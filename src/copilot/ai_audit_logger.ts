/**
 * Aegis Enterprise — AI Audit Logger
 *
 * Immutable audit logger for all AI interactions.
 * Writes to the ai_audit_logs SQLite table — no DELETE, no UPDATE ever permitted.
 * Every interaction (delivered, blocked, or failed) produces an audit record.
 *
 * Schema is defined in server_db.ts — call initAIAuditTable() at startup.
 */

import { createHash } from "crypto";
import { dbRun, dbGet } from "../server_db.js";
import { logStructured } from "../observability/logger.js";
import type { GuardrailResult } from "./guardrail_engine.js";
import type { EvidenceValidationResult } from "./evidence_validator.js";
import type { ConfidenceGateResult } from "./confidence_gate.js";
import type { TruthEngineResult } from "./truth_engine.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type AIAuditOutcome =
  | "DELIVERED"
  | "DELIVERED_CACHED"
  | "BLOCKED_INJECTION"
  | "BLOCKED_POLICY"
  | "BLOCKED_EVIDENCE"
  | "BLOCKED_CONFIDENCE"
  | "HALLUCINATION_DETECTED"
  | "SAFE_FALLBACK"
  | "LLM_TIMEOUT"
  | "LLM_ERROR"
  | "EVIDENCE_INTEGRITY_FAILURE"
  | "CIRCUIT_OPEN";

export interface AIAuditRecord {
  // ── Identity ──────────────────────────────────────────────────
  audit_id: string; // UUID v4
  prompt_id: string; // Unique per prompt submission
  request_id: string;
  session_id: string | null;

  // ── Versioning ────────────────────────────────────────────────
  evidence_version: string; // SHA-256 hash of evidence bundle
  model_version: string;
  prompt_template_version: number;
  response_schema_version: string;

  // ── User & Tenant ─────────────────────────────────────────────
  user_id: number | null;
  tenant_id: number;
  user_role: string;
  ip_address: string;

  // ── Timestamps ────────────────────────────────────────────────
  request_timestamp: number;
  response_timestamp: number;
  latency_ms: number;

  // ── Content Hashes (PII protection — raw prompts not stored) ──
  prompt_hash: string; // SHA-256 of assembled prompt
  response_hash: string; // SHA-256 of raw LLM response
  evidence_bundle_hash: string; // SHA-256 of evidence bundle

  // ── Decision Trace ───────────────────────────────────────────
  guardrail_allowed: boolean;
  guardrail_violations: string[];
  evidence_valid: boolean;
  evidence_missing_fields: string[];
  confidence_level: string;
  confidence_score: number;
  rag_documents_retrieved: number;
  truth_score: number;
  hallucinations_detected: string[];

  // ── Outcome ──────────────────────────────────────────────────
  outcome: AIAuditOutcome;
  policy_violations: string[];
  safe_fallback_used: boolean;

  // ── Performance ──────────────────────────────────────────────
  tokens_input: number;
  tokens_output: number;
}

// ─── AI Audit Logger ─────────────────────────────────────────────────────────

export class AIAuditLogger {
  /**
   * Write an immutable audit record to the database.
   * If DB write fails, falls back to structured log (never throws).
   */
  async log(record: AIAuditRecord): Promise<void> {
    try {
      await dbRun(
        `INSERT INTO ai_audit_logs (
          audit_id, prompt_id, request_id, session_id,
          evidence_version, model_version, prompt_template_version, response_schema_version,
          user_id, tenant_id, user_role, ip_address,
          request_timestamp, response_timestamp, latency_ms,
          prompt_hash, response_hash, evidence_bundle_hash,
          guardrail_allowed, guardrail_violations,
          evidence_valid, evidence_missing_fields,
          confidence_level, confidence_score,
          rag_documents_retrieved, truth_score, hallucinations_detected,
          outcome, policy_violations, safe_fallback_used,
          tokens_input, tokens_output
        ) VALUES (
          ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )`,
        [
          record.audit_id,
          record.prompt_id,
          record.request_id,
          record.session_id,
          record.evidence_version,
          record.model_version,
          record.prompt_template_version,
          record.response_schema_version,
          record.user_id,
          record.tenant_id,
          record.user_role,
          record.ip_address,
          record.request_timestamp,
          record.response_timestamp,
          record.latency_ms,
          record.prompt_hash,
          record.response_hash,
          record.evidence_bundle_hash,
          record.guardrail_allowed ? 1 : 0,
          JSON.stringify(record.guardrail_violations),
          record.evidence_valid ? 1 : 0,
          JSON.stringify(record.evidence_missing_fields),
          record.confidence_level,
          record.confidence_score,
          record.rag_documents_retrieved,
          record.truth_score,
          JSON.stringify(record.hallucinations_detected),
          record.outcome,
          JSON.stringify(record.policy_violations),
          record.safe_fallback_used ? 1 : 0,
          record.tokens_input,
          record.tokens_output,
        ],
      );
    } catch (err) {
      // Never throw from audit logger — fall back to structured log
      logStructured(
        "error",
        "[AIAuditLogger] DB write failed — logging to stdout",
        {
          audit_id: record.audit_id,
          outcome: record.outcome,
          error: err instanceof Error ? err.message : String(err),
        },
      );
    }

    // Always emit structured log regardless of DB outcome
    logStructured(
      record.outcome.startsWith("BLOCKED") ||
        record.outcome === "HALLUCINATION_DETECTED"
        ? "warn"
        : "info",
      "[AIAuditLogger] AI interaction recorded",
      {
        audit_id: record.audit_id,
        tenant_id: record.tenant_id,
        outcome: record.outcome,
        truth_score: record.truth_score,
        latency_ms: record.latency_ms,
        tokens_in: record.tokens_input,
        tokens_out: record.tokens_output,
      },
    );
  }

  /**
   * Build a standard AIAuditRecord from pipeline components.
   * Convenience factory used by the AI Orchestrator.
   */
  static buildRecord(params: {
    requestId: string;
    sessionId: string | null;
    tenantId: number;
    userId: number | null;
    userRole: string;
    ipAddress: string;
    promptText: string;
    responseText: string;
    evidenceBundleJson: string;
    modelVersion: string;
    promptTemplateVersion: number;
    requestTimestamp: number;
    guardrailResult: GuardrailResult | null;
    evidenceValidationResult: EvidenceValidationResult | null;
    confidenceGateResult: ConfidenceGateResult | null;
    truthResult: TruthEngineResult | null;
    ragDocumentsRetrieved: number;
    tokensInput: number;
    tokensOutput: number;
    outcome: AIAuditOutcome;
    safeFallbackUsed: boolean;
    policyViolations: string[];
  }): AIAuditRecord {
    const { v4: uuidv4 } = require("crypto");
    const auditId = createHash("sha256")
      .update(params.requestId + Date.now())
      .digest("hex")
      .slice(0, 36);

    return {
      audit_id: auditId,
      prompt_id: createHash("sha256")
        .update(params.promptText)
        .digest("hex")
        .slice(0, 36),
      request_id: params.requestId,
      session_id: params.sessionId,
      evidence_version: createHash("sha256")
        .update(params.evidenceBundleJson)
        .digest("hex"),
      model_version: params.modelVersion,
      prompt_template_version: params.promptTemplateVersion,
      response_schema_version: "2.0.0",
      user_id: params.userId,
      tenant_id: params.tenantId,
      user_role: params.userRole,
      ip_address: params.ipAddress,
      request_timestamp: params.requestTimestamp,
      response_timestamp: Date.now(),
      latency_ms: Date.now() - params.requestTimestamp,
      prompt_hash: createHash("sha256").update(params.promptText).digest("hex"),
      response_hash: createHash("sha256")
        .update(params.responseText)
        .digest("hex"),
      evidence_bundle_hash: createHash("sha256")
        .update(params.evidenceBundleJson)
        .digest("hex"),
      guardrail_allowed: params.guardrailResult?.allowed ?? true,
      guardrail_violations: params.guardrailResult?.violations ?? [],
      evidence_valid: params.evidenceValidationResult?.valid ?? false,
      evidence_missing_fields:
        params.evidenceValidationResult?.missing_fields ?? [],
      confidence_level: params.confidenceGateResult?.level ?? "LOW",
      confidence_score: params.confidenceGateResult?.score ?? 0,
      rag_documents_retrieved: params.ragDocumentsRetrieved,
      truth_score: params.truthResult?.truth_score ?? 0,
      hallucinations_detected: params.truthResult?.hallucinations ?? [],
      outcome: params.outcome,
      policy_violations: params.policyViolations,
      safe_fallback_used: params.safeFallbackUsed,
      tokens_input: params.tokensInput,
      tokens_output: params.tokensOutput,
    };
  }
}

// ─── DDL (call from server_db.ts initializeSchema) ───────────────────────────

export const AI_AUDIT_LOGS_DDL = `
CREATE TABLE IF NOT EXISTS ai_audit_logs (
  id                        INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id                  TEXT NOT NULL UNIQUE,
  prompt_id                 TEXT NOT NULL,
  request_id                TEXT NOT NULL,
  session_id                TEXT,
  evidence_version          TEXT NOT NULL,
  model_version             TEXT NOT NULL,
  prompt_template_version   INTEGER NOT NULL DEFAULT 1,
  response_schema_version   TEXT NOT NULL DEFAULT '2.0.0',
  user_id                   INTEGER,
  tenant_id                 INTEGER NOT NULL,
  user_role                 TEXT NOT NULL DEFAULT 'unknown',
  ip_address                TEXT NOT NULL,
  request_timestamp         INTEGER NOT NULL,
  response_timestamp        INTEGER NOT NULL,
  latency_ms                INTEGER NOT NULL DEFAULT 0,
  prompt_hash               TEXT NOT NULL,
  response_hash             TEXT NOT NULL,
  evidence_bundle_hash      TEXT NOT NULL,
  guardrail_allowed         INTEGER NOT NULL DEFAULT 1,
  guardrail_violations      TEXT NOT NULL DEFAULT '[]',
  evidence_valid            INTEGER NOT NULL DEFAULT 1,
  evidence_missing_fields   TEXT NOT NULL DEFAULT '[]',
  confidence_level          TEXT NOT NULL DEFAULT 'LOW',
  confidence_score          REAL NOT NULL DEFAULT 0,
  rag_documents_retrieved   INTEGER NOT NULL DEFAULT 0,
  truth_score               REAL NOT NULL DEFAULT 0,
  hallucinations_detected   TEXT NOT NULL DEFAULT '[]',
  outcome                   TEXT NOT NULL,
  policy_violations         TEXT NOT NULL DEFAULT '[]',
  safe_fallback_used        INTEGER NOT NULL DEFAULT 0,
  tokens_input              INTEGER NOT NULL DEFAULT 0,
  tokens_output             INTEGER NOT NULL DEFAULT 0,
  created_at                INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_ai_audit_tenant ON ai_audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_audit_outcome ON ai_audit_logs(outcome);
CREATE INDEX IF NOT EXISTS idx_ai_audit_timestamp ON ai_audit_logs(request_timestamp);
CREATE INDEX IF NOT EXISTS idx_ai_audit_truth_score ON ai_audit_logs(truth_score);
`;

// ─── Singleton ────────────────────────────────────────────────────────────────

export const aiAuditLogger = new AIAuditLogger();
