/**
 * Aegis Enterprise — AI Decision Ledger
 *
 * Append-only ledger of every AI decision and its outcome.
 * Complements the audit logger with structured, queryable decision tracking.
 *
 * Differences from Audit Logger:
 *  - Audit Logger: Full operational record (hashes, tokens, timing, all pipeline stages)
 *  - Decision Ledger: Structured decision record linking anomaly → AI decision → analyst feedback
 *
 * The ledger is the authoritative record for governance reporting and compliance audits.
 */

import { createHash } from "crypto";
import { dbRun, dbAll, dbGet } from "../server_db.js";
import { logStructured } from "../observability/logger.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type DecisionType =
  "EXPLANATION" | "SUMMARIZATION" | "SEARCH" | "REPORT";
export type DecisionOutcome = "DELIVERED" | "BLOCKED" | "SAFE_FALLBACK";
export type AnalystFeedback =
  "CORRECT" | "PARTIAL" | "INCORRECT" | "MISLEADING" | "INCOMPLETE";

export interface AIDecisionEntry {
  ledger_id: string; // UUID — never modified after write
  audit_id: string; // Link to ai_audit_logs record
  tenant_id: number;
  anomaly_id: number | null;
  decision_type: DecisionType;
  decision_timestamp: number;
  evidence_hash: string; // Hash of evidence bundle
  truth_score: number; // 0.0 – 1.0
  confidence_level: "HIGH" | "MEDIUM" | "LOW";
  outcome: DecisionOutcome;
  model_version: string;
  // ── Analyst Feedback (updated post-delivery, never changes ledger_id) ────
  analyst_feedback: AnalystFeedback | null;
  feedback_timestamp: number | null;
  feedback_notes: string | null;
}

// ─── AI Decision Ledger ───────────────────────────────────────────────────────

export class AIDecisionLedger {
  /**
   * Append a new decision to the ledger.
   * Once written, the ledger_id and core fields are immutable.
   */
  async append(
    entry: Omit<
      AIDecisionEntry,
      "analyst_feedback" | "feedback_timestamp" | "feedback_notes"
    >,
  ): Promise<string> {
    const ledgerId = createHash("sha256")
      .update(entry.audit_id + entry.decision_timestamp + entry.tenant_id)
      .digest("hex")
      .slice(0, 36);

    try {
      await dbRun(
        `INSERT INTO ai_decision_ledger (
          ledger_id, audit_id, tenant_id, anomaly_id,
          decision_type, decision_timestamp, evidence_hash,
          truth_score, confidence_level, outcome, model_version,
          analyst_feedback, feedback_timestamp, feedback_notes
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL)`,
        [
          ledgerId,
          entry.audit_id,
          entry.tenant_id,
          entry.anomaly_id,
          entry.decision_type,
          entry.decision_timestamp,
          entry.evidence_hash,
          entry.truth_score,
          entry.confidence_level,
          entry.outcome,
          entry.model_version,
        ],
      );
      logStructured("info", "[DecisionLedger] Decision appended", {
        ledger_id: ledgerId,
        outcome: entry.outcome,
        truth_score: entry.truth_score,
      });
    } catch (err) {
      logStructured("error", "[DecisionLedger] DB write failed", {
        audit_id: entry.audit_id,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return ledgerId;
  }

  /**
   * Record analyst feedback on a delivered AI response.
   * Updates feedback fields only — core decision fields are not changed.
   */
  async recordFeedback(
    ledgerId: string,
    feedback: AnalystFeedback,
    notes: string | null,
    tenantId: number,
  ): Promise<boolean> {
    try {
      await dbRun(
        `UPDATE ai_decision_ledger
         SET analyst_feedback = ?, feedback_timestamp = ?, feedback_notes = ?
         WHERE ledger_id = ? AND tenant_id = ? AND analyst_feedback IS NULL`,
        [feedback, Date.now(), notes, ledgerId, tenantId],
      );
      logStructured("info", "[DecisionLedger] Analyst feedback recorded", {
        ledger_id: ledgerId,
        feedback,
        tenant_id: tenantId,
      });
      return true;
    } catch (err) {
      logStructured("error", "[DecisionLedger] Feedback write failed", {
        ledger_id: ledgerId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /**
   * Query decision ledger for reliability analytics.
   */
  async getFeedbackSummary(
    tenantId: number,
    sinceMs: number,
  ): Promise<{
    total: number;
    correct: number;
    partial: number;
    incorrect: number;
    misleading: number;
    incomplete: number;
    feedbackRate: number;
  }> {
    try {
      const rows = (await dbAll(
        `SELECT analyst_feedback, COUNT(*) as count
         FROM ai_decision_ledger
         WHERE tenant_id = ? AND decision_timestamp >= ?
         GROUP BY analyst_feedback`,
        [tenantId, sinceMs],
      )) as { analyst_feedback: string | null; count: number }[];

      const total = rows.reduce((s, r) => s + r.count, 0);
      const get = (fb: string) =>
        rows.find((r) => r.analyst_feedback === fb)?.count ?? 0;
      const feedbackCount = rows
        .filter((r) => r.analyst_feedback !== null)
        .reduce((s, r) => s + r.count, 0);

      return {
        total,
        correct: get("CORRECT"),
        partial: get("PARTIAL"),
        incorrect: get("INCORRECT"),
        misleading: get("MISLEADING"),
        incomplete: get("INCOMPLETE"),
        feedbackRate: total > 0 ? feedbackCount / total : 0,
      };
    } catch {
      return {
        total: 0,
        correct: 0,
        partial: 0,
        incorrect: 0,
        misleading: 0,
        incomplete: 0,
        feedbackRate: 0,
      };
    }
  }
}

// ─── DDL ─────────────────────────────────────────────────────────────────────

export const AI_DECISION_LEDGER_DDL = `
CREATE TABLE IF NOT EXISTS ai_decision_ledger (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  ledger_id           TEXT NOT NULL UNIQUE,
  audit_id            TEXT NOT NULL,
  tenant_id           INTEGER NOT NULL,
  anomaly_id          INTEGER,
  decision_type       TEXT NOT NULL,
  decision_timestamp  INTEGER NOT NULL,
  evidence_hash       TEXT NOT NULL,
  truth_score         REAL NOT NULL DEFAULT 0,
  confidence_level    TEXT NOT NULL DEFAULT 'LOW',
  outcome             TEXT NOT NULL,
  model_version       TEXT NOT NULL,
  analyst_feedback    TEXT,
  feedback_timestamp  INTEGER,
  feedback_notes      TEXT,
  created_at          INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant ON ai_decision_ledger(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ledger_outcome ON ai_decision_ledger(outcome);
CREATE INDEX IF NOT EXISTS idx_ledger_feedback ON ai_decision_ledger(analyst_feedback);
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ai_decision_ledger(decision_timestamp);
`;

// ─── Singleton ────────────────────────────────────────────────────────────────

export const aiDecisionLedger = new AIDecisionLedger();
