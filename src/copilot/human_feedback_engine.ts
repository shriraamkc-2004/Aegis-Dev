/**
 * Aegis Enterprise — Human Feedback Engine
 *
 * Implements a feedback collection mechanism for analyst corrections on AI responses.
 * Stores feedback in the SQLite database to track system performance over time.
 * Calculates correction stats to identify recurring topics of inaccuracy.
 */

import { dbRun, dbAll, dbGet } from "../server_db.js";
import { logStructured } from "../observability/logger.js";

export type FeedbackRating =
  "CORRECT" | "PARTIAL" | "INCORRECT" | "MISLEADING" | "INCOMPLETE";

export interface AIResponseFeedback {
  id?: number;
  audit_id: string;
  tenant_id: number;
  rating: FeedbackRating;
  corrected_text: string | null;
  notes: string | null;
  analyst_user_id: number;
  timestamp: number;
}

export class HumanFeedbackEngine {
  /**
   * Save analyst feedback for a given AI response audit record.
   */
  async submitFeedback(
    feedback: Omit<AIResponseFeedback, "timestamp">,
  ): Promise<boolean> {
    const timestamp = Date.now();
    try {
      await dbRun(
        `INSERT INTO ai_response_feedback (
          audit_id, tenant_id, rating, corrected_text, notes, analyst_user_id, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          feedback.audit_id,
          feedback.tenant_id,
          feedback.rating,
          feedback.corrected_text,
          feedback.notes,
          feedback.analyst_user_id,
          timestamp,
        ],
      );

      logStructured(
        "info",
        "[HumanFeedbackEngine] Submitted analyst feedback",
        {
          audit_id: feedback.audit_id,
          rating: feedback.rating,
          tenant_id: feedback.tenant_id,
        },
      );
      return true;
    } catch (err) {
      logStructured(
        "error",
        "[HumanFeedbackEngine] Failed to submit feedback",
        {
          audit_id: feedback.audit_id,
          error: err instanceof Error ? err.message : String(err),
        },
      );
      return false;
    }
  }

  /**
   * Get feedback records by tenant.
   */
  async getFeedbackForTenant(
    tenantId: number,
    limit = 50,
  ): Promise<AIResponseFeedback[]> {
    try {
      const rows = await dbAll(
        "SELECT * FROM ai_response_feedback WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
        [tenantId, limit],
      );
      return rows as AIResponseFeedback[];
    } catch (err) {
      return [];
    }
  }
}

export const AI_FEEDBACK_DDL = `
CREATE TABLE IF NOT EXISTS ai_response_feedback (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id          TEXT NOT NULL,
  tenant_id         INTEGER NOT NULL,
  rating            TEXT NOT NULL,
  corrected_text    TEXT,
  notes             TEXT,
  analyst_user_id   INTEGER NOT NULL,
  timestamp         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_audit ON ai_response_feedback(audit_id);
CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON ai_response_feedback(tenant_id);
`;

export const humanFeedbackEngine = new HumanFeedbackEngine();
