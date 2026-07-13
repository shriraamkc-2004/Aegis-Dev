/**
 * Aegis Enterprise — AI Reliability Engine
 *
 * Tracks, aggregates, and reports AI reliability KPIs:
 *  - Factual Truth Score averages
 *  - Hallucination Rates (percentage of responses with flagged hallucinations)
 *  - Safe Fallback trigger rates
 *  - Average API latencies and token usage trends
 */

import { dbAll, dbGet } from "../server_db.js";
import { logStructured } from "../observability/logger.js";

export interface ReliabilityMetrics {
  total_requests: number;
  mean_truth_score: number;
  hallucination_rate: number;
  fallback_rate: number;
  avg_latency_ms: number;
  total_tokens: number;
}

export class AIReliabilityEngine {
  /**
   * Calculate reliability metrics over a sliding time window for a tenant.
   */
  async calculateMetrics(
    tenantId: number,
    sinceMs: number,
  ): Promise<ReliabilityMetrics> {
    try {
      const stats = (await dbGet(
        `SELECT
          COUNT(*) as total,
          AVG(truth_score) as avg_truth,
          AVG(CASE WHEN outcome = 'HALLUCINATION_DETECTED' THEN 1 ELSE 0 END) as hallucination_rate,
          AVG(CASE WHEN safe_fallback_used = 1 THEN 1 ELSE 0 END) as fallback_rate,
          AVG(latency_ms) as avg_latency,
          SUM(tokens_input + tokens_output) as total_tokens
         FROM ai_audit_logs
         WHERE tenant_id = ? AND request_timestamp >= ?`,
        [tenantId, sinceMs],
      )) as {
        total: number;
        avg_truth: number | null;
        hallucination_rate: number | null;
        fallback_rate: number | null;
        avg_latency: number | null;
        total_tokens: number | null;
      };

      const metrics = {
        total_requests: stats?.total ?? 0,
        mean_truth_score: stats?.avg_truth ?? 1.0,
        hallucination_rate: stats?.hallucination_rate ?? 0.0,
        fallback_rate: stats?.fallback_rate ?? 0.0,
        avg_latency_ms: stats?.avg_latency ?? 0.0,
        total_tokens: stats?.total_tokens ?? 0,
      };

      logStructured(
        "info",
        "[AIReliabilityEngine] Reliability metrics computed",
        {
          tenantId,
          total_requests: metrics.total_requests,
          mean_truth_score: metrics.mean_truth_score.toFixed(2),
        },
      );

      return metrics;
    } catch (err) {
      logStructured(
        "error",
        "[AIReliabilityEngine] Failed to compute metrics",
        {
          tenantId,
          error: err instanceof Error ? err.message : String(err),
        },
      );
      return {
        total_requests: 0,
        mean_truth_score: 1.0,
        hallucination_rate: 0.0,
        fallback_rate: 0.0,
        avg_latency_ms: 0.0,
        total_tokens: 0,
      };
    }
  }
}

export const aiReliabilityEngine = new AIReliabilityEngine();
