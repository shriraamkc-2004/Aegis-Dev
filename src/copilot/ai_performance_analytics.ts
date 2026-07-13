/**
 * Aegis Enterprise — AI Performance Analytics
 *
 * Compiles performance metrics and trend reports based on historical audit logs.
 * Analyzes latency percentiles, throughput, and token usage efficiency.
 */

import { dbAll, dbGet } from "../server_db.js";
import { logStructured } from "../observability/logger.js";

export interface PerformanceStats {
  p50_latency: number;
  p90_latency: number;
  p99_latency: number;
  total_tokens: number;
  requests_count: number;
}

export class AIPerformanceAnalytics {
  /**
   * Get latency percentiles and token analytics for a tenant.
   */
  async getPerformanceStats(
    tenantId: number,
    sinceMs: number,
  ): Promise<PerformanceStats> {
    try {
      const rows = (await dbAll(
        `SELECT latency_ms
         FROM ai_audit_logs
         WHERE tenant_id = ? AND request_timestamp >= ?
         ORDER BY latency_ms ASC`,
        [tenantId, sinceMs],
      )) as { latency_ms: number }[];

      const count = rows.length;
      if (count === 0) {
        return {
          p50_latency: 0,
          p90_latency: 0,
          p99_latency: 0,
          total_tokens: 0,
          requests_count: 0,
        };
      }

      const p50 = rows[Math.floor(count * 0.5)].latency_ms;
      const p90 = rows[Math.floor(count * 0.9)].latency_ms;
      const p99 = rows[Math.floor(count * 0.99)].latency_ms;

      const tokenStats = (await dbGet(
        `SELECT SUM(tokens_input + tokens_output) as total
         FROM ai_audit_logs
         WHERE tenant_id = ? AND request_timestamp >= ?`,
        [tenantId, sinceMs],
      )) as { total: number | null };

      logStructured(
        "info",
        "[AIPerformanceAnalytics] Performance stats computed",
        {
          tenantId,
          requests: count,
          p50: p50 + "ms",
          p90: p90 + "ms",
        },
      );

      return {
        p50_latency: p50,
        p90_latency: p90,
        p99_latency: p99,
        total_tokens: tokenStats?.total ?? 0,
        requests_count: count,
      };
    } catch (err) {
      logStructured(
        "error",
        "[AIPerformanceAnalytics] Analytics retrieval failed",
        {
          error: err instanceof Error ? err.message : String(err),
        },
      );
      return {
        p50_latency: 0,
        p90_latency: 0,
        p99_latency: 0,
        total_tokens: 0,
        requests_count: 0,
      };
    }
  }
}

export const aiPerformanceAnalytics = new AIPerformanceAnalytics();
