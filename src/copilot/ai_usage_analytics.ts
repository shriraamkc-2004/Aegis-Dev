/**
 * Aegis Enterprise — AI Usage Analytics
 *
 * Compiles metrics on tenant usage of the Security Copilot service:
 *  - Requests count by category / assistant persona
 *  - Top active analysts using the system
 *  - Daily usage volumes
 */

import { dbAll } from "../server_db.js";
import { logStructured } from "../observability/logger.js";

export interface CategoryUsage {
  category: string;
  count: number;
}

export interface UserUsage {
  user_id: number | null;
  user_role: string;
  count: number;
}

export interface UsageAnalyticsReport {
  tenant_id: number;
  total_requests: number;
  by_category: CategoryUsage[];
  by_user: UserUsage[];
}

export class AIUsageAnalytics {
  /**
   * Compile usage metrics for a given tenant over a window.
   */
  async getUsageReport(
    tenantId: number,
    sinceMs: number,
  ): Promise<UsageAnalyticsReport> {
    try {
      const categoryRows = (await dbAll(
        `SELECT
          outcome as category,
          COUNT(*) as count
         FROM ai_audit_logs
         WHERE tenant_id = ? AND request_timestamp >= ?
         GROUP BY outcome`,
        [tenantId, sinceMs],
      )) as { category: string; count: number }[];

      const userRows = (await dbAll(
        `SELECT
          user_id,
          user_role,
          COUNT(*) as count
         FROM ai_audit_logs
         WHERE tenant_id = ? AND request_timestamp >= ?
         GROUP BY user_id, user_role`,
        [tenantId, sinceMs],
      )) as { user_id: number | null; user_role: string; count: number }[];

      const totalRequests = categoryRows.reduce((sum, r) => sum + r.count, 0);

      logStructured("info", "[AIUsageAnalytics] Completed usage analysis", {
        tenantId,
        totalRequests,
      });

      return {
        tenant_id: tenantId,
        total_requests: totalRequests,
        by_category: categoryRows,
        by_user: userRows,
      };
    } catch (err) {
      logStructured(
        "error",
        "[AIUsageAnalytics] Failed to compile usage report",
        {
          tenantId,
          error: err instanceof Error ? err.message : String(err),
        },
      );
      return {
        tenant_id: tenantId,
        total_requests: 0,
        by_category: [],
        by_user: [],
      };
    }
  }
}

export const aiUsageAnalytics = new AIUsageAnalytics();
