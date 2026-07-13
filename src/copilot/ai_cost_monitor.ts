/**
 * Aegis Enterprise — AI Cost Monitor
 *
 * Implements token cost calculation and budget limits per tenant.
 * Computes USD cost per model and blocks requests if tenant budget is exceeded.
 */

import { dbGet } from "../server_db.js";
import { logStructured } from "../observability/logger.js";
import { aiModelRegistry } from "./ai_model_registry.js";

export interface TenantCostSummary {
  tenant_id: number;
  total_cost_usd: number;
  tokens_consumed: number;
  budget_limit_usd: number;
  budget_exceeded: boolean;
}

export class AICostMonitor {
  private readonly DEFAULT_MONTHLY_BUDGET_USD = 50.0; // $50 default budget

  /**
   * Calculate cumulative costs for a tenant in the current month.
   */
  async getCostSummary(tenantId: number): Promise<TenantCostSummary> {
    const startOfMonthMs = new Date(
      new Date().getFullYear(),
      new Date().getMonth(),
      1,
    ).getTime();
    try {
      // Sum input and output tokens grouped by model
      const usage = (await dbGet(
        `SELECT
          SUM(tokens_input) as total_in,
          SUM(tokens_output) as total_out
         FROM ai_audit_logs
         WHERE tenant_id = ? AND request_timestamp >= ?`,
        [tenantId, startOfMonthMs],
      )) as { total_in: number | null; total_out: number | null };

      const totalIn = usage?.total_in ?? 0;
      const totalOut = usage?.total_out ?? 0;

      // Cost calculation based on default Gemini 2.5 Flash pricing
      const modelInfo = aiModelRegistry.getModel("gemini-2.5-flash");
      const costIn = modelInfo
        ? (totalIn / 1000) * modelInfo.cost_per_1k_input_usd
        : 0.0;
      const costOut = modelInfo
        ? (totalOut / 1000) * modelInfo.cost_per_1k_output_usd
        : 0.0;
      const totalCostUsd = costIn + costOut;

      const budgetExceeded = totalCostUsd >= this.DEFAULT_MONTHLY_BUDGET_USD;

      if (budgetExceeded) {
        logStructured("warn", "[AICostMonitor] Budget exceeded for tenant", {
          tenantId,
          totalCostUsd: totalCostUsd.toFixed(4),
          budgetLimitUsd: this.DEFAULT_MONTHLY_BUDGET_USD,
        });
      }

      return {
        tenant_id: tenantId,
        total_cost_usd: totalCostUsd,
        tokens_consumed: totalIn + totalOut,
        budget_limit_usd: this.DEFAULT_MONTHLY_BUDGET_USD,
        budget_exceeded: budgetExceeded,
      };
    } catch (err) {
      logStructured(
        "error",
        "[AICostMonitor] Failed to retrieve cost summary",
        {
          tenantId,
          error: err instanceof Error ? err.message : String(err),
        },
      );
      return {
        tenant_id: tenantId,
        total_cost_usd: 0,
        tokens_consumed: 0,
        budget_limit_usd: this.DEFAULT_MONTHLY_BUDGET_USD,
        budget_exceeded: false,
      };
    }
  }
}

export const aiCostMonitor = new AICostMonitor();
