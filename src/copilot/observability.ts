/**
 * Aegis Enterprise — Observability & Cost Monitoring Service
 * Tracks Gemini latency, Qdrant retrieval times, RAG success rates,
 * API performance, error rates, token usage, and cost estimates.
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface MetricRecord {
  type: MetricType;
  value: number;
  tenant_id?: number;
  metadata?: Record<string, unknown>;
  timestamp: number;
}

export type MetricType =
  | "gemini_latency"
  | "qdrant_latency"
  | "rag_success"
  | "api_performance"
  | "error_rate"
  | "token_usage";

export interface CostRecord {
  tenant_id: number;
  user_id?: number;
  date: string; // YYYY-MM-DD
  model: string;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  estimated_cost_usd: number;
  request_count: number;
}

export interface ObservabilityDashboard {
  gemini: {
    avg_latency_ms: number;
    p95_latency_ms: number;
    total_requests: number;
    error_rate: number;
  };
  qdrant: {
    avg_latency_ms: number;
    p95_latency_ms: number;
    total_searches: number;
  };
  rag: {
    success_rate: number;
    avg_sources_retrieved: number;
    avg_confidence: number;
  };
  api: {
    total_requests: number;
    avg_latency_ms: number;
    error_rate: number;
  };
  cost: {
    today_input_tokens: number;
    today_output_tokens: number;
    today_estimated_usd: number;
    month_input_tokens: number;
    month_output_tokens: number;
    month_estimated_usd: number;
  };
}

// ─── Cost Rates (Gemini 2.5 Flash pricing as of 2025) ───────────────────────────

const INPUT_COST_PER_1K = parseFloat(process.env.GEMINI_INPUT_COST_PER_1K || "0.000125");
const OUTPUT_COST_PER_1K = parseFloat(process.env.GEMINI_OUTPUT_COST_PER_1K || "0.000375");

// ─── Observability Service ──────────────────────────────────────────────────────

export class ObservabilityService {
  private metrics: MetricRecord[] = [];
  private costRecords: CostRecord[] = [];
  private readonly MAX_METRICS = 10000;

  // ─── Record Metrics ───────────────────────────────────────────────────────

  recordGeminiLatency(latencyMs: number, tenantId?: number, success: boolean = true): void {
    this.addMetric({
      type: "gemini_latency",
      value: latencyMs,
      tenant_id: tenantId,
      metadata: { success },
      timestamp: Date.now(),
    });

    if (!success) {
      this.addMetric({
        type: "error_rate",
        value: 1,
        tenant_id: tenantId,
        metadata: { source: "gemini" },
        timestamp: Date.now(),
      });
    }
  }

  recordQdrantLatency(latencyMs: number, tenantId?: number, sourcesFound: number = 0): void {
    this.addMetric({
      type: "qdrant_latency",
      value: latencyMs,
      tenant_id: tenantId,
      metadata: { sources_found: sourcesFound },
      timestamp: Date.now(),
    });

    this.addMetric({
      type: "rag_success",
      value: sourcesFound > 0 ? 1 : 0,
      tenant_id: tenantId,
      metadata: { sources_found: sourcesFound },
      timestamp: Date.now(),
    });
  }

  recordApiLatency(latencyMs: number, endpoint: string, success: boolean = true): void {
    this.addMetric({
      type: "api_performance",
      value: latencyMs,
      metadata: { endpoint, success },
      timestamp: Date.now(),
    });
  }

  recordTokenUsage(
    inputTokens: number,
    outputTokens: number,
    model: string = "gemini-2.5-flash",
    tenantId: number = 1,
    userId?: number
  ): void {
    const totalTokens = inputTokens + outputTokens;
    const estimatedCost =
      (inputTokens / 1000) * INPUT_COST_PER_1K +
      (outputTokens / 1000) * OUTPUT_COST_PER_1K;

    this.addMetric({
      type: "token_usage",
      value: totalTokens,
      tenant_id: tenantId,
      metadata: { input_tokens: inputTokens, output_tokens: outputTokens, model },
      timestamp: Date.now(),
    });

    // Aggregate cost record
    const today = new Date().toISOString().slice(0, 10);
    const existing = this.costRecords.find(
      (r) => r.tenant_id === tenantId && r.date === today && r.model === model
    );

    if (existing) {
      existing.input_tokens += inputTokens;
      existing.output_tokens += outputTokens;
      existing.total_tokens += totalTokens;
      existing.estimated_cost_usd += estimatedCost;
      existing.request_count += 1;
    } else {
      this.costRecords.push({
        tenant_id: tenantId,
        user_id: userId,
        date: today,
        model,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        total_tokens: totalTokens,
        estimated_cost_usd: estimatedCost,
        request_count: 1,
      });
    }
  }

  // ─── Dashboard ────────────────────────────────────────────────────────────

  getDashboard(tenantId?: number): ObservabilityDashboard {
    const now = Date.now();
    const oneDayAgo = now - 24 * 60 * 60 * 1000;
    const oneMonthAgo = now - 30 * 24 * 60 * 60 * 1000;
    const today = new Date().toISOString().slice(0, 10);

    const filtered = tenantId
      ? this.metrics.filter((m) => m.tenant_id === tenantId || m.tenant_id === undefined)
      : this.metrics;

    // Gemini metrics
    const geminiMetrics = filtered.filter(
      (m) => m.type === "gemini_latency" && m.timestamp > oneDayAgo
    );
    const geminiLatencies = geminiMetrics.map((m) => m.value);
    const geminiErrors = geminiMetrics.filter(
      (m) => m.metadata?.success === false
    ).length;

    // Qdrant metrics
    const qdrantMetrics = filtered.filter(
      (m) => m.type === "qdrant_latency" && m.timestamp > oneDayAgo
    );
    const qdrantLatencies = qdrantMetrics.map((m) => m.value);

    // RAG metrics
    const ragMetrics = filtered.filter(
      (m) => m.type === "rag_success" && m.timestamp > oneDayAgo
    );
    const ragSuccesses = ragMetrics.filter((m) => m.value === 1).length;
    const ragSources = ragMetrics.map(
      (m) => (m.metadata?.sources_found as number) || 0
    );

    // API metrics
    const apiMetrics = filtered.filter(
      (m) => m.type === "api_performance" && m.timestamp > oneDayAgo
    );
    const apiLatencies = apiMetrics.map((m) => m.value);
    const apiErrors = apiMetrics.filter(
      (m) => m.metadata?.success === false
    ).length;

    // Cost metrics
    const todayRecords = this.costRecords.filter((r) => r.date === today);
    const monthRecords = this.costRecords.filter(
      (r) => r.date >= new Date(oneMonthAgo).toISOString().slice(0, 10)
    );

    return {
      gemini: {
        avg_latency_ms: this.avg(geminiLatencies),
        p95_latency_ms: this.percentile(geminiLatencies, 95),
        total_requests: geminiMetrics.length,
        error_rate: geminiMetrics.length > 0 ? geminiErrors / geminiMetrics.length : 0,
      },
      qdrant: {
        avg_latency_ms: this.avg(qdrantLatencies),
        p95_latency_ms: this.percentile(qdrantLatencies, 95),
        total_searches: qdrantMetrics.length,
      },
      rag: {
        success_rate: ragMetrics.length > 0 ? ragSuccesses / ragMetrics.length : 0,
        avg_sources_retrieved: this.avg(ragSources),
        avg_confidence: 0, // Populated from audit log
      },
      api: {
        total_requests: apiMetrics.length,
        avg_latency_ms: this.avg(apiLatencies),
        error_rate: apiMetrics.length > 0 ? apiErrors / apiMetrics.length : 0,
      },
      cost: {
        today_input_tokens: todayRecords.reduce((s, r) => s + r.input_tokens, 0),
        today_output_tokens: todayRecords.reduce((s, r) => s + r.output_tokens, 0),
        today_estimated_usd: todayRecords.reduce((s, r) => s + r.estimated_cost_usd, 0),
        month_input_tokens: monthRecords.reduce((s, r) => s + r.input_tokens, 0),
        month_output_tokens: monthRecords.reduce((s, r) => s + r.output_tokens, 0),
        month_estimated_usd: monthRecords.reduce((s, r) => s + r.estimated_cost_usd, 0),
      },
    };
  }

  // ─── Cost Reports ─────────────────────────────────────────────────────────

  getCostReport(
    startDate: string,
    endDate: string,
    tenantId?: number
  ): CostRecord[] {
    return this.costRecords.filter(
      (r) =>
        r.date >= startDate &&
        r.date <= endDate &&
        (!tenantId || r.tenant_id === tenantId)
    );
  }

  getCostSummary(tenantId?: number): {
    total_input_tokens: number;
    total_output_tokens: number;
    total_cost_usd: number;
    total_requests: number;
    by_model: Record<string, { input: number; output: number; cost: number }>;
  } {
    const filtered = tenantId
      ? this.costRecords.filter((r) => r.tenant_id === tenantId)
      : this.costRecords;

    const byModel: Record<string, { input: number; output: number; cost: number }> = {};

    for (const r of filtered) {
      if (!byModel[r.model]) byModel[r.model] = { input: 0, output: 0, cost: 0 };
      byModel[r.model].input += r.input_tokens;
      byModel[r.model].output += r.output_tokens;
      byModel[r.model].cost += r.estimated_cost_usd;
    }

    return {
      total_input_tokens: filtered.reduce((s, r) => s + r.input_tokens, 0),
      total_output_tokens: filtered.reduce((s, r) => s + r.output_tokens, 0),
      total_cost_usd: filtered.reduce((s, r) => s + r.estimated_cost_usd, 0),
      total_requests: filtered.reduce((s, r) => s + r.request_count, 0),
      by_model: byModel,
    };
  }

  // ─── Metric Query ─────────────────────────────────────────────────────────

  queryMetrics(
    type: MetricType,
    since: number,
    tenantId?: number,
    limit: number = 100
  ): MetricRecord[] {
    return this.metrics
      .filter(
        (m) =>
          m.type === type &&
          m.timestamp >= since &&
          (!tenantId || m.tenant_id === tenantId || m.tenant_id === undefined)
      )
      .slice(-limit);
  }

  // ─── Internal Helpers ─────────────────────────────────────────────────────

  private addMetric(metric: MetricRecord): void {
    this.metrics.push(metric);
    if (this.metrics.length > this.MAX_METRICS) {
      this.metrics = this.metrics.slice(-this.MAX_METRICS / 2);
    }
  }

  private avg(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  private percentile(values: number[], p: number): number {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
  }

  // ─── Health ───────────────────────────────────────────────────────────────

  getStatus() {
    return {
      service: "observability",
      metrics_count: this.metrics.length,
      cost_records: this.costRecords.length,
      max_metrics: this.MAX_METRICS,
    };
  }
}

// Singleton instance
export const observabilityService = new ObservabilityService();
