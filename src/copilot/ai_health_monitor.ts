/**
 * Aegis Enterprise — AI Health Monitor
 *
 * Real-time monitoring of AI service status.
 * Tracks Gemini API availability, latency trends, error rates, and model drift.
 */

import { logStructured } from "../observability/logger.js";
import { aiCircuitBreaker } from "./ai_circuit_breaker.js";

export interface AIHealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  latency_status: "optimal" | "warning" | "critical";
  circuit_breaker_state: string;
  error_rate: number;
  uptime_score: number;
}

export class AIHealthMonitor {
  private totalRequests = 0;
  private failedRequests = 0;
  private responseTimes: number[] = [];

  recordRequest(latencyMs: number, success: boolean): void {
    this.totalRequests++;
    if (!success) {
      this.failedRequests++;
    }
    this.responseTimes.push(latencyMs);
    if (this.responseTimes.length > 100) {
      this.responseTimes.shift(); // rolling window of 100 requests
    }
  }

  getHealth(): AIHealthStatus {
    const errorRate =
      this.totalRequests > 0 ? this.failedRequests / this.totalRequests : 0.0;
    const avgLatency =
      this.responseTimes.length > 0
        ? this.responseTimes.reduce((a, b) => a + b, 0) /
          this.responseTimes.length
        : 0;

    let status: "healthy" | "degraded" | "unhealthy" = "healthy";
    if (aiCircuitBreaker.isOpen() || errorRate > 0.5) {
      status = "unhealthy";
    } else if (errorRate > 0.1 || avgLatency > 5000) {
      status = "degraded";
    }

    let latencyStatus: "optimal" | "warning" | "critical" = "optimal";
    if (avgLatency > 5000) {
      latencyStatus = "critical";
    } else if (avgLatency > 2000) {
      latencyStatus = "warning";
    }

    logStructured("info", "[AIHealthMonitor] Compiled AI Health metrics", {
      status,
      errorRate: errorRate.toFixed(2),
      avgLatency: avgLatency.toFixed(0) + "ms",
    });

    return {
      status,
      latency_status: latencyStatus,
      circuit_breaker_state: aiCircuitBreaker.getState(),
      error_rate: errorRate,
      uptime_score: 1.0 - errorRate,
    };
  }
}

export const aiHealthMonitor = new AIHealthMonitor();
