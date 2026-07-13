/**
 * Aegis Enterprise — AI Circuit Breaker
 *
 * Implements a CLOSED / OPEN / HALF-OPEN circuit breaker pattern for the LLM layer.
 * Prevents cascade failures when Gemini API is unavailable or degraded.
 * On OPEN: all AI requests immediately return a deterministic safe fallback.
 */

import { logStructured } from "../observability/logger.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type CircuitState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerConfig {
  /** Consecutive failures before opening the circuit */
  failureThreshold: number;
  /** Error-rate window in milliseconds */
  windowMs: number;
  /** Seconds the circuit remains OPEN before probing */
  openDurationMs: number;
  /** Consecutive successes in HALF_OPEN to close the circuit */
  successThreshold: number;
}

export interface CircuitBreakerStatus {
  state: CircuitState;
  failures: number;
  successes: number;
  lastFailureAt: number | null;
  openedAt: number | null;
  totalRequests: number;
  totalFailures: number;
  totalSuccesses: number;
}

const DEFAULT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  windowMs: 60_000, // 60 seconds rolling window
  openDurationMs: 30_000, // 30 seconds before HALF-OPEN probe
  successThreshold: 3, // 3 consecutive successes to re-CLOSE
};

// ─── Circuit Breaker ──────────────────────────────────────────────────────────

export class AICircuitBreaker {
  private state: CircuitState = "CLOSED";
  private failures = 0;
  private successes = 0;
  private lastFailureAt: number | null = null;
  private openedAt: number | null = null;
  private totalRequests = 0;
  private totalFailures = 0;
  private totalSuccesses = 0;
  private readonly failureTimes: number[] = [];

  constructor(private readonly config: CircuitBreakerConfig = DEFAULT_CONFIG) {}

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Check whether a request should be allowed through.
   * Returns false if the circuit is OPEN and not ready to probe.
   */
  allowRequest(): boolean {
    this.totalRequests++;

    if (this.state === "CLOSED") return true;

    if (this.state === "OPEN") {
      const now = Date.now();
      if (
        this.openedAt !== null &&
        now - this.openedAt >= this.config.openDurationMs
      ) {
        logStructured(
          "info",
          "[CircuitBreaker] Transitioning to HALF_OPEN — sending probe request",
          {},
        );
        this.state = "HALF_OPEN";
        this.successes = 0;
        return true;
      }
      return false; // Still OPEN — reject immediately
    }

    // HALF_OPEN: allow exactly one probe at a time
    return true;
  }

  /**
   * Record a successful LLM call.
   */
  recordSuccess(): void {
    this.totalSuccesses++;

    if (this.state === "HALF_OPEN") {
      this.successes++;
      if (this.successes >= this.config.successThreshold) {
        logStructured(
          "info",
          "[CircuitBreaker] Circuit CLOSED — LLM recovery confirmed",
          {
            consecutiveSuccesses: this.successes,
          },
        );
        this.close();
      }
    } else if (this.state === "CLOSED") {
      this.failures = 0;
      this.purgeOldFailures();
    }
  }

  /**
   * Record a failed LLM call.
   */
  recordFailure(error?: string): void {
    const now = Date.now();
    this.totalFailures++;
    this.failures++;
    this.lastFailureAt = now;
    this.failureTimes.push(now);
    this.purgeOldFailures();

    if (this.state === "HALF_OPEN") {
      logStructured(
        "warn",
        "[CircuitBreaker] HALF_OPEN probe failed — re-opening circuit",
        {
          error,
        },
      );
      this.open();
      return;
    }

    const recentFailures = this.failureTimes.filter(
      (t) => now - t <= this.config.windowMs,
    ).length;
    if (
      this.state === "CLOSED" &&
      (this.failures >= this.config.failureThreshold ||
        recentFailures >= this.config.failureThreshold)
    ) {
      logStructured(
        "error",
        "[CircuitBreaker] Circuit OPENED — LLM failure threshold breached",
        {
          failures: this.failures,
          recentFailures,
          error,
        },
      );
      this.open();
    }
  }

  getStatus(): CircuitBreakerStatus {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailureAt: this.lastFailureAt,
      openedAt: this.openedAt,
      totalRequests: this.totalRequests,
      totalFailures: this.totalFailures,
      totalSuccesses: this.totalSuccesses,
    };
  }

  getState(): CircuitState {
    return this.state;
  }

  isOpen(): boolean {
    return this.state === "OPEN";
  }

  // ── Private ────────────────────────────────────────────────────────────────

  private open(): void {
    this.state = "OPEN";
    this.openedAt = Date.now();
    this.successes = 0;
  }

  private close(): void {
    this.state = "CLOSED";
    this.failures = 0;
    this.successes = 0;
    this.openedAt = null;
    this.failureTimes.length = 0;
  }

  private purgeOldFailures(): void {
    const cutoff = Date.now() - this.config.windowMs;
    let i = 0;
    while (i < this.failureTimes.length && this.failureTimes[i] < cutoff) i++;
    this.failureTimes.splice(0, i);
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const aiCircuitBreaker = new AICircuitBreaker();
