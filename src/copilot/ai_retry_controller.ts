/**
 * Aegis Enterprise — AI Retry Controller
 *
 * Exponential backoff with jitter for LLM API calls.
 * Works in concert with the Circuit Breaker — retry failures
 * are reported to the circuit breaker after max retries are exhausted.
 *
 * Retry Policy:
 *  Attempt 1: Immediate
 *  Attempt 2: ~1 second delay
 *  Attempt 3: ~4 seconds delay (exponential with ±500ms jitter)
 *  After 3 failures: stop — let circuit breaker decide next action
 */

import { logStructured } from "../observability/logger.js";
import { aiCircuitBreaker } from "./ai_circuit_breaker.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface RetryResult<T> {
  success: boolean;
  result: T | null;
  attempts: number;
  total_latency_ms: number;
  last_error: string | null;
}

export interface RetryConfig {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  jitterMs: number;
  retryableErrors: string[];
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxAttempts: 3,
  baseDelayMs: 1_000,
  maxDelayMs: 8_000,
  jitterMs: 500,
  retryableErrors: [
    "timeout",
    "ECONNRESET",
    "ECONNREFUSED",
    "rate limit",
    "503",
    "502",
    "429",
    "service unavailable",
  ],
};

// ─── AI Retry Controller ──────────────────────────────────────────────────────

export class AIRetryController {
  constructor(private readonly config: RetryConfig = DEFAULT_RETRY_CONFIG) {}

  /**
   * Execute an async operation with exponential backoff and jitter.
   * Reports final failure to circuit breaker.
   */
  async execute<T>(
    operation: () => Promise<T>,
    operationName: string,
  ): Promise<RetryResult<T>> {
    const startMs = Date.now();
    let lastError = "";
    let attempts = 0;

    for (let attempt = 0; attempt < this.config.maxAttempts; attempt++) {
      attempts++;

      if (attempt > 0) {
        const delay = this.calculateDelay(attempt);
        logStructured("info", "[RetryController] Retrying after delay", {
          operation: operationName,
          attempt: attempt + 1,
          delay_ms: delay,
        });
        await this.sleep(delay);
      }

      try {
        const result = await operation();
        aiCircuitBreaker.recordSuccess();
        return {
          success: true,
          result,
          attempts,
          total_latency_ms: Date.now() - startMs,
          last_error: null,
        };
      } catch (err: unknown) {
        lastError = err instanceof Error ? err.message : String(err);

        logStructured("warn", "[RetryController] Attempt failed", {
          operation: operationName,
          attempt: attempt + 1,
          error: lastError,
          retryable: this.isRetryable(lastError),
        });

        // Non-retryable errors: fail immediately
        if (!this.isRetryable(lastError)) {
          break;
        }
      }
    }

    // All attempts exhausted
    aiCircuitBreaker.recordFailure(lastError);
    logStructured("error", "[RetryController] All attempts failed", {
      operation: operationName,
      attempts,
      last_error: lastError,
    });

    return {
      success: false,
      result: null,
      attempts,
      total_latency_ms: Date.now() - startMs,
      last_error: lastError,
    };
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private calculateDelay(attempt: number): number {
    const exponential = this.config.baseDelayMs * Math.pow(2, attempt - 1);
    const capped = Math.min(exponential, this.config.maxDelayMs);
    const jitter = (Math.random() * 2 - 1) * this.config.jitterMs;
    return Math.max(0, Math.round(capped + jitter));
  }

  private isRetryable(error: string): boolean {
    const lower = error.toLowerCase();
    return this.config.retryableErrors.some((retryable) =>
      lower.includes(retryable.toLowerCase()),
    );
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const aiRetryController = new AIRetryController();
