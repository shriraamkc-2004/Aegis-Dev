/**
 * Aegis Enterprise — AI Cache Layer
 *
 * Implements a Redis-based response cache for AI responses.
 * Reduces Gemini API costs and response latency by caching responses
 * for identical prompts and evidence hashes.
 */

import { getCached, setCached, invalidateCache } from "../redis/cache.js";
import { logStructured } from "../observability/logger.js";
import { createHash } from "crypto";

export interface CachedAIResponse {
  response: string;
  truth_score: number;
  truth_badge: "HIGH" | "MEDIUM" | "LOW" | "REJECTED";
  confidence_level: "HIGH" | "MEDIUM" | "LOW";
  model_used: string;
  evidence_hash: string;
  response_hash: string;
  rag_citations: string[];
  limitations: string[];
  cached_at: number;
}

export class AICache {
  private readonly DEFAULT_TTL_SECONDS = 300; // 5 minutes cache TTL

  /**
   * Check if a prompt and evidence bundle hash is cached.
   */
  async get(
    prompt: string,
    evidenceHash: string,
    tenantId: number,
  ): Promise<CachedAIResponse | null> {
    const key = this.buildKey(prompt, evidenceHash, tenantId);
    try {
      const cached = await getCached<CachedAIResponse>(key);
      if (cached) {
        logStructured("info", "[AICache] Cache HIT", {
          tenantId,
          evidenceHash: evidenceHash.slice(0, 12) + "…",
        });
        return cached;
      }
    } catch (err) {
      logStructured("warn", "[AICache] Cache read failed", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
    return null;
  }

  /**
   * Cache an AI response.
   */
  async set(
    prompt: string,
    evidenceHash: string,
    tenantId: number,
    response: CachedAIResponse,
    ttlSeconds: number = this.DEFAULT_TTL_SECONDS,
  ): Promise<void> {
    const key = this.buildKey(prompt, evidenceHash, tenantId);
    try {
      await setCached(key, response, ttlSeconds);
      logStructured("info", "[AICache] Cache SET completed", {
        tenantId,
        evidenceHash: evidenceHash.slice(0, 12) + "…",
        ttlSeconds,
      });
    } catch (err) {
      logStructured("warn", "[AICache] Cache write failed", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * Invalidate a cached AI response.
   */
  async invalidate(
    prompt: string,
    evidenceHash: string,
    tenantId: number,
  ): Promise<void> {
    const key = this.buildKey(prompt, evidenceHash, tenantId);
    try {
      await invalidateCache(key);
      logStructured("info", "[AICache] Cache invalidated", {
        tenantId,
      });
    } catch (err) {
      logStructured("warn", "[AICache] Cache invalidation failed", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private buildKey(
    prompt: string,
    evidenceHash: string,
    tenantId: number,
  ): string {
    const promptHash = createHash("sha256").update(prompt.trim()).digest("hex");
    return `ai_cache:${tenantId}:${promptHash}:${evidenceHash}`;
  }
}

export const aiCache = new AICache();
