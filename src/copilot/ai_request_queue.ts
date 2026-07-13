/**
 * Aegis Enterprise — AI Request Queue
 *
 * Implements a backpressure queue for incoming LLM requests.
 * Prevents API rate limit exhaustion and resource starvation during traffic bursts.
 */

import { logStructured } from "../observability/logger.js";

export interface QueuedRequest {
  id: string;
  tenant_id: number;
  priority: number; // Higher is processed first
  execute: () => Promise<any>;
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  queued_at: number;
}

export class AIRequestQueue {
  private queue: QueuedRequest[] = [];
  private activeConnections = 0;
  private readonly MAX_CONCURRENT_REQUESTS = 3;

  /**
   * Queue a request for execution.
   */
  enqueue<T>(
    tenantId: number,
    priority: number,
    execute: () => Promise<T>,
  ): Promise<T> {
    const id = Math.random().toString(36).substring(7);
    return new Promise<T>((resolve, reject) => {
      this.queue.push({
        id,
        tenant_id: tenantId,
        priority,
        execute,
        resolve,
        reject,
        queued_at: Date.now(),
      });

      // Sort queue by priority (descending) and age (ascending)
      this.queue.sort(
        (a, b) => b.priority - a.priority || a.queued_at - b.queued_at,
      );

      logStructured("info", "[AIRequestQueue] Request enqueued", {
        queue_size: this.queue.length,
        tenantId,
        priority,
      });

      this.processNext();
    });
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private async processNext(): Promise<void> {
    if (this.activeConnections >= this.MAX_CONCURRENT_REQUESTS) {
      return;
    }

    const req = this.queue.shift();
    if (!req) {
      return;
    }

    this.activeConnections++;
    logStructured("info", "[AIRequestQueue] Executing queued request", {
      id: req.id,
      tenantId: req.tenant_id,
      active_connections: this.activeConnections,
    });

    try {
      const result = await req.execute();
      req.resolve(result);
    } catch (err) {
      req.reject(err);
    } finally {
      this.activeConnections--;
      this.processNext();
    }
  }
}

export const aiRequestQueue = new AIRequestQueue();
