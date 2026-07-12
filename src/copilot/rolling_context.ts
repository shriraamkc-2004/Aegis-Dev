/**
 * Aegis Enterprise — Real-Time Context Engine
 *
 * Tracks lightweight rolling state in memory for streaming events:
 *   - Recent request frequency per IP/Source
 *   - Authentication failure metrics per User
 *   - Rolling global burst ratios and unique source entropy
 */

interface TelemetryEventPayload {
  event_type: string;
  source: string;
  timestamp: number; // Unix epoch seconds
  username?: string;
}

export class RealTimeContextEngine {
  private events: TelemetryEventPayload[] = [];
  private maxRetentionSec = 300; // Keep last 5 minutes of event metadata in memory

  // In-memory counters for faster lookups
  private authFailures: Map<string, number[]> = new Map(); // Username -> Timestamps
  private sourceActivity: Map<string, number[]> = new Map(); // Source IP -> Timestamps

  /** Record an incoming event in the rolling memory buffer */
  addEvent(event: TelemetryEventPayload): void {
    const tNow = event.timestamp;
    this.events.push(event);

    // Track user-specific authentication failures
    if (event.event_type === "failed_login" && event.username) {
      const user = event.username.trim().toLowerCase();
      if (!this.authFailures.has(user)) {
        this.authFailures.set(user, []);
      }
      this.authFailures.get(user)!.push(tNow);
    }

    // Track source activity (requests/events per IP)
    const src = event.source || "unknown";
    if (!this.sourceActivity.has(src)) {
      this.sourceActivity.set(src, []);
    }
    this.sourceActivity.get(src)!.push(tNow);

    // Evict older events to maintain tight memory consumption
    this.evictOldState(tNow - this.maxRetentionSec);
  }

  /** Prune memory buffers older than the cutoff timestamp */
  private evictOldState(cutoff: number): void {
    // Prune global list
    let head = 0;
    while (head < this.events.length && this.events[head].timestamp < cutoff) {
      head++;
    }
    if (head > 0) {
      this.events = this.events.slice(head);
    }

    // Prune auth failure maps
    for (const [user, times] of this.authFailures.entries()) {
      const active = times.filter((t) => t >= cutoff);
      if (active.length === 0) {
        this.authFailures.delete(user);
      } else {
        this.authFailures.set(user, active);
      }
    }

    // Prune source activity maps
    for (const [src, times] of this.sourceActivity.entries()) {
      const active = times.filter((t) => t >= cutoff);
      if (active.length === 0) {
        this.sourceActivity.delete(src);
      } else {
        this.sourceActivity.set(src, active);
      }
    }
  }

  /** Calculate current event rate per second (rolling average) */
  getGlobalRate(windowSec: number): number {
    const cutoff = Date.now() / 1000 - windowSec;
    const count = this.events.filter((e) => e.timestamp >= cutoff).length;
    return count / windowSec;
  }

  /** Get requests/events per second from a specific source IP */
  getSourceRate(source: string, windowSec: number): number {
    const times = this.sourceActivity.get(source);
    if (!times) return 0;
    const cutoff = Date.now() / 1000 - windowSec;
    return times.filter((t) => t >= cutoff).length / windowSec;
  }

  /** Get authentication failures for a user within a rolling window */
  getUserAuthFailures(username: string, windowSec: number): number {
    const times = this.authFailures.get(username.trim().toLowerCase());
    if (!times) return 0;
    const cutoff = Date.now() / 1000 - windowSec;
    return times.filter((t) => t >= cutoff).length;
  }

  /** Get count of unique source IPs seen in the rolling window */
  getUniqueSourcesCount(windowSec: number): number {
    const cutoff = Date.now() / 1000 - windowSec;
    const unique = new Set<string>();
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      unique.add(this.events[i].source);
    }
    return unique.size;
  }

  /** Compute Shannon entropy of source IP distribution over window */
  getSourceEntropy(windowSec: number): number {
    const cutoff = Date.now() / 1000 - windowSec;
    const counts: Record<string, number> = {};
    let total = 0;

    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      const src = this.events[i].source;
      counts[src] = (counts[src] || 0) + 1;
      total++;
    }

    if (total === 0) return 0;
    let entropy = 0;
    for (const count of Object.values(counts)) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /** Calculate burst ratio (max per-second rate / average rate) in rolling window */
  getBurstRatio(windowSec: number): number {
    const cutoff = Date.now() / 1000 - windowSec;
    const perSecCounts: Record<number, number> = {};

    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      const sec = Math.floor(this.events[i].timestamp);
      perSecCounts[sec] = (perSecCounts[sec] || 0) + 1;
    }

    const rates = Object.values(perSecCounts);
    if (rates.length === 0) return 0;

    const maxRate = Math.max(...rates);
    const sum = rates.reduce((a, b) => a + b, 0);
    const avgRate = sum / rates.length;

    return avgRate > 0 ? maxRate / avgRate : maxRate;
  }

  /** Reset all buffers (for demo refresh) */
  reset(): void {
    this.events = [];
    this.authFailures.clear();
    this.sourceActivity.clear();
  }
}

export const contextEngine = new RealTimeContextEngine();
