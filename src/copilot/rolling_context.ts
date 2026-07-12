/**
 * Aegis Enterprise — Real-Time Context Engine
 *
 * Tracks lightweight rolling state in memory for streaming events:
 *   - Recent request frequency per IP/Source
 *   - Authentication failure metrics per User
 *   - Rolling global burst ratios and unique source entropy
 */

export interface TelemetryEventPayload {
  event_type: string;
  source: string;
  timestamp: number; // Unix epoch seconds
  username?: string;
  bytes?: number;
  destination?: string;
  protocol?: string;
  severity?: string;
  is_anomaly?: boolean;
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
    if (
      (event.event_type === "failed_login" ||
        event.event_type === "auth_failure") &&
      event.username
    ) {
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

  /** Helper to anchor the 'now' timestamp around the latest incoming telemetry event */
  private getReferenceNow(): number {
    if (this.events.length === 0) {
      return Date.now() / 1000;
    }
    return this.events[this.events.length - 1].timestamp;
  }

  /** Calculate current event rate per second (rolling average) */
  getGlobalRate(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    const count = this.events.filter((e) => e.timestamp >= cutoff).length;
    return count / windowSec;
  }

  /** Calculate rolling average and standard deviation of global rates per second */
  getGlobalRateStats(windowSec: number): { mean: number; stdDev: number } {
    if (this.events.length === 0) {
      return { mean: 0, stdDev: 0 };
    }
    const latestEventTime = this.getReferenceNow();
    const cutoff = latestEventTime - windowSec;
    const perSecCounts: Record<number, number> = {};

    const tNow = Math.floor(latestEventTime);
    for (let i = 0; i < windowSec; i++) {
      perSecCounts[tNow - i] = 0;
    }

    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      const sec = Math.floor(this.events[i].timestamp);
      if (sec in perSecCounts) {
        perSecCounts[sec]++;
      }
    }

    const rates = Object.values(perSecCounts);
    const mean = rates.reduce((a, b) => a + b, 0) / windowSec;
    const variance =
      rates.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / windowSec;
    const stdDev = Math.sqrt(variance);

    return { mean, stdDev };
  }

  /** Get failed authentication counts in the sliding window */
  getFailedAuthCount(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    let count = 0;
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      if (
        this.events[i].event_type === "failed_login" ||
        this.events[i].event_type === "auth_failure"
      ) {
        count++;
      }
    }
    return count;
  }

  /** Get requests/events per second from a specific source IP */
  getSourceRate(source: string, windowSec: number): number {
    const times = this.sourceActivity.get(source);
    if (!times) return 0;
    const cutoff = this.getReferenceNow() - windowSec;
    return times.filter((t) => t >= cutoff).length / windowSec;
  }

  /** Get requests/events per second from a specific user */
  getUserRate(username: string, windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    let count = 0;
    const userLower = username.trim().toLowerCase();
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      if (this.events[i].username?.trim().toLowerCase() === userLower) {
        count++;
      }
    }
    return count / windowSec;
  }

  /** Get active session (unique users) frequencies */
  getUniqueUsersCount(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    const unique = new Set<string>();
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      if (this.events[i].username) {
        unique.add(this.events[i].username);
      }
    }
    return unique.size;
  }

  /** Get total bytes transferred in the rolling window */
  getBytesTransferred(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    let totalBytes = 0;
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      totalBytes += this.events[i].bytes || 0;
    }
    return totalBytes;
  }

  /** Get count of unique destinations seen in the window */
  getUniqueDestinationsCount(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    const unique = new Set<string>();
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      const dest = this.events[i].destination;
      if (dest) unique.add(dest);
    }
    return unique.size;
  }

  /** Get protocol distribution in the window */
  getProtocolDistribution(windowSec: number): Record<string, number> {
    const cutoff = this.getReferenceNow() - windowSec;
    const distribution: Record<string, number> = {};
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      const proto = this.events[i].protocol;
      if (proto) {
        distribution[proto] = (distribution[proto] || 0) + 1;
      }
    }
    return distribution;
  }

  /** Get count of flagged anomalies/high severity events in the window */
  getAnomalyDensity(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    let count = 0;
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      const sev = this.events[i].severity;
      if (sev === "HIGH" || sev === "CRITICAL" || this.events[i].is_anomaly) {
        count++;
      }
    }
    return count;
  }

  /** Get authentication failures for a user within a rolling window */
  getUserAuthFailures(username: string, windowSec: number): number {
    const times = this.authFailures.get(username.trim().toLowerCase());
    if (!times) return 0;
    const cutoff = this.getReferenceNow() - windowSec;
    return times.filter((t) => t >= cutoff).length;
  }

  /** Get count of unique source IPs seen in the rolling window */
  getUniqueSourcesCount(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
    const unique = new Set<string>();
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].timestamp < cutoff) break;
      unique.add(this.events[i].source);
    }
    return unique.size;
  }

  /** Compute Shannon entropy of source IP distribution over window */
  getSourceEntropy(windowSec: number): number {
    const cutoff = this.getReferenceNow() - windowSec;
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
    const cutoff = this.getReferenceNow() - windowSec;
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
