/**
 * Aegis Enterprise — Health Monitor Service
 * Monitors connectivity to PostgreSQL, Qdrant, MinIO, and Gemini.
 * Generates alerts on failure and implements graceful degradation strategies.
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export type ServiceName = "postgresql" | "qdrant" | "minio" | "gemini" | "copilot_python" | "sqlite";
export type ServiceStatus = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface ServiceHealth {
  service: ServiceName;
  status: ServiceStatus;
  latency_ms: number;
  last_check: number;
  last_healthy: number | null;
  consecutive_failures: number;
  error: string | null;
  degradation_mode: boolean;
  degradation_message: string | null;
}

export interface HealthAlert {
  id: string;
  service: ServiceName;
  severity: "warning" | "critical" | "resolved";
  message: string;
  timestamp: number;
  acknowledged: boolean;
}

export interface DegradationStrategy {
  service: ServiceName;
  strategy: string;
  description: string;
  affected_features: string[];
  fallback_behavior: string;
}

// ─── Configuration ──────────────────────────────────────────────────────────────

const CHECK_INTERVAL_MS = 15000; // 15 seconds
const FAILURE_THRESHOLD = 3;     // consecutive failures before alert
const TIMEOUT_MS = 5000;         // 5 second timeout per health check

// Degradation strategies
const DEGRADATION_STRATEGIES: Record<ServiceName, DegradationStrategy> = {
  postgresql: {
    service: "postgresql",
    strategy: "SQLITE_FALLBACK",
    description: "Enterprise metadata unavailable. Falling back to SQLite for core operations.",
    affected_features: ["Multi-tenant isolation", "Enterprise audit log", "Case management", "Copilot sessions"],
    fallback_behavior: "Core anomaly detection and incident tracking continue via SQLite. Enterprise features paused.",
  },
  qdrant: {
    service: "qdrant",
    strategy: "CACHED_RESPONSES",
    description: "Vector database unavailable. RAG retrieval disabled. Using cached responses.",
    affected_features: ["RAG-powered copilot", "Knowledge base search", "Semantic similarity matching"],
    fallback_behavior: "Copilot returns safe fallback responses. No hallucinated content. Recommend human analyst escalation.",
  },
  minio: {
    service: "minio",
    strategy: "UPLOAD_DISABLED",
    description: "Object storage unavailable. Document upload/download disabled.",
    affected_features: ["Document upload", "File retrieval", "Knowledge base indexing"],
    fallback_behavior: "Existing indexed content remains queryable. New uploads queued for retry when MinIO recovers.",
  },
  gemini: {
    service: "gemini",
    strategy: "SAFE_FALLBACK",
    description: "Gemini AI unavailable. Copilot responses limited to retrieved knowledge only.",
    affected_features: ["AI explanations", "Threat summarization", "Anomaly diagnosis", "Root cause analysis"],
    fallback_behavior: "System notifies user, avoids speculation, and recommends escalation to human analyst.",
  },
  copilot_python: {
    service: "copilot_python",
    strategy: "LOCAL_PROCESSING",
    description: "Python copilot service unavailable. Using server-side fallback.",
    affected_features: ["RAG pipeline", "LangChain processing", "Vector embeddings"],
    fallback_behavior: "Copilot chat returns maintenance notice. Existing cached responses served where available.",
  },
  sqlite: {
    service: "sqlite",
    strategy: "READ_ONLY",
    description: "SQLite database degraded. System in read-only mode.",
    affected_features: ["Event recording", "Anomaly creation", "Incident creation", "Settings changes"],
    fallback_behavior: "Dashboard remains viewable. No new data can be written. Alerts fire to Discord.",
  },
};

// ─── Health Monitor Service ─────────────────────────────────────────────────────

export class HealthMonitorService {
  private services: Map<ServiceName, ServiceHealth> = new Map();
  private alerts: HealthAlert[] = [];
  private checkTimer: NodeJS.Timeout | null = null;
  private alertIdCounter = 0;

  constructor() {
    this.initServices();
  }

  private initServices(): void {
    const services: ServiceName[] = ["postgresql", "qdrant", "minio", "gemini", "copilot_python", "sqlite"];
    for (const svc of services) {
      this.services.set(svc, {
        service: svc,
        status: "unknown",
        latency_ms: 0,
        last_check: 0,
        last_healthy: null,
        consecutive_failures: 0,
        error: null,
        degradation_mode: false,
        degradation_message: null,
      });
    }
  }

  // ─── Connectivity Checks ──────────────────────────────────────────────────

  async checkPostgres(): Promise<ServiceHealth> {
    const health = this.services.get("postgresql")!;
    const start = Date.now();

    try {
      const pgHost = process.env.POSTGRES_HOST || "localhost";
      const pgPort = process.env.POSTGRES_PORT || "5432";
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const response = await fetch(
        `http://${pgHost}:${pgPort}/`,
        { signal: controller.signal }
      ).catch(() => null);
      clearTimeout(timeout);

      // PostgreSQL doesn't respond to HTTP, so we check via a simple connection test
      // In Docker, we rely on the pg_isready check in docker-compose healthcheck
      // Here we just test if the port is reachable
      const { createConnection } = await import("net");
      const reachable = await new Promise<boolean>((resolve) => {
        const socket = createConnection(
          { host: pgHost, port: parseInt(pgPort) },
          () => { socket.destroy(); resolve(true); }
        );
        socket.on("error", () => { socket.destroy(); resolve(false); });
        socket.setTimeout(TIMEOUT_MS, () => { socket.destroy(); resolve(false); });
      });

      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();

      if (reachable) {
        this.markHealthy(health);
      } else {
        this.markUnhealthy(health, "PostgreSQL port unreachable");
      }
    } catch (err: any) {
      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();
      this.markUnhealthy(health, err.message);
    }

    return health;
  }

  async checkQdrant(): Promise<ServiceHealth> {
    const health = this.services.get("qdrant")!;
    const start = Date.now();

    try {
      const qdrantHost = process.env.QDRANT_HOST || "localhost";
      const qdrantPort = process.env.QDRANT_PORT || "6333";
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const response = await fetch(`http://${qdrantHost}:${qdrantPort}/readyz`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);

      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();

      if (response.ok) {
        this.markHealthy(health);
      } else {
        this.markUnhealthy(health, `Qdrant returned HTTP ${response.status}`);
      }
    } catch (err: any) {
      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();
      this.markUnhealthy(health, err.message);
    }

    return health;
  }

  async checkMinIO(): Promise<ServiceHealth> {
    const health = this.services.get("minio")!;
    const start = Date.now();

    try {
      const minioEndpoint = process.env.MINIO_ENDPOINT || "localhost:9000";
      const [host, port] = minioEndpoint.split(":");
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const response = await fetch(`http://${host}:${port || 9000}/minio/health/live`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);

      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();

      if (response.ok || response.status === 403) {
        // 403 means MinIO is running but requires auth — still healthy
        this.markHealthy(health);
      } else {
        this.markUnhealthy(health, `MinIO returned HTTP ${response.status}`);
      }
    } catch (err: any) {
      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();
      this.markUnhealthy(health, err.message);
    }

    return health;
  }

  async checkGemini(): Promise<ServiceHealth> {
    const health = this.services.get("gemini")!;
    const start = Date.now();
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey || apiKey.trim() === "") {
      health.latency_ms = 0;
      health.last_check = Date.now();
      health.status = "degraded";
      health.consecutive_failures = 0;
      health.error = "GEMINI_API_KEY not configured";
      health.degradation_mode = true;
      health.degradation_message = DEGRADATION_STRATEGIES.gemini.fallback_behavior;
      return health;
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      // Lightweight check: list models endpoint
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey.slice(0, 10)}...`,
        { signal: controller.signal }
      );
      clearTimeout(timeout);

      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();

      // 400/403 means API is reachable but key may be invalid/limited — still connectivity OK
      if (response.status < 500) {
        this.markHealthy(health);
      } else {
        this.markUnhealthy(health, `Gemini API returned HTTP ${response.status}`);
      }
    } catch (err: any) {
      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();
      this.markUnhealthy(health, err.message);
    }

    return health;
  }

  async checkCopilotPython(): Promise<ServiceHealth> {
    const health = this.services.get("copilot_python")!;
    const start = Date.now();

    try {
      const copilotUrl = process.env.COPILOT_URL || "http://localhost:8110";
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const response = await fetch(`${copilotUrl}/health`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);

      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();

      if (response.ok) {
        this.markHealthy(health);
      } else {
        this.markUnhealthy(health, `Copilot Python returned HTTP ${response.status}`);
      }
    } catch (err: any) {
      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();
      this.markUnhealthy(health, err.message);
    }

    return health;
  }

  async checkSQLite(): Promise<ServiceHealth> {
    const health = this.services.get("sqlite")!;
    const start = Date.now();

    try {
      const fs = await import("fs");
      const path = await import("path");
      const dbPath = path.join(process.cwd(), "storage", "core.db");
      const exists = fs.existsSync(dbPath);

      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();

      if (exists) {
        this.markHealthy(health);
      } else {
        this.markUnhealthy(health, "SQLite database file not found");
      }
    } catch (err: any) {
      health.latency_ms = Date.now() - start;
      health.last_check = Date.now();
      this.markUnhealthy(health, err.message);
    }

    return health;
  }

  // ─── Health State Management ───────────────────────────────────────────────

  private markHealthy(health: ServiceHealth): void {
    const wasUnhealthy = health.status === "unhealthy" || health.degradation_mode;

    health.status = "healthy";
    health.error = null;
    health.consecutive_failures = 0;
    health.last_healthy = Date.now();
    health.degradation_mode = false;
    health.degradation_message = null;

    if (wasUnhealthy) {
      this.generateAlert(health.service, "resolved", `${health.service} has recovered. Normal operations resumed.`);
      console.log(`[Health] ✓ ${health.service} recovered`);
    }
  }

  private markUnhealthy(health: ServiceHealth, error: string): void {
    health.consecutive_failures++;
    health.error = error;

    if (health.consecutive_failures >= FAILURE_THRESHOLD) {
      const wasHealthy = health.status !== "unhealthy";
      health.status = "unhealthy";
      health.degradation_mode = true;

      const strategy = DEGRADATION_STRATEGIES[health.service];
      health.degradation_message = strategy.fallback_behavior;

      if (wasHealthy) {
        this.generateAlert(
          health.service,
          "critical",
          `${health.service} is DOWN after ${health.consecutive_failures} consecutive failures. Degradation active: ${strategy.strategy}`
        );
        console.error(`[Health] ✗ ${health.service} UNHEALTHY — degradation: ${strategy.strategy}`);
      }
    } else if (health.consecutive_failures === 1) {
      health.status = "degraded";
      this.generateAlert(
        health.service,
        "warning",
        `${health.service} health check failed (attempt ${health.consecutive_failures}/${FAILURE_THRESHOLD}). Error: ${error}`
      );
      console.warn(`[Health] ⚠ ${health.service} check failed (${health.consecutive_failures}/${FAILURE_THRESHOLD}): ${error}`);
    }
  }

  // ─── Alert Management ─────────────────────────────────────────────────────

  private generateAlert(service: ServiceName, severity: "warning" | "critical" | "resolved", message: string): void {
    this.alertIdCounter++;
    const alert: HealthAlert = {
      id: `ha_${this.alertIdCounter}`,
      service,
      severity,
      message,
      timestamp: Date.now(),
      acknowledged: false,
    };
    this.alerts.push(alert);
    // Keep alerts bounded
    if (this.alerts.length > 500) {
      this.alerts = this.alerts.slice(-250);
    }
  }

  acknowledgeAlert(alertId: string): boolean {
    const alert = this.alerts.find((a) => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      return true;
    }
    return false;
  }

  // ─── Automated Health Check Loop ──────────────────────────────────────────

  async runAllChecks(): Promise<Map<ServiceName, ServiceHealth>> {
    await Promise.allSettled([
      this.checkPostgres(),
      this.checkQdrant(),
      this.checkMinIO(),
      this.checkGemini(),
      this.checkCopilotPython(),
      this.checkSQLite(),
    ]);
    return this.services;
  }

  startMonitoring(): void {
    if (this.checkTimer) return;

    // Initial check
    this.runAllChecks().catch((err) => {
      console.error("[Health] Initial check failed:", err.message);
    });

    // Recurring checks
    this.checkTimer = setInterval(() => {
      this.runAllChecks().catch((err) => {
        console.error("[Health] Periodic check failed:", err.message);
      });
    }, CHECK_INTERVAL_MS);

    console.log(`[Health] Monitoring started (every ${CHECK_INTERVAL_MS / 1000}s)`);
  }

  stopMonitoring(): void {
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }
  }

  // ─── Safe Failure Response ─────────────────────────────────────────────────

  isServiceAvailable(service: ServiceName): boolean {
    const health = this.services.get(service);
    return health?.status === "healthy" || health?.status === "unknown";
  }

  getFallbackMessage(service: ServiceName): string {
    const strategy = DEGRADATION_STRATEGIES[service];
    return (
      `⚠ Service Unavailable: ${service} is currently unreachable.\n\n` +
      `${strategy.description}\n\n` +
      `Fallback: ${strategy.fallback_behavior}\n\n` +
      `I could not find sufficient evidence in the indexed knowledge base to answer this confidently. ` +
      `Please escalate to a human analyst for investigation.`
    );
  }

  getAffectedFeatures(): string[] {
    const affected: string[] = [];
    for (const [, health] of this.services) {
      if (health.degradation_mode) {
        const strategy = DEGRADATION_STRATEGIES[health.service];
        affected.push(...strategy.affected_features);
      }
    }
    return [...new Set(affected)];
  }

  // ─── Status & Reporting ────────────────────────────────────────────────────

  getStatus() {
    const services: Record<string, ServiceHealth> = {};
    let overallStatus: ServiceStatus = "healthy";

    for (const [name, health] of this.services) {
      services[name] = health;
      if (health.status === "unhealthy") overallStatus = "unhealthy";
      else if (health.status === "degraded" && overallStatus !== "unhealthy") overallStatus = "degraded";
    }

    return {
      service: "health_monitor",
      overall_status: overallStatus,
      services,
      monitoring_active: this.checkTimer !== null,
      check_interval_ms: CHECK_INTERVAL_MS,
      failure_threshold: FAILURE_THRESHOLD,
      degradation_strategies: DEGRADATION_STRATEGIES,
    };
  }

  getAlerts(limit: number = 50): HealthAlert[] {
    return this.alerts.slice(-limit).reverse();
  }

  getUnacknowledgedAlerts(): HealthAlert[] {
    return this.alerts.filter((a) => !a.acknowledged).reverse();
  }

  getDegradationStrategies(): DegradationStrategy[] {
    return Object.values(DEGRADATION_STRATEGIES);
  }
}

// Singleton instance
export const healthMonitorService = new HealthMonitorService();
