/**
 * Aegis Enterprise — Collector Ingestion Framework
 *
 * Sets up ingress listeners (Syslog/HTTP JSON) to accept, normalise,
 * and validate external telemetry formats before passing to the Event Bus.
 */

import { eventBus } from "../event_bus.js";
import { schemaRegistry } from "../schema_registry/schema_registry.js";

export interface RawInputPayload {
  raw: string;
  sourceType: "syslog" | "http_json";
  ip: string;
}

export class TelemetryCollectorFramework {
  /** Ingest raw string or JSON payload from sockets/endpoints */
  async ingestRaw(
    payload: RawInputPayload,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      let normalized: any = null;

      // 1. Normalization Step
      if (payload.sourceType === "http_json") {
        normalized = JSON.parse(payload.raw);
      } else if (payload.sourceType === "syslog") {
        // Mock RFC 5424 syslog parser
        const parts = payload.raw.split(" | ");
        normalized = {
          event_type: parts[1] || "syslog_event",
          source: payload.ip,
          timestamp: Date.now() / 1000,
        };
      }

      if (!normalized) {
        return { success: false, error: "Normalization failed" };
      }

      // 2. Schema Validation Step
      const validation = schemaRegistry.validate(normalized, "v1");
      if (!validation.isValid) {
        return {
          success: false,
          error: `Schema violation: ${validation.errors.join(", ")}`,
        };
      }

      // 3. Publish to Event Bus
      eventBus.publish("telemetry_ingress", normalized);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: `Parsing error: ${err.message}` };
    }
  }
}

export const collectorFramework = new TelemetryCollectorFramework();
