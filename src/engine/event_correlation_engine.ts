/**
 * Aegis SIEM — Multi-Event Correlation Engine
 *
 * Correlates sequences of telemetry events and individual anomaly signals across
 * time windows to detect complex multi-stage attack chains (kill chains).
 *
 * Example Correlated Attack Chains:
 *   1. Brute Force Compromise: N Failed Logins → 1 Successful Login from same IP/User
 *   2. Account Takeover & Escalation: Login → Privilege Escalation → Mass Data Transfer
 *   3. Suspicious Persistence: New User Created → Admin Group Added → Disabling Audit Logs
 */

import { getPrismaClient, isPostgresConnected } from "../saas/prisma_client.js";

export interface EventSignal {
  id?: number | string;
  organization_id: number;
  event_type: string;
  source: string;
  user_name?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  timestamp: Date;
  details?: Record<string, any>;
}

export interface CorrelatedIncident {
  id?: string;
  organization_id: number;
  rule_id: string;
  rule_name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  title: string;
  summary: string;
  entity_id: string; // e.g. user or IP address
  event_ids: (number | string)[];
  first_seen: Date;
  last_seen: Date;
  confidence: number; // 0.0 to 1.0
}

export interface CorrelationPatternRule {
  id: string;
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  window_ms: number; // Correlation time window (e.g., 5 min = 300,000ms)
  sequence: Array<{
    event_type: string | RegExp;
    min_occurs?: number;
  }>;
  groupBy: "source" | "user_name";
}

// Pre-configured SIEM Attack Correlation Rules
export const SIEM_CORRELATION_RULES: CorrelationPatternRule[] = [
  {
    id: "RULE_BRUTE_FORCE_SUCCESS",
    name: "Brute Force Followed by Successful Login (Account Compromise)",
    severity: "CRITICAL",
    window_ms: 10 * 60 * 1000, // 10 minutes
    groupBy: "source",
    sequence: [
      {
        event_type: /login_failed|auth_failure|failed_password/i,
        min_occurs: 3,
      },
      {
        event_type: /login_success|auth_success|accepted_password/i,
        min_occurs: 1,
      },
    ],
  },
  {
    id: "RULE_TAKEOVER_EXFILTRATION",
    name: "Successful Login Followed by Data Exfiltration",
    severity: "CRITICAL",
    window_ms: 15 * 60 * 1000, // 15 minutes
    groupBy: "user_name",
    sequence: [
      { event_type: /login_success|auth_success/i, min_occurs: 1 },
      { event_type: /mass_download|data_export|exfiltration/i, min_occurs: 1 },
    ],
  },
  {
    id: "RULE_PRIVILEGE_ESCALATION_CHAIN",
    name: "Privilege Escalation after Anonymous Session",
    severity: "HIGH",
    window_ms: 5 * 60 * 1000, // 5 minutes
    groupBy: "source",
    sequence: [
      { event_type: /login_success/i, min_occurs: 1 },
      {
        event_type: /privilege_escalation|sudo_grant|admin_add/i,
        min_occurs: 1,
      },
    ],
  },
];

// In-memory sliding correlation window buffer per organization
const eventBuffers = new Map<number, EventSignal[]>();

/**
 * Push an event into the correlation buffer and evaluate all active correlation rules.
 * Returns any newly correlated incidents detected.
 */
export async function correlateEvents(
  orgId: number,
  newEvent: EventSignal,
): Promise<CorrelatedIncident[]> {
  const now = Date.now();
  const maxWindowMs = 30 * 60 * 1000; // 30 min sliding window

  // Get or init buffer for this organization
  let buffer = eventBuffers.get(orgId) || [];
  buffer.push(newEvent);

  // Prune events older than 30 minutes
  buffer = buffer.filter((e) => now - e.timestamp.getTime() <= maxWindowMs);
  eventBuffers.set(orgId, buffer);

  const incidents: CorrelatedIncident[] = [];

  for (const rule of SIEM_CORRELATION_RULES) {
    // Filter events within rule window
    const windowEvents = buffer.filter(
      (e) => now - e.timestamp.getTime() <= rule.window_ms,
    );

    // Group events by entity (source IP or user_name)
    const grouped = new Map<string, EventSignal[]>();
    for (const ev of windowEvents) {
      const key = rule.groupBy === "user_name" ? ev.user_name : ev.source;
      if (!key) continue;
      const list = grouped.get(key) || [];
      list.push(ev);
      grouped.set(key, list);
    }

    // Evaluate sequence rules per entity
    for (const [entityId, events] of grouped.entries()) {
      let matchedAllStages = true;
      const matchedEventIds: (number | string)[] = [];

      for (const stage of rule.sequence) {
        const matchingStageEvents = events.filter((e) => {
          if (typeof stage.event_type === "string") {
            return (
              e.event_type.toLowerCase() === stage.event_type.toLowerCase()
            );
          } else {
            return stage.event_type.test(e.event_type);
          }
        });

        if (matchingStageEvents.length < (stage.min_occurs || 1)) {
          matchedAllStages = false;
          break;
        }

        matchingStageEvents.forEach((e) => {
          if (e.id && !matchedEventIds.includes(e.id))
            matchedEventIds.push(e.id);
        });
      }

      if (matchedAllStages) {
        const sorted = events.sort(
          (a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
        );
        const incident: CorrelatedIncident = {
          id: `corr_${rule.id}_${entityId}_${Date.now()}`,
          organization_id: orgId,
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          title: `Correlated Security Incident: ${rule.name}`,
          summary: `Matched attack pattern '${rule.name}' for entity '${entityId}' across ${events.length} correlated events.`,
          entity_id: entityId,
          event_ids: matchedEventIds,
          first_seen: sorted[0].timestamp,
          last_seen: sorted[sorted.length - 1].timestamp,
          confidence: 0.95,
        };

        incidents.push(incident);

        // Audit log in PostgreSQL if available
        if (await isPostgresConnected()) {
          try {
            const prisma = getPrismaClient();
            await prisma.auditLog.create({
              data: {
                organization_id: orgId,
                action: "EVENT_CORRELATION_TRIGGERED",
                resource: "correlation_engine",
                details: JSON.stringify({
                  rule_id: rule.id,
                  entity_id: entityId,
                  matched_events_count: matchedEventIds.length,
                }),
              },
            });
          } catch {
            /* ignore non-critical */
          }
        }
      }
    }
  }

  return incidents;
}
