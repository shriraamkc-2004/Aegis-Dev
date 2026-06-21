/**
 * Aegis Enterprise — Case Management Service
 * Manages incident ownership, analyst assignment, status tracking,
 * SLA monitoring, incident timeline, and runbook suggestions.
 */

import { dbRun, dbAll, dbGet } from "../server_db.js";

// ─── Types ──────────────────────────────────────────────────────────────────────

export type CaseStatus =
  | "open"
  | "assigned"
  | "investigating"
  | "pending_approval"
  | "mitigating"
  | "resolved"
  | "closed";

export type CaseSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type TimelineEventType =
  | "alert"
  | "investigation"
  | "ai_recommendation"
  | "approval"
  | "mitigation"
  | "closure"
  | "note"
  | "status_change";

export interface Case {
  id: number;
  tenant_id: number;
  title: string;
  description: string;
  severity: CaseSeverity;
  status: CaseStatus;
  assigned_to: number | null;
  created_by: number | null;
  alert_id: number | null;
  incident_id: number | null;
  mitre_techniques: string[];
  mitre_tactics: string[];
  root_cause: string;
  resolution: string;
  lessons_learned: string;
  sla_deadline: number | null;
  sla_breached: boolean;
  created_at: number;
  updated_at: number;
  resolved_at: number | null;
  closed_at: number | null;
}

export interface CaseTimelineEvent {
  id: number;
  case_id: number;
  event_type: TimelineEventType;
  description: string;
  metadata: Record<string, unknown>;
  created_by: number | null;
  created_at: number;
}

export interface RunbookSuggestion {
  id: string;
  title: string;
  description: string;
  steps: string[];
  mitre_technique?: string;
  applicable_severity: CaseSeverity[];
  context_tags: string[];
}

// ─── SLA Configuration (minutes) ────────────────────────────────────────────────

const SLA_DEADLINES: Record<CaseSeverity, number> = {
  CRITICAL: 60,   // 1 hour
  HIGH: 240,      // 4 hours
  MEDIUM: 1440,   // 24 hours
  LOW: 10080,     // 7 days
};

// ─── Runbook Templates ──────────────────────────────────────────────────────────

const RUNBOOK_TEMPLATES: RunbookSuggestion[] = [
  {
    id: "rb_brute_force",
    title: "Brute Force Attack Response",
    description: "Standard playbook for responding to brute force authentication attacks.",
    steps: [
      "Verify the attack by reviewing authentication logs for repeated failed attempts",
      "Identify the targeted accounts and source IP addresses",
      "Temporarily lock targeted accounts if compromise is suspected",
      "Block malicious source IPs at the firewall level",
      "Enable MFA on all targeted accounts if not already enabled",
      "Review account access logs for any successful unauthorized access",
      "Document findings and update the incident report",
      "Conduct post-incident review within 48 hours",
    ],
    mitre_technique: "T1110",
    applicable_severity: ["HIGH", "CRITICAL"],
    context_tags: ["authentication", "brute_force", "login"],
  },
  {
    id: "rb_ddos",
    title: "DDoS Mitigation Playbook",
    description: "Response procedure for Distributed Denial of Service attacks.",
    steps: [
      "Confirm the DDoS attack by analyzing traffic patterns and source distribution",
      "Activate DDoS mitigation services (CDN, WAF, rate limiting)",
      "Identify and block top offending IP ranges",
      "Scale infrastructure if possible to absorb traffic",
      "Contact ISP for upstream filtering if attack volume exceeds capacity",
      "Monitor service availability and response times",
      "Document attack vectors, duration, and impact",
      "Review and update DDoS response plan post-incident",
    ],
    mitre_technique: "T1498",
    applicable_severity: ["HIGH", "CRITICAL"],
    context_tags: ["ddos", "traffic_spike", "denial_of_service"],
  },
  {
    id: "rb_exfiltration",
    title: "Data Exfiltration Response",
    description: "Investigation and containment of suspected data exfiltration.",
    steps: [
      "Identify the data flow — source, destination, volume, and protocol",
      "Determine what data was potentially exfiltrated (classification level)",
      "Isolate the affected system(s) from the network",
      "Preserve forensic evidence (memory dumps, disk images, network captures)",
      "Review user activity logs for the compromised account",
      "Check for lateral movement indicators",
      "Notify legal and compliance teams if sensitive data is involved",
      "Conduct thorough forensic analysis and document findings",
    ],
    mitre_technique: "T1041",
    applicable_severity: ["HIGH", "CRITICAL"],
    context_tags: ["exfiltration", "data_transfer", "outbound"],
  },
  {
    id: "rb_insider",
    title: "Insider Threat Investigation",
    description: "Procedure for investigating potential insider threat activity.",
    steps: [
      "Review the privileged actions that triggered the alert",
      "Correlate with HR records for recent personnel changes",
      "Analyze access patterns — time, frequency, scope of actions",
      "Check for data staging or unusual file access patterns",
      "Interview the user's manager (with HR involvement)",
      "Preserve all evidence and maintain chain of custody",
      "Coordinate with legal before taking disciplinary action",
      "Review and tighten access controls post-incident",
    ],
    mitre_technique: "T1078",
    applicable_severity: ["MEDIUM", "HIGH", "CRITICAL"],
    context_tags: ["insider", "privileged", "unauthorized_access"],
  },
  {
    id: "rb_service_failure",
    title: "Service Failure Recovery",
    description: "Standard recovery procedure for critical service failures.",
    steps: [
      "Identify the failed service and its dependencies",
      "Check system resources (CPU, memory, disk, network)",
      "Review application and system logs for root cause",
      "Attempt service restart with monitoring",
      "If restart fails, activate failover or backup systems",
      "Verify service health and dependent system recovery",
      "Review monitoring thresholds and alerting rules",
      "Document root cause and implement preventive measures",
    ],
    applicable_severity: ["MEDIUM", "HIGH"],
    context_tags: ["service_failure", "heartbeat", "availability"],
  },
];

// ─── Case Management Service ────────────────────────────────────────────────────

export class CaseManagerService {
  private cases: Map<number, Case> = new Map();
  private timelines: Map<number, CaseTimelineEvent[]> = new Map();
  private nextCaseId = 1;
  private nextTimelineId = 1;

  // ─── Case CRUD ────────────────────────────────────────────────────────────

  async createCase(params: {
    tenant_id: number;
    title: string;
    description?: string;
    severity: CaseSeverity;
    created_by?: number;
    alert_id?: number;
    incident_id?: number;
    mitre_techniques?: string[];
    mitre_tactics?: string[];
  }): Promise<Case> {
    const now = Date.now() / 1000;
    const slaMinutes = SLA_DEADLINES[params.severity] || SLA_DEADLINES.MEDIUM;

    const caseRecord: Case = {
      id: this.nextCaseId++,
      tenant_id: params.tenant_id,
      title: params.title,
      description: params.description || "",
      severity: params.severity,
      status: "open",
      assigned_to: null,
      created_by: params.created_by || null,
      alert_id: params.alert_id || null,
      incident_id: params.incident_id || null,
      mitre_techniques: params.mitre_techniques || [],
      mitre_tactics: params.mitre_tactics || [],
      root_cause: "",
      resolution: "",
      lessons_learned: "",
      sla_deadline: now + slaMinutes * 60,
      sla_breached: false,
      created_at: now,
      updated_at: now,
      resolved_at: null,
      closed_at: null,
    };

    this.cases.set(caseRecord.id, caseRecord);

    // Create initial timeline event
    await this.addTimelineEvent(caseRecord.id, "alert", "Case created", {
      severity: params.severity,
      title: params.title,
    }, params.created_by);

    return caseRecord;
  }

  async assignCase(
    caseId: number,
    analystId: number,
    assignedBy: number
  ): Promise<Case | null> {
    const c = this.cases.get(caseId);
    if (!c) return null;

    c.assigned_to = analystId;
    c.status = "assigned";
    c.updated_at = Date.now() / 1000;

    await this.addTimelineEvent(caseId, "status_change", `Assigned to analyst #${analystId}`, {
      assigned_to: analystId,
      assigned_by: assignedBy,
    }, assignedBy);

    return c;
  }

  async updateCaseStatus(
    caseId: number,
    status: CaseStatus,
    userId: number,
    notes?: string
  ): Promise<Case | null> {
    const c = this.cases.get(caseId);
    if (!c) return null;

    const oldStatus = c.status;
    c.status = status;
    c.updated_at = Date.now() / 1000;

    if (status === "resolved") {
      c.resolved_at = Date.now() / 1000;
    }
    if (status === "closed") {
      c.closed_at = Date.now() / 1000;
    }

    await this.addTimelineEvent(
      caseId,
      "status_change",
      `Status changed: ${oldStatus} → ${status}${notes ? `. ${notes}` : ""}`,
      { old_status: oldStatus, new_status: status },
      userId
    );

    return c;
  }

  async updateCase(
    caseId: number,
    updates: Partial<Case>
  ): Promise<Case | null> {
    const c = this.cases.get(caseId);
    if (!c) return null;

    Object.assign(c, updates, { updated_at: Date.now() / 1000 });
    return c;
  }

  // ─── Case Queries ─────────────────────────────────────────────────────────

  async getCase(caseId: number): Promise<Case | null> {
    return this.cases.get(caseId) || null;
  }

  async listCases(
    tenantId: number,
    filters?: {
      status?: CaseStatus;
      severity?: CaseSeverity;
      assigned_to?: number;
      sla_breached?: boolean;
    }
  ): Promise<Case[]> {
    let results = Array.from(this.cases.values()).filter(
      (c) => c.tenant_id === tenantId
    );

    if (filters?.status) results = results.filter((c) => c.status === filters.status);
    if (filters?.severity) results = results.filter((c) => c.severity === filters.severity);
    if (filters?.assigned_to) results = results.filter((c) => c.assigned_to === filters.assigned_to);
    if (filters?.sla_breached !== undefined) {
      results = results.filter((c) => c.sla_breached === filters.sla_breached);
    }

    // Check SLA breaches
    const now = Date.now() / 1000;
    for (const c of results) {
      if (c.sla_deadline && now > c.sla_deadline && !["resolved", "closed"].includes(c.status)) {
        c.sla_breached = true;
      }
    }

    return results.sort((a, b) => b.created_at - a.created_at);
  }

  async getCasesByAnalyst(tenantId: number, analystId: number): Promise<Case[]> {
    return this.listCases(tenantId, { assigned_to: analystId });
  }

  // ─── Timeline ─────────────────────────────────────────────────────────────

  async addTimelineEvent(
    caseId: number,
    eventType: TimelineEventType,
    description: string,
    metadata: Record<string, unknown> = {},
    userId?: number
  ): Promise<CaseTimelineEvent> {
    const event: CaseTimelineEvent = {
      id: this.nextTimelineId++,
      case_id: caseId,
      event_type: eventType,
      description,
      metadata,
      created_by: userId || null,
      created_at: Date.now() / 1000,
    };

    if (!this.timelines.has(caseId)) {
      this.timelines.set(caseId, []);
    }
    this.timelines.get(caseId)!.push(event);

    return event;
  }

  async getTimeline(caseId: number): Promise<CaseTimelineEvent[]> {
    return (this.timelines.get(caseId) || []).sort(
      (a, b) => a.created_at - b.created_at
    );
  }

  // ─── Runbook Suggestions ──────────────────────────────────────────────────

  suggestRunbooks(
    severity: CaseSeverity,
    context: string,
    mitreTechnique?: string
  ): RunbookSuggestion[] {
    const contextLower = context.toLowerCase();
    const scored = RUNBOOK_TEMPLATES.map((rb) => {
      let score = 0;

      // Severity match
      if (rb.applicable_severity.includes(severity)) score += 2;

      // MITRE technique match
      if (mitreTechnique && rb.mitre_technique === mitreTechnique) score += 5;

      // Context tag matching
      for (const tag of rb.context_tags) {
        if (contextLower.includes(tag)) score += 3;
      }

      // Title/description keyword matching
      const words = contextLower.split(/\s+/);
      for (const word of words) {
        if (word.length > 3 && rb.title.toLowerCase().includes(word)) score += 1;
        if (word.length > 3 && rb.description.toLowerCase().includes(word)) score += 1;
      }

      return { runbook: rb, score };
    });

    return scored
      .filter((s) => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map((s) => s.runbook);
  }

  // ─── SLA Monitoring ───────────────────────────────────────────────────────

  getSLAStatus(tenantId: number): {
    total_active: number;
    breached: number;
    approaching_deadline: number;
    by_severity: Record<CaseSeverity, { total: number; breached: number }>;
  } {
    const now = Date.now() / 1000;
    const activeCases = Array.from(this.cases.values()).filter(
      (c) => c.tenant_id === tenantId && !["resolved", "closed"].includes(c.status)
    );

    const breached = activeCases.filter(
      (c) => c.sla_deadline && now > c.sla_deadline
    );

    const approaching = activeCases.filter(
      (c) =>
        c.sla_deadline &&
        now > c.sla_deadline - 3600 && // Within 1 hour of deadline
        now <= c.sla_deadline
    );

    const bySeverity: Record<CaseSeverity, { total: number; breached: number }> = {
      CRITICAL: { total: 0, breached: 0 },
      HIGH: { total: 0, breached: 0 },
      MEDIUM: { total: 0, breached: 0 },
      LOW: { total: 0, breached: 0 },
    };

    for (const c of activeCases) {
      bySeverity[c.severity].total++;
      if (c.sla_deadline && now > c.sla_deadline) {
        bySeverity[c.severity].breached++;
      }
    }

    return {
      total_active: activeCases.length,
      breached: breached.length,
      approaching_deadline: approaching.length,
      by_severity: bySeverity,
    };
  }

  // ─── Health ───────────────────────────────────────────────────────────────

  getStatus() {
    return {
      service: "case_manager",
      total_cases: this.cases.size,
      active_cases: Array.from(this.cases.values()).filter(
        (c) => !["resolved", "closed"].includes(c.status)
      ).length,
      runbook_templates: RUNBOOK_TEMPLATES.length,
    };
  }
}

// Singleton instance
export const caseManager = new CaseManagerService();
