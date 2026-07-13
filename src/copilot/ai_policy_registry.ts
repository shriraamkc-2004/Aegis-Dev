/**
 * Aegis Enterprise — AI Policy Registry
 *
 * Dynamic, hot-reloadable registry of all AI governance policies.
 * Replaces hard-coded policy arrays. Supports versioning, tenant overrides,
 * and graduated enforcement actions (BLOCK / WARN / LOG / ENFORCE_FORMAT).
 *
 * Immutable policies (tenant_override_allowed = false) cannot be disabled by any tenant.
 */

import { logStructured } from "../observability/logger.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type PolicySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type PolicyAction =
  "BLOCK_AND_AUDIT" | "BLOCK" | "WARN" | "LOG" | "ENFORCE_FORMAT";

export interface AIPolicy {
  id: string; // "POL-001"
  name: string;
  rule: string;
  severity: PolicySeverity;
  action: PolicyAction;
  enabled: boolean;
  version: number;
  tenant_override_allowed: boolean; // false = immutable by all tenants
  last_updated: number;
  updated_by: string;
}

export interface PolicyEvaluationResult {
  policy_id: string;
  policy_name: string;
  violated: boolean;
  action: PolicyAction;
  severity: PolicySeverity;
  message: string;
}

export interface PolicyRegistryEvaluation {
  allowed: boolean;
  violations: PolicyEvaluationResult[];
  warnings: PolicyEvaluationResult[];
  enforced_formats: PolicyEvaluationResult[];
  highest_severity: PolicySeverity | null;
}

// ─── Default Policy Set (20 Policies) ────────────────────────────────────────

const BASE_POLICIES: AIPolicy[] = [
  // ── Immutable Critical Policies (POL-001 to POL-012) ─────────────────────
  {
    id: "POL-001",
    name: "No Evidence Fabrication",
    rule: "AI cannot invent evidence not present in EvidenceBundle",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-002",
    name: "No Detection Override",
    rule: "AI cannot override, modify, or dispute deterministic engine outputs",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-003",
    name: "No Severity Modification",
    rule: "AI cannot suggest changing incident severity",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-004",
    name: "No Confidence Modification",
    rule: "AI cannot modify, inflate or deflate confidence scores",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-005",
    name: "No Incident Creation",
    rule: "AI cannot create, close, or escalate incidents",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-006",
    name: "No MITRE Fabrication",
    rule: "AI cannot invent MITRE technique IDs not provided by ThreatFusion",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-007",
    name: "No Threat Actor Fabrication",
    rule: "AI cannot name threat actors not present in threat intelligence",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-008",
    name: "No IOC Fabrication",
    rule: "AI cannot fabricate IP addresses, domains, hashes, or CVE IDs",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-009",
    name: "No Cross-Tenant Access",
    rule: "AI cannot access, reference, or leak data from another tenant",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-010",
    name: "No Autonomous Actions",
    rule: "AI cannot initiate or recommend immediate autonomous security actions",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-011",
    name: "Citation Required",
    rule: "Every AI claim must identify its deterministic source engine",
    severity: "MEDIUM",
    action: "ENFORCE_FORMAT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-012",
    name: "Limitations Must Be Stated",
    rule: "AI must explicitly state when evidence is incomplete or absent",
    severity: "MEDIUM",
    action: "ENFORCE_FORMAT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  // ── Enhanced Policies (POL-013 to POL-020) ───────────────────────────────
  {
    id: "POL-013",
    name: "No Stale Evidence Reference",
    rule: "AI cannot reference evidence older than 30 minutes without disclaimer",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: true,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-014",
    name: "No Unverified Network Topology",
    rule: "AI cannot reference network segments not in asset context",
    severity: "MEDIUM",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: true,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-015",
    name: "Limitations Section Required",
    rule: "AI response must include Limitations section",
    severity: "MEDIUM",
    action: "ENFORCE_FORMAT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-016",
    name: "No Unsupported Recommendations",
    rule: "AI cannot fabricate analyst recommendations without rule evidence",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-017",
    name: "Minimum Truth Score",
    rule: "AI cannot produce responses without Truth Score >= 0.70",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-018",
    name: "Human Approval Flag Required",
    rule: "AI cannot suggest automated remediation without human approval flag",
    severity: "HIGH",
    action: "ENFORCE_FORMAT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-019",
    name: "Session Context Isolation",
    rule: "Session context must not contain previous tenant data",
    severity: "CRITICAL",
    action: "BLOCK_AND_AUDIT",
    enabled: true,
    version: 1,
    tenant_override_allowed: false,
    last_updated: Date.now(),
    updated_by: "system",
  },
  {
    id: "POL-020",
    name: "Cost Budget Enforcement",
    rule: "AI cost per tenant must not exceed monthly budget",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    version: 1,
    tenant_override_allowed: true,
    last_updated: Date.now(),
    updated_by: "system",
  },
];

// ─── Policy Registry ──────────────────────────────────────────────────────────

export class AIPolicyRegistry {
  private policies: Map<string, AIPolicy> = new Map();
  private tenantOverrides: Map<number, Map<string, boolean>> = new Map();

  constructor() {
    for (const p of BASE_POLICIES) {
      this.policies.set(p.id, { ...p });
    }
    logStructured("info", "[PolicyRegistry] Loaded base policies", {
      count: this.policies.size,
    });
  }

  // ── Policy Retrieval ──────────────────────────────────────────────────────

  getPolicy(id: string): AIPolicy | undefined {
    return this.policies.get(id);
  }

  getActivePolicies(tenantId?: number): AIPolicy[] {
    return Array.from(this.policies.values()).filter((p) => {
      if (!p.enabled) return false;
      if (tenantId !== undefined) {
        const overrides = this.tenantOverrides.get(tenantId);
        if (overrides?.has(p.id)) {
          // Immutable policies cannot be overridden
          if (!p.tenant_override_allowed) return true;
          return overrides.get(p.id) ?? true;
        }
      }
      return true;
    });
  }

  // ── Policy Evaluation ─────────────────────────────────────────────────────

  /**
   * Evaluate a request context against all active policies.
   * Returns structured evaluation with violations, warnings, and format enforcements.
   */
  evaluate(
    context: PolicyEvaluationContext,
    tenantId?: number,
  ): PolicyRegistryEvaluation {
    const policies = this.getActivePolicies(tenantId);
    const violations: PolicyEvaluationResult[] = [];
    const warnings: PolicyEvaluationResult[] = [];
    const enforced_formats: PolicyEvaluationResult[] = [];

    for (const policy of policies) {
      const violated = this.checkViolation(policy, context);
      if (!violated) continue;

      const result: PolicyEvaluationResult = {
        policy_id: policy.id,
        policy_name: policy.name,
        violated: true,
        action: policy.action,
        severity: policy.severity,
        message: `Policy ${policy.id} (${policy.name}): ${policy.rule}`,
      };

      if (policy.action === "BLOCK_AND_AUDIT" || policy.action === "BLOCK") {
        violations.push(result);
      } else if (policy.action === "WARN" || policy.action === "LOG") {
        warnings.push(result);
      } else if (policy.action === "ENFORCE_FORMAT") {
        enforced_formats.push(result);
      }
    }

    const blockingViolations = violations.filter(
      (v) => v.action === "BLOCK" || v.action === "BLOCK_AND_AUDIT",
    );

    const severityOrder: PolicySeverity[] = [
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
    ];
    const allViolations = [...violations, ...warnings];
    let highestSeverity: PolicySeverity | null = null;
    for (const sev of severityOrder) {
      if (allViolations.some((v) => v.severity === sev)) {
        highestSeverity = sev;
        break;
      }
    }

    return {
      allowed: blockingViolations.length === 0,
      violations,
      warnings,
      enforced_formats,
      highest_severity: highestSeverity,
    };
  }

  // ── Hot-Reload ────────────────────────────────────────────────────────────

  updatePolicy(policy: AIPolicy, updatedBy: string): boolean {
    const existing = this.policies.get(policy.id);
    if (!existing) {
      logStructured(
        "warn",
        "[PolicyRegistry] Cannot update — policy not found",
        {
          id: policy.id,
        },
      );
      return false;
    }
    this.policies.set(policy.id, {
      ...policy,
      last_updated: Date.now(),
      updated_by: updatedBy,
      version: existing.version + 1,
    });
    logStructured("info", "[PolicyRegistry] Policy updated", {
      id: policy.id,
      updatedBy,
    });
    return true;
  }

  setTenantOverride(
    tenantId: number,
    policyId: string,
    enabled: boolean,
  ): boolean {
    const policy = this.policies.get(policyId);
    if (!policy) return false;
    if (!policy.tenant_override_allowed) {
      logStructured(
        "warn",
        "[PolicyRegistry] Cannot override immutable policy",
        {
          policyId,
          tenantId,
        },
      );
      return false;
    }
    if (!this.tenantOverrides.has(tenantId)) {
      this.tenantOverrides.set(tenantId, new Map());
    }
    this.tenantOverrides.get(tenantId)!.set(policyId, enabled);
    return true;
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private checkViolation(
    policy: AIPolicy,
    ctx: PolicyEvaluationContext,
  ): boolean {
    switch (policy.id) {
      case "POL-003":
      case "POL-004":
        return (
          ctx.request_type === "modify_severity" ||
          ctx.request_type === "modify_confidence"
        );
      case "POL-005":
        return (
          ctx.request_type === "create_incident" ||
          ctx.request_type === "close_incident"
        );
      case "POL-010":
        return ctx.contains_autonomous_action === true;
      case "POL-013":
        return (
          ctx.evidence_age_ms !== undefined &&
          ctx.evidence_age_ms > 30 * 60 * 1000
        );
      case "POL-019":
        return ctx.session_tenant_mismatch === true;
      case "POL-020":
        return ctx.budget_exceeded === true;
      default:
        return false; // Runtime violations checked in Truth Engine / Guardrail Engine
    }
  }
}

// ─── Context Passed to Policy Evaluator ──────────────────────────────────────

export interface PolicyEvaluationContext {
  request_type?: string;
  evidence_age_ms?: number;
  contains_autonomous_action?: boolean;
  session_tenant_mismatch?: boolean;
  budget_exceeded?: boolean;
  truth_score?: number;
  [key: string]: unknown;
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const aiPolicyRegistry = new AIPolicyRegistry();
