/**
 * Aegis Enterprise — AI Capability Registry
 *
 * Enforces tenant-level and role-level capability checks.
 * Determines if a given tenant has paid for/subscribed to specific AI features,
 * and if the calling user's role is permitted to execute that capability.
 */

import { logStructured } from "../observability/logger.js";

export type AICapability =
  | "anomaly_explanation"
  | "incident_summarization"
  | "mitigation_recommendation"
  | "knowledge_search"
  | "executive_report";

export interface TenantCapabilityAssignment {
  tenant_id: number;
  allowed_capabilities: AICapability[];
  max_requests_per_day: number;
}

export class AICapabilityRegistry {
  private tenantAssignments: Map<number, TenantCapabilityAssignment> =
    new Map();

  // Role hierarchy mapping: higher roles inherit permissions from lower roles
  private roleCapabilities: Record<string, AICapability[]> = {
    analyst: [
      "anomaly_explanation",
      "incident_summarization",
      "knowledge_search",
    ],
    lead_analyst: [
      "anomaly_explanation",
      "incident_summarization",
      "mitigation_recommendation",
      "knowledge_search",
    ],
    admin: [
      "anomaly_explanation",
      "incident_summarization",
      "mitigation_recommendation",
      "knowledge_search",
      "executive_report",
    ],
  };

  /**
   * Check if a tenant and user role combination has access to a capability.
   */
  hasCapability(
    tenantId: number,
    role: string,
    capability: AICapability,
  ): boolean {
    // 1. Tenant entitlement verification
    const tenantAssignment = this.tenantAssignments.get(tenantId);
    if (tenantAssignment) {
      if (!tenantAssignment.allowed_capabilities.includes(capability)) {
        logStructured(
          "warn",
          "[AICapabilityRegistry] Tenant not entitled to capability",
          {
            tenantId,
            capability,
          },
        );
        return false;
      }
    }

    // 2. Role-based entitlement check
    const allowedForRole = this.roleCapabilities[role.toLowerCase()] || [];
    if (!allowedForRole.includes(capability)) {
      logStructured(
        "warn",
        "[AICapabilityRegistry] Role lacks permission for capability",
        {
          role,
          capability,
        },
      );
      return false;
    }

    return true;
  }

  /**
   * Set tenant-specific capability assignments.
   */
  setTenantAssignment(assignment: TenantCapabilityAssignment): void {
    this.tenantAssignments.set(assignment.tenant_id, assignment);
    logStructured("info", "[AICapabilityRegistry] Tenant assignments updated", {
      tenantId: assignment.tenant_id,
      capabilities: assignment.allowed_capabilities,
    });
  }
}

export const aiCapabilityRegistry = new AICapabilityRegistry();
