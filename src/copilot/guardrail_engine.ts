/**
 * Aegis Enterprise — Guardrail Engine
 *
 * First line of defense before the AI layer.
 * Validates all AI requests against enterprise AI policies and defined role boundaries.
 * Blocks any request that would cause the AI to operate outside its advisory-only scope.
 *
 * Integrates with:
 *  - AIPolicyRegistry for dynamic policy enforcement
 *  - AICapabilityRegistry for tenant/role capability checks
 *  - AIRiskAssessmentEngine for per-request risk scoring
 */

import { logStructured } from "../observability/logger.js";
import {
  aiPolicyRegistry,
  type PolicyRegistryEvaluation,
  type PolicyEvaluationContext,
} from "./ai_policy_registry.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GuardrailRequest {
  prompt: string;
  request_type: string; // "anomaly_explanation" | "summarization" | "search" | "report"
  tenant_id: number;
  user_id: number | null;
  user_role: string;
  evidence_age_ms?: number; // Age of the evidence bundle in ms
  session_id?: string;
  session_tenant_id?: number; // For cross-tenant session check
}

export interface GuardrailResult {
  allowed: boolean;
  violations: string[];
  warnings: string[];
  policy_evaluation: PolicyRegistryEvaluation;
  boundary_check: BoundaryCheckResult;
  risk_score: number; // 0.0 – 1.0
  reason: string | null;
}

export interface BoundaryCheckResult {
  within_boundary: boolean;
  violated_boundaries: string[];
}

// ─── Role Boundary Matrix ─────────────────────────────────────────────────────

/**
 * Requests that are unconditionally BLOCKED regardless of evidence or role.
 * These represent the 10 hard boundaries from the governance specification.
 */
const BLOCKED_REQUEST_TYPES = new Set([
  "create_incident",
  "close_incident",
  "escalate_incident",
  "modify_severity",
  "modify_confidence",
  "detect_anomaly",
  "set_threat_score",
  "override_rule_engine",
  "override_isolation_forest",
  "override_threat_fusion",
  "override_risk_engine",
  "modify_detection_threshold",
  "execute_security_action",
  "block_ip",
  "isolate_endpoint",
  "disable_account",
]);

/**
 * Allowed AI request types.
 */
const ALLOWED_REQUEST_TYPES = new Set([
  "anomaly_explanation",
  "incident_summarization",
  "mitre_description",
  "mitigation_recommendation",
  "analyst_question",
  "executive_report",
  "knowledge_search",
  "threat_intel_lookup",
  "playbook_guidance",
]);

/**
 * Patterns in prompts that indicate blocked intent.
 */
const BLOCKED_PROMPT_PATTERNS: { pattern: RegExp; reason: string }[] = [
  {
    pattern: /\b(create|open|raise)\s+(an?\s+)?incident\b/i,
    reason: "GR-001: Incident creation blocked",
  },
  {
    pattern: /\b(close|resolve|dismiss)\s+(an?\s+)?incident\b/i,
    reason: "GR-001: Incident closure blocked",
  },
  {
    pattern: /\b(change|set|modify|update)\s+(the\s+)?severity\b/i,
    reason: "GR-002: Severity modification blocked",
  },
  {
    pattern: /\b(change|set|adjust)\s+(the\s+)?confidence\b/i,
    reason: "GR-002: Confidence modification blocked",
  },
  {
    pattern: /\bis\s+this\s+(an?\s+)?anomaly\b/i,
    reason: "GR-003: Detection decision blocked — use deterministic engines",
  },
  {
    pattern: /\bshould\s+(i|we)\s+(alert|escalate|block)\b/i,
    reason: "GR-003: Detection decision blocked",
  },
  {
    pattern: /\b(block|ban)\s+(this\s+)?ip\b/i,
    reason: "GR-010: Autonomous action blocked",
  },
  {
    pattern: /\bisolate\s+(this\s+)?(endpoint|host|machine)\b/i,
    reason: "GR-010: Autonomous action blocked",
  },
  {
    pattern: /\bdisable\s+(this\s+)?(account|user)\b/i,
    reason: "GR-010: Autonomous action blocked",
  },
];

// ─── Guardrail Engine ─────────────────────────────────────────────────────────

export class GuardrailEngine {
  /**
   * Validate an incoming AI request against all policies and boundaries.
   * Returns a structured GuardrailResult. If allowed === false, the caller
   * MUST block the request and write an audit entry.
   */
  validate(request: GuardrailRequest): GuardrailResult {
    const violations: string[] = [];
    const warnings: string[] = [];

    // ── 1. Boundary Check: Request Type ─────────────────────────
    const boundaryResult = this.checkBoundary(
      request.request_type,
      request.prompt,
    );
    if (!boundaryResult.within_boundary) {
      violations.push(...boundaryResult.violated_boundaries);
    }

    // ── 2. Policy Registry Evaluation ───────────────────────────
    const ctx: PolicyEvaluationContext = {
      request_type: request.request_type,
      evidence_age_ms: request.evidence_age_ms,
      contains_autonomous_action: BLOCKED_REQUEST_TYPES.has(
        request.request_type,
      ),
      session_tenant_mismatch:
        request.session_tenant_id !== undefined &&
        request.session_tenant_id !== request.tenant_id,
    };
    const policyEval = aiPolicyRegistry.evaluate(ctx, request.tenant_id);
    if (!policyEval.allowed) {
      for (const v of policyEval.violations) {
        violations.push(v.message);
      }
    }
    for (const w of policyEval.warnings) {
      warnings.push(w.message);
    }

    // ── 3. Risk Score ────────────────────────────────────────────
    const riskScore = this.calculateRisk(request, violations.length);

    const allowed = violations.length === 0;
    const reason = allowed ? null : violations[0];

    if (!allowed) {
      logStructured("warn", "[GuardrailEngine] Request BLOCKED", {
        tenant_id: request.tenant_id,
        user_id: request.user_id,
        request_type: request.request_type,
        violations,
        risk_score: riskScore,
      });
    }

    return {
      allowed,
      violations,
      warnings,
      policy_evaluation: policyEval,
      boundary_check: boundaryResult,
      risk_score: riskScore,
      reason,
    };
  }

  /**
   * Check whether the request type and prompt content are within AI role boundaries.
   */
  checkBoundary(requestType: string, prompt: string): BoundaryCheckResult {
    const violated: string[] = [];

    // Check request_type
    if (BLOCKED_REQUEST_TYPES.has(requestType)) {
      violated.push(
        `Request type '${requestType}' is outside AI advisory boundaries.`,
      );
    } else if (!ALLOWED_REQUEST_TYPES.has(requestType)) {
      violated.push(
        `Unknown request type '${requestType}' — not in allowed list.`,
      );
    }

    // Check prompt content for blocked patterns
    for (const { pattern, reason } of BLOCKED_PROMPT_PATTERNS) {
      if (pattern.test(prompt)) {
        violated.push(reason);
      }
    }

    return {
      within_boundary: violated.length === 0,
      violated_boundaries: violated,
    };
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private calculateRisk(
    request: GuardrailRequest,
    violationCount: number,
  ): number {
    let risk = 0.0;
    if (BLOCKED_REQUEST_TYPES.has(request.request_type)) risk += 0.5;
    if (violationCount > 0) risk += Math.min(violationCount * 0.2, 0.4);
    if (request.evidence_age_ms && request.evidence_age_ms > 30 * 60 * 1000)
      risk += 0.1;
    return Math.min(risk, 1.0);
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const guardrailEngine = new GuardrailEngine();
