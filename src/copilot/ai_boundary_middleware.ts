/**
 * Aegis Enterprise — AI Boundary Enforcement Middleware
 * Wraps copilot responses with mandatory boundary checks.
 * Ensures AI NEVER exceeds defined operational limits.
 * Implements safe failure responses when services are unavailable.
 */

import { governanceService, type GovernanceDecision, type RetrievedDocument } from "./governance_service.js";
import { healthMonitorService } from "./health_monitor.js";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface CopilotResponseMetadata {
  governance: GovernanceDecision | null;
  boundary_check: {
    violations: string[];
    blocked: boolean;
    details: string[];
  };
  service_health: {
    all_healthy: boolean;
    degraded_services: string[];
    fallback_active: boolean;
  };
  safe_fallback_used: boolean;
  requires_human_approval: boolean;
  approval_action: string | null;
}

export interface ProcessedCopilotResponse {
  response: string;
  metadata: CopilotResponseMetadata;
}

// ─── Safe Failure Response ──────────────────────────────────────────────────────

const SAFE_FAILURE_RESPONSE =
  "I could not find sufficient evidence in the indexed knowledge base to answer this confidently. " +
  "I recommend escalating this to a human analyst for investigation.\n\n" +
  "⚠ This response was generated in safe-failure mode due to service limitations.";

// ─── Process Copilot Response ───────────────────────────────────────────────────

/**
 * Process a raw copilot response through all governance and boundary checks.
 * This is the central enforcement point for all AI security boundaries.
 */
export function processCopilotResponse(
  rawResponse: string,
  userPrompt: string,
  sources: RetrievedDocument[],
  confidence: number,
  tenantId: number | null = null,
  sessionId: string | null = null,
  modelUsed: string = "gemini-2.5-flash"
): ProcessedCopilotResponse {
  const responseId = sessionId || `resp_${Date.now()}`;

  // Step 1: Check service health — if critical services are down, return safe fallback
  const serviceHealth = getServiceHealth();
  if (!serviceHealth.all_healthy && serviceHealth.fallback_active) {
    // If Gemini or Qdrant is down, use safe fallback
    const degradedList = serviceHealth.degraded_services.join(", ");
    const fallbackMsg = healthMonitorService.getFallbackMessage(
      serviceHealth.degraded_services[0] as any
    );

    const governance = governanceService.evaluate(
      responseId,
      fallbackMsg,
      [],
      0,
      userPrompt,
      modelUsed,
      tenantId
    );

    // Record audit
    governanceService.recordAudit({
      tenant_id: tenantId || 1,
      user_id: null,
      prompt: userPrompt,
      retrieved_documents: [],
      llm_response: fallbackMsg,
      confidence_score: 0,
      evidence_sufficient: false,
      requires_approval: false,
      approval_granted: null,
      model_used: modelUsed,
      reasoning: `Safe failure: degraded services [${degradedList}]`,
      ip_address: "system",
      timestamp: Date.now(),
    });

    return {
      response: fallbackMsg,
      metadata: {
        governance,
        boundary_check: { violations: [], blocked: false, details: [] },
        service_health: serviceHealth,
        safe_fallback_used: true,
        requires_human_approval: false,
        approval_action: null,
      },
    };
  }

  // Step 2: Run governance evaluation (includes boundary enforcement)
  const governance = governanceService.evaluate(
    responseId,
    rawResponse,
    sources,
    confidence,
    userPrompt,
    modelUsed,
    tenantId
  );

  // Step 3: Run explicit boundary check
  const boundaryCheck = governanceService.enforceAIBoundaries(rawResponse, userPrompt, tenantId);

  // Step 4: Apply PII masking
  const { masked } = governanceService.maskPII(rawResponse);

  // Step 5: Determine final response
  let finalResponse: string;
  let safeFallbackUsed = false;

  if (governance.safe_fallback_triggered || boundaryCheck.blocked) {
    // Replace response with safe fallback if governance flags it
    safeFallbackUsed = true;
    finalResponse = governanceService.getSafeFallbackResponse();

    // Add context about WHY fallback was triggered
    const reasons: string[] = [];
    if (!governance.evidence_sufficient) reasons.push("insufficient evidence");
    if (governance.hallucination_detected) reasons.push("potential hallucination detected");
    if (boundaryCheck.blocked) reasons.push(`AI boundary violations: ${boundaryCheck.violations.join(", ")}`);

    finalResponse += `\n\n⚠ Safe fallback triggered: ${reasons.join("; ")}`;
    finalResponse += "\n\nPlease escalate to a human analyst for investigation.";
  } else {
    finalResponse = masked;
  }

  // Step 6: Record audit
  governanceService.recordAudit({
    tenant_id: tenantId || 1,
    user_id: null,
    prompt: userPrompt,
    retrieved_documents: sources,
    llm_response: finalResponse,
    confidence_score: confidence,
    evidence_sufficient: governance.evidence_sufficient,
    requires_approval: governance.requires_approval,
    approval_granted: null,
    model_used: modelUsed,
    reasoning: governance.explanation,
    ip_address: "system",
    timestamp: Date.now(),
  });

  return {
    response: finalResponse,
    metadata: {
      governance,
      boundary_check: boundaryCheck,
      service_health: serviceHealth,
      safe_fallback_used: safeFallbackUsed,
      requires_human_approval: governance.requires_approval,
      approval_action: governance.pending_action,
    },
  };
}

// ─── Service Health Aggregation ─────────────────────────────────────────────────

function getServiceHealth(): {
  all_healthy: boolean;
  degraded_services: string[];
  fallback_active: boolean;
} {
  const status = healthMonitorService.getStatus();
  const degraded: string[] = [];
  let fallbackActive = false;

  for (const [name, health] of Object.entries(status.services)) {
    if (health.status === "unhealthy") {
      degraded.push(name);
      // Gemini or Qdrant being down triggers fallback
      if (name === "gemini" || name === "qdrant" || name === "copilot_python") {
        fallbackActive = true;
      }
    }
  }

  return {
    all_healthy: degraded.length === 0,
    degraded_services: degraded,
    fallback_active: fallbackActive,
  };
}

// ─── Pre-Request Validation ─────────────────────────────────────────────────────

/**
 * Validate a copilot request BEFORE sending to AI.
 * Blocks requests that would violate boundaries.
 */
export function validateCopilotRequest(
  prompt: string,
  tenantId: number | null
): { allowed: boolean; reason: string | null } {
  // Check for prompts requesting prohibited actions
  const prohibitedPatterns = [
    { pattern: /\b(block|blacklist)\s+(this\s+)?ip\b/i, boundary: "BOUNDARY_001" },
    { pattern: /\bisolate\s+(this\s+)?(endpoint|host|machine)\b/i, boundary: "BOUNDARY_002" },
    { pattern: /\bdisable\s+(this\s+)?(account|user)\b/i, boundary: "BOUNDARY_003" },
    { pattern: /\b(change|modify|adjust)\s+(the\s+)?(threshold|sensitivity)\b/i, boundary: "BOUNDARY_004" },
    { pattern: /\b(execute|run|apply)\s+(mitigation|remediation|countermeasure)\b/i, boundary: "BOUNDARY_005" },
    { pattern: /\b(override|bypass)\s+(rbac|permission|access)\b/i, boundary: "BOUNDARY_006" },
    { pattern: /\b(show|get|access)\s+(other|another)\s+(tenant|org)\b/i, boundary: "BOUNDARY_007" },
    { pattern: /\b(show|reveal|display)\s+(password|secret|api\s*key|credential)\b/i, boundary: "BOUNDARY_008" },
  ];

  for (const { pattern, boundary } of prohibitedPatterns) {
    if (pattern.test(prompt)) {
      const boundaryDef = governanceService.getStatus().ai_boundaries?.find((b: any) => b.id === boundary);
      return {
        allowed: false,
        reason:
          `⚠ Request blocked by AI Security Boundary [${boundary}]: ` +
          `${boundaryDef?.name || "Unknown boundary"}.\n\n` +
          "The Aegis AI provides advisory recommendations only. " +
          "This action requires explicit human authorization.",
      };
    }
  }

  return { allowed: true, reason: null };
}

// ─── Express Middleware ─────────────────────────────────────────────────────────

/**
 * Express middleware that attaches boundary metadata to copilot responses.
 */
export function aiBoundaryMiddleware(req: any, res: any, next: any): void {
  // Attach boundary notice to all copilot-related requests
  if (req.path?.includes("/copilot")) {
    res.setHeader("X-AI-Boundary-Notice", "Advisory Only - Human Approval Required for High-Impact Actions");
  }
  next();
}
