/**
 * Aegis Enterprise — Responsible AI Governance Service
 * Implements prompt versioning, policy enforcement, hallucination detection,
 * confidence evaluation, citation validation, approval workflows,
 * safe fallback enforcement, and PII/secret masking.
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface GovernanceDecision {
  response_id: string;
  evidence_sufficient: boolean;
  confidence_level: "high" | "moderate" | "low";
  confidence_score: number;
  hallucination_detected: boolean;
  citations_valid: boolean;
  requires_approval: boolean;
  pending_action: string | null;
  safe_fallback_triggered: boolean;
  pii_masked: boolean;
  policy_violations: string[];
  explanation: string;
}

export interface CopilotAuditRecord {
  id?: number;
  tenant_id: number;
  user_id: number | null;
  prompt: string;
  retrieved_documents: RetrievedDocument[];
  llm_response: string;
  confidence_score: number;
  evidence_sufficient: boolean;
  requires_approval: boolean;
  approval_granted: boolean | null;
  model_used: string;
  reasoning: string;
  ip_address: string;
  timestamp: number;
}

export interface RetrievedDocument {
  source: string;
  filename: string;
  score: number;
  collection: string;
}

export interface ApprovalDecision {
  response_id: string;
  approved: boolean;
  approver_id: number;
  notes: string;
  timestamp: number;
}

export interface PromptVersion {
  name: string;
  version: number;
  template: string;
  system_hint: string;
  variables: Record<string, string>;
  is_active: boolean;
  governance_reviewed: boolean;
}

// ─── Configuration ──────────────────────────────────────────────────────────────

const CONFIDENCE_HIGH = 0.80;
const CONFIDENCE_MODERATE = 0.50;
const CONFIDENCE_LOW = 0.0;

const HIGH_IMPACT_ACTIONS = [
  "isolate_endpoint",
  "block_ip",
  "block_user",
  "disable_account",
  "revoke_credentials",
  "modify_security_controls",
  "shutdown_service",
  "change_detection_threshold",
  "execute_mitigation",
];

// ─── AI Security Boundaries (Hard-Coded Prohibitions) ───────────────────────────

export interface AIBoundary {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high";
  enforcement: "hard_block" | "require_approval" | "audit_only";
}

export const AI_BOUNDARIES: AIBoundary[] = [
  { id: "BOUNDARY_001", name: "No Automatic IP Blocking", description: "AI MUST NEVER automatically block IP addresses.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_002", name: "No Endpoint Isolation", description: "AI MUST NEVER automatically isolate endpoints.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_003", name: "No Account Disabling", description: "AI MUST NEVER automatically disable user accounts.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_004", name: "No Threshold Alteration", description: "AI MUST NEVER automatically alter anomaly detection thresholds.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_005", name: "No Mitigation Execution", description: "AI MUST NEVER automatically execute mitigation commands.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_006", name: "No RBAC Override", description: "AI MUST NEVER override Role-Based Access Control permissions.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_007", name: "No Cross-Tenant Access", description: "AI MUST NEVER access data belonging to another tenant.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_008", name: "No Secret Exposure", description: "AI MUST NEVER expose secrets, credentials, or restricted information.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_009", name: "No Evidence Fabrication", description: "AI MUST NEVER fabricate evidence or citations.", severity: "critical", enforcement: "hard_block" },
  { id: "BOUNDARY_010", name: "No Unsupported Claims", description: "AI MUST NEVER provide answers unsupported by retrieved knowledge.", severity: "high", enforcement: "hard_block" },
];

// Patterns that indicate boundary violations in AI responses
const BOUNDARY_VIOLATION_PATTERNS: { boundary: string; patterns: RegExp[] }[] = [
  {
    boundary: "BOUNDARY_001",
    patterns: [
      /\b(blocking|blocked|will\s+block)\s+(ip|address|host)\b/i,
      /\bip\s+(blocking|blacklist|firewall\s+rule)\s+(applied|executed|activated)\b/i,
    ],
  },
  {
    boundary: "BOUNDARY_002",
    patterns: [
      /\b(isolating|isolated|will\s+isolate)\s+(endpoint|host|machine|device)\b/i,
      /\bendpoint\s+(quarantine|isolation)\s+(applied|executed)\b/i,
    ],
  },
  {
    boundary: "BOUNDARY_003",
    patterns: [
      /\b(disabling|disabled|will\s+disable)\s+(account|user|credential)\b/i,
      /\baccount\s+(disabled|locked|suspended)\s+(automatically|now)\b/i,
    ],
  },
  {
    boundary: "BOUNDARY_004",
    patterns: [
      /\b(changing|changed|adjusted|modifying)\s+(threshold|sensitivity|detection\s+parameter)\b/i,
      /\bthreshold\s+(set|changed|adjusted)\s+to\b/i,
    ],
  },
  {
    boundary: "BOUNDARY_005",
    patterns: [
      /\b(executing|executed|running)\s+(mitigation|remediation|countermeasure)\b/i,
      /\bmitigation\s+(applied|deployed|executed|activated)\b/i,
    ],
  },
  {
    boundary: "BOUNDARY_006",
    patterns: [
      /\b(overriding|bypassing|escalating)\s+(rbac|permission|access\s+control|role)\b/i,
      /\bprivilege\s+(escalation|elevation)\s+(applied|granted)\b/i,
    ],
  },
  {
    boundary: "BOUNDARY_008",
    patterns: [
      /\b(api[_\s]?key|password|secret|credential|token)\s*[:=]\s*["']?[A-Za-z0-9_\-]{8,}/gi,
    ],
  },
];

const SAFE_FALLBACK_RESPONSE =
  "I could not find sufficient evidence in the indexed knowledge base to answer this confidently. " +
  "Please provide more context, upload relevant documentation, or consult a senior analyst.";

// PII patterns for masking
const PII_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "[SSN]" },
  { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, label: "[EMAIL]" },
  { pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, label: "[IP]" },
  { pattern: /\b(?:sk|pk|ak|key)[-_]?[A-Za-z0-9]{16,}\b/gi, label: "[API_KEY]" },
  { pattern: /(?:password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']+/gi, label: "[SECRET]" },
];

// ─── Governance Service ─────────────────────────────────────────────────────────

export class GovernanceService {
  private pendingApprovals: Map<string, ApprovalDecision> = new Map();
  private auditLog: CopilotAuditRecord[] = [];

  // ─── Confidence Framework ───────────────────────────────────────────────────

  evaluateConfidence(score: number): "high" | "moderate" | "low" {
    if (score >= CONFIDENCE_HIGH) return "high";
    if (score >= CONFIDENCE_MODERATE) return "moderate";
    return "low";
  }

  isEvidenceSufficient(score: number, sourceCount: number): boolean {
    return score >= CONFIDENCE_MODERATE && sourceCount > 0;
  }

  // ─── Hallucination Detection ────────────────────────────────────────────────

  detectHallucination(
    response: string,
    sources: RetrievedDocument[],
    confidence: number
  ): boolean {
    // If no sources and high-confidence claims detected, likely hallucination
    if (sources.length === 0 && confidence < CONFIDENCE_MODERATE) return true;

    // Check for unsupported absolute claims
    const absolutePatterns = /\b(always|never|definitely|certainly|guaranteed|100%)\b/gi;
    const hasAbsoluteClaims = absolutePatterns.test(response);
    if (hasAbsoluteClaims && confidence < CONFIDENCE_HIGH && sources.length < 2) {
      return true;
    }

    return false;
  }

  // ─── Citation Validation ────────────────────────────────────────────────────

  validateCitations(
    response: string,
    sources: RetrievedDocument[]
  ): { valid: boolean; citedCount: number; uncited: string[] } {
    if (sources.length === 0) {
      return { valid: false, citedCount: 0, uncited: [] };
    }

    const cited: string[] = [];
    const uncited: string[] = [];

    for (const src of sources) {
      const filename = src.filename || src.source || "unknown";
      // Check if response references the source (by name, index, or collection)
      const isReferenced =
        response.includes(filename) ||
        response.includes(src.collection) ||
        response.toLowerCase().includes("source") ||
        response.toLowerCase().includes("evidence") ||
        response.toLowerCase().includes("retrieved");

      if (isReferenced) {
        cited.push(filename);
      } else {
        uncited.push(filename);
      }
    }

    return {
      valid: cited.length > 0,
      citedCount: cited.length,
      uncited,
    };
  }

  // ─── High-Impact Action Detection (Human-in-the-Loop) ───────────────────────

  detectHighImpactAction(prompt: string, response: string): string | null {
    const combined = (prompt + " " + response).toLowerCase();
    for (const action of HIGH_IMPACT_ACTIONS) {
      const normalized = action.replace(/_/g, " ");
      if (combined.includes(normalized) || combined.includes(action)) {
        return action;
      }
    }
    return null;
  }

  // ─── PII & Secret Masking ──────────────────────────────────────────────────

  maskPII(text: string): { masked: string; wasMasked: boolean } {
    let result = text;
    let wasMasked = false;
    for (const { pattern, label } of PII_PATTERNS) {
      const newResult = result.replace(pattern, label);
      if (newResult !== result) wasMasked = true;
      result = newResult;
    }
    return { masked: result, wasMasked };
  }

  // ─── Policy Enforcement ─────────────────────────────────────────────────────

  checkPolicyViolations(prompt: string, response: string): string[] {
    const violations: string[] = [];
    const combined = (prompt + " " + response).toLowerCase();

    // Check for unauthorized autonomous actions
    const autonomousPatterns = [
      /\bexecuting\s+(block|isolate|disable|shutdown)\b/i,
      /\bautonomous\s+(mitigation|response|action)\b/i,
      /\bautomatically\s+(blocked|isolated|disabled)\b/i,
    ];

    for (const pat of autonomousPatterns) {
      if (pat.test(combined)) {
        violations.push("AUTONOMOUS_ACTION_DETECTED: AI must not execute actions autonomously");
      }
    }

    // Check for speculative language without evidence
    const speculativePatterns = [
      /\bprobably\s+(a\s+)?(hack|attack|breach|exploit)\b/i,
      /\bmight\s+be\s+(a\s+)?(hack|attack|breach)\b/i,
    ];

    for (const pat of speculativePatterns) {
      if (pat.test(combined)) {
        violations.push("SPECULATIVE_CLAIM: Response contains unsupported speculation");
      }
    }

    return violations;
  }

  // ─── AI Security Boundary Enforcement ─────────────────────────────────────

  enforceAIBoundaries(
    response: string,
    prompt: string,
    tenantId: number | null
  ): { violations: string[]; blocked: boolean; details: string[] } {
    const violations: string[] = [];
    const details: string[] = [];
    const combined = (prompt + " " + response).toLowerCase();

    for (const { boundary, patterns } of BOUNDARY_VIOLATION_PATTERNS) {
      for (const pattern of patterns) {
        if (pattern.test(response)) {
          const boundaryDef = AI_BOUNDARIES.find((b) => b.id === boundary);
          if (boundaryDef) {
            violations.push(boundary);
            details.push(`[${boundary}] ${boundaryDef.name}: ${boundaryDef.description}`);
          }
          break;
        }
      }
    }

    // BOUNDARY_007: Cross-tenant check (enforced at data layer, but audit if prompt references other tenants)
    const crossTenantPatterns = [
      /\b(other\s+tenant|another\s+organization|tenant\s+\d+)\b/i,
      /\baccess\s+(all|other)\s+(tenants?|organizations?|companies)\b/i,
    ];
    for (const pattern of crossTenantPatterns) {
      if (pattern.test(combined)) {
        violations.push("BOUNDARY_007");
        details.push("[BOUNDARY_007] No Cross-Tenant Access: AI must not access data belonging to another tenant.");
        break;
      }
    }

    // BOUNDARY_010: Unsupported claims — if response makes definitive claims without sources
    const unsupportedPatterns = [
      /\b(definitely|certainly|guaranteed|100%)\s+(a\s+)?(threat|attack|breach|exploit|vulnerability)\b/i,
      /\b(confirmed|verified)\s+(that\s+this\s+is\s+a\s+)?(attack|breach|threat)\b/i,
    ];
    for (const pattern of unsupportedPatterns) {
      if (pattern.test(response)) {
        violations.push("BOUNDARY_010");
        details.push("[BOUNDARY_010] No Unsupported Claims: Response contains definitive claims without sufficient evidence.");
        break;
      }
    }

    return {
      violations,
      blocked: violations.length > 0,
      details,
    };
  }

  // ─── Full Governance Evaluation ─────────────────────────────────────────────

  evaluate(
    responseId: string,
    rawResponse: string,
    sources: RetrievedDocument[],
    confidence: number,
    userPrompt: string,
    modelUsed: string = "gemini-2.5-flash",
    tenantId: number | null = null
  ): GovernanceDecision {
    const confidenceLevel = this.evaluateConfidence(confidence);
    const evidenceSufficient = this.isEvidenceSufficient(confidence, sources.length);
    const hallucinationDetected = this.detectHallucination(rawResponse, sources, confidence);
    const citationValidation = this.validateCitations(rawResponse, sources);
    const highImpactAction = this.detectHighImpactAction(userPrompt, rawResponse);
    const policyViolations = this.checkPolicyViolations(userPrompt, rawResponse);
    const { wasMasked } = this.maskPII(rawResponse);

    // AI Security Boundary Enforcement
    const boundaryCheck = this.enforceAIBoundaries(rawResponse, userPrompt, tenantId);
    if (boundaryCheck.violations.length > 0) {
      policyViolations.push(...boundaryCheck.details);
    }

    const safeFallbackTriggered = !evidenceSufficient || hallucinationDetected || boundaryCheck.blocked;

    // Build explanation
    const explanationParts: string[] = [
      `Confidence: ${confidence.toFixed(2)} (${confidenceLevel})`,
      `Sources retrieved: ${sources.length}`,
      `Evidence sufficient: ${evidenceSufficient}`,
      `Hallucination check: ${hallucinationDetected ? "FLAGGED" : "PASS"}`,
      `Citation validation: ${citationValidation.valid ? "PASS" : "WARN"} (${citationValidation.citedCount}/${sources.length} cited)`,
      `Model: ${modelUsed} (Google Gemini 2.5 Flash)`,
    ];
    if (highImpactAction) {
      explanationParts.push(`⚠ HIGH-IMPACT ACTION: ${highImpactAction} requires analyst approval`);
    }
    if (policyViolations.length > 0) {
      explanationParts.push(`Policy violations: ${policyViolations.join(", ")}`);
    }

    return {
      response_id: responseId,
      evidence_sufficient: evidenceSufficient,
      confidence_level: confidenceLevel,
      confidence_score: confidence,
      hallucination_detected: hallucinationDetected,
      citations_valid: citationValidation.valid,
      requires_approval: highImpactAction !== null,
      pending_action: highImpactAction,
      safe_fallback_triggered: safeFallbackTriggered,
      pii_masked: wasMasked,
      policy_violations: policyViolations,
      explanation: explanationParts.join("\n"),
    };
  }

  // ─── Safe Fallback ─────────────────────────────────────────────────────────

  getSafeFallbackResponse(): string {
    return SAFE_FALLBACK_RESPONSE;
  }

  // ─── Approval Workflow ──────────────────────────────────────────────────────

  recordApproval(decision: ApprovalDecision): void {
    this.pendingApprovals.set(decision.response_id, decision);
  }

  getApproval(responseId: string): ApprovalDecision | undefined {
    return this.pendingApprovals.get(responseId);
  }

  getPendingApprovals(): ApprovalDecision[] {
    return Array.from(this.pendingApprovals.values());
  }

  // ─── Audit Log ──────────────────────────────────────────────────────────────

  recordAudit(record: CopilotAuditRecord): void {
    this.auditLog.push(record);
    // Keep in-memory log bounded
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-500);
    }
  }

  getAuditLog(limit: number = 50): CopilotAuditRecord[] {
    return this.auditLog.slice(-limit).reverse();
  }

  // ─── Health ─────────────────────────────────────────────────────────────────

  getStatus() {
    return {
      service: "governance",
      pending_approvals: this.pendingApprovals.size,
      audit_log_size: this.auditLog.length,
      confidence_thresholds: {
        high: CONFIDENCE_HIGH,
        moderate: CONFIDENCE_MODERATE,
        low: CONFIDENCE_LOW,
      },
      high_impact_actions: HIGH_IMPACT_ACTIONS,
      ai_boundaries: AI_BOUNDARIES.map((b) => ({
        id: b.id,
        name: b.name,
        severity: b.severity,
        enforcement: b.enforcement,
      })),
      ai_boundaries_count: AI_BOUNDARIES.length,
    };
  }

  // ─── Boundary Notice (for frontend display) ──────────────────────────────

  getBoundaryNotice(): {
    enabled: boolean;
    advisory_text: string;
    boundaries: AIBoundary[];
    human_approval_required: string;
  } {
    return {
      enabled: true,
      advisory_text:
        "This system provides advisory recommendations only. " +
        "Human validation is required before executing high-impact security actions.",
      boundaries: AI_BOUNDARIES,
      human_approval_required:
        "All high-impact recommendations must transition to PENDING_APPROVAL before execution. " +
        "Explicit analyst authorization is required. All approval decisions are recorded in audit logs.",
    };
  }
}

// Singleton instance
export const governanceService = new GovernanceService();
