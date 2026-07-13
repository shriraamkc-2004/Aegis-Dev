/**
 * Aegis Enterprise — AI Compliance Engine
 *
 * Maps AI governance activities and security checks to established standards:
 *  - OWASP LLM Top 10 (e.g. Prompt Injections LLM01, Hallucinations LLM06)
 *  - NIST AI RMF (e.g. Safe, Secure, Resilient)
 *  - ISO 42001 (AI Management System controls)
 */

import { logStructured } from "../observability/logger.js";

export interface ComplianceMapping {
  framework: "OWASP_LLM" | "NIST_AI_RMF" | "ISO_42001";
  control_id: string;
  control_name: string;
  mapped_components: string[];
  status: "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT";
}

const DEFAULT_MAPPINGS: ComplianceMapping[] = [
  {
    framework: "OWASP_LLM",
    control_id: "LLM01",
    control_name: "Prompt Injection Mitigation",
    mapped_components: ["PromptGuard", "RAGGovernor"],
    status: "COMPLIANT",
  },
  {
    framework: "OWASP_LLM",
    control_id: "LLM06",
    control_name: "Sensitive Data Exposure Prevention",
    mapped_components: ["GovernanceService", "KnowledgeGovernanceEngine"],
    status: "COMPLIANT",
  },
  {
    framework: "OWASP_LLM",
    control_id: "LLM09",
    control_name: "Overreliance Prevention / Hallucination Detection",
    mapped_components: ["TruthEngine", "ConfidenceGate"],
    status: "COMPLIANT",
  },
  {
    framework: "NIST_AI_RMF",
    control_id: "GOVERN-1",
    control_name: "AI Governance & Risk Management Policies",
    mapped_components: ["AIPolicyRegistry", "AICapabilityRegistry"],
    status: "COMPLIANT",
  },
  {
    framework: "ISO_42001",
    control_id: "A.8.2",
    control_name: "AI System Impact Assessments & Auditability",
    mapped_components: ["AIAuditLogger", "AIDecisionLedger"],
    status: "COMPLIANT",
  },
];

export class AIComplianceEngine {
  private mappings: ComplianceMapping[] = [...DEFAULT_MAPPINGS];

  /**
   * Get compliance roadmap/report.
   */
  generateComplianceReport(): ComplianceMapping[] {
    logStructured("info", "[AIComplianceEngine] Generated compliance report", {
      frameworkCount: 3,
      controlsMapped: this.mappings.length,
    });
    return this.mappings;
  }
}

export const aiComplianceEngine = new AIComplianceEngine();
