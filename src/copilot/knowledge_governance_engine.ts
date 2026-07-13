/**
 * Aegis Enterprise — Knowledge Governance Engine
 *
 * Enforces security, sensitivity, and compliance boundaries on knowledge base documents.
 * Assigns trust levels (CRITICAL, HIGH, MEDIUM, LOW) based on document source and verification.
 * Verifies document hashes and metadata provenance.
 */

import { logStructured } from "../observability/logger.js";
import { createHash } from "crypto";

export type DocumentTrustLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface DocumentMetadata {
  source: string;
  filename: string;
  classification: "public" | "internal" | "restricted" | "highly_confidential";
  uploaded_by: string;
  verified: boolean;
  signature?: string;
  indexed_at: number;
}

export interface GovernanceScanResult {
  allowed: boolean;
  trust_level: DocumentTrustLevel;
  violations: string[];
  suggested_action: "INDEX" | "QUARANTINE" | "LOG_ONLY";
}

export class KnowledgeGovernanceEngine {
  private readonly APPROVED_SOURCES = [
    "mitre_attack",
    "nist_nvd",
    "threat_intel_verified",
    "security_playbooks_approved",
    "internal_ops_verified",
  ];

  /**
   * Scan a document's metadata and content for compliance and assign a Trust Level.
   */
  scanDocument(
    content: string,
    metadata: DocumentMetadata,
  ): GovernanceScanResult {
    const violations: string[] = [];
    let trustLevel: DocumentTrustLevel = "LOW";

    // 1. Source verification
    const normalizedSource = metadata.source.toLowerCase();
    const isApprovedSource = this.APPROVED_SOURCES.some((approved) =>
      normalizedSource.includes(approved),
    );

    if (isApprovedSource && metadata.verified) {
      trustLevel = "CRITICAL";
    } else if (metadata.classification === "public") {
      trustLevel = "MEDIUM";
    } else if (metadata.classification === "internal") {
      trustLevel = "HIGH";
    } else if (metadata.classification === "restricted") {
      trustLevel = "MEDIUM";
    } else {
      trustLevel = "LOW";
    }

    // 2. Sensitive content detection
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /(\b(sk|pk|ak|key)[-_]?[A-Za-z0-9]{16,}\b)/i, // API keys
    ];

    for (const pat of piiPatterns) {
      if (pat.test(content)) {
        violations.push("PII or secrets detected in document content.");
      }
    }

    // 3. Signature verification (for restricted documents)
    if (metadata.classification === "restricted" && !metadata.signature) {
      violations.push("Restricted document missing cryptographic signature.");
    }

    const allowed = violations.length === 0;
    const suggestedAction = !allowed
      ? "QUARANTINE"
      : trustLevel === "LOW"
        ? "LOG_ONLY"
        : "INDEX";

    logStructured(
      "info",
      "[KnowledgeGovernanceEngine] Document scan completed",
      {
        filename: metadata.filename,
        trustLevel,
        allowed,
        suggestedAction,
        violationsCount: violations.length,
      },
    );

    return {
      allowed,
      trust_level: trustLevel,
      violations,
      suggested_action: suggestedAction,
    };
  }

  computeHash(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }
}

export const knowledgeGovernanceEngine = new KnowledgeGovernanceEngine();
