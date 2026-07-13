/**
 * Aegis Enterprise — Truth Engine
 *
 * Promotes the Response Validator to a first-class governance component.
 * Parses every factual claim in an AI response and verifies it against the
 * deterministic EvidenceBundle. Calculates a Truth Score (0.0–1.0).
 *
 * Truth Score Thresholds:
 *   ≥ 0.95 → HIGH confidence badge
 *   0.85–0.94 → MEDIUM confidence badge
 *   0.70–0.84 → LOW confidence + review recommendation
 *   < 0.70  → REJECT — trigger Safe Fallback (never deliver a partial hallucination)
 *
 * The Truth Engine NEVER modifies the response content — it only validates
 * and annotates. The Safe Fallback is triggered by the orchestrator.
 */

import { createHash } from "crypto";
import { logStructured } from "../observability/logger.js";
import type { EvidenceBundle } from "./evidence_validator.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface FactualClaim {
  type:
    | "cve_id"
    | "mitre_technique"
    | "ioc_ip"
    | "ioc_domain"
    | "ioc_hash"
    | "threat_actor"
    | "confidence_claim"
    | "severity_claim"
    | "generic";
  value: string;
  context: string; // Surrounding text snippet (50 chars)
  verified: boolean;
  verification_source: string | null;
  severity_weight: number; // Penalty weight for unverified claims
}

export type TruthBadge = "HIGH" | "MEDIUM" | "LOW" | "REJECTED";

export interface TruthEngineResult {
  truth_score: number; // 0.0 – 1.0
  badge: TruthBadge;
  claims: FactualClaim[];
  hallucinations: string[]; // Descriptions of detected hallucinations
  response_hash: string; // SHA-256 of raw response for integrity
  safe_fallback_triggered: boolean;
  rejection_reason: string | null;
  verified_count: number;
  total_claims: number;
}

// ─── Thresholds and Weights ───────────────────────────────────────────────────

const TRUTH_HIGH = 0.95;
const TRUTH_MEDIUM = 0.85;
const TRUTH_LOW_OK = 0.7; // Below this → REJECTED

const SEVERITY_WEIGHTS: Record<FactualClaim["type"], number> = {
  cve_id: 0.8,
  mitre_technique: 0.6,
  ioc_ip: 1.0,
  ioc_domain: 1.0,
  ioc_hash: 1.0,
  threat_actor: 0.7,
  confidence_claim: 0.5,
  severity_claim: 0.5,
  generic: 0.2,
};

// ─── Regex Extractors ─────────────────────────────────────────────────────────

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/gi;
const MITRE_PATTERN = /T\d{4}(?:\.\d{3})?/g;
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_PATTERN =
  /\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|in|co|gov|edu|xyz|top|biz)\b/gi;
const HASH_MD5 = /\b[a-fA-F0-9]{32}\b/g;
const HASH_SHA1 = /\b[a-fA-F0-9]{40}\b/g;
const HASH_SHA256 = /\b[a-fA-F0-9]{64}\b/g;
const CONFIDENCE_CLAIM = /\b(\d{1,3}(?:\.\d+)?)\s*%\s*confidence\b/gi;
const SEVERITY_CLAIM = /\b(low|medium|high|critical)\s+severity\b/gi;

// ─── Truth Engine ─────────────────────────────────────────────────────────────

export class TruthEngine {
  /**
   * Validate an AI response against the deterministic evidence bundle.
   * Returns a TruthEngineResult. If safe_fallback_triggered === true, the
   * orchestrator must discard the LLM response and return a safe fallback.
   */
  validate(rawResponse: string, evidence: EvidenceBundle): TruthEngineResult {
    const responseHash = createHash("sha256").update(rawResponse).digest("hex");
    const claims: FactualClaim[] = [];
    const hallucinations: string[] = [];

    // ── Extract and verify all claim types ──────────────────────
    this.extractCVEs(rawResponse, evidence, claims, hallucinations);
    this.extractMITRE(rawResponse, evidence, claims, hallucinations);
    this.extractIPs(rawResponse, evidence, claims, hallucinations);
    this.extractDomains(rawResponse, evidence, claims, hallucinations);
    this.extractHashes(rawResponse, evidence, claims, hallucinations);
    this.extractThreatActors(rawResponse, evidence, claims, hallucinations);
    this.extractConfidenceClaims(rawResponse, evidence, claims, hallucinations);
    this.extractSeverityClaims(rawResponse, evidence, claims, hallucinations);

    // ── Calculate Truth Score ────────────────────────────────────
    const truthScore = this.calculateTruthScore(claims);
    const badge = this.badge(truthScore);
    const safeFallback = truthScore < TRUTH_LOW_OK || hallucinations.length > 0;

    if (safeFallback) {
      logStructured("error", "[TruthEngine] Safe fallback triggered", {
        anomaly_id: evidence.anomaly_id,
        truth_score: truthScore,
        hallucinations,
        total_claims: claims.length,
      });
    } else {
      logStructured("info", "[TruthEngine] Validation passed", {
        anomaly_id: evidence.anomaly_id,
        truth_score: truthScore,
        badge,
        verified: claims.filter((c) => c.verified).length,
        total: claims.length,
      });
    }

    return {
      truth_score: truthScore,
      badge,
      claims,
      hallucinations,
      response_hash: responseHash,
      safe_fallback_triggered: safeFallback,
      rejection_reason: safeFallback
        ? `Truth Score ${truthScore.toFixed(2)} below threshold or hallucinations detected: ${hallucinations.join("; ")}`
        : null,
      verified_count: claims.filter((c) => c.verified).length,
      total_claims: claims.length,
    };
  }

  // ── Extractors ────────────────────────────────────────────────────────────

  private extractCVEs(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const matches = [...text.matchAll(CVE_PATTERN)];
    // Valid CVE format: CVE-YYYY-NNNNN
    const validFormat = /^CVE-\d{4}-\d{4,7}$/;
    for (const m of matches) {
      const value = m[0];
      const formatOk = validFormat.test(value);
      // Check if present in threat intelligence
      const inThreatIntel = ev.threat_intelligence.some(
        (ti) => ti.indicator_value === value,
      );
      const verified = formatOk && inThreatIntel;
      if (!formatOk) {
        hallucinations.push(`Invalid CVE format: ${value}`);
      } else if (!inThreatIntel) {
        hallucinations.push(
          `CVE ${value} not in threat intelligence — possible fabrication`,
        );
      }
      claims.push({
        type: "cve_id",
        value,
        context: this.context(text, m.index ?? 0),
        verified,
        verification_source: inThreatIntel ? "threat_intelligence" : null,
        severity_weight: SEVERITY_WEIGHTS["cve_id"],
      });
    }
  }

  private extractMITRE(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const matches = [...text.matchAll(MITRE_PATTERN)];
    const mappingIds = new Set(ev.mitre_mappings.map((m) => m.technique_id));
    for (const m of matches) {
      const value = m[0];
      const inMappings = mappingIds.has(value);
      if (!inMappings) {
        hallucinations.push(
          `MITRE technique ${value} not in evidence mitre_mappings — possible fabrication`,
        );
      }
      claims.push({
        type: "mitre_technique",
        value,
        context: this.context(text, m.index ?? 0),
        verified: inMappings,
        verification_source: inMappings ? "mitre_mappings" : null,
        severity_weight: SEVERITY_WEIGHTS["mitre_technique"],
      });
    }
  }

  private extractIPs(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const matches = [...text.matchAll(IPV4_PATTERN)];
    const tiIPs = new Set(
      ev.threat_intelligence
        .filter((ti) => ti.indicator_type === "ip")
        .map((ti) => ti.indicator_value),
    );
    const assetIP = ev.asset_context?.ip_address ?? null;
    for (const m of matches) {
      const value = m[0];
      // RFC 1918 / loopback — allowed without verification
      if (this.isPrivateOrLoopback(value)) continue;
      const inTI = tiIPs.has(value);
      const isAssetIP = value === assetIP;
      const verified = inTI || isAssetIP;
      if (!verified) {
        hallucinations.push(
          `IP ${value} not in threat intelligence or asset context — possible fabrication`,
        );
      }
      claims.push({
        type: "ioc_ip",
        value,
        context: this.context(text, m.index ?? 0),
        verified,
        verification_source: inTI
          ? "threat_intelligence"
          : isAssetIP
            ? "asset_context"
            : null,
        severity_weight: SEVERITY_WEIGHTS["ioc_ip"],
      });
    }
  }

  private extractDomains(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const matches = [...text.matchAll(DOMAIN_PATTERN)];
    const tiDomains = new Set(
      ev.threat_intelligence
        .filter((ti) => ti.indicator_type === "domain")
        .map((ti) => ti.indicator_value.toLowerCase()),
    );
    for (const m of matches) {
      const value = m[0].toLowerCase();
      const inTI = tiDomains.has(value);
      if (!inTI) {
        hallucinations.push(
          `Domain ${value} not in threat intelligence — verify before use`,
        );
      }
      claims.push({
        type: "ioc_domain",
        value,
        context: this.context(text, m.index ?? 0),
        verified: inTI,
        verification_source: inTI ? "threat_intelligence" : null,
        severity_weight: SEVERITY_WEIGHTS["ioc_domain"],
      });
    }
  }

  private extractHashes(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const tiHashes = new Set(
      ev.threat_intelligence
        .filter((ti) => ti.indicator_type === "hash")
        .map((ti) => ti.indicator_value.toLowerCase()),
    );
    const allHashPatterns = [HASH_MD5, HASH_SHA1, HASH_SHA256];
    for (const pat of allHashPatterns) {
      pat.lastIndex = 0;
      const matches = [...text.matchAll(pat)];
      for (const m of matches) {
        const value = m[0].toLowerCase();
        const inTI = tiHashes.has(value);
        if (!inTI) {
          hallucinations.push(
            `Hash ${value.slice(0, 8)}… not in threat intelligence — possible fabrication`,
          );
        }
        claims.push({
          type: "ioc_hash",
          value,
          context: this.context(text, m.index ?? 0),
          verified: inTI,
          verification_source: inTI ? "threat_intelligence" : null,
          severity_weight: SEVERITY_WEIGHTS["ioc_hash"],
        });
      }
    }
  }

  private extractThreatActors(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    // Extract known threat actor names from threat intelligence descriptions/tags
    const knownActors = new Set<string>();
    for (const ti of ev.threat_intelligence) {
      for (const tag of ti.tags) {
        knownActors.add(tag.toLowerCase());
      }
      if (ti.description) {
        // Actor name pattern: "APT" + digits, or "Lazarus", "Cozy Bear" etc.
        const actorPattern =
          /\b(APT\d{1,3}|Lazarus|Cozy\s+Bear|Fancy\s+Bear|Sandworm|Carbanak|FIN\d|TA\d{3,4})\b/gi;
        const actorMatches = [...ti.description.matchAll(actorPattern)];
        for (const a of actorMatches) knownActors.add(a[0].toLowerCase());
      }
    }

    const actorPattern =
      /\b(APT\d{1,3}|Lazarus\s+Group|Cozy\s+Bear|Fancy\s+Bear|Sandworm|Carbanak|FIN\d|TA\d{3,4})\b/gi;
    const matches = [...text.matchAll(actorPattern)];
    for (const m of matches) {
      const value = m[0];
      const inTI = knownActors.has(value.toLowerCase());
      if (!inTI) {
        hallucinations.push(
          `Threat actor '${value}' not in threat intelligence — possible fabrication`,
        );
      }
      claims.push({
        type: "threat_actor",
        value,
        context: this.context(text, m.index ?? 0),
        verified: inTI,
        verification_source: inTI ? "threat_intelligence" : null,
        severity_weight: SEVERITY_WEIGHTS["threat_actor"],
      });
    }
  }

  private extractConfidenceClaims(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const matches = [...text.matchAll(CONFIDENCE_CLAIM)];
    const evidenceConfidencePct = ev.confidence * 100;
    for (const m of matches) {
      const claimedPct = parseFloat(m[1]);
      // AI cannot claim higher confidence than deterministic engines
      const verified = claimedPct <= evidenceConfidencePct + 5; // 5% tolerance
      if (!verified) {
        hallucinations.push(
          `Confidence claim ${claimedPct}% exceeds evidence confidence ${evidenceConfidencePct.toFixed(0)}% — inflation detected`,
        );
      }
      claims.push({
        type: "confidence_claim",
        value: m[0],
        context: this.context(text, m.index ?? 0),
        verified,
        verification_source: verified ? "confidence_gate" : null,
        severity_weight: SEVERITY_WEIGHTS["confidence_claim"],
      });
    }
  }

  private extractSeverityClaims(
    text: string,
    ev: EvidenceBundle,
    claims: FactualClaim[],
    hallucinations: string[],
  ): void {
    const matches = [...text.matchAll(SEVERITY_CLAIM)];
    const detSeverity = ev.severity.toLowerCase();
    for (const m of matches) {
      const claimedSeverity = m[1].toLowerCase();
      const verified = claimedSeverity === detSeverity;
      if (!verified) {
        hallucinations.push(
          `Severity claim '${m[1]}' does not match deterministic severity '${ev.severity}' — fabrication detected`,
        );
      }
      claims.push({
        type: "severity_claim",
        value: m[0],
        context: this.context(text, m.index ?? 0),
        verified,
        verification_source: verified ? "hybrid_detector" : null,
        severity_weight: SEVERITY_WEIGHTS["severity_claim"],
      });
    }
  }

  // ── Score Calculation ─────────────────────────────────────────────────────

  private calculateTruthScore(claims: FactualClaim[]): number {
    if (claims.length === 0) return 1.0; // No claims = nothing to hallucinate
    const totalWeight = claims.reduce((sum, c) => sum + c.severity_weight, 0);
    if (totalWeight === 0) return 1.0;
    const verifiedWeight = claims
      .filter((c) => c.verified)
      .reduce((sum, c) => sum + c.severity_weight, 0);
    return verifiedWeight / totalWeight;
  }

  private badge(score: number): TruthBadge {
    if (score >= TRUTH_HIGH) return "HIGH";
    if (score >= TRUTH_MEDIUM) return "MEDIUM";
    if (score >= TRUTH_LOW_OK) return "LOW";
    return "REJECTED";
  }

  private context(text: string, index: number): string {
    return text.slice(Math.max(0, index - 25), index + 25).replace(/\n/g, " ");
  }

  private isPrivateOrLoopback(ip: string): boolean {
    return (
      ip.startsWith("10.") ||
      ip.startsWith("192.168.") ||
      ip.startsWith("172.16.") ||
      ip.startsWith("172.17.") ||
      ip.startsWith("127.") ||
      ip === "0.0.0.0"
    );
  }
}

// ─── Safe Fallback Response ───────────────────────────────────────────────────

export function buildSafeFallbackResponse(evidence: EvidenceBundle): string {
  return [
    "## ⚠ AI Analysis Unavailable — Deterministic Evidence Only",
    "",
    "The AI response did not meet the minimum Truth Score threshold and has been discarded.",
    "The following information is from verified deterministic engines only:",
    "",
    `**Anomaly ID:** ${evidence.anomaly_id}`,
    `**Detection Method:** ${evidence.detection_method}`,
    `**Severity:** ${evidence.severity}`,
    `**Hybrid Score:** ${(evidence.hybrid_score * 100).toFixed(0)}%`,
    `**Confidence:** ${(evidence.confidence * 100).toFixed(0)}%`,
    `**Risk Score:** ${(evidence.risk_score * 100).toFixed(0)}%`,
    "",
    "**Matched Rules:**",
    ...evidence.matched_rules
      .filter((r) => r.matched)
      .map((r) => `- ${r.rule_name}`),
    "",
    "**Explainability:**",
    evidence.explainability_summary.evidenceText,
    "",
    "**Recommended Action (from Rule Engine):**",
    evidence.explainability_summary.recommendation,
    "",
    "---",
    "*Please escalate to a human analyst for further investigation.*",
  ].join("\n");
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const truthEngine = new TruthEngine();
