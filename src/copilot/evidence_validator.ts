/**
 * Aegis Enterprise — Evidence Validator
 *
 * Validates the completeness and consistency of an EvidenceBundle before
 * any AI invocation. If validation fails, the AI layer is blocked entirely —
 * the system NEVER speculates when evidence is incomplete.
 *
 * Also defines the canonical EvidenceBundle type used across the AI layer.
 */

import { logStructured } from "../observability/logger.js";

// ─── Evidence Bundle Types ────────────────────────────────────────────────────

export interface MatchedRule {
  rule_id: string;
  rule_name: string;
  matched: boolean;
  details: string | null;
}

export interface ThreatFusionResult {
  name: string | null;
  category: string | null;
  possible_threat: string | null;
  threat_confidence: number | null;
}

export interface ThreatIntelMatch {
  source: string;
  indicator_type: "ip" | "domain" | "hash" | "url";
  indicator_value: string;
  confidence: number;
  severity: string;
  description: string | null;
  tags: string[];
  last_seen: number | null;
}

export interface AssetContext {
  asset_id: string | null;
  hostname: string | null;
  ip_address: string | null;
  asset_type: string | null;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null;
  owner: string | null;
  environment: "production" | "staging" | "dev" | null;
  tags: string[];
}

export interface BehaviorContext {
  window_seconds: number;
  events_per_second: number;
  burst_ratio: number;
  source_entropy: number;
  unique_sources: number;
  unique_destinations: number;
  dominant_protocol: string | null;
  bytes_transferred: number;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  source: "threat_fusion" | "rule_engine";
}

export interface ExplanationSummary {
  anomaly_id?: number;
  overallScore: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  topContributingFeatures: string[];
  moduleBreakdown: { name: string; score: number }[];
  evidenceText: string;
  recommendation: string;
}

/**
 * The canonical EvidenceBundle: the single source of truth passed to the AI layer.
 * Every field that is "not available" must be null or [].
 * The AI layer MUST NOT infer, guess, or fabricate missing fields.
 */
export interface EvidenceBundle {
  // ── Identification ────────────────────────────────────────────
  anomaly_id: number;
  tenant_id: number;
  detection_timestamp: number;
  detection_method: string;

  // ── Deterministic Scores (never modified by AI) ───────────────
  z_score: number;
  iforest_score: number;
  ewma_score: number;
  hybrid_score: number;
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number; // 0.0 – 1.0

  // ── Rule Matches (at least 1 required) ────────────────────────
  matched_rules: MatchedRule[];

  // ── Threat Fusion (null if unavailable) ───────────────────────
  threat_fusion: ThreatFusionResult | null;

  // ── Threat Intelligence (empty array if none) ─────────────────
  threat_intelligence: ThreatIntelMatch[];

  // ── Asset Context (null if unavailable) ───────────────────────
  asset_context: AssetContext | null;

  // ── Behavior Context (null if unavailable) ────────────────────
  behavior_context: BehaviorContext | null;

  // ── MITRE Mappings (empty array if none — NEVER fabricated) ───
  mitre_mappings: MitreMapping[];

  // ── Explainability Engine output (required) ───────────────────
  explainability_summary: ExplanationSummary;

  // ── Data Quality Metadata ─────────────────────────────────────
  data_quality: {
    threat_intel_available: boolean;
    asset_context_available: boolean;
    behavior_context_available: boolean;
    mitre_mapping_available: boolean;
    threat_fusion_available: boolean;
    completeness_score: number; // 0.0 – 1.0
  };
}

// ─── Validation Result ────────────────────────────────────────────────────────

export interface EvidenceValidationResult {
  valid: boolean;
  missing_fields: string[];
  warning_fields: string[]; // Present but suspicious / incomplete
  completeness_score: number; // 0.0 – 1.0
  rejection_reason: string | null;
}

// ─── Evidence Validator ───────────────────────────────────────────────────────

export class EvidenceValidator {
  // Minimum confidence below which AI is blocked
  private readonly MIN_CONFIDENCE = 0.3;

  /**
   * Validate an EvidenceBundle for completeness and consistency.
   * Returns a structured result — caller decides whether to block.
   */
  validate(bundle: EvidenceBundle): EvidenceValidationResult {
    const missing: string[] = [];
    const warnings: string[] = [];

    // ── Required Identity Fields ────────────────────────────────
    if (!bundle.anomaly_id || bundle.anomaly_id <= 0)
      missing.push("anomaly_id");
    if (!bundle.tenant_id || bundle.tenant_id <= 0) missing.push("tenant_id");
    if (!bundle.detection_timestamp || bundle.detection_timestamp <= 0)
      missing.push("detection_timestamp");
    if (!bundle.detection_method) missing.push("detection_method");

    // ── Required Scores ─────────────────────────────────────────
    if (typeof bundle.hybrid_score !== "number" || isNaN(bundle.hybrid_score))
      missing.push("hybrid_score");
    if (typeof bundle.confidence !== "number" || isNaN(bundle.confidence))
      missing.push("confidence");
    if (!bundle.severity) missing.push("severity");

    // ── Minimum Confidence ──────────────────────────────────────
    if (
      typeof bundle.confidence === "number" &&
      bundle.confidence < this.MIN_CONFIDENCE
    ) {
      missing.push(
        `confidence_below_threshold (${bundle.confidence.toFixed(2)} < ${this.MIN_CONFIDENCE})`,
      );
    }

    // ── Required: At Least One Rule Match ───────────────────────
    if (!bundle.matched_rules || bundle.matched_rules.length === 0) {
      missing.push("matched_rules (at least 1 required)");
    }

    // ── Required: Explainability Summary ────────────────────────
    if (!bundle.explainability_summary) {
      missing.push("explainability_summary");
    }

    // ── Optional but Warn If Missing ────────────────────────────
    if (bundle.threat_fusion === null)
      warnings.push("threat_fusion unavailable — limited threat context");
    if (bundle.threat_intelligence.length === 0)
      warnings.push("threat_intelligence empty — no external IOC correlation");
    if (bundle.asset_context === null)
      warnings.push("asset_context unavailable — cannot assess impact");
    if (bundle.behavior_context === null)
      warnings.push("behavior_context unavailable — no baseline comparison");
    if (bundle.mitre_mappings.length === 0)
      warnings.push("mitre_mappings empty — technique unknown");

    // ── Score Sanity Checks ─────────────────────────────────────
    if (
      typeof bundle.hybrid_score === "number" &&
      (bundle.hybrid_score < 0 || bundle.hybrid_score > 1)
    )
      warnings.push(`hybrid_score out of range: ${bundle.hybrid_score}`);
    if (
      typeof bundle.confidence === "number" &&
      (bundle.confidence < 0 || bundle.confidence > 1)
    )
      warnings.push(`confidence out of range: ${bundle.confidence}`);

    // ── Completeness Score ──────────────────────────────────────
    const sources = [
      bundle.matched_rules.length > 0,
      bundle.threat_fusion !== null,
      bundle.threat_intelligence.length > 0,
      bundle.asset_context !== null,
      bundle.behavior_context !== null,
      bundle.mitre_mappings.length > 0,
      bundle.explainability_summary != null,
    ];
    const completeness = sources.filter(Boolean).length / sources.length;

    const valid = missing.length === 0;
    const rejectionReason = valid
      ? null
      : `Evidence validation failed. Missing: ${missing.join(", ")}`;

    if (!valid) {
      logStructured(
        "warn",
        "[EvidenceValidator] Validation failed — AI blocked",
        {
          anomaly_id: bundle.anomaly_id,
          missing,
          completeness,
        },
      );
    } else if (warnings.length > 0) {
      logStructured(
        "info",
        "[EvidenceValidator] Validation passed with warnings",
        {
          anomaly_id: bundle.anomaly_id,
          warnings,
          completeness,
        },
      );
    }

    return {
      valid,
      missing_fields: missing,
      warning_fields: warnings,
      completeness_score: completeness,
      rejection_reason: rejectionReason,
    };
  }

  /**
   * Calculate the confidence score for the Confidence Gate
   * based on presence of evidence sources.
   */
  calculateConfidenceScore(bundle: EvidenceBundle): number {
    let score = 0.0;
    if (bundle.matched_rules.length > 0) score += 0.3;
    if (bundle.threat_fusion !== null) score += 0.2;
    if (bundle.threat_intelligence.length > 0) score += 0.15;
    if (bundle.asset_context !== null) score += 0.1;
    if (bundle.behavior_context !== null) score += 0.1;
    if (bundle.mitre_mappings.length > 0) score += 0.1;
    if (bundle.hybrid_score > 0.7) score += 0.05;
    return Math.min(score, 1.0);
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const evidenceValidator = new EvidenceValidator();
