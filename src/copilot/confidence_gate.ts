/**
 * Aegis Enterprise — Confidence Gate
 *
 * THREE-TIER routing engine for AI requests based on calculated confidence score.
 *
 * HIGH  (≥ 0.80): Full evidence-based AI explanation
 * MEDIUM (0.50–0.79): Explanation delivered with uncertainty disclaimer
 * LOW   (< 0.50): Request BLOCKED — AI cannot speculate without sufficient evidence
 *
 * Includes temporal confidence decay for aging evidence bundles.
 */

import { logStructured } from "../observability/logger.js";
import {
  evidenceValidator,
  type EvidenceBundle,
} from "./evidence_validator.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type ConfidenceLevel = "HIGH" | "MEDIUM" | "LOW";

export interface ConfidenceGateResult {
  level: ConfidenceLevel;
  score: number; // 0.0 – 1.0 (evidence-based, post-decay)
  raw_score: number; // Pre-decay score
  decay_applied: number; // Decay factor subtracted
  allow: boolean; // false = block (LOW tier)
  disclaimer: string | null; // Injected for MEDIUM tier
  limitations: string[]; // Missing evidence fields
}

const THRESHOLD_HIGH = 0.8;
const THRESHOLD_MEDIUM = 0.5;

// Decay constants
const DECAY_START_MS = 5 * 60 * 1000; // Decay starts after 5 minutes
const DECAY_MAX_MS = 30 * 60 * 1000; // Full decay at 30 minutes (staleness limit)
const MAX_DECAY = 0.25; // Maximum deduction from score

// ─── Disclaimer Templates ─────────────────────────────────────────────────────

const MEDIUM_DISCLAIMER =
  "⚠ **Partial Evidence:** This explanation is based on incomplete evidence. " +
  "Some aspects are uncertain. Analyst verification is strongly recommended " +
  "before acting on these recommendations.";

const LOW_BLOCK_MESSAGE =
  "❌ **Insufficient Evidence:** The detection confidence and available evidence " +
  "are below the minimum threshold required for a reliable AI explanation. " +
  "Please investigate using raw telemetry data and expand the evidence window " +
  "before requesting an AI analysis.";

// ─── Confidence Gate ──────────────────────────────────────────────────────────

export class ConfidenceGate {
  /**
   * Evaluate an evidence bundle and return a routing decision with confidence level.
   */
  evaluate(
    bundle: EvidenceBundle,
    evidenceAgeMs: number = 0,
  ): ConfidenceGateResult {
    // 1. Calculate base evidence score
    const rawScore = evidenceValidator.calculateConfidenceScore(bundle);

    // 2. Apply temporal decay
    const decay = this.calculateDecay(evidenceAgeMs);
    const score = Math.max(0, rawScore - decay);

    // 3. Route to tier
    const level = this.route(score);
    const allow = level !== "LOW";

    // 4. Collect limitation descriptions
    const limitations = this.collectLimitations(bundle);

    // 5. Generate disclaimer
    let disclaimer: string | null = null;
    if (level === "MEDIUM") disclaimer = MEDIUM_DISCLAIMER;
    if (level === "LOW") disclaimer = LOW_BLOCK_MESSAGE;

    logStructured(
      allow ? "info" : "warn",
      "[ConfidenceGate] Routing decision",
      {
        anomaly_id: bundle.anomaly_id,
        raw_score: rawScore,
        decay,
        score,
        level,
        allow,
        limitations_count: limitations.length,
      },
    );

    return {
      level,
      score,
      raw_score: rawScore,
      decay_applied: decay,
      allow,
      disclaimer,
      limitations,
    };
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private route(score: number): ConfidenceLevel {
    if (score >= THRESHOLD_HIGH) return "HIGH";
    if (score >= THRESHOLD_MEDIUM) return "MEDIUM";
    return "LOW";
  }

  /**
   * Temporal decay model: score decays linearly between 5 and 30 minutes.
   * Older evidence reduces AI confidence — AI should not explain stale events
   * with the same confidence as fresh detections.
   */
  private calculateDecay(ageMs: number): number {
    if (ageMs <= DECAY_START_MS) return 0;
    const window = DECAY_MAX_MS - DECAY_START_MS;
    const elapsed = Math.min(ageMs - DECAY_START_MS, window);
    return (elapsed / window) * MAX_DECAY;
  }

  private collectLimitations(bundle: EvidenceBundle): string[] {
    const lim: string[] = [];
    if (bundle.threat_fusion === null) lim.push("Threat Fusion: unavailable");
    if (bundle.threat_intelligence.length === 0)
      lim.push("Threat Intelligence: no external IOC correlation");
    if (bundle.asset_context === null)
      lim.push("Asset Context: unavailable — impact scope unknown");
    if (bundle.behavior_context === null)
      lim.push("Behavior Context: unavailable — no baseline comparison");
    if (bundle.mitre_mappings.length === 0)
      lim.push("MITRE Mapping: technique unknown");
    return lim;
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

export const confidenceGate = new ConfidenceGate();
