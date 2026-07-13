/**
 * Aegis Enterprise — Explainability Engine
 *
 * Generates structured explanation metadata based on scores, features, and risk values.
 * This report provides a deterministic, transparent diagnostic summary before LLM attribution.
 */

import { FeatureVector } from "./hybrid_detector.js";
import { ModuleDetectionResult } from "./detection_orchestrator.js";

export interface ExplanationSummary {
  anomalyId?: number;
  anomaly_id?: number; // compat with copilot validators
  overallScore: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  topContributingFeatures: string[];
  moduleBreakdown: { name: string; score: number }[];
  evidenceText: string;
  recommendation: string;
}

export class ExplainabilityEngine {
  generateExplanation(
    features: FeatureVector,
    moduleResults: ModuleDetectionResult[],
    overallScore: number,
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  ): ExplanationSummary {
    // 1. Identify top contributing features based on deviations
    const contributors: string[] = [];
    if (features.burstRatio > 2.0)
      contributors.push(
        "High Event Burst Ratio (" + features.burstRatio.toFixed(1) + "x)",
      );
    if (features.sourceEntropy < 1.0 && features.uniqueSources > 0)
      contributors.push("Traffic Source Concentration (low entropy)");
    if (features.rateAcceleration > 10)
      contributors.push(
        "Rate Acceleration Spike (" +
          features.rateAcceleration.toFixed(1) +
          "/s)",
      );

    // 2. Synthesize evidence text
    const moduleBreakdown = moduleResults.map((r) => ({
      name: r.moduleName,
      score: r.score,
    }));
    const evidenceText =
      `Real-time event rate triggered at ${features.eventsPerSec.toFixed(1)} events/sec. ` +
      `System evaluated threat score at ${(overallScore * 100).toFixed(0)}% matching a ${severity} severity anomaly profile. ` +
      `Contributing indicators: ${contributors.join(", ") || "none detected"}.`;

    // 3. Synthesize recommendation
    let recommendation = "Monitor baseline telemetry trends.";
    if (severity === "CRITICAL" || severity === "HIGH") {
      recommendation =
        "Immediate: Check source entity for anomalous traffic. Apply rate limiting policy and execute threat hunt playbook.";
    }

    return {
      overallScore,
      severity,
      topContributingFeatures: contributors,
      moduleBreakdown,
      evidenceText,
      recommendation,
    };
  }
}

export const explainabilityEngine = new ExplainabilityEngine();
