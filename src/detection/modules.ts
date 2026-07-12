/**
 * Aegis Enterprise — Detection Engine Modules
 *
 * Standalone implementations of IDetectionModule wrapping core algorithms.
 */

import {
  IDetectionModule,
  TelemetryEvent,
  ModuleDetectionResult,
} from "../detection_orchestrator.js";
import { FeatureVector, featureVectorToArray } from "../hybrid_detector.js";
import { assetContext } from "../asset_context.js";

/** Rule Engine Module */
export class RuleEngineModule implements IDetectionModule {
  name = "Rule Engine";
  order = 1;
  timeoutMs = 100;

  async execute(
    event: TelemetryEvent,
    features: FeatureVector,
  ): Promise<ModuleDetectionResult> {
    let score = 0;
    const metadata: Record<string, any> = {};

    // Match signature patterns
    if (event.event_type === "failed_login") {
      score = 0.4; // Base warning score for failed logins
      metadata.matchedRule = "FAILED_LOGIN_SIGNATURE";
    } else if (
      event.event_type === "brute_force" ||
      features.burstRatio > 5.0
    ) {
      score = 0.9;
      metadata.matchedRule = "SURGE_RATE_LIMIT_EXCEEDED";
    }

    return {
      moduleName: this.name,
      score,
      metadata,
    };
  }
}

/** Isolation Forest ML Module */
export class IsolationForestModule implements IDetectionModule {
  name = "Isolation Forest";
  order = 2;
  timeoutMs = 250;
  private modelRef: any;

  constructor(modelRef: any) {
    this.modelRef = modelRef;
  }

  async execute(
    event: TelemetryEvent,
    features: FeatureVector,
  ): Promise<ModuleDetectionResult> {
    let score = 0;
    if (
      this.modelRef &&
      typeof this.modelRef.score === "function" &&
      this.modelRef.isTrained()
    ) {
      score = this.modelRef.score(featureVectorToArray(features));
    }
    return {
      moduleName: this.name,
      score,
      metadata: { trained: this.modelRef?.isTrained() ?? false },
    };
  }
}

/** Behavioral Baseline Analysis Module */
export class BehavioralEngineModule implements IDetectionModule {
  name = "Behavioral Engine";
  order = 3;
  timeoutMs = 150;

  async execute(
    event: TelemetryEvent,
    features: FeatureVector,
  ): Promise<ModuleDetectionResult> {
    // Score based on entropy deviations (entropy drop indicates high volume focus/anomaly)
    const entropyScore = features.sourceEntropy < 1.0 ? 0.7 : 0.0;
    return {
      moduleName: this.name,
      score: entropyScore,
      metadata: { entropy: features.sourceEntropy },
    };
  }
}

/** Asset Criticality Risk Engine Module */
export class RiskEngineModule implements IDetectionModule {
  name = "Risk Engine";
  order = 4;
  timeoutMs = 100;

  async execute(
    event: TelemetryEvent,
    features: FeatureVector,
  ): Promise<ModuleDetectionResult> {
    // Query asset database risk weighting multiplier
    const multiplier = assetContext.getRiskMultiplier(event.source);
    return {
      moduleName: this.name,
      score: multiplier > 1.5 ? 0.8 : 0.2,
      metadata: { multiplier, host: event.source },
    };
  }
}
