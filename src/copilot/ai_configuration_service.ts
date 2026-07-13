/**
 * Aegis Enterprise — AI Configuration Service
 *
 * Exposes runtime config controls for the AI layer.
 * Allows dynamically tuning thresholds, TTL parameters, and weights
 * without redeploying the express service.
 */

import { logStructured } from "../observability/logger.js";

export interface AIConfiguration {
  confidence_high_threshold: number;
  confidence_medium_threshold: number;
  circuit_failure_threshold: number;
  circuit_open_duration_ms: number;
  evidence_staleness_threshold_ms: number;
  max_request_concurrency: number;
}

const DEFAULT_CONFIG: AIConfiguration = {
  confidence_high_threshold: 0.8,
  confidence_medium_threshold: 0.5,
  circuit_failure_threshold: 5,
  circuit_open_duration_ms: 30_000,
  evidence_staleness_threshold_ms: 30 * 60 * 1000, // 30 minutes
  max_request_concurrency: 3,
};

export class AIConfigurationService {
  private currentConfig: AIConfiguration = { ...DEFAULT_CONFIG };

  /**
   * Get the current active configuration values.
   */
  getConfig(): AIConfiguration {
    return { ...this.currentConfig };
  }

  /**
   * Update the configuration values at runtime.
   */
  updateConfig(update: Partial<AIConfiguration>): void {
    this.currentConfig = {
      ...this.currentConfig,
      ...update,
    };
    logStructured(
      "info",
      "[AIConfigurationService] Runtime configuration updated",
      {
        config: this.currentConfig,
      },
    );
  }
}

export const aiConfigurationService = new AIConfigurationService();
