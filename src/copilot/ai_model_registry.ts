/**
 * Aegis Enterprise — AI Model Registry
 *
 * Governs all approved LLM versions, their maximum token thresholds, cost structures,
 * and operational fallback mappings. Prevents unapproved models from being called.
 */

import { logStructured } from "../observability/logger.js";

export interface LLMModelInfo {
  model_id: string;
  display_name: string;
  provider: "google" | "openai" | "anthropic" | "local";
  max_input_tokens: number;
  max_output_tokens: number;
  cost_per_1k_input_usd: number;
  cost_per_1k_output_usd: number;
  approved: boolean;
  fallback_model_id: string | null;
}

const DEFAULT_MODELS: LLMModelInfo[] = [
  {
    model_id: "gemini-2.5-flash",
    display_name: "Gemini 2.5 Flash",
    provider: "google",
    max_input_tokens: 1048576,
    max_output_tokens: 8192,
    cost_per_1k_input_usd: 0.000075,
    cost_per_1k_output_usd: 0.0003,
    approved: true,
    fallback_model_id: "gemini-2.5-pro",
  },
  {
    model_id: "gemini-2.5-pro",
    display_name: "Gemini 2.5 Pro",
    provider: "google",
    max_input_tokens: 2097152,
    max_output_tokens: 8192,
    cost_per_1k_input_usd: 0.00125,
    cost_per_1k_output_usd: 0.005,
    approved: true,
    fallback_model_id: "gemini-1.5-flash",
  },
  {
    model_id: "gemini-1.5-flash",
    display_name: "Gemini 1.5 Flash (Legacy Fallback)",
    provider: "google",
    max_input_tokens: 1048576,
    max_output_tokens: 8192,
    cost_per_1k_input_usd: 0.000075,
    cost_per_1k_output_usd: 0.0003,
    approved: true,
    fallback_model_id: null,
  },
];

export class AIModelRegistry {
  private models: Map<string, LLMModelInfo> = new Map();

  constructor() {
    for (const model of DEFAULT_MODELS) {
      this.models.set(model.model_id, model);
    }
  }

  /**
   * Check if a model is approved and register its metadata.
   */
  getModel(modelId: string): LLMModelInfo | undefined {
    return this.models.get(modelId);
  }

  /**
   * Register or update a model in the registry.
   */
  registerModel(model: LLMModelInfo): void {
    this.models.set(model.model_id, model);
    logStructured("info", "[AIModelRegistry] Registered model", {
      model_id: model.model_id,
      approved: model.approved,
    });
  }

  /**
   * Verify if a model is allowed to run.
   */
  isModelApproved(modelId: string): boolean {
    const model = this.models.get(modelId);
    return model ? model.approved : false;
  }

  /**
   * Retrieve the fallback model if a model fails.
   */
  getFallbackModel(modelId: string): string | null {
    const model = this.models.get(modelId);
    return model ? model.fallback_model_id : null;
  }
}

export const aiModelRegistry = new AIModelRegistry();
