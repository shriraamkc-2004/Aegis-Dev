/**
 * Aegis Enterprise — Detection Orchestrator
 *
 * Coordinates execution of independent detection modules, handles timeouts,
 * failure fallbacks, and executes threat score fusion.
 */

import { FeatureVector } from "./hybrid_detector.js";

export interface TelemetryEvent {
  event_type: string;
  source: string;
  timestamp: number;
}

export interface ModuleDetectionResult {
  moduleName: string;
  score: number; // Normalized [0, 1]
  metadata?: Record<string, any>;
}

export interface IDetectionModule {
  name: string;
  order: number;
  timeoutMs: number;
  execute(
    event: TelemetryEvent,
    features: FeatureVector,
  ): Promise<ModuleDetectionResult>;
}

export class DetectionOrchestrator {
  private modules: IDetectionModule[] = [];

  registerModule(module: IDetectionModule): void {
    this.modules.push(module);
    // Keep modules sorted by execution order preference
    this.modules.sort((a, b) => a.order - b.order);
  }

  /** Run all modules with safe timeouts and gather scores */
  async execute(
    event: TelemetryEvent,
    features: FeatureVector,
  ): Promise<ModuleDetectionResult[]> {
    const results: ModuleDetectionResult[] = [];

    for (const mod of this.modules) {
      const execPromise = mod.execute(event, features);

      // Race module execution with timeout limit
      const timeoutPromise = new Promise<ModuleDetectionResult>((_, reject) => {
        setTimeout(
          () => reject(new Error(`Timeout exceeding ${mod.timeoutMs}ms`)),
          mod.timeoutMs,
        );
      });

      try {
        const res = await Promise.race([execPromise, timeoutPromise]);
        results.push(res);
      } catch (err: any) {
        console.warn(
          `[DetectionOrchestrator] Fallback triggered for "${mod.name}":`,
          err.message,
        );
        results.push({
          moduleName: mod.name,
          score: 0,
          metadata: { error: err.message },
        });
      }
    }

    return results;
  }
}

export const detectionOrchestrator = new DetectionOrchestrator();
