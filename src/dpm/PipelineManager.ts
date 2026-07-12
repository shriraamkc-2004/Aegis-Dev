/**
 * Aegis Enterprise — Detection Pipeline Manager (DPM)
 *
 * Manages runtime status of detection engine components and dynamic configurations.
 */

import { IDetectionModule } from "../detection_orchestrator.js";

export interface PipelineModuleStatus {
  id: string;
  name: string;
  enabled: boolean;
  order: number;
}

export class DetectionPipelineManager {
  private static instance: DetectionPipelineManager;
  private engines: Map<string, IDetectionModule> = new Map();
  private enabledStates: Map<string, boolean> = new Map();

  private constructor() {}

  public static getInstance(): DetectionPipelineManager {
    if (!DetectionPipelineManager.instance) {
      DetectionPipelineManager.instance = new DetectionPipelineManager();
    }
    return DetectionPipelineManager.instance;
  }

  registerEngine(
    id: string,
    engine: IDetectionModule,
    defaultEnabled = true,
  ): void {
    this.engines.set(id, engine);
    this.enabledStates.set(id, defaultEnabled);
  }

  toggleEngine(id: string, enabled: boolean): void {
    if (this.engines.has(id)) {
      this.enabledStates.set(id, enabled);
      console.log(
        `[DPM] Detection engine "${id}" state toggled to: ${enabled ? "ENABLED" : "DISABLED"}`,
      );
    }
  }

  isEngineEnabled(id: string): boolean {
    return this.enabledStates.get(id) ?? false;
  }

  getPipelineStatus(): PipelineModuleStatus[] {
    const list: PipelineModuleStatus[] = [];
    for (const [id, engine] of this.engines.entries()) {
      list.push({
        id,
        name: engine.name,
        enabled: this.isEngineEnabled(id),
        order: engine.order,
      });
    }
    return list.sort((a, b) => a.order - b.order);
  }
}

export const pipelineManager = DetectionPipelineManager.getInstance();
