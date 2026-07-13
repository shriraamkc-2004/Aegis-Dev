/**
 * Aegis Enterprise — AI Version Manager
 *
 * Coordinates versioning of all active AI sub-components.
 * Ensures consistent alignment between:
 *  - Active Prompt templates
 *  - Response schemas
 *  - Active LLM model models
 */

import { logStructured } from "../observability/logger.js";

export interface SystemVersionMatrix {
  deployment_version: string;
  prompt_version: number;
  response_schema_version: string;
  model_id: string;
  governance_spec_version: string;
}

export class AIVersionManager {
  private currentMatrix: SystemVersionMatrix = {
    deployment_version: "2.0.0",
    prompt_version: 1,
    response_schema_version: "2.0.0",
    model_id: "gemini-2.5-flash",
    governance_spec_version: "2.0.0",
  };

  /**
   * Retrieve the active version matrix for system header and logging contexts.
   */
  getActiveVersionMatrix(): SystemVersionMatrix {
    return { ...this.currentMatrix };
  }

  /**
   * Set and update the active configuration version matrix.
   */
  updateVersionMatrix(update: Partial<SystemVersionMatrix>): void {
    this.currentMatrix = {
      ...this.currentMatrix,
      ...update,
    };
    logStructured("info", "[AIVersionManager] Version matrix updated", {
      matrix: this.currentMatrix,
    });
  }
}

export const aiVersionManager = new AIVersionManager();
