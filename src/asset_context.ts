/**
 * Aegis Enterprise — Asset Context Engine
 *
 * Enriches events with operational metadata (criticality, exposures, servers roles)
 * to calculate business risk scores dynamically.
 */

export interface AssetProfile {
  hostName: string;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  businessUnit: string;
  role: string;
  isPublicExposed: boolean;
  sensitiveDataFlag: boolean;
}

export class AssetContextEngine {
  private assets: Map<string, AssetProfile> = new Map();

  constructor() {
    // Seed default assets
    this.registerAsset({
      hostName: "DC-01.internal",
      criticality: "CRITICAL",
      businessUnit: "Infrastructure",
      role: "Domain Controller",
      isPublicExposed: false,
      sensitiveDataFlag: true,
    });
    this.registerAsset({
      hostName: "web-prod-01.public",
      criticality: "HIGH",
      businessUnit: "eCommerce",
      role: "Web Application Server",
      isPublicExposed: true,
      sensitiveDataFlag: false,
    });
  }

  registerAsset(profile: AssetProfile): void {
    this.assets.set(profile.hostName.toLowerCase(), profile);
  }

  getAssetProfile(hostName: string): AssetProfile {
    const key = hostName.toLowerCase();
    if (this.assets.has(key)) {
      return this.assets.get(key)!;
    }
    // Return standard fallback profile
    return {
      hostName,
      criticality: "MEDIUM",
      businessUnit: "General",
      role: "Generic Workstation",
      isPublicExposed: false,
      sensitiveDataFlag: false,
    };
  }

  /** Calculate asset risk multiplier (1.0 to 3.0) */
  getRiskMultiplier(hostName: string): number {
    const profile = this.getAssetProfile(hostName);
    let multiplier = 1.0;

    if (profile.criticality === "CRITICAL") multiplier += 1.0;
    else if (profile.criticality === "HIGH") multiplier += 0.5;

    if (profile.isPublicExposed) multiplier += 0.5;
    if (profile.sensitiveDataFlag) multiplier += 0.5;

    return multiplier;
  }
}

export const assetContext = new AssetContextEngine();
