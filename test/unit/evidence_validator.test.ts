import { evidenceValidator } from "../../src/copilot/evidence_validator.js";
import { evidenceIntegrityValidator } from "../../src/copilot/evidence_integrity_validator.js";

describe("Evidence & Integrity Validator Tests", () => {
  const validEvidence: any = {
    anomaly_id: 1,
    tenant_id: 1,
    severity: "HIGH",
    detection_timestamp: Date.now(),
    detection_method: "hybrid",
    z_score: 2.5,
    iforest_score: 0.4,
    ewma_score: 0.8,
    hybrid_score: 0.85,
    confidence: 0.9,
    risk_score: 0.8,
    matched_rules: [
      {
        rule_id: "R-001",
        rule_name: "Mock Rule",
        matched: true,
        details: null,
      },
    ],
    threat_fusion: null,
    threat_intelligence: [],
    asset_context: null,
    behavior_context: null,
    mitre_mappings: [],
    explainability_summary: {
      overallScore: 0.85,
      severity: "HIGH",
      topContributingFeatures: [],
      moduleBreakdown: [],
      evidenceText: "Mock",
      recommendation: "Mock",
    },
    data_quality: {
      threat_intel_available: false,
      asset_context_available: false,
      behavior_context_available: false,
      mitre_mapping_available: false,
      threat_fusion_available: false,
      completeness_score: 0.7,
    },
  };

  it("should validate complete evidence", () => {
    const result = evidenceValidator.validate(validEvidence);
    expect(result.valid).toBe(true);
    expect(result.missing_fields).toHaveLength(0);
  });

  it("should reject evidence missing fields", () => {
    const incomplete = { ...validEvidence };
    delete incomplete.explainability_summary;
    const result = evidenceValidator.validate(incomplete);
    expect(result.valid).toBe(false);
    expect(result.missing_fields).toContain("explainability_summary");
  });

  it("should stamp and verify evidence integrity", () => {
    const stamp = evidenceIntegrityValidator.stamp(validEvidence);
    expect(stamp.hash).toBeDefined();

    const verified = evidenceIntegrityValidator.verify(validEvidence, stamp);
    expect(verified.valid).toBe(true);
  });
});
