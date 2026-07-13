import { truthEngine } from "../../src/copilot/truth_engine.js";

describe("Truth Engine Tests", () => {
  const mockEvidence: any = {
    anomaly_id: 1,
    tenant_id: 1,
    severity: "HIGH",
    detection_timestamp: Date.now(),
    detection_method: "hybrid",
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
    asset_context: {
      ip_address: "192.168.1.100",
      hostname: "prod-db-01",
      criticality: "HIGH",
    },
    behavior_context: null,
    mitre_mappings: [],
    explainability_summary: {
      overallScore: 0.85,
      severity: "HIGH",
      topContributingFeatures: [],
      moduleBreakdown: [],
      evidenceText: "Anomaly detected in event stream.",
      recommendation: "Investigate server logs.",
    },
  };

  it("should pass validation for responses matching evidence", () => {
    const response =
      "An anomaly was detected on prod-db-01 (192.168.1.100) with a confidence of 90%.";
    const result = truthEngine.validate(response, mockEvidence);
    expect(result.truth_score).toBeGreaterThanOrEqual(0.7);
    expect(result.safe_fallback_triggered).toBe(false);
  });

  it("should flag safe fallback for hallucinated details", () => {
    const response =
      "A severe threat actor Cozy Bear attacked host server-unknown (10.0.0.5) using CVE-2023-38606.";
    const result = truthEngine.validate(response, mockEvidence);
    expect(result.truth_score).toBeLessThan(0.7);
    expect(result.safe_fallback_triggered).toBe(true);
  });
});
