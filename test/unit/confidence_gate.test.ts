import { confidenceGate } from "../../src/copilot/confidence_gate.js";

describe("Confidence Gate Tests", () => {
  const mockEvidence: any = {
    anomaly_id: 1,
    tenant_id: 1,
    severity: "HIGH",
    detection_timestamp: Date.now(),
    hybrid_score: 0.85,
    confidence: 0.9,
    risk_score: 0.8,
    matched_rules: [{ matched: true }],
    threat_fusion: {
      name: "Mock Fusion",
      category: "phishing",
      possible_threat: "High",
      threat_confidence: 0.9,
    },
    threat_intelligence: [
      {
        source: "feed",
        indicator_type: "ip",
        indicator_value: "1.1.1.1",
        confidence: 0.9,
        severity: "HIGH",
        description: "Malicious",
        tags: [],
        last_seen: Date.now(),
      },
    ],
    asset_context: { criticality: "HIGH" },
    behavior_context: {
      window_seconds: 60,
      events_per_second: 10,
      burst_ratio: 2,
      source_entropy: 3,
      unique_sources: 2,
      unique_destinations: 2,
      dominant_protocol: "TCP",
      bytes_transferred: 1000,
    },
    mitre_mappings: [
      {
        technique_id: "T1059",
        technique_name: "Scripting",
        tactic: "Execution",
        confidence: 0.9,
        source: "rule_engine",
      },
    ],
    explainability_summary: {},
  };

  it("should assign HIGH confidence with rich evidence", () => {
    const result = confidenceGate.evaluate(mockEvidence);
    expect(result.level).toBe("HIGH");
    expect(result.score).toBeGreaterThan(0.7);
  });

  it("should decay confidence over time", () => {
    const result = confidenceGate.evaluate(mockEvidence, 25 * 60 * 60 * 1000); // 25 hours old
    expect(result.decay_applied).toBeGreaterThan(0);
    expect(result.level).toBe("MEDIUM"); // Suffered temporal decay from HIGH to MEDIUM
  });
});
