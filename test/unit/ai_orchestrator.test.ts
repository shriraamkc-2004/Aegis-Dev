import { aiOrchestrator } from "../../src/copilot/ai_orchestrator.js";
import { evidenceIntegrityValidator } from "../../src/copilot/evidence_integrity_validator.js";

describe("AI Orchestrator Pipeline Tests", () => {
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
    explainability_summary: {
      overallScore: 0.85,
      severity: "HIGH",
      topContributingFeatures: [],
      moduleBreakdown: [],
      evidenceText: "Anomaly detected in event stream.",
      recommendation: "Investigate server logs.",
    },
    data_quality: {
      threat_intel_available: true,
      asset_context_available: true,
      behavior_context_available: true,
      mitre_mapping_available: true,
      threat_fusion_available: true,
      completeness_score: 1.0,
    },
  };

  it("should reject invalid or tampered evidence signatures", async () => {
    const fakeStamp = {
      hash: "fake-hash",
      signature: "fake-signature",
      timestamp: Date.now(),
      stamped_at: Date.now(),
      anomaly_id: 1,
      tenant_id: 1,
    };
    const response = await aiOrchestrator.processRequest({
      request_id: "req-1",
      session_id: null,
      tenant_id: 1,
      user_id: 1,
      user_role: "analyst",
      ip_address: "127.0.0.1",
      prompt: "Explain this anomaly.",
      request_type: "anomaly_explanation",
      evidence: mockEvidence,
      evidence_stamp: fakeStamp,
      evidence_age_ms: 0,
    });

    expect(response.outcome).toBe("BLOCKED_EVIDENCE");
    expect(response.response).toContain("Possible tampering detected");
  });

  it("should fall back safely when circuit is open", async () => {
    const stamp = evidenceIntegrityValidator.stamp(mockEvidence);
    const {
      aiCircuitBreaker,
    } = require("../../src/copilot/ai_circuit_breaker.js");
    (aiCircuitBreaker as any).state = "OPEN";

    const response = await aiOrchestrator.processRequest({
      request_id: "req-2",
      session_id: null,
      tenant_id: 1,
      user_id: 1,
      user_role: "analyst",
      ip_address: "127.0.0.1",
      prompt: "Explain this anomaly.",
      request_type: "anomaly_explanation",
      evidence: mockEvidence,
      evidence_stamp: stamp,
      evidence_age_ms: 0,
    });

    expect(response.safe_fallback_used).toBe(true);
    expect(response.response).toContain("AI Analysis Unavailable");
  });
});
