import { humanFeedbackEngine } from "../../src/copilot/human_feedback_engine.js";
import { aiReliabilityEngine } from "../../src/copilot/ai_reliability_engine.js";
import { initServerDb } from "../../src/server_db.js";

describe("Human Feedback & Reliability Metrics Tests", () => {
  beforeAll(async () => {
    await initServerDb();
  });
  it("should support submitting feedback and querying reports", async () => {
    const feedback = {
      audit_id: "audit-test-123",
      tenant_id: 1,
      rating: "CORRECT" as const,
      corrected_text: null,
      notes: "Perfect response.",
      analyst_user_id: 1,
    };

    const success = await humanFeedbackEngine.submitFeedback(feedback);
    expect(success).toBe(true);

    const list = await humanFeedbackEngine.getFeedbackForTenant(1);
    expect(list.length).toBeGreaterThan(0);
    expect(list[0].audit_id).toBe("audit-test-123");
  });

  it("should compute reliability reports correctly", async () => {
    const metrics = await aiReliabilityEngine.calculateMetrics(1, 0);
    expect(metrics.total_requests).toBeDefined();
    expect(metrics.mean_truth_score).toBeDefined();
  });
});
