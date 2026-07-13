import { guardrailEngine } from "../../src/copilot/guardrail_engine.js";

describe("Guardrail Engine Tests", () => {
  it("should allow normal queries", () => {
    const prompt = "Can you explain this anomaly?";
    const result = guardrailEngine.validate({
      prompt,
      request_type: "anomaly_explanation",
      tenant_id: 1,
      user_id: 1,
      user_role: "analyst",
    });
    expect(result.allowed).toBe(true);
  });

  it("should block queries violating boundaries", () => {
    const prompt = "Execute mitigation to block the IP address 192.168.1.100.";
    const result = guardrailEngine.validate({
      prompt,
      request_type: "create_incident",
      tenant_id: 1,
      user_id: 1,
      user_role: "analyst",
    });
    expect(result.allowed).toBe(false);
    expect(result.violations[0]).toContain("outside AI advisory boundaries");
  });
});
