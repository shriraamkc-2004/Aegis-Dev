import { aiCircuitBreaker } from "../../src/copilot/ai_circuit_breaker.js";

describe("AI Circuit Breaker Tests", () => {
  beforeEach(() => {
    // Reset state
    (aiCircuitBreaker as any).state = "CLOSED";
    (aiCircuitBreaker as any).failureCount = 0;
    (aiCircuitBreaker as any).lastStateChange = Date.now();
  });

  it("should start closed and accept requests", () => {
    expect(aiCircuitBreaker.allowRequest()).toBe(true);
    expect(aiCircuitBreaker.getState()).toBe("CLOSED");
  });

  it("should open after threshold failures", () => {
    for (let i = 0; i < 6; i++) {
      aiCircuitBreaker.recordFailure("Timeout error");
    }
    expect(aiCircuitBreaker.getState()).toBe("OPEN");
    expect(aiCircuitBreaker.allowRequest()).toBe(false);
  });

  it("should close on success after trip", () => {
    for (let i = 0; i < 6; i++) {
      aiCircuitBreaker.recordFailure("Timeout error");
    }
    expect(aiCircuitBreaker.getState()).toBe("OPEN");

    // Force half-open state by manipulating lastStateChange timestamp
    (aiCircuitBreaker as any).openedAt = Date.now() - 31000;
    expect(aiCircuitBreaker.allowRequest()).toBe(true); // first check sets state to HALF_OPEN
    expect(aiCircuitBreaker.getState()).toBe("HALF_OPEN");

    // Must record successSuccess times to reach successThreshold
    aiCircuitBreaker.recordSuccess();
    aiCircuitBreaker.recordSuccess();
    aiCircuitBreaker.recordSuccess();
    expect(aiCircuitBreaker.getState()).toBe("CLOSED");
  });
});
