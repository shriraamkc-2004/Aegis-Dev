import { HybridDetector } from "../../src/hybrid_detector.js";
import { contextEngine } from "../../src/copilot/rolling_context.js";

describe("Real-Time Anomaly Detection Engine Tests", () => {
  let detector: HybridDetector;

  beforeEach(() => {
    detector = new HybridDetector({ iforestEnabled: true, ewmaAlpha: 0.15 });
    contextEngine.reset();
  });

  it("should analyze a streaming telemetry event immediately", async () => {
    const tNow = Date.now() / 1000;
    const event = {
      event_type: "order_placed",
      source: "web",
      timestamp: tNow,
    };

    const startTime = Date.now();
    const result = await detector.analyzeEvent(event, 60, 3.0);
    const latency = Date.now() - startTime;

    expect(latency).toBeLessThan(1000); // Verify latency is under 1 second (target < 1s)
    expect(result.zScore).toBeDefined();
    expect(result.ewmaScore).toBeDefined();
    expect(result.hybridScore).toBeDefined();
    expect(result.features).not.toBeNull();
    expect(result.features!.eventsPerSec).toBeGreaterThanOrEqual(0);
  });

  it("should flag severe anomaly burst rates using EWMA and Z-Score components", async () => {
    const tNow = Date.now() / 1000;

    // Inject 10 normal baseline events
    for (let i = 0; i < 10; i++) {
      await detector.analyzeEvent(
        { event_type: "order_placed", source: "web", timestamp: tNow - 10 + i },
        60,
        3.0,
      );
    }

    // Inject a massive burst of events at the current second
    const burstResults = [];
    for (let i = 0; i < 30; i++) {
      const res = await detector.analyzeEvent(
        { event_type: "order_placed", source: "web", timestamp: tNow },
        60,
        3.0,
      );
      burstResults.push(res);
    }

    const finalResult = burstResults[burstResults.length - 1];
    expect(finalResult.hybridScore).toBeGreaterThan(0);
    expect(finalResult.zScore).toBeGreaterThan(0);
  });
});
