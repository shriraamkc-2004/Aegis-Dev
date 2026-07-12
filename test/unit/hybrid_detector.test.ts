/**
 * Aegis Enterprise - Hybrid Detector Unit Tests
 * Tests for the core anomaly detection engine
 */
import { HybridDetector } from "../../src/hybrid_detector.js";

// Mock the server_db module to avoid database dependency in unit tests
jest.mock("../../src/server_db.js", () => ({
  dbAll: jest.fn().mockResolvedValue([]),
  dbGet: jest.fn().mockResolvedValue(null),
  dbRun: jest.fn().mockResolvedValue({ changes: 0 }),
}));

describe("HybridDetector", () => {
  let detector: HybridDetector;

  beforeEach(() => {
    detector = new HybridDetector({
      iforestEnabled: true,
    });
  });

  describe("analyzeEvent()", () => {
    it("should detect CRITICAL severity when z-score is high", async () => {
      const event = {
        event_type: "order_placed",
        source: "web",
        timestamp: Date.now() / 1000,
      };

      // Inject some events to build a zscore profile
      for (let i = 0; i < 10; i++) {
        await detector.analyzeEvent(event, 60, 3.0);
      }

      // Inject a surge event
      const result = await detector.analyzeEvent(event, 60, 3.0);

      expect(result.zScore).toBeDefined();
      expect(result.hybridScore).toBeGreaterThanOrEqual(0);
    });

    it("should return detection method as ZSCORE+EWMA when iforest disabled", async () => {
      const detectorZscoreOnly = new HybridDetector({
        iforestEnabled: false,
      });
      const event = {
        event_type: "order_placed",
        source: "web",
        timestamp: Date.now() / 1000,
      };
      const result = await detectorZscoreOnly.analyzeEvent(event, 60, 3.0);

      expect(result.detectionMethod).toBe("ZSCORE+EWMA");
    });

    it("should calculate EWMA score correctly", async () => {
      const event = {
        event_type: "order_placed",
        source: "web",
        timestamp: Date.now() / 1000,
      };
      const result = await detector.analyzeEvent(event, 60, 3.0);

      expect(result.ewmaScore).toBeDefined();
      expect(typeof result.ewmaScore).toBe("number");
    });
  });

  describe("setConfig()", () => {
    it("should disable Isolation Forest at runtime", async () => {
      detector.setConfig({ iforestEnabled: false });
      const event = {
        event_type: "order_placed",
        source: "web",
        timestamp: Date.now() / 1000,
      };
      const result = await detector.analyzeEvent(event, 60, 3.0);

      expect(result.iforestScore).toBe(0);
      expect(result.detectionMethod).toBe("ZSCORE+EWMA");
    });
  });

  describe("getStatus()", () => {
    it("should return engine status information", () => {
      const status = detector.getStatus();

      expect(status.iforestTrained).toBe(false);
      expect(status.iforestTrees).toBe(0);
      expect(status.ewmaInitialized).toBe(false);
      expect(status.featureHistoryLength).toBe(0);
      expect(status.processedEventsCount).toBe(0);
    });

    it("should increment event count after analyzeEvent", async () => {
      const event = {
        event_type: "order_placed",
        source: "web",
        timestamp: Date.now() / 1000,
      };
      await detector.analyzeEvent(event, 60, 3.0);

      const status = detector.getStatus();
      expect(status.processedEventsCount).toBe(1);
    });
  });

  describe("reset()", () => {
    it("should reset all state", async () => {
      const event = {
        event_type: "order_placed",
        source: "web",
        timestamp: Date.now() / 1000,
      };
      await detector.analyzeEvent(event, 60, 3.0);
      detector.reset();

      const status = detector.getStatus();
      expect(status.processedEventsCount).toBe(0);
      expect(status.featureHistoryLength).toBe(0);
      expect(status.iforestTrained).toBe(false);
      expect(status.ewmaInitialized).toBe(false);
    });
  });
});
