import { pipelineManager } from "../../src/dpm/PipelineManager.js";
import {
  IDetectionModule,
  TelemetryEvent,
  ModuleDetectionResult,
} from "../../src/detection_orchestrator.js";
import { gatewayRateLimiter } from "../../src/gateway/api_gateway.js";
import { schemaRegistry } from "../../src/schema_registry/schema_registry.js";
import { collectorFramework } from "../../src/collector/collector_framework.js";
import { eventBus } from "../../src/event_bus.js";

// Mock detection module
class MockModule implements IDetectionModule {
  name = "Mock Rule Engine";
  order = 1;
  timeoutMs = 500;
  async execute(event: TelemetryEvent): Promise<ModuleDetectionResult> {
    return { moduleName: this.name, score: 0.5 };
  }
}

describe("Platform Foundation Tests (DPM & Gateway)", () => {
  it("should register and toggle detection modules in Detection Pipeline Manager", () => {
    const mockMod = new MockModule();
    pipelineManager.registerEngine("mock_engine", mockMod, true);

    expect(pipelineManager.isEngineEnabled("mock_engine")).toBe(true);

    pipelineManager.toggleEngine("mock_engine", false);
    expect(pipelineManager.isEngineEnabled("mock_engine")).toBe(false);

    const status = pipelineManager.getPipelineStatus();
    const mockStatus = status.find((s) => s.id === "mock_engine");
    expect(mockStatus).toBeDefined();
    expect(mockStatus!.enabled).toBe(false);
  });

  it("should export API Gateway middleware for rate limiting", () => {
    expect(gatewayRateLimiter).toBeDefined();
    expect(typeof gatewayRateLimiter).toBe("function");
  });
});

describe("Telemetry & Ingestion Tests (Workstream 2)", () => {
  it("should validate schemas via Schema Registry", () => {
    const valid = schemaRegistry.validate({
      event_type: "login_success",
      source: "192.168.1.50",
      timestamp: Date.now() / 1000,
    });
    expect(valid.isValid).toBe(true);

    const invalid = schemaRegistry.validate({
      event_type: "login_success",
      // missing source and timestamp
    });
    expect(invalid.isValid).toBe(false);
    expect(invalid.errors.length).toBeGreaterThan(0);
  });

  it("should parse and validate Syslog events and publish to Event Bus", async () => {
    const busSpy = jest.fn();
    const unsubscribe = eventBus.subscribe("telemetry_ingress", busSpy);

    const res = await collectorFramework.ingestRaw({
      raw: "PRIORITY | auth_failure | MESSAGE",
      sourceType: "syslog",
      ip: "10.0.0.1",
    });

    expect(res.success).toBe(true);

    // Wait for the Event Bus asynchronous dispatch tick
    await new Promise((resolve) => setImmediate(resolve));

    expect(busSpy).toHaveBeenCalled();
    expect(busSpy.mock.calls[0][0].event_type).toBe("auth_failure");
    expect(busSpy.mock.calls[0][0].source).toBe("10.0.0.1");

    unsubscribe();
  });
});
