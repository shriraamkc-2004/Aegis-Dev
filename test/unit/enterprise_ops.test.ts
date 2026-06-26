import { iocIngestionService } from "../../src/copilot/ioc_ingestion.js";
import { sigmaRulesEngine } from "../../src/copilot/sigma_rules.js";
import { webhookDispatcherService } from "../../src/observability/webhook_dispatcher.js";

describe("Enterprise Operations Services", () => {
  describe("IOC Ingestion Service", () => {
    it("should initialize default indicators", () => {
      const status = iocIngestionService.getStatus();
      expect(status.total_indicators).toBeGreaterThan(0);
      expect(status.types.ip).toBeGreaterThan(0);
    });

    it("should ingest raw indicators in JSON format", async () => {
      const rawJson = '{"value":"192.0.2.1", "type":"ip", "source":"threat_feed", "severity":"HIGH", "description":"Test IP"}\n';
      const count = await iocIngestionService.ingestFromRaw(rawJson, "json");
      expect(count).toBe(1);
      
      const check = await iocIngestionService.checkIndicator("ip", "192.0.2.1");
      expect(check.length).toBeGreaterThan(0);
      expect(check[0].severity).toBe("HIGH");
    });
  });

  describe("Sigma Rules Engine", () => {
    it("should match event against brute force rule", () => {
      const event = {
        status: "failed",
        event_type: "auth_attempt",
        user_name: "attacker"
      };
      
      const matches = sigmaRulesEngine.evaluateEvent(event);
      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].id).toBe("sigma-01");
    });

    it("should ignore events that do not match", () => {
      const event = {
        status: "success",
        event_type: "auth_attempt"
      };
      
      const matches = sigmaRulesEngine.evaluateEvent(event);
      expect(matches.length).toBe(0);
    });
  });

  describe("Webhook Dispatcher Service", () => {
    it("should mock dispatching alerts to Slack", async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({})
      });

      const payload = {
        incident_id: "inc-123",
        severity: "CRITICAL" as const,
        title: "Database Breach",
        description: "Potential exfiltration detected",
        timestamp: Date.now()
      };

      const success = await webhookDispatcherService.dispatchSlack("http://mock-slack-webhook", payload);
      expect(success).toBe(true);
      expect(fetch).toHaveBeenCalled();
    });
  });
});
