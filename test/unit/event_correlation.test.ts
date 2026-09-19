/**
 * Aegis SIEM — Event Correlation Engine Unit Tests
 */

import { correlateEvents } from "../../src/engine/event_correlation_engine.js";

describe("SIEM Event Correlation Engine", () => {
  it("should correlate multiple failed logins followed by a successful login into a Brute Force Compromise incident", async () => {
    const orgId = 42;
    const attackerIp = "198.51.100.44";
    const now = new Date();

    // 1. Simulate 3 failed logins
    await correlateEvents(orgId, {
      id: 1001,
      organization_id: orgId,
      event_type: "login_failed",
      source: attackerIp,
      severity: "MEDIUM",
      timestamp: new Date(now.getTime() - 4000),
    });

    await correlateEvents(orgId, {
      id: 1002,
      organization_id: orgId,
      event_type: "login_failed",
      source: attackerIp,
      severity: "MEDIUM",
      timestamp: new Date(now.getTime() - 3000),
    });

    await correlateEvents(orgId, {
      id: 1003,
      organization_id: orgId,
      event_type: "login_failed",
      source: attackerIp,
      severity: "MEDIUM",
      timestamp: new Date(now.getTime() - 2000),
    });

    // 2. Simulate 1 successful login from same IP
    const incidents = await correlateEvents(orgId, {
      id: 1004,
      organization_id: orgId,
      event_type: "login_success",
      source: attackerIp,
      severity: "INFO",
      timestamp: new Date(now.getTime() - 1000),
    });

    expect(incidents.length).toBeGreaterThan(0);
    const bruteForceIncident = incidents.find(
      (i) => i.rule_id === "RULE_BRUTE_FORCE_SUCCESS",
    );
    expect(bruteForceIncident).toBeDefined();
    expect(bruteForceIncident?.severity).toBe("CRITICAL");
    expect(bruteForceIncident?.entity_id).toBe(attackerIp);
    expect(bruteForceIncident?.confidence).toBe(0.95);
  });

  it("should correlate login_success followed by data_exfiltration into an Account Takeover incident", async () => {
    const orgId = 99;
    const username = "admin_john";
    const now = new Date();

    await correlateEvents(orgId, {
      id: 2001,
      organization_id: orgId,
      event_type: "login_success",
      source: "10.0.0.1",
      user_name: username,
      severity: "INFO",
      timestamp: new Date(now.getTime() - 2000),
    });

    const incidents = await correlateEvents(orgId, {
      id: 2002,
      organization_id: orgId,
      event_type: "data_exfiltration",
      source: "10.0.0.1",
      user_name: username,
      severity: "HIGH",
      timestamp: new Date(now.getTime() - 1000),
    });

    expect(incidents.length).toBeGreaterThan(0);
    const exfilIncident = incidents.find(
      (i) => i.rule_id === "RULE_TAKEOVER_EXFILTRATION",
    );
    expect(exfilIncident).toBeDefined();
    expect(exfilIncident?.entity_id).toBe(username);
  });
});
