/**
 * Aegis Comprehensive Validation Verification Script
 * Executes empirical runtime verification across Log Normalization, Detection, SOAR Guardrails, Multi-Tenancy, and Auth.
 */

import { normalizeLog } from "../src/collector/log_normalizer.js";
import { checkAndIncrementEventQuota } from "../src/saas/tenant_quota.js";
import { runPlaybooks, runQuickResponse } from "../src/soar/playbook_engine.ts";
import { isRefreshTokenRevoked, revokeRefreshToken } from "../src/auth.js";

async function runComprehensiveVerification() {
  console.log("=================================================");
  console.log("🛡️ ANOMALY AEGIS COMPREHENSIVE RUNTIME VALIDATION");
  console.log("=================================================\n");

  const results: Record<string, boolean> = {};

  // 1. Log Normalization Tests
  try {
    const jsonInput = JSON.stringify({
      event_type: "login_failed",
      user_name: "alice",
      source_ip: "192.168.1.10",
    });
    const normJson = normalizeLog(jsonInput, "json");

    const syslogInput =
      "<34>1 2026-09-19T12:00:00Z firewall1 kernel - - [meta] Failed password for root from 10.0.0.1";
    const normSyslog = normalizeLog(syslogInput, "syslog");

    const cefInput =
      "CEF:0|Vendor|Product|1.0|100|Failed Login|8|src=10.0.0.5 suser=bob msg=Invalid password";
    const normCef = normalizeLog(cefInput, "cef");

    const kvInput =
      "time=2026-09-19T12:00:00Z action=block src=1.2.3.4 dst=5.6.7.8 user=charlie";
    const normKv = normalizeLog(kvInput, "kv");

    const passNorm =
      normJson.length > 0 &&
      normSyslog.length > 0 &&
      normCef.length > 0 &&
      normKv.length > 0;
    results["Log Normalization (JSON/Syslog/CEF/KV)"] = passNorm;
    console.log(`[+] Log Normalization: ${passNorm ? "PASS ✅" : "FAIL ❌"}`);
  } catch (err: any) {
    results["Log Normalization (JSON/Syslog/CEF/KV)"] = false;
    console.log(`[-] Log Normalization Error: ${err.message}`);
  }

  // 2. SOAR Human-in-the-Loop Safety Guardrails Test
  try {
    const quickResult = await runQuickResponse(
      {
        organization_id: 1,
        anomaly_id: 101,
        severity: "CRITICAL",
        z_score: 4.8,
        detection_method: "HYBRID",
        timestamp: new Date(),
      },
      [
        {
          type: "notify_slack",
          params: { webhook_url: "https://hooks.slack.com/mock" },
        },
        { type: "block_ip", params: { ip: "1.2.3.4" } }, // Destructive — MUST be blocked by guardrail!
        { type: "delete_data", params: { target: "all" } }, // Destructive — MUST be blocked by guardrail!
      ],
    );

    const guardrailBlocked =
      quickResult.actions_skipped.includes("block_ip") &&
      quickResult.actions_skipped.includes("delete_data") &&
      quickResult.errors.some((e) => e.includes("GUARDRAIL BLOCKED"));

    results["SOAR Human-in-the-Loop Guardrail Safety"] = guardrailBlocked;
    console.log(
      `[+] SOAR Safety Guardrails: ${guardrailBlocked ? "PASS ✅ (Destructive actions blocked!)" : "FAIL ❌"}`,
    );
  } catch (err: any) {
    results["SOAR Human-in-the-Loop Guardrail Safety"] = false;
    console.log(`[-] SOAR Guardrail Error: ${err.message}`);
  }

  // 3. Tenant Quotas & Rate Control Test
  try {
    const quota1 = await checkAndIncrementEventQuota(999, "starter", 5000);
    const quota2 = await checkAndIncrementEventQuota(999, "starter", 6000); // Exceeds 10,000 limit

    const quotaPass = quota1.allowed === true && quota2.allowed === false;
    results["In-Memory Tenant Quotas & Enforcement"] = quotaPass;
    console.log(
      `[+] Tenant Quotas: ${quotaPass ? "PASS ✅ (Over-quota request rejected!)" : "FAIL ❌"}`,
    );
  } catch (err: any) {
    results["In-Memory Tenant Quotas & Enforcement"] = false;
    console.log(`[-] Quota Error: ${err.message}`);
  }

  // 4. Token Revocation & Auth Blacklist Test
  try {
    const sampleToken = "sample_test_refresh_token_string_12345";
    const beforeRevoke = await isRefreshTokenRevoked(sampleToken);
    await revokeRefreshToken(sampleToken);
    const afterRevoke = await isRefreshTokenRevoked(sampleToken);

    const authPass = !beforeRevoke && afterRevoke;
    results["In-Memory Auth Blacklist Revocation"] = authPass;
    console.log(
      `[+] Token Revocation Blacklist: ${authPass ? "PASS ✅" : "FAIL ❌"}`,
    );
  } catch (err: any) {
    results["In-Memory Auth Blacklist Revocation"] = false;
    console.log(`[-] Token Revocation Error: ${err.message}`);
  }

  console.log("\n=================================================");
  console.log("VERIFICATION SUMMARY:", JSON.stringify(results, null, 2));
  console.log("=================================================");
}

runComprehensiveVerification();
