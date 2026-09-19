import jwt from "jsonwebtoken";

const JWT_SECRET =
  process.env.JWT_SECRET ||
  "Kqp-MpRPM24fgP3L6vwb9d7T7HXbtTXRGzp1XuONUVMlng0oB2H5qUdGG06n__KPG_yjpw3Z4fKpEowlnl-xVg";

async function verifyAll() {
  console.log("=====================================================");
  console.log(" Aegis Comprehensive Backend Consistency Audit");
  console.log("=====================================================");

  // 1. Test Login endpoint
  console.log("\n[1] Testing Auth Endpoint (/api/auth/login)...");
  const loginRes = await fetch("http://localhost:3010/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "demo_admin",
      password: "demo123",
      mode: "demo",
    }),
  });
  console.log("Login Status:", loginRes.status);
  const loginData = (await loginRes.json()) as any;
  if (loginRes.status !== 200 || !loginData.token) {
    console.error("❌ Login failed:", loginData);
    process.exit(1);
  }
  const token = loginData.token;
  console.log("✅ Authenticated successfully as demo_admin. Token received.");

  // 2. Test Endpoints
  const routes = [
    { url: "http://localhost:3010/api/history", name: "Telemetry History" },
    { url: "http://localhost:3010/api/anomalies", name: "Anomaly Log" },
    { url: "http://localhost:3010/api/incidents", name: "Incidents" },
    { url: "http://localhost:3010/api/cases", name: "Cases" },
    {
      url: "http://localhost:3010/api/governance/policies",
      name: "Governance Policies",
    },
    {
      url: "http://localhost:3010/api/threat-intel/indicators",
      name: "Threat Intel Indicators",
    },
    {
      url: "http://localhost:3010/api/dr/status",
      name: "Disaster Recovery Status",
    },
    {
      url: "http://localhost:3010/api/health/detailed",
      name: "Detailed Health",
    },
    {
      url: "http://localhost:3010/api/observability/metrics",
      name: "Observability Metrics",
    },
    {
      url: "http://localhost:3010/api/mitre/matrix",
      name: "MITRE ATT&CK Matrix",
    },
    { url: "http://localhost:3010/api/connectors", name: "Connectors" },
    { url: "http://localhost:3010/api/users", name: "Users" },
  ];

  console.log("\n[2] Checking Core Endpoints Consistency...");
  let passCount = 0;
  for (const r of routes) {
    try {
      const res = await fetch(r.url, {
        headers: { Authorization: "Bearer " + token },
      });
      const text = await res.text();
      let data: any = null;
      try {
        data = JSON.parse(text);
      } catch (e) {}

      if (res.status >= 200 && res.status < 400) {
        const desc = Array.isArray(data)
          ? `Array[${data.length}]`
          : typeof data === "object" && data !== null
            ? Object.keys(data).slice(0, 4).join(", ")
            : typeof data;
        console.log(
          `  ✅ [PASS] ${r.name.padEnd(28)} Status ${res.status} | Data: ${desc}`,
        );
        passCount++;
      } else {
        console.log(
          `  ❌ [FAIL] ${r.name.padEnd(28)} Status ${res.status} | Response: ${text.slice(0, 100)}`,
        );
      }
    } catch (err: any) {
      console.log(
        `  ❌ [ERROR] ${r.name.padEnd(28)} Exception: ${err.message}`,
      );
    }
  }

  console.log(`\nResults: ${passCount}/${routes.length} endpoints passed.`);

  // 3. Test Ingestion Flow
  console.log("\n[3] Testing Ingestion Pipeline (/api/ingestion/status)...");
  const ingestRes = await fetch("http://localhost:3010/api/ingestion/status", {
    headers: {
      Authorization: "Bearer " + token,
    },
  });
  console.log(`Ingest Status: ${ingestRes.status}`);
  if (ingestRes.status === 200 || ingestRes.status === 201) {
    const ingestData = await ingestRes.json();
    console.log("✅ Ingestion pipeline status active:", ingestData);
  } else {
    const ingestText = await ingestRes.text();
    console.log("Note on Ingest:", ingestText.slice(0, 100));
  }

  console.log("\n=====================================================");
  console.log(" Backend Consistency Check Finished");
  console.log("=====================================================");
}

verifyAll().catch((err) => {
  console.error("Fatal audit script error:", err);
  process.exit(1);
});
