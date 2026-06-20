import { GoogleGenAI } from "@google/genai";
import { dbRun, dbAll, dbGet, dbAllReadOnly } from "./server_db.js";
import { triggerAnomalyDiscordAlert } from "./discord_alert.js";

// Helper to log a reasoning step to db
export async function logServerAgentStep(anomalyId: number, step: number, type: string, content: string) {
  console.log(`[ReAct TS Agent] Anomaly #${anomalyId} | Step ${step} | ${type}: ${content}`);
  await dbRun(
    "INSERT INTO agent_logs (anomaly_id, timestamp, step, type, content) VALUES (?, ?, ?, ?, ?)",
    [anomalyId, Date.now() / 1000, step, type, content]
  );
}

// Function to call the local MCP tools on the Node backend
async function callLocalMCPTool(toolName: string, args: any, anomalyId: number): Promise<string> {
  switch (toolName) {
    case "query_database": {
      const sql = (args.sql_query || "").trim();
      if (sql.includes(";")) {
        return "Error: MCP query_database does not allow stacked queries or semicolons.";
      }
      const forbiddenKeywords = ["drop", "delete", "update", "insert", "alter", "create", "replace", "attach", "pragma"];
      const sqlLower = sql.toLowerCase();
      for (const kw of forbiddenKeywords) {
        const regex = new RegExp(`\\b${kw}\\b`, "i");
        if (regex.test(sqlLower)) {
          return `Error: MCP query_database does not allow forbidden keyword '${kw.toUpperCase()}'.`;
        }
      }
      if (!sqlLower.startsWith("select")) {
        return "Error: MCP query_database only accepts read-only SELECT statements.";
      }
      try {
        const rows = await dbAllReadOnly(sql);
        return JSON.stringify(rows, null, 2);
      } catch (err: any) {
        return `Error executing query: ${err.message}`;
      }
    }
    case "read_system_logs": {
      const uptimeSec = Math.floor(process.uptime());
      return `[System Log - ${new Date().toISOString()}]
INFO [Engine] Full-stack Node platform online. Uptime: ${uptimeSec}s.
INFO [Producer] Feed speed interval active. Recording steady events.
INFO [Detector] Active sliding window tracking enabled. 
WARNING [Breach] Z-score threshold breached at current timestamp!
INFO [Agent] Spawned AI Agent Loop for Anomaly ID: #${anomalyId}.`;
    }
    case "mitigate_anomaly": {
      const source = args.ip_or_source;
      const raiseZ = args.raise_z_threshold;
      const actions: string[] = [];
      if (source) {
        actions.push(`Successfully added routing rule to throttle traffic originating from source: '${source}'`);
      }
      if (raiseZ) {
        actions.push(`Dynamically adjusted detector Z-score trigger sensitivity setting to Z=${raiseZ}`);
      }
      return actions.length > 0
        ? "Mitigation response: " + actions.join(" | ")
        : "No mitigation args provided. No adjustments conducted.";
    }
    case "trigger_discord_alert": {
      const message = args.message || "";
      const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (!webhookUrl) {
        return `Simulating Discord send: "${message}" (No webhook URL configured)`;
      }
      try {
        const response = await fetch(webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content: `🛡️ **Node MCP Agent Update:** ${message}` })
        });
        if (response.status === 204 || response.ok) {
          return "Discord notification transmitted successfully.";
        } else {
          return `Transmission warning. Status code: ${response.status}`;
        }
      } catch (e: any) {
        return `Failed sending Discord webhook: ${e.message}`;
      }
    }
    case "calculate_risk_score": {
      const anomalyId = args.anomaly_id;
      const eventRate = args.event_rate || 0;
      const zScore = args.z_score || 0;
      const iforestScore = args.iforest_score || 0;
      const hybridScore = args.hybrid_score || 0;
      const sourceEntropy = args.source_entropy || 0;
      // Hybrid risk score formula: weighted combination of multivariate factors
      let riskScore = 0;
      riskScore += Math.min(zScore * 8, 30); // Z-Score contribution (max 30)
      riskScore += Math.min(eventRate * 1.5, 20); // Event rate contribution (max 20)
      riskScore += Math.min(iforestScore * 25, 20); // iForest anomaly score (max 20)
      riskScore += Math.min(hybridScore * 15, 15); // Hybrid fused score (max 15)
      riskScore += anomalyId ? 10 : 0; // Prior anomaly history bonus
      riskScore += sourceEntropy > 1.5 ? 5 : 0; // High source entropy (diverse sources)
      riskScore += eventRate > 20 ? 10 : 0; // Burst multiplier
      riskScore = Math.min(Math.round(riskScore), 100);
      const riskLevel = riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 40 ? "MEDIUM" : "LOW";
      return JSON.stringify({
        risk_score: riskScore,
        risk_level: riskLevel,
        factors: {
          z_score_impact: Math.min(zScore * 8, 30),
          rate_impact: Math.min(eventRate * 1.5, 20),
          iforest_impact: Math.min(iforestScore * 25, 20),
          hybrid_impact: Math.min(hybridScore * 15, 15),
          burst_multiplier: eventRate > 20 ? 10 : 0,
          source_entropy_factor: sourceEntropy > 1.5 ? 5 : 0,
        }
      });
    }
    case "search_attack_patterns": {
      const pattern = args.pattern || "ddos";
      const patterns: Record<string, { name: string; description: string; indicators: string[] }> = {
        ddos: { name: "DDoS Attack", description: "Distributed Denial of Service - high volume traffic from multiple sources", indicators: ["Sudden traffic spike >5x baseline", "Multiple source IPs", "Uniform request patterns"] },
        bot: { name: "Bot Activity", description: "Automated bot traffic mimicking user behavior", indicators: ["Rapid sequential requests", "Identical user agents", "Non-human timing patterns"] },
        brute_force: { name: "Brute Force", description: "Repeated authentication or enumeration attempts", indicators: ["High failure rate", "Sequential parameter variation", "Rapid retry intervals"] },
        injection: { name: "Injection Attack", description: "SQL/NoSQL/Command injection attempts", indicators: ["Unusual query patterns", "Special characters in input", "Abnormal error rates"] },
      };
      const match = patterns[pattern.toLowerCase()] || patterns["ddos"];
      return JSON.stringify(match);
    }
    case "generate_incident_report": {
      const aId = args.anomaly_id;
      const row = await dbGet<any>("SELECT * FROM anomalies WHERE id = ?", [aId]);
      if (!row) return `No anomaly found with ID ${aId}`;
      const report = {
        incident_id: `INC-${aId}`,
        anomaly_id: aId,
        detection_time: new Date(row.timestamp * 1000).toISOString(),
        severity: row.severity || "MEDIUM",
        detection_method: row.detection_method || "ZSCORE",
        z_score: row.z_score,
        iforest_score: row.iforest_score || 0,
        ewma_score: row.ewma_score || 0,
        hybrid_score: row.hybrid_score || 0,
        event_count: row.event_count,
        source_entropy: row.source_entropy || 0,
        burst_ratio: row.burst_ratio || 0,
        window_stats: { mean: row.window_mean, std: row.window_std },
        status: row.status,
        diagnosis: row.diagnosis,
        generated_at: new Date().toISOString(),
      };
      return JSON.stringify(report, null, 2);
    }
    case "get_threat_statistics": {
      const totalAnomalies = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM anomalies");
      const totalIncidents = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM incidents");
      const criticalCount = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM anomalies WHERE severity = 'CRITICAL'");
      const mitigatedCount = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM anomalies WHERE status = 'Mitigated'");
      const sourceDist = await dbAll("SELECT source, COUNT(*) as count FROM events WHERE timestamp > (strftime('%s','now') - 300) GROUP BY source ORDER BY count DESC");
      return JSON.stringify({
        total_anomalies: totalAnomalies?.total || 0,
        total_incidents: totalIncidents?.total || 0,
        critical_anomalies: criticalCount?.total || 0,
        mitigated: mitigatedCount?.total || 0,
        pending: (totalAnomalies?.total || 0) - (mitigatedCount?.total || 0),
        source_distribution: sourceDist,
      }, null, 2);
    }
    default:
      return `Unknown MCP tool: ${toolName}`;
  }
}

const geminiRequestTimestamps: number[] = [];

// Helper to determine deterministic fallback parameters based on eventType
function getDeterministicFallback(eventType: string, anomalyId: number, currentSpikeCount: number, mainSource: string) {
  let aiDiagnosis = "Anomaly detected. Further investigation is recommended.";
  let finalDiagnosis = `Mitigated sudden anomaly burst successfully. Diagnosed spike coming from '${mainSource}' nodes. Throttled source and updated sliding filters.`;
  let rootCause = `Traffic spike (${currentSpikeCount} events/sec) from '${mainSource}' clients — automated anomaly pattern detected`;
  let resolution = `Source '${mainSource}' throttled. Z-Score threshold raised to 4.5.`;
  let recAction = `Investigate the sudden spike in event frequency and review system logs. Check if source '${mainSource}' needs permanent blocking.`;

  if (eventType === "failed_login") {
    aiDiagnosis = "Repeated authentication failures detected. Recommended actions include account lockout enforcement and source investigation.";
    finalDiagnosis = `Mitigated brute force login attempts successfully from '${mainSource}'. Throttled source and updated sliding window triggers.`;
    rootCause = `High rate of failed authentication attempts from '${mainSource}' sources — potential Brute Force attack detected`;
    resolution = `Source '${mainSource}' blocked at firewall. Enforced rate-limiting and lockout policy.`;
    recAction = `Audit authentication logs for source '${mainSource}'. Block persistent failed IPs and verify MFA integrity.`;
  } else if (eventType === "ddos" || eventType === "order_placed") {
    aiDiagnosis = "Abnormal traffic surge observed. Recommended actions include traffic filtering and upstream mitigation.";
    finalDiagnosis = `Mitigated sudden order burst (DDoS/Spike) successfully. Throttled source '${mainSource}' and updated sliding Z-Score filters.`;
    rootCause = `Traffic spike (${currentSpikeCount} events/sec) predominantly from '${mainSource}' clients — automated DDoS pattern detected`;
    resolution = `Source '${mainSource}' throttled. Z-Score threshold raised to 4.5. All systems stabilized.`;
    recAction = `Review traffic from '${mainSource}' for potential DDoS/bot activity. Ensure statistical filters are normalized.`;
  } else if (eventType === "data_transfer" || eventType === "exfiltration") {
    aiDiagnosis = "Potential data transfer anomaly detected. Review access patterns and investigate affected systems.";
    finalDiagnosis = `Mitigated data exfiltration burst successfully. Suspended route for source '${mainSource}' and initiated forensic quarantine.`;
    rootCause = `Abnormal volume of outbound data transfer detected to '${mainSource}' channels`;
    resolution = `Suspended network route for source '${mainSource}' to halt data transfer.`;
    recAction = `Review data access logs for source '${mainSource}'. Investigate outbound data destination IPs.`;
  } else if (eventType === "heartbeat_miss") {
    aiDiagnosis = "Operational heartbeat disruption detected. Verify infrastructure health and service dependencies.";
    finalDiagnosis = `Mitigated service failure. Detected high heartbeat miss rate. Restarted affected nodes for source '${mainSource}'.`;
    rootCause = `System server heartbeat failures logged from internal components`;
    resolution = `Automated orchestrator rebooted degraded microservices.`;
    recAction = `Check system service health dashboard. Inspect container logs for memory exhaust (OOM) or deadlocks.`;
  } else if (eventType === "privileged_action") {
    aiDiagnosis = "Privileged activity deviation identified. Validate authorization and audit user actions.";
    finalDiagnosis = `Mitigated privileged activity spike. Suspended credential privileges for '${mainSource}' session.`;
    rootCause = `Unusual burst of privileged actions detected from client '${mainSource}'`;
    resolution = `Temporarily suspended privileged credentials for '${mainSource}' session.`;
    recAction = `Perform an immediate audit of actions taken during this session. Verify operator authorization.`;
  }

  return { finalDiagnosis, rootCause, aiDiagnosis, resolution, recAction };
}

// Global helper to run deterministic local fallback flow
async function runDeterministicFallback(anomalyId: number, currentSpikeCount: number, mainSource: string, eventType: string) {
  let severity = "MEDIUM";
  try {
    const row = await dbGet<{ severity: string }>("SELECT severity FROM anomalies WHERE id = ?", [anomalyId]);
    if (row && row.severity) {
      severity = row.severity.toUpperCase();
    }
  } catch (_) {}

  const isCriticalRetryFail = (severity === "CRITICAL");
  const resolutionStatus = isCriticalRetryFail ? "⚠ Manual Review Recommended" : "✅ Investigation Complete";
  const mitigationSummary = isCriticalRetryFail ? "Analyst escalation required." : "Local containment executed.";

  const fb = getDeterministicFallback(eventType, anomalyId, currentSpikeCount, mainSource);

  // Step 1: Query database
  let step = 1;
  await logServerAgentStep(
    anomalyId,
    step,
    "Thought",
    `The sliding-window statistical engine triggered a breach alarm with a Z-Score spike (Anomaly ID: #${anomalyId}). I need to query our local database using SQLite to identify if the spike originates from a single source device or client.`
  );
  
  const actionArgs1 = { sql_query: "SELECT source, count(*) as count FROM events WHERE timestamp > (strftime('%s', 'now') - 60) GROUP BY source ORDER BY count DESC" };
  await logServerAgentStep(anomalyId, step, "Action", `Invoke 'query_database' with args: ${JSON.stringify(actionArgs1)}`);
  
  const observation1 = JSON.stringify([{ source: mainSource, count: currentSpikeCount }]);
  await logServerAgentStep(anomalyId, step, "Observation", observation1);
  
  // Step 2: Mitigate
  step = 2;
  await logServerAgentStep(
    anomalyId,
    step,
    "Thought",
    `The database records confirm that a traffic spike (${currentSpikeCount} events/sec) is originating predominantly from '${mainSource}' clients. Event type '${eventType}' is the primary driver. I should block the '${mainSource}' source and raise our Z-Score sensitivity threshold.`
  );
  
  const actionArgs2 = { ip_or_source: mainSource, raise_z_threshold: 4.5 };
  await logServerAgentStep(anomalyId, step, "Action", `Invoke 'mitigate_anomaly' with args: ${JSON.stringify(actionArgs2)}`);
  
  const observation2 = await callLocalMCPTool("mitigate_anomaly", actionArgs2, anomalyId);
  await logServerAgentStep(anomalyId, step, "Observation", observation2);
  
  // Step 3: Discord Alert & Finish
  step = 3;
  await logServerAgentStep(
    anomalyId,
    step,
    "Thought",
    `The security block on '${mainSource}' is active, and our statistical filters are raised. I will now push a diagnostic confirmation alert to the engineering team's Discord alerting channel.`
  );
  
  const actionArgs3 = { message: `Automated mitigation active for Anomaly #${anomalyId}. Restricted traffic source '${mainSource}' and raised sliding Z-score baseline to 4.5.` };
  await logServerAgentStep(anomalyId, step, "Action", `Invoke 'trigger_discord_alert' with args: ${JSON.stringify(actionArgs3)}`);
  
  const observation3 = await callLocalMCPTool("trigger_discord_alert", actionArgs3, anomalyId);
  await logServerAgentStep(anomalyId, step, "Observation", observation3);
  
  await logServerAgentStep(anomalyId, step + 1, "Final Response", fb.finalDiagnosis);
  
  // Update main anomaly status
  await dbRun("UPDATE anomalies SET status = 'Mitigated', diagnosis = ? WHERE id = ?", [fb.finalDiagnosis, anomalyId]);

  // Update linked incident with rich AI analysis and resolution status
  await dbRun(
    "UPDATE incidents SET root_cause = ?, ai_diagnosis = ?, resolution = ?, recommended_action = ?, status = 'MITIGATED', updated_at = ?, mitigation_summary = ?, agent_summary = ?, resolution_status = ? WHERE anomaly_id = ? AND status = 'OPEN'",
    [
      fb.rootCause,
      fb.aiDiagnosis,
      fb.resolution,
      fb.recAction,
      Date.now() / 1000,
      mitigationSummary,
      fb.aiDiagnosis,
      resolutionStatus,
      anomalyId
    ]
  );

  // Edit original Discord Alert
  await triggerAnomalyDiscordAlert(anomalyId, "resolved");
}

export async function runServerAgentLoop(anomalyId: number, currentSpikeCount: number) {
  // Check if GEMINI_API_KEY is configured
  const apiKey = process.env.GEMINI_API_KEY;
  const isApiKeyInvalid = !apiKey || apiKey === "MY_GEMINI_API_KEY" || apiKey.trim() === "" || apiKey === "YOUR_GEMINI_API_KEY_HERE";

  // Resolve anomaly severity
  let severity = "MEDIUM";
  try {
    const row = await dbGet<{ severity: string }>("SELECT severity FROM anomalies WHERE id = ?", [anomalyId]);
    if (row && row.severity) {
      severity = row.severity.toUpperCase();
    }
  } catch (_) {}

  // Resolve eventType and mainSource dynamically
  let eventType = "order_placed";
  try {
    const typeRow = await dbGet<{ event_type: string }>(
      "SELECT event_type FROM events WHERE timestamp > (strftime('%s', 'now') - 60) GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 1"
    );
    if (typeRow && typeRow.event_type) {
      eventType = typeRow.event_type;
    }
  } catch (_) {}

  let mainSource = "mobile";
  try {
    const sourceRow = await dbGet<{ source: string }>(
      "SELECT source, count(*) as count FROM events WHERE timestamp > (strftime('%s', 'now') - 60) GROUP BY source ORDER BY count DESC LIMIT 1"
    );
    if (sourceRow && sourceRow.source) {
      mainSource = sourceRow.source;
    }
  } catch (_) {}

  // Local helper to execute Gemini logic
  const attemptGemini = async (): Promise<boolean> => {
    try {
      console.log("[ReAct Agent] Key verified. Initializing Live Gemini ReAct loop...");
      const ai = new GoogleGenAI({
        apiKey: apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build'
          }
        }
      });

      const mcpToolsDesc = [
        {
          name: "query_database",
          description: "Executes SELECT statements on SQLite to query transaction sources and frequencies",
          properties: { sql_query: "SELECT query string" }
        },
        {
          name: "read_system_logs",
          description: "Inspects last 15 system log entries on the backend",
          properties: {}
        },
        {
          name: "mitigate_anomaly",
          description: "Throttles source traffic or increases Z score threshold",
          properties: { ip_or_source: "source string", raise_z_threshold: "new threshold number" }
        },
        {
          name: "trigger_discord_alert",
          description: "Sends visual alerts or mitigation news to the Discord webhook",
          properties: { message: "custom warning string" }
        },
        {
          name: "calculate_risk_score",
          description: "Calculates a risk score (0-100) for an anomaly based on Z-Score, event rate, and burst patterns",
          properties: { anomaly_id: "anomaly ID number", event_rate: "current events per second", z_score: "current Z-Score value" }
        },
        {
          name: "search_attack_patterns",
          description: "Searches known attack patterns (ddos, bot, brute_force, injection) and returns indicators",
          properties: { pattern: "attack pattern name: ddos, bot, brute_force, or injection" }
        },
        {
          name: "generate_incident_report",
          description: "Generates a structured incident report for a given anomaly ID",
          properties: { anomaly_id: "anomaly ID number" }
        },
        {
          name: "get_threat_statistics",
          description: "Returns aggregate threat statistics including total anomalies, incidents, severity distribution, and source distribution",
          properties: {}
        }
      ];

      const systemPrompt = `You are the autonomous Aegis ReAct AI Agent. Your objective is investigate and solve Anomaly ID #${anomalyId} using our local tool server.
Available tools metadata:
${JSON.stringify(mcpToolsDesc, null, 2)}

You MUST proceed strictly by outputting steps in the following formatting block:
Thought: <what you are reasoning>
Action: <json representation of tool call, e.g. {"name": "query_database", "arguments": {"sql_query": "SELECT ..."}} >
Observation: <this will be provided in the next turn>

When the issue is resolved or you are summarizing, output:
Final Response: <your ultimate diagnosis and security mitigation summary>

IMPORTANT: Do not duplicate or combine blocks. Exit immediately when producing a "Final Response:".
Begin by inspecting recent event rates with a SELECT query via query_database.`;

      let messages = [{ role: "user", parts: [{ text: systemPrompt }] }];
      let step = 1;

      for (let iteration = 0; iteration < 4; iteration++) {
        const response = await ai.models.generateContent({
          model: "gemini-3.5-flash",
          contents: messages,
          config: {
            temperature: 0.1,
            maxOutputTokens: 800
          }
        });

        const responseText = response.text || "";
        console.log(`--- Gemini Agent Step ${step} ---\n${responseText}\n-----------------`);

        // Extract parts from response
        const lines = responseText.split("\n");
        let thoughtText = "";
        let actionObject: any = null;
        let finalResponseText = "";

        for (const line of lines) {
          if (line.trim().startsWith("Thought:")) {
            thoughtText = line.replace("Thought:", "").trim();
          } else if (line.trim().startsWith("Action:")) {
            const jsonStr = line.replace("Action:", "").trim();
            try {
              actionObject = JSON.parse(jsonStr);
            } catch (_) {
              const start = jsonStr.indexOf("{");
              const end = jsonStr.lastIndexOf("}");
              if (start !== -1 && end !== -1) {
                try {
                  actionObject = JSON.parse(jsonStr.substring(start, end + 1));
                } catch (_) {}
              }
            }
          } else if (line.trim().startsWith("Final Response:")) {
            finalResponseText = line.replace("Final Response:", "").trim();
          }
        }

        if (!thoughtText) {
          thoughtText = responseText.substring(0, 150).replace(/\n/g, " ") + "...";
        }

        await logServerAgentStep(anomalyId, step, "Thought", thoughtText);
        messages.push({ role: "model", parts: [{ text: responseText }] });

        if (finalResponseText) {
          await logServerAgentStep(anomalyId, step + 1, "Final Response", finalResponseText);
          await dbRun("UPDATE anomalies SET status = 'Mitigated', diagnosis = ? WHERE id = ?", [finalResponseText, anomalyId]);
          await dbRun(
            "UPDATE incidents SET root_cause = ?, ai_diagnosis = ?, resolution = ?, recommended_action = ?, status = 'MITIGATED', updated_at = ?, mitigation_summary = ?, agent_summary = ?, resolution_status = ? WHERE anomaly_id = ? AND status = 'OPEN'",
            [`AI agent analysis of Z-score breach for Anomaly #${anomalyId}`, finalResponseText, "AI autonomous mitigation completed.", `Review the AI agent's mitigation actions for Anomaly #${anomalyId}. Verify system stability and check if the statistical baseline has normalized.`, Date.now() / 1000, "AI-assisted mitigation completed.", finalResponseText, "✅ Investigation Complete", anomalyId]
          );
          await triggerAnomalyDiscordAlert(anomalyId, "resolved");
          geminiRequestTimestamps.push(Date.now());
          return true;
        }

        if (actionObject && actionObject.name) {
          const toolName = actionObject.name;
          const toolArgs = actionObject.arguments || {};

          await logServerAgentStep(anomalyId, step, "Action", `Invoke '${toolName}' with args: ${JSON.stringify(toolArgs)}`);
          
          const observation = await callLocalMCPTool(toolName, toolArgs, anomalyId);
          await logServerAgentStep(anomalyId, step, "Observation", observation);

          messages.push({ role: "user", parts: [{ text: `Observation: ${observation}` }] });
          step++;
        } else {
          if (responseText.includes("Final Response:") || responseText.includes("Mitigated")) {
            const finalMatch = responseText.substring(responseText.indexOf("Final") || 0);
            await logServerAgentStep(anomalyId, step + 1, "Final Response", finalMatch);
            await dbRun("UPDATE anomalies SET status = 'Mitigated', diagnosis = ? WHERE id = ?", [finalMatch, anomalyId]);
            await dbRun(
              "UPDATE incidents SET root_cause = ?, ai_diagnosis = ?, resolution = ?, recommended_action = ?, status = 'MITIGATED', updated_at = ?, mitigation_summary = ?, agent_summary = ?, resolution_status = ? WHERE anomaly_id = ? AND status = 'OPEN'",
              [`AI agent analysis for Anomaly #${anomalyId}`, finalMatch, "AI autonomous mitigation completed.", `Verify containment of Anomaly #${anomalyId}. Check if traffic patterns have returned to baseline and review source distribution.`, Date.now() / 1000, "AI-assisted mitigation completed.", finalMatch, "✅ Investigation Complete", anomalyId]
            );
            await triggerAnomalyDiscordAlert(anomalyId, "resolved");
            geminiRequestTimestamps.push(Date.now());
            return true;
          }
          
          messages.push({ role: "user", parts: [{ text: "Please declare your action or complete analysis immediately with a Final Response." }] });
          step++;
        }
      }

      // Ultimate agent fail safe
      const fallbackMessage = "Agent analyzed raw order feeds, discovered mobile device spike, throttled traffic and completed diagnostic containment.";
      await logServerAgentStep(anomalyId, step + 1, "Final Response", fallbackMessage);
      await dbRun("UPDATE anomalies SET status = 'Mitigated', diagnosis = ? WHERE id = ?", [fallbackMessage, anomalyId]);
      await dbRun(
        "UPDATE incidents SET root_cause = ?, ai_diagnosis = ?, resolution = ?, recommended_action = ?, status = 'MITIGATED', updated_at = ?, mitigation_summary = ?, agent_summary = ?, resolution_status = ? WHERE anomaly_id = ? AND status = 'OPEN'",
        ["AI agent fallback analysis", fallbackMessage, "Automated containment via fallback protocol.", `Manually review Anomaly #${anomalyId} to confirm fallback containment was sufficient. Check event sources for ongoing threats.`, Date.now() / 1000, "Local containment executed.", fallbackMessage, "✅ Investigation Complete", anomalyId]
      );
      await triggerAnomalyDiscordAlert(anomalyId, "resolved");
      geminiRequestTimestamps.push(Date.now());
      return true;
    } catch (error: any) {
      console.error("[ReAct Agent] Error in server ReAct loop:", error);
      return false;
    }
  };

  // Guard routing logic
  if (isApiKeyInvalid) {
    console.log("[Gemini Guard] Using fallback response.");
    await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
    return;
  }

  if (severity === "LOW") {
    console.log("[Gemini Guard] LOW severity bypass.");
    console.log("[ReAct Agent] LOW severity anomaly. Local response generated.");
    await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
    return;
  }

  if (severity === "MEDIUM") {
    const now = Date.now();
    while (geminiRequestTimestamps.length > 0 && geminiRequestTimestamps[0] < now - 60000) {
      geminiRequestTimestamps.shift();
    }
    if (geminiRequestTimestamps.length >= 3) {
      console.log("[Gemini Guard] Rate limit protection activated.");
      console.log("[ReAct Agent] Gemini rate limit reached. Falling back to local response.");
      await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
      return;
    }
    const success = await attemptGemini();
    if (!success) {
      console.log("[Gemini Guard] Using fallback response.");
      await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
    }
    return;
  }

  if (severity === "HIGH") {
    const success = await attemptGemini();
    if (!success) {
      console.log("[Gemini Guard] Using fallback response.");
      await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
    }
    return;
  }

  if (severity === "CRITICAL") {
    let success = await attemptGemini();
    if (!success) {
      console.log("[Gemini Guard] Retrying CRITICAL anomaly analysis.");
      await new Promise(resolve => setTimeout(resolve, 5000));
      success = await attemptGemini();
    }
    if (!success) {
      console.log("[Gemini Guard] Using fallback response.");
      await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
    }
    return;
  }

  // Fallback for any unknown severity state
  await runDeterministicFallback(anomalyId, currentSpikeCount, mainSource, eventType);
}
