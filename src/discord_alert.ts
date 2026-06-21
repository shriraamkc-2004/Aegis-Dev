import { dbGet, dbAll, dbRun } from "./server_db.js";

// Helper to mask PII in TypeScript
export function maskPii(text: string | null | undefined, valueType?: string): string {
  if (!text) return "";
  
  let masked = text;
  
  if (valueType === "username") {
    if (masked.length <= 2) {
      return "*".repeat(masked.length);
    }
    return masked[0] + "*".repeat(masked.length - 2) + masked[masked.length - 1];
  }

  // Mask email patterns: john.doe@company.com -> j***@company.com
  const emailRegex = /([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})/g;
  masked = masked.replace(emailRegex, (match, emailUser, emailDomain, emailExt) => {
    if (emailUser.length <= 1) {
      return `${emailUser[0]}***@${emailDomain}.${emailExt}`;
    }
    return `${emailUser[0]}***@${emailDomain}.${emailExt}`;
  });

  // Mask IPv4 IP patterns: 192.168.1.54 -> 192.168.xxx.xxx
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  masked = masked.replace(ipRegex, (match) => {
    const parts = match.split(".");
    return `${parts[0]}.${parts[1]}.xxx.xxx`;
  });

  // Mask IPv6 patterns: preserve first three segments, mask the rest with xxxx
  const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b/g;
  masked = masked.replace(ipv6Regex, (match) => {
    const parts = match.split(":");
    return `${parts.slice(0, 3).join(":")}:${parts.slice(3).map(() => "xxxx").join(":")}`;
  });

  return masked;
}

// Rule-based Threat Classifier in TypeScript matching Python classifier
export async function classifyAnomalyThreat(
  timestamp: number,
  eventCount: number,
  zScore: number
): Promise<{ possibleThreat: string; threatConfidence: number; recommendation: string }> {
  let failedLogins = 0;
  let largeTransfers = 0;
  let privilegedActions = 0;
  let serviceDrops = 0;

  try {
    const startTime = timestamp - 60;

    // Get list of existing tables
    const tables = await dbAll<{ name: string }>("SELECT name FROM sqlite_master WHERE type='table'");
    const tableNames = tables.map(r => r.name);

    // Query standard events table
    const recentEvents = await dbAll<{ event_type: string; source: string; order_id: string }>(
      "SELECT event_type, source, order_id FROM events WHERE timestamp >= ?",
      [startTime]
    );

    for (const event of recentEvents) {
      const etLower = (event.event_type || "").toLowerCase();
      const srcLower = (event.source || "").toLowerCase();
      const ordLower = (event.order_id || "").toLowerCase();

      // Check for Brute force indicators
      if (
        etLower.includes("fail") || etLower.includes("auth") || etLower.includes("login") || etLower.includes("brute") ||
        srcLower.includes("fail") || srcLower.includes("auth") || srcLower.includes("login") || srcLower.includes("brute") ||
        ordLower.includes("fail") || ordLower.includes("auth") || ordLower.includes("login") || ordLower.includes("brute")
      ) {
        if (etLower.includes("fail") || ordLower.includes("fail") || etLower.includes("brute")) {
          failedLogins++;
        }
      }

      // Check for Exfiltration indicators
      if (
        etLower.includes("exfil") || etLower.includes("transfer") || etLower.includes("outbound") || etLower.includes("export") || etLower.includes("download") ||
        srcLower.includes("exfil") || srcLower.includes("transfer") || srcLower.includes("outbound") || srcLower.includes("export") || srcLower.includes("download") ||
        ordLower.includes("exfil") || ordLower.includes("transfer") || ordLower.includes("outbound") || ordLower.includes("export") || ordLower.includes("download")
      ) {
        largeTransfers++;
      }

      // Check for Insider threat indicators
      if (
        etLower.includes("privileged") || etLower.includes("config") || etLower.includes("admin") || etLower.includes("policy") || etLower.includes("sensitive") || etLower.includes("insider") ||
        srcLower.includes("privileged") || srcLower.includes("config") || srcLower.includes("admin") || srcLower.includes("policy") || srcLower.includes("sensitive") || srcLower.includes("insider") ||
        ordLower.includes("privileged") || ordLower.includes("config") || ordLower.includes("admin") || ordLower.includes("policy") || ordLower.includes("sensitive") || ordLower.includes("insider")
      ) {
        privilegedActions++;
      }

      // Check for Service Failure indicators
      if (
        etLower.includes("heartbeat") || etLower.includes("drop") || etLower.includes("miss") || etLower.includes("failure") || etLower.includes("inactive") || etLower.includes("service_fail") ||
        srcLower.includes("heartbeat") || srcLower.includes("drop") || srcLower.includes("miss") || srcLower.includes("failure") || srcLower.includes("inactive") || srcLower.includes("service_fail") ||
        ordLower.includes("heartbeat") || ordLower.includes("drop") || ordLower.includes("miss") || ordLower.includes("failure") || ordLower.includes("inactive") || ordLower.includes("service_fail")
      ) {
        serviceDrops++;
      }
    }

    // Check sandbox tables if they exist in Org mode
    if (tableNames.includes("authentication_logs")) {
      try {
        const countRow = await dbGet<{ cnt: number }>(
          "SELECT COUNT(*) as cnt FROM authentication_logs WHERE event_time >= ? AND status = 'failed'",
          [startTime]
        );
        if (countRow) failedLogins += countRow.cnt;
      } catch (_) {}
    }
    if (tableNames.includes("vpn_logs")) {
      try {
        const countRow = await dbGet<{ cnt: number }>(
          "SELECT COUNT(*) as cnt FROM vpn_logs WHERE event_time >= ? AND status = 'failed'",
          [startTime]
        );
        if (countRow) failedLogins += countRow.cnt;
      } catch (_) {}
    }
    if (tableNames.includes("network_events")) {
      try {
        const countRow = await dbGet<{ cnt: number }>(
          "SELECT COUNT(*) as cnt FROM network_events WHERE event_time >= ? AND (event_type = 'data_transfer' OR amount > 1000000)",
          [startTime]
        );
        if (countRow) largeTransfers += countRow.cnt;
      } catch (_) {}
    }
    if (tableNames.includes("application_logs")) {
      try {
        const countRow = await dbGet<{ cnt: number }>(
          "SELECT COUNT(*) as cnt FROM application_logs WHERE event_time >= ? AND (severity_level = 'CRITICAL' OR user_name IN ('admin', 'superadmin') OR event_type = 'privileged_action')",
          [startTime]
        );
        if (countRow) privilegedActions += countRow.cnt;
      } catch (_) {}
    }
  } catch (e: any) {
    console.error(`[ThreatClassifier TS Error] Database check failed: ${e.message}`);
  }

  // Classification mapping rules matching Python exactly
  if (failedLogins >= 10) {
    return {
      possibleThreat: "Possible Brute Force Activity",
      threatConfidence: 82.0,
      recommendation: "Review authentication logs and lock affected accounts."
    };
  } else if (serviceDrops > 0 || eventCount <= 2) {
    return {
      possibleThreat: "Possible Service Failure",
      threatConfidence: 74.0,
      recommendation: "Investigate infrastructure health and service availability."
    };
  } else if (largeTransfers > 0) {
    return {
      possibleThreat: "Possible Data Exfiltration",
      threatConfidence: 71.0,
      recommendation: "Review outbound traffic and investigate affected systems."
    };
  } else if (privilegedActions > 0) {
    return {
      possibleThreat: "Possible Insider Threat",
      threatConfidence: 69.0,
      recommendation: "Audit privileged access and investigate user activity."
    };
  } else if (eventCount >= 10 || zScore > 3.0) {
    return {
      possibleThreat: "Possible DDoS Activity",
      threatConfidence: 76.0,
      recommendation: "Review network traffic and enable mitigation controls."
    };
  } else {
    return {
      possibleThreat: "Possible DDoS Activity",
      threatConfidence: 65.0,
      recommendation: "Review network traffic and enable mitigation controls."
    };
  }
}

// Enterprise Discord incident lifecycle manager (trigger and edit-in-place)
export async function triggerAnomalyDiscordAlert(
  anomalyId: number,
  mode: "investigating" | "resolved"
): Promise<boolean> {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl || webhookUrl.trim() === "") {
    console.log(`[Discord Alert] No webhook URL configured. Anomaly #${anomalyId} skipped.`);
    return false;
  }

  try {
    // 1. Retrieve anomaly details
    const anomaly = await dbGet<any>(
      "SELECT severity, z_score, iforest_score, ewma_score, hybrid_score, event_count, window_mean, window_std, timestamp, possible_threat, threat_confidence, recommendation FROM anomalies WHERE id = ?",
      [anomalyId]
    );

    if (!anomaly) {
      console.error(`[Discord Alert Error] No anomaly row found for ID: ${anomalyId}`);
      return false;
    }

    // 2. Retrieve linked incident details
    const incident = await dbGet<any>(
      "SELECT discord_message_id, discord_channel_id, root_cause, ai_diagnosis, recommendation, recommended_action, gemini_summary, mitigation_summary, agent_summary, resolution_status FROM incidents WHERE anomaly_id = ?",
      [anomalyId]
    );

    if (!incident) {
      console.error(`[Discord Alert Error] No incident row found for anomaly ID: ${anomalyId}`);
      return false;
    }

    // Assign anomaly variables
    const severity = (anomaly.severity || "MEDIUM").toUpperCase();
    const hybridScore = anomaly.hybrid_score !== null ? anomaly.hybrid_score : 0.0;
    const zScore = anomaly.z_score !== null ? anomaly.z_score : 0.0;
    const iforestScore = anomaly.iforest_score !== null ? anomaly.iforest_score : 0.0;
    const ewmaScore = anomaly.ewma_score !== null ? anomaly.ewma_score : 0.0;
    const orderCount = anomaly.event_count !== null ? anomaly.event_count : 0;
    const mean = anomaly.window_mean !== null ? anomaly.window_mean : 0.0;
    const std = anomaly.window_std !== null ? anomaly.window_std : 0.0;
    const timestamp = anomaly.timestamp || (Date.now() / 1000);

    const possibleThreat = maskPii(anomaly.possible_threat || "Suspicious Activity");
    const threatConfidence = anomaly.threat_confidence !== null ? anomaly.threat_confidence : 65.0;

    let recommendation = anomaly.recommendation || "Review network traffic and enable mitigation controls.";
    if (incident.recommendation) {
      recommendation = incident.recommendation;
    } else if (incident.recommended_action) {
      recommendation = incident.recommended_action;
    }
    recommendation = maskPii(recommendation);

    // Map color codes to severity levels
    let color = 15158332; // Vibrant Red (HIGH default)
    if (severity === "LOW") {
      color = 16768000; // Yellow
    } else if (severity === "MEDIUM") {
      color = 16744192; // Orange
    } else if (severity === "HIGH") {
      color = 15158332; // Red
    } else if (severity === "CRITICAL") {
      color = 9109504; // Dark Red
    }

    const timeStr = new Date(timestamp * 1000).toISOString().replace("T", " ").substring(0, 19) + " UTC";

    // Setup fields array
    const fields = [
      { name: "Anomaly ID", value: `#${anomalyId}`, inline: true },
      { name: "Severity", value: `**${severity}**`, inline: true },
      { name: "Possible Threat", value: possibleThreat, inline: true },
      { name: "Threat Confidence", value: `${threatConfidence.toFixed(1)}%`, inline: true },
      { name: "Hybrid Score", value: `**${hybridScore.toFixed(2)}**`, inline: true },
      { name: "Current Z-Score", value: `**${zScore.toFixed(2)}**`, inline: true },
      { name: "Isolation Forest Score", value: `**${iforestScore.toFixed(3)}**`, inline: true },
      { name: "EWMA Score", value: `**${ewmaScore.toFixed(2)}**`, inline: true },
      { name: "Events in Window", value: `${orderCount} orders`, inline: true },
      { name: "Baseline Mean", value: `${mean.toFixed(2)} orders/sec`, inline: true },
      { name: "Baseline Std Dev", value: `${std.toFixed(2)}`, inline: true },
      { name: "Timestamp", value: timeStr, inline: false }
    ];

    let statusString = "🟡 ReAct Agent Investigating...";
    let recommendationString = "Analysis in progress.";

    if (mode === "resolved") {
      // Determine final resolution status string
      let resStatus = "✅ Investigation Complete";
      
      // Look for critical retry failure indicators
      const isCriticalRetryFail = (severity === "CRITICAL") && 
        (!incident.gemini_summary || incident.gemini_summary.trim() === "") && 
        (incident.ai_diagnosis && incident.ai_diagnosis.includes("fallback"));

      if (isCriticalRetryFail || incident.resolution_status === "Escalated" || incident.mitigation_summary?.includes("escalat") || incident.agent_summary?.includes("escalat")) {
        resStatus = "⚠ Manual Review Recommended";
      }

      statusString = resStatus;
      recommendationString = recommendation;

      // Determine mitigation summary details
      let mitigation = "Local containment executed.";
      if (resStatus === "⚠ Manual Review Recommended") {
        mitigation = "Analyst escalation required.";
      } else if (incident.gemini_summary && incident.gemini_summary.trim() !== "") {
        mitigation = "AI-assisted mitigation completed.";
      } else if (incident.mitigation_summary) {
        mitigation = incident.mitigation_summary;
      }

      fields.push(
        { name: "Status", value: statusString, inline: true },
        { name: "Recommendation", value: recommendationString, inline: false },
        { name: "Root Cause", value: maskPii(incident.root_cause || `Traffic spike of ${orderCount} events/sec from main nodes.`), inline: false },
        { name: "Mitigation", value: maskPii(incident.mitigation_summary || mitigation), inline: false }
      );

      const summary = incident.gemini_summary || incident.ai_diagnosis || incident.agent_summary;
      if (summary && summary.trim() !== "") {
        fields.push({ name: "Agent Summary", value: maskPii(summary), inline: false });
      }
    } else {
      fields.push(
        { name: "Status", value: statusString, inline: true },
        { name: "Recommendation", value: recommendationString, inline: false }
      );
    }

    const embed = {
      title: "🚨 INCIDENT ALERT",
      color: color,
      fields: fields,
      description: mode === "investigating" 
        ? "Aegis ReAct AI Agent has been activated."
        : "The Aegis ReAct AI Agent has completed the incident lifecycle investigation and mitigation responses.",
      footer: {
        text: "Aegis Streaming Control Loop"
      }
    };

    // Format plain text backup structure
    const msgLines = [
      "🚨 INCIDENT ALERT",
      `Severity: ${severity}`,
      `Hybrid Score: ${hybridScore.toFixed(2)}`,
      `Possible Threat: ${possibleThreat}`,
      `Threat Confidence: ${threatConfidence.toFixed(1)}%`,
      `Recommendation: ${recommendationString}`
    ];
    
    const summaryText = incident.gemini_summary || incident.ai_diagnosis || incident.agent_summary;
    if (mode === "resolved" && summaryText && summaryText.trim() !== "") {
      msgLines.push(`Gemini Summary: ${summaryText}`);
    }

    const msgContent = msgLines.join("\n\n");

    const payload = {
      content: msgContent,
      embeds: [embed]
    };

    // Edit vs Post Routing
    if (mode === "resolved" && incident.discord_message_id) {
      console.log(`[Discord Alert] Updating existing alert message ${incident.discord_message_id} to closed state...`);
      // Strip any query parameter for PATCH edit request
      const cleanUrl = webhookUrl.split("?")[0];
      const patchUrl = `${cleanUrl}/messages/${incident.discord_message_id}`;
      
      const response = await fetch(patchUrl, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        console.log(`[Discord Alert] Successfully closed incident #${anomalyId} alert on Discord.`);
        // Save closed status in resolution_status
        await dbRun(
          "UPDATE incidents SET resolution_status = ?, status = 'MITIGATED' WHERE anomaly_id = ?",
          [statusString, anomalyId]
        );
        return true;
      } else {
        console.error(`[Discord Alert Error] PATCH message returned status: ${response.status}`);
        return false;
      }
    } else {
      console.log(`[Discord Alert] Dispatches new alert message for anomaly #${anomalyId}...`);
      // Append wait=true to get message context from response
      const separator = webhookUrl.includes("?") ? "&" : "?";
      const postUrl = `${webhookUrl}${separator}wait=true`;

      const response = await fetch(postUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        const resJson = await response.json();
        const messageId = resJson.id;
        const channelId = resJson.channel_id;
        
        await dbRun(
          "UPDATE incidents SET discord_message_id = ?, discord_channel_id = ?, resolution_status = ? WHERE anomaly_id = ?",
          [messageId, channelId, statusString, anomalyId]
        );
        console.log(`[Discord Alert] Created alert message ID: ${messageId} on Discord.`);
        return true;
      } else {
        console.error(`[Discord Alert Error] POST message returned status: ${response.status}`);
        return false;
      }
    }
  } catch (e: any) {
    console.error(`[Discord Alert TS Error] Failed sending Discord webhook: ${e.message}`);
    return false;
  }
}
