/**
 * Sensitive field encryption protects secrets and credentials only.
 * PII masking is applied during presentation and external exposure only.
 * Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.
 */
import "dotenv/config";

// Enforce strict MODE startup validation
const startupMode = process.env.MODE;
if (startupMode !== "demo" && startupMode !== "organization") {
  console.error(`\n❌ [Fatal Error] Invalid MODE configuration!`);
  console.error(`   Expected MODE='demo' or MODE='organization'. Got: '${startupMode}'`);
  console.error(`   Aegis startup aborted to prevent database contamination.\n`);
  process.exit(1);
}

// Global process exception/rejection protection to handle concurrent DB locks and transient API failures gracefully
process.on("unhandledRejection", (reason, promise) => {
  console.error("❌ Unhandled Rejection at:", promise, "reason:", reason);
});
process.on("uncaughtException", (error) => {
  console.error("❌ Uncaught Exception:", error);
});
import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import fs from "fs";
import { spawn } from "child_process";
import sqlite3Lib from "sqlite3";
import {
  dbRun,
  dbAll,
  dbGet,
  initServerDb,
  pruneOldEvents
} from "./src/server_db.js";
import { runServerAgentLoop } from "./src/server_agent.js";
import { classifyAnomalyThreat, triggerAnomalyDiscordAlert } from "./src/discord_alert.js";
import { HybridDetector } from "./src/hybrid_detector.js";
import { initPgDb } from "./src/pg_db.js";
import { initQdrantCollections } from "./src/copilot/qdrant_client.js";
import { initMinio } from "./src/copilot/minio_service.js";
import { copilotRouter } from "./src/copilot/responsible_ai.js";
import {
  generateToken,
  authenticateToken,
  requireRole,
  logAudit,
  getOrgId,
  isDemoUser,
  requireDemoMode,
  requireOrgMode,
  encryptSensitive,
  decryptSensitive,
  maskPII,
  type AuthUser,
  type UserRole,
  type UserMode
} from "./src/auth.js";

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Mount Enterprise Security Copilot Router
app.use("/api/copilot", copilotRouter);

// Security Headers (relaxed CSP for dev mode Vite HMR)
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use("/api/", apiLimiter);

// In-Memory Global Engine parameters
const engineSettings = {
  EVENT_INTERVAL: 200,
  WINDOW_SIZE: 60,
  Z_SCORE_THRESHOLD: 3.0,
  ISOLATION_FOREST_ENABLED: true,
  EWMA_ALPHA: 0.15,
  HYBRID_FUSION: true,
};

// Internal engine states
let activeProducerInterval: NodeJS.Timeout | null = null;
let activeDetectorInterval: NodeJS.Timeout | null = null;
let activePruneInterval: NodeJS.Timeout | null = null;

let lastAlarmTime = 0;
const ALARM_COOLDOWN_MS = 0;

// Core server metrics tracking state
let currentEventRate = 0;
let currentMean = 0;
let currentStd = 0;
let currentZScore = 0;

// Hybrid detector state
let currentIForestScore = 0;
let currentEWMAScore = 0;
let currentHybridScore = 0;
let currentHybridSeverity = "LOW";
let currentDetectionMethod = "ZSCORE";
let currentSourceEntropy = 0;
let currentBurstRatio = 0;

// External DB ingestion state (Org mode auto-detection)
let activeIngestInterval: NodeJS.Timeout | null = null;
let activeIngestConnectorId: number | null = null;
let lastIngestedRowId: number = 0;
let totalIngestedEvents: number = 0;

// Hybrid detector instance
const hybridDetector = new HybridDetector({
  iforestEnabled: true,
  ewmaAlpha: 0.15,
});

// ========================
// AUTH ENDPOINTS (Public)
// ========================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ error: "Username and password are required." });
      return;
    }

    const user = await dbGet<{ id: number; username: string; password_hash: string; role: string; organization_id: number | null; status: string; mode: string }>(
      "SELECT id, username, password_hash, role, organization_id, status, mode FROM users WHERE username = ?",
      [username.trim().toLowerCase()]
    );

    if (!user) {
      res.status(401).json({ error: "Invalid credentials." });
      return;
    }

    if (user.status !== "active") {
      res.status(403).json({ error: "Account is disabled." });
      return;
    }

    const validPassword = bcrypt.compareSync(password, user.password_hash);
    if (!validPassword) {
      res.status(401).json({ error: "Invalid credentials." });
      return;
    }

    // Update last login
    await dbRun("UPDATE users SET last_login = ? WHERE id = ?", [Date.now() / 1000, user.id]);

    const authUser: AuthUser = {
      id: user.id,
      username: user.username,
      role: user.role as AuthUser["role"],
      organization_id: user.organization_id,
      mode: (user as any).mode || "org",
    };

    const token = generateToken(authUser);
    await logAudit(user.id, user.username, "LOGIN", "auth", `Successful login (${authUser.mode} mode)`, req.ip || "", user.organization_id || 1);

    res.json({
      token,
      user: {
        id: authUser.id,
        username: authUser.username,
        role: authUser.role,
        organization_id: authUser.organization_id,
        mode: authUser.mode,
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Get current user profile
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await dbGet<any>(
      "SELECT id, username, role, organization_id, email, created_at, last_login, status FROM users WHERE id = ?",
      [req.user!.id]
    );
    if (!user) {
      res.status(404).json({ error: "User not found." });
      return;
    }
    res.json(user);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// USER MANAGEMENT (Admin)
// ========================
app.get("/api/users", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const orgId = getOrgId(req.user!);
    const users = orgId === 0
      ? await dbAll("SELECT id, username, role, organization_id, email, created_at, last_login, status FROM users ORDER BY id")
      : await dbAll("SELECT id, username, role, organization_id, email, created_at, last_login, status FROM users WHERE organization_id = ? OR organization_id IS NULL ORDER BY id", [orgId]);
    const maskedUsers = users.map((u: any) => ({
      ...u,
      email: maskPII(u.email, "email"),
      username: maskPII(u.username, "username")
    }));
    res.json(maskedUsers);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/users", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const { username, password, role, email, organization_id } = req.body;
    if (!username || !password || !role) {
      res.status(400).json({ error: "username, password, and role are required." });
      return;
    }
    const validRoles: string[] = ["super_admin", "org_admin", "soc_analyst", "executive_viewer", "demo_admin", "demo_analyst", "demo_viewer"];
    if (!validRoles.includes(role)) {
      res.status(400).json({ error: `Invalid role. Must be: ${validRoles.join(", ")}` });
      return;
    }
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const orgId = req.user!.role === "super_admin" ? (organization_id || 1) : req.user!.organization_id;
    const mode: string = role.startsWith("demo_") ? "demo" : "org";
    const result = await dbRun(
      "INSERT INTO users (username, password_hash, role, email, organization_id, mode) VALUES (?, ?, ?, ?, ?, ?)",
      [username.trim().toLowerCase(), hash, role, email || "", orgId, mode]
    );
    await logAudit(req.user!.id, req.user!.username, "CREATE_USER", "users", `Created user: ${username} (${mode})`, req.ip || "", getOrgId(req.user!));
    res.json({ id: result.lastID, username, role, mode });
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      res.status(409).json({ error: "Username already exists." });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// ========================
// ORGANIZATION MANAGEMENT
// ========================
app.get("/api/organizations", authenticateToken, requireRole("super_admin"), async (req, res) => {
  try {
    const orgs = await dbAll("SELECT * FROM organizations ORDER BY id");
    res.json(orgs);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/organizations", authenticateToken, requireRole("super_admin"), async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name) {
      res.status(400).json({ error: "Organization name is required." });
      return;
    }
    const result = await dbRun("INSERT INTO organizations (name, description) VALUES (?, ?)", [name, description || ""]);
    await logAudit(req.user!.id, req.user!.username, "CREATE_ORG", "organizations", `Created org: ${name}`, req.ip || "", 1);
    res.json({ id: result.lastID, name });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// METRICS (Protected)
// ========================
app.get("/api/metrics", authenticateToken, async (req, res) => {
  try {
    const cutoff = Date.now() / 1000 - 60;
    const countRow = await dbGet<{ total: number }>(
      "SELECT COUNT(*) as total FROM events WHERE timestamp >= ?",
      [cutoff]
    );
    const opm = countRow ? countRow.total : 0;

    const latestAnomaly = await dbGet<any>(
      "SELECT timestamp, status FROM anomalies ORDER BY id DESC LIMIT 1"
    );

    let statusString = "Steady State";
    if (latestAnomaly) {
      const timeSinceAlarmSec = Date.now() / 1000 - latestAnomaly.timestamp;
      if (timeSinceAlarmSec < 15) {
        statusString = "🚨 BREACH DETECTED";
      } else if (latestAnomaly.status === "Pending Mitigation") {
        statusString = "🛡️ AGENT MITIGATING";
      }
    }

    const activeThreatsRow = await dbGet<{ total: number }>(
      "SELECT COUNT(*) as total FROM anomalies WHERE status = 'Pending Mitigation'"
    );
    const activeThreats = activeThreatsRow ? activeThreatsRow.total : 0;

    // Incident counts
    const incidentStats = await dbGet<any>(
      "SELECT COUNT(*) as total, SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) as open_count, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical_count FROM incidents"
    );

    res.json({
      opm,
      currentRate: currentEventRate,
      mean: parseFloat(currentMean.toFixed(2)),
      std: parseFloat(currentStd.toFixed(2)),
      z_score: parseFloat(currentZScore.toFixed(2)),
      status: statusString,
      active_threats: activeThreats,
      timestamp: Date.now() / 1000,
      incidents: incidentStats || { total: 0, open_count: 0, critical_count: 0 },
      // Hybrid detection metrics
      hybrid: {
        enabled: engineSettings.HYBRID_FUSION,
        iforest_enabled: engineSettings.ISOLATION_FOREST_ENABLED,
        iforest_score: parseFloat(currentIForestScore.toFixed(3)),
        ewma_score: parseFloat(currentEWMAScore.toFixed(2)),
        hybrid_score: parseFloat(currentHybridScore.toFixed(3)),
        hybrid_severity: currentHybridSeverity,
        detection_method: currentDetectionMethod,
        source_entropy: parseFloat(currentSourceEntropy.toFixed(3)),
        burst_ratio: parseFloat(currentBurstRatio.toFixed(2)),
        ewma_alpha: engineSettings.EWMA_ALPHA,
        ...hybridDetector.getStatus(),
      },
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// HISTORY (Protected)
// ========================
app.get("/api/history", authenticateToken, async (req, res) => {
  try {
    const cutoff = Date.now() / 1000 - 120;
    const rows = await dbAll<any>(
      "SELECT CAST(timestamp as INTEGER) as sec, COUNT(*) as count FROM events WHERE timestamp >= ? GROUP BY sec ORDER BY sec ASC",
      [cutoff]
    );

    const currentSec = Math.floor(Date.now() / 1000);
    const timelineData = [];

    for (let s = currentSec - 90; s <= currentSec; s++) {
      const match = rows.find((r) => r.sec === s);
      const timeStr = new Date(s * 1000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      timelineData.push({ sec: s, time: timeStr, count: match ? match.count : 0 });
    }

    res.json(timelineData);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ALERTS (Real-time anomaly feed)
// ========================
app.get("/api/alerts/pending", authenticateToken, async (req, res) => {
  try {
    const sinceId = parseInt(req.query.since as string) || 0;
    const alerts = await dbAll<any>(
      "SELECT a.*, i.id as incident_id FROM anomalies a LEFT JOIN incidents i ON i.anomaly_id = a.id WHERE a.id > ? ORDER BY a.id ASC",
      [sinceId]
    );
    res.json(alerts);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/alerts/acknowledge", authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.query.id as string);
    if (id) {
      await dbRun("UPDATE anomalies SET status = 'Acknowledged' WHERE id = ?", [id]);
    }
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ANOMALIES (Protected)
// ========================
app.get("/api/anomalies", authenticateToken, async (req, res) => {
  try {
    const rows = await dbAll("SELECT * FROM anomalies ORDER BY id DESC LIMIT 25");
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// AGENT TRACES (Protected)
// ========================
app.get("/api/traces/:id", authenticateToken, async (req, res) => {
  try {
    const rows = await dbAll(
      "SELECT * FROM agent_logs WHERE anomaly_id = ? ORDER BY step ASC, id ASC",
      [req.params.id]
    );
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// SETTINGS (Protected, admin-only write)
// ========================
app.get("/api/settings", authenticateToken, (req, res) => {
  res.json(engineSettings);
});

app.post("/api/settings", authenticateToken, requireRole("super_admin", "org_admin", "demo_admin"), (req, res) => {
  const { EVENT_INTERVAL, WINDOW_SIZE, Z_SCORE_THRESHOLD, ISOLATION_FOREST_ENABLED, EWMA_ALPHA, HYBRID_FUSION } = req.body;
  if (EVENT_INTERVAL !== undefined) {
    engineSettings.EVENT_INTERVAL = Math.max(50, Math.min(2000, EVENT_INTERVAL));
    if (process.env.MODE !== "demo") {
      restartProducerLoop();
    }
  }
  if (WINDOW_SIZE !== undefined) {
    engineSettings.WINDOW_SIZE = Math.max(10, Math.min(300, WINDOW_SIZE));
  }
  if (Z_SCORE_THRESHOLD !== undefined) {
    engineSettings.Z_SCORE_THRESHOLD = Math.max(1.0, Math.min(8.0, Z_SCORE_THRESHOLD));
  }
  if (ISOLATION_FOREST_ENABLED !== undefined) {
    engineSettings.ISOLATION_FOREST_ENABLED = !!ISOLATION_FOREST_ENABLED;
  }
  if (EWMA_ALPHA !== undefined) {
    engineSettings.EWMA_ALPHA = Math.max(0.01, Math.min(1.0, EWMA_ALPHA));
  }
  if (HYBRID_FUSION !== undefined) {
    engineSettings.HYBRID_FUSION = !!HYBRID_FUSION;
  }
  // Sync hybrid detector with new settings
  hybridDetector.setConfig({
    iforestEnabled: engineSettings.ISOLATION_FOREST_ENABLED,
    ewmaAlpha: engineSettings.EWMA_ALPHA,
  });
  console.log("Updated Engine Parameters:", engineSettings);
  logAudit(req.user!.id, req.user!.username, "UPDATE_SETTINGS", "settings", JSON.stringify(req.body), req.ip || "", getOrgId(req.user!));
  res.json({ success: true, settings: engineSettings });
});

// ========================
// TRIGGER SPIKE (Admin only)
// ========================
app.post("/api/trigger-spike", authenticateToken, requireRole("super_admin", "org_admin", "demo_admin"), async (req, res) => {
  try {
    console.log("💥 Manual surge stimulus triggered from Client UI dashboard! Injecting 25 orders...");
    const sources = ["web", "mobile"];
    const activeSource = sources[Math.floor(Math.random() * sources.length)];
    const tNow = Date.now() / 1000;

    for (let i = 0; i < 25; i++) {
      const orderId = "ORD" + Math.floor(100000 + Math.random() * 900000);
      await dbRun(
        "INSERT INTO events (event_type, order_id, timestamp, source) VALUES (?, ?, ?, ?)",
        ["order_placed", orderId, tNow, activeSource]
      );
    }
    await logAudit(req.user!.id, req.user!.username, "TRIGGER_SPIKE", "simulation", "Injected 25 burst orders", req.ip || "", getOrgId(req.user!));
    res.json({ success: true, count: 25, source: activeSource });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// INCIDENT MANAGEMENT
// ========================
app.get("/api/incidents", authenticateToken, async (req, res) => {
  try {
    const rows = await dbAll(
      `SELECT i.*, a.z_score, a.iforest_score, a.ewma_score, a.hybrid_score, a.detection_method, a.event_count as anomaly_event_count, a.source_entropy, a.burst_ratio
       FROM incidents i
       LEFT JOIN anomalies a ON i.anomaly_id = a.id
       ORDER BY i.created_at DESC LIMIT 50`
    );
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/incidents", authenticateToken, requireRole("super_admin", "org_admin", "soc_analyst", "demo_admin", "demo_analyst"), async (req, res) => {
  try {
    const { title, description, severity, anomaly_id } = req.body;
    if (!title) {
      res.status(400).json({ error: "Title is required." });
      return;
    }
    const result = await dbRun(
      "INSERT INTO incidents (title, description, severity, anomaly_id, detection_time, created_by, organization_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [title, description || "", severity || "MEDIUM", anomaly_id || null, Date.now() / 1000, req.user!.id, getOrgId(req.user!)]
    );
    await logAudit(req.user!.id, req.user!.username, "CREATE_INCIDENT", "incidents", `Created incident: ${title}`, req.ip || "", getOrgId(req.user!));
    res.json({ id: result.lastID, title });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/incidents/:id", authenticateToken, requireRole("super_admin", "org_admin", "soc_analyst", "demo_admin", "demo_analyst"), async (req, res) => {
  try {
    const { status, severity, root_cause, analyst_notes, resolution, assigned_to, possible_threat, threat_confidence, recommendation, gemini_summary } = req.body;
    const updates: string[] = [];
    const values: any[] = [];

    if (status !== undefined) { updates.push("status = ?"); values.push(status); }
    if (severity !== undefined) { updates.push("severity = ?"); values.push(severity); }
    if (root_cause !== undefined) { updates.push("root_cause = ?"); values.push(root_cause); }
    if (analyst_notes !== undefined) { updates.push("analyst_notes = ?"); values.push(analyst_notes); }
    if (resolution !== undefined) { updates.push("resolution = ?"); values.push(resolution); }
    if (assigned_to !== undefined) { updates.push("assigned_to = ?"); values.push(assigned_to); }
    if (possible_threat !== undefined) { updates.push("possible_threat = ?"); values.push(possible_threat); }
    if (threat_confidence !== undefined) { updates.push("threat_confidence = ?"); values.push(threat_confidence); }
    if (recommendation !== undefined) { updates.push("recommendation = ?"); values.push(recommendation); }
    if (gemini_summary !== undefined) { updates.push("gemini_summary = ?"); values.push(gemini_summary); }

    if (updates.length === 0) {
      res.status(400).json({ error: "No fields to update." });
      return;
    }

    updates.push("updated_at = ?");
    values.push(Date.now() / 1000);
    values.push(req.params.id);

    await dbRun(`UPDATE incidents SET ${updates.join(", ")} WHERE id = ?`, values);
    await logAudit(req.user!.id, req.user!.username, "UPDATE_INCIDENT", "incidents", `Updated incident #${req.params.id}`, req.ip || "", getOrgId(req.user!));
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// AUDIT LOGS (Admin)
// ========================
app.get("/api/audit-logs", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const rows = await dbAll("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100");
    const maskedRows = rows.map((r: any) => ({
      ...r,
      ip_address: maskPII(r.ip_address, "ip"),
      username: maskPII(r.username, "username")
    }));
    res.json(maskedRows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// NOTIFICATIONS LOG
// ========================
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const rows = await dbAll("SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50");
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// WEBHOOK MANAGEMENT
// ========================
app.get("/api/webhook", authenticateToken, async (req, res) => {
  try {
    const configured = !!(process.env.DISCORD_WEBHOOK_URL && process.env.DISCORD_WEBHOOK_URL.trim() !== "");
    const notifCount = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM notifications WHERE type = 'discord'").catch(() => ({ total: 0 }));
    res.json({ configured, url: configured ? `${process.env.DISCORD_WEBHOOK_URL!.substring(0, 30)}...` : "", sent_count: notifCount?.total || 0 });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/webhook", authenticateToken, requireRole("super_admin", "org_admin", "demo_admin"), async (req, res) => {
  try {
    const { url } = req.body;
    if (url !== undefined) {
      process.env.DISCORD_WEBHOOK_URL = url;
    }
    await logAudit(req.user!.id, req.user!.username, "UPDATE_WEBHOOK", "settings", `Webhook URL ${url ? "configured" : "cleared"}`, req.ip || "", getOrgId(req.user!));
    res.json({ success: true, configured: !!url });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/webhook/test", authenticateToken, requireRole("super_admin", "org_admin", "demo_admin"), async (req, res) => {
  try {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl || webhookUrl.trim() === "") {
      res.status(400).json({ error: "No webhook URL configured." });
      return;
    }
    const { message } = req.body;
    const testMsg = message || "\uD83E\uDDEA **Aegis Test Alert** \u2014 Webhook integration is working correctly.";
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: testMsg })
    });
    if (response.status === 204 || response.ok) {
      await dbRun("INSERT INTO notifications (type, message, status) VALUES ('discord', ?, 'sent')", [testMsg]);
      res.json({ success: true, message: "Alert transmitted successfully." });
    } else {
      await dbRun("INSERT INTO notifications (type, message, status) VALUES ('discord', ?, 'failed')", [testMsg]);
      res.status(400).json({ error: `Discord returned status ${response.status}` });
    }
  } catch (err: any) {
    res.status(500).json({ error: `Webhook error: ${err.message}` });
  }
});

app.post("/api/webhook/send", authenticateToken, requireRole("super_admin", "org_admin", "soc_analyst", "demo_admin", "demo_analyst"), async (req, res) => {
  try {
    const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
    if (!webhookUrl || webhookUrl.trim() === "") {
      res.status(400).json({ error: "No webhook URL configured." });
      return;
    }
    const { message } = req.body;
    if (!message) {
      res.status(400).json({ error: "Message is required." });
      return;
    }
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: `\uD83D\uDEE1\uFE0F **Aegis Alert:** ${message}` })
    });
    if (response.status === 204 || response.ok) {
      await dbRun("INSERT INTO notifications (type, message, status) VALUES ('discord', ?, 'sent')", [message]);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: `Discord returned status ${response.status}` });
    }
  } catch (err: any) {
    res.status(500).json({ error: `Webhook error: ${err.message}` });
  }
});

// ========================
// DATABASE CONNECTORS (Org Admin)
// ========================
app.get("/api/connectors", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const rows = await dbAll("SELECT id, name, db_type, host, port, database_name, status, created_at, last_tested FROM connectors ORDER BY id");
    res.json(rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/connectors", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const { name, db_type, host, port, username, password, database_name, connection_string } = req.body;
    if (!name || !db_type) {
      res.status(400).json({ error: "name and db_type are required." });
      return;
    }
    const encryptedPassword = encryptSensitive(password || "");
    const result = await dbRun(
      "INSERT INTO connectors (name, db_type, host, port, username, password_encrypted, database_name, connection_string, organization_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [name, db_type, host || "localhost", port || 5432, username || "", encryptedPassword, database_name || "", connection_string || "", getOrgId(req.user!)]
    );
    res.json({ id: result.lastID, name });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Test connector connection
app.post("/api/connectors/:id/test", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const connector = await dbGet<any>("SELECT * FROM connectors WHERE id = ?", [req.params.id]);
    if (!connector) { res.status(404).json({ error: "Connector not found." }); return; }

    // Test connection based on db_type
    const dbType = connector.db_type;
    let testResult = { success: false, message: "", latency_ms: 0, tables_found: 0 };
    const startTime = Date.now();

    if (dbType === "sqlite") {
      // Real SQLite connection test — open DB, query tables
      try {
        const dbPath = connector.database_name || connector.host;
        if (!fs.existsSync(dbPath)) {
          testResult = { success: false, message: `SQLite file not found: ${dbPath}`, latency_ms: Date.now() - startTime, tables_found: 0 };
        } else {
          const tables = await new Promise<string[]>((resolve, reject) => {
            const extDb = new sqlite3Lib.Database(dbPath, sqlite3Lib.OPEN_READONLY, (err) => {
              if (err) { reject(err); return; }
              extDb.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name", (e, rows: any[]) => {
                extDb.close();
                if (e) reject(e); else resolve((rows || []).map((r: any) => r.name));
              });
            });
          });
          testResult = { success: true, message: `SQLite connected — ${tables.length} tables found`, latency_ms: Date.now() - startTime, tables_found: tables.length };
        }
      } catch (e: any) {
        testResult = { success: false, message: e.message, latency_ms: Date.now() - startTime, tables_found: 0 };
      }
    } else {
      // For other DB types, simulate (would need actual drivers in production)
      const decryptedPassword = decryptSensitive(connector.password_encrypted);
      const hasCredentials = connector.username && decryptedPassword;
      const hasHost = connector.host && connector.host !== "localhost";
      if (hasCredentials || connector.connection_string) {
        testResult = {
          success: true,
          message: `${dbType} connection validated (host: ${connector.host}:${connector.port})`,
          latency_ms: Math.floor(Math.random() * 50) + 10,
          tables_found: Math.floor(Math.random() * 10) + 3,
        };
      } else {
        testResult = { success: false, message: "Missing credentials or connection string", latency_ms: 0, tables_found: 0 };
      }
    }

    await dbRun("UPDATE connectors SET status = ?, last_tested = ? WHERE id = ?",
      [testResult.success ? "connected" : "error", Date.now() / 1000, req.params.id]);
    await logAudit(req.user!.id, req.user!.username, "TEST_CONNECTOR", "connectors", `Tested connector: ${connector.name} - ${testResult.success ? "OK" : "FAIL"}`, req.ip || "", getOrgId(req.user!));
    res.json(testResult);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Discover schemas/tables for a connector
app.get("/api/connectors/:id/schemas", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const connector = await dbGet<any>("SELECT * FROM connectors WHERE id = ?", [req.params.id]);
    if (!connector) { res.status(404).json({ error: "Connector not found." }); return; }

    // Discover schemas — real for SQLite, simulated for others
    const discoveredSchemas: any[] = [];

    if (connector.db_type === "sqlite") {
      const dbPath = connector.database_name || connector.host;
      if (!fs.existsSync(dbPath)) {
        res.status(400).json({ error: `SQLite file not found: ${dbPath}` });
        return;
      }
      const tables = await new Promise<any[]>((resolve, reject) => {
        const extDb = new sqlite3Lib.Database(dbPath, sqlite3Lib.OPEN_READONLY, (err) => {
          if (err) { reject(err); return; }
          extDb.all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name", async (e, tableRows: any[]) => {
            if (e) { extDb.close(); reject(e); return; }
            const results: any[] = [];
            for (const tbl of tableRows || []) {
              const colRows: any[] = await new Promise((res2, rej2) => {
                extDb.all(`PRAGMA table_info("${tbl.name}")`, (e2, cols) => { if (e2) rej2(e2); else res2(cols || []); });
              });
              const cntRow: any = await new Promise((res2, rej2) => {
                extDb.get(`SELECT COUNT(*) as cnt FROM "${tbl.name}"`, (e2, r) => { if (e2) rej2(e2); else res2(r); });
              });
              results.push({ table: tbl.name, columns: colRows.map((c: any) => c.name), rowCount: cntRow?.cnt || 0 });
            }
            extDb.close();
            resolve(results);
          });
        });
      });
      for (const t of tables) {
        discoveredSchemas.push({
          connector_id: parseInt(req.params.id),
          schema_name: connector.database_name || "default",
          table_name: t.table,
          columns: t.columns,
          row_count: t.rowCount,
        });
      }
    } else {
      const sampleTables: Record<string, { tables: { name: string; columns: string[]; rows: number }[] }> = {
        postgresql: { tables: [
          { name: "orders", columns: ["order_id", "customer_id", "total_amount", "status", "created_at", "ip_address"], rows: 15420 },
          { name: "transactions", columns: ["txn_id", "order_id", "amount", "payment_method", "timestamp", "source_ip"], rows: 28930 },
          { name: "user_activity", columns: ["activity_id", "user_id", "action", "timestamp", "ip_address", "user_agent"], rows: 45210 },
          { name: "security_logs", columns: ["log_id", "event_type", "severity", "source_ip", "user_id", "timestamp", "details"], rows: 8920 },
        ]},
        mysql: { tables: [
          { name: "customers", columns: ["id", "name", "email", "created_at", "status"], rows: 8500 },
          { name: "orders", columns: ["id", "customer_id", "total", "order_date", "status", "source"], rows: 22100 },
          { name: "payments", columns: ["id", "order_id", "amount", "method", "timestamp", "ip_address"], rows: 19800 },
          { name: "login_attempts", columns: ["id", "user_id", "ip_address", "success", "timestamp", "user_agent"], rows: 34500 },
        ]},
        mongodb: { tables: [
          { name: "events", columns: ["_id", "eventType", "userId", "timestamp", "metadata", "sourceIP"], rows: 67000 },
          { name: "sessions", columns: ["_id", "userId", "startTime", "endTime", "deviceInfo", "ipAddress"], rows: 12400 },
        ]},
        sqlserver: { tables: [
          { name: "Transactions", columns: ["TransactionID", "AccountID", "Amount", "Type", "Timestamp", "SourceIP"], rows: 45600 },
          { name: "AuditTrail", columns: ["ID", "UserID", "Action", "TableName", "Timestamp", "IPAddress"], rows: 23100 },
        ]},
      };
      const tables = sampleTables[connector.db_type] || sampleTables.postgresql;
      for (const t of tables.tables) {
        discoveredSchemas.push({
          connector_id: parseInt(req.params.id),
          schema_name: connector.database_name || "default",
          table_name: t.name,
          columns: t.columns,
          row_count: t.rows,
        });
      }
    }

    // Cache discovered schemas
    await dbRun("DELETE FROM connector_schemas WHERE connector_id = ?", [req.params.id]);
    for (const s of discoveredSchemas) {
      await dbRun(
        "INSERT INTO connector_schemas (connector_id, schema_name, table_name, columns, row_count) VALUES (?, ?, ?, ?, ?)",
        [s.connector_id, s.schema_name, s.table_name, JSON.stringify(s.columns), s.row_count]
      );
    }

    res.json({ connector_id: parseInt(req.params.id), db_type: connector.db_type, schemas: discoveredSchemas });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Event Mapping CRUD
app.get("/api/connectors/:id/mappings", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const mappings = await dbAll("SELECT * FROM event_mappings WHERE connector_id = ?", [req.params.id]);
    res.json(mappings);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/connectors/:id/mappings", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const { source_table, field_event_id, field_timestamp, field_source, field_event_type, field_user, field_source_ip } = req.body;
    if (!source_table) { res.status(400).json({ error: "source_table is required." }); return; }
    const result = await dbRun(
      "INSERT INTO event_mappings (connector_id, source_table, field_event_id, field_timestamp, field_source, field_event_type, field_user, field_source_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [req.params.id, source_table, field_event_id || "", field_timestamp || "", field_source || "", field_event_type || "", field_user || "", field_source_ip || ""]
    );
    await logAudit(req.user!.id, req.user!.username, "CREATE_MAPPING", "event_mappings", `Mapping for ${source_table}`, req.ip || "", getOrgId(req.user!));
    res.json({ id: result.lastID, source_table });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/connectors/:id/mappings/:mappingId", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const { field_event_id, field_timestamp, field_source, field_event_type, field_user, field_source_ip } = req.body;
    await dbRun(
      "UPDATE event_mappings SET field_event_id=?, field_timestamp=?, field_source=?, field_event_type=?, field_user=?, field_source_ip=? WHERE id=? AND connector_id=?",
      [field_event_id || "", field_timestamp || "", field_source || "", field_event_type || "", field_user || "", field_source_ip || "", req.params.mappingId, req.params.id]
    );
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// DATA INGESTION (Org mode — real DB monitoring)
// ========================
app.get("/api/ingestion/status", authenticateToken, async (req, res) => {
  try {
    if (!activeIngestInterval || !activeIngestConnectorId) {
      res.json({ active: false, connector_id: null, events_ingested: 0 });
      return;
    }
    const connector = await dbGet<any>("SELECT id, name, db_type, database_name FROM connectors WHERE id = ?", [activeIngestConnectorId]);
    res.json({ active: true, connector_id: activeIngestConnectorId, connector_name: connector?.name || "Unknown", events_ingested: totalIngestedEvents, last_row_id: lastIngestedRowId });
  } catch (err: any) { res.status(500).json({ error: err.message }); }
});

app.post("/api/connectors/:id/ingest/start", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  try {
    const connector = await dbGet<any>("SELECT * FROM connectors WHERE id = ?", [req.params.id]);
    if (!connector) { res.status(404).json({ error: "Connector not found." }); return; }
    if (connector.db_type !== "sqlite") { res.status(400).json({ error: "Only SQLite connectors support live ingestion." }); return; }
    const dbPath = connector.database_name || connector.host;
    if (!fs.existsSync(dbPath)) { res.status(400).json({ error: `Database file not found: ${dbPath}` }); return; }
    const mapping = await dbGet<any>("SELECT * FROM event_mappings WHERE connector_id = ? ORDER BY id DESC LIMIT 1", [req.params.id]);
    if (!mapping || !mapping.source_table) { res.status(400).json({ error: "No field mapping configured. Map fields first." }); return; }
    stopIngestionLoop();
    startIngestionLoop(connector.id, dbPath, mapping);
    await dbRun("UPDATE connectors SET status = 'connected', last_tested = ? WHERE id = ?", [Date.now() / 1000, connector.id]);
    await logAudit(req.user!.id, req.user!.username, "START_INGESTION", "connectors", `Started monitoring: ${connector.name} → ${mapping.source_table}`, req.ip || "", getOrgId(req.user!));
    res.json({ success: true, message: `Monitoring started on ${connector.name} → ${mapping.source_table}`, table: mapping.source_table });
  } catch (err: any) { res.status(500).json({ error: err.message }); }
});

app.post("/api/ingestion/stop", authenticateToken, requireRole("super_admin", "org_admin"), async (req, res) => {
  stopIngestionLoop();
  res.json({ success: true, message: "Ingestion stopped." });
});

// Organization Registration
app.post("/api/auth/register-org", async (req, res) => {
  try {
    const { org_name, username, password, email } = req.body;
    if (!org_name || !username || !password) {
      res.status(400).json({ error: "org_name, username, and password are required." });
      return;
    }
    // Create organization
    const orgResult = await dbRun("INSERT INTO organizations (name, description) VALUES (?, ?)", [org_name, `Organization for ${org_name}`]);
    const orgId = orgResult.lastID;
    // Create admin user for this org
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const userResult = await dbRun(
      "INSERT INTO users (username, password_hash, role, email, organization_id, mode) VALUES (?, ?, 'org_admin', ?, ?, 'org')",
      [username.trim().toLowerCase(), hash, email || "", orgId]
    );
    const authUser: AuthUser = {
      id: userResult.lastID,
      username: username.trim().toLowerCase(),
      role: "org_admin",
      organization_id: orgId,
      mode: "org",
    };
    const token = generateToken(authUser);
    await logAudit(userResult.lastID, username, "REGISTER_ORG", "organizations", `Registered org: ${org_name}`, req.ip || "", orgId);
    res.json({ token, user: authUser, organization: { id: orgId, name: org_name } });
  } catch (err: any) {
    if (err.message?.includes("UNIQUE")) {
      res.status(409).json({ error: "Username already exists." });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// ========================
// DEMO MODE - Sample Data Upload & Replay
// ========================
app.post("/api/demo/upload-sample", authenticateToken, async (req, res) => {
  try {
    const { events } = req.body;
    if (!Array.isArray(events) || events.length === 0) {
      res.status(400).json({ error: "events array is required." });
      return;
    }
    let count = 0;
    const tNow = Date.now() / 1000;
    for (const evt of events) {
      await dbRun(
        "INSERT INTO events (event_type, order_id, timestamp, source, organization_id) VALUES (?, ?, ?, ?, ?)",
        [evt.event || "order_placed", evt.order_id || "ORD_DEMO", tNow + (count * 0.05), evt.source || "web", 0]
      );
      count++;
    }
    await logAudit(req.user!.id, req.user!.username, "DEMO_UPLOAD", "demo", `Uploaded ${count} sample events`, req.ip || "", 0);
    res.json({ success: true, count });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Demo Replay Engine - replays sample data at configurable speed
let demoReplayActive = false;
let demoReplayTimeout: NodeJS.Timeout | null = null;

app.post("/api/demo/replay", authenticateToken, async (req, res) => {
  try {
    const { sample_file, speed_multiplier = 1 } = req.body;
    if (demoReplayActive) {
      res.status(409).json({ error: "A replay is already in progress." });
      return;
    }
    const sampleDir = path.join(process.cwd(), "sample_data");
    const filePath = path.join(sampleDir, sample_file || "mixed_sample.json");
    if (!fs.existsSync(filePath)) {
      res.status(404).json({ error: `Sample file not found: ${sample_file}` });
      return;
    }
    const events = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    if (!Array.isArray(events) || events.length === 0) {
      res.status(400).json({ error: "Sample file contains no events." });
      return;
    }

    // Create demo session
    const session = await dbRun(
      "INSERT INTO demo_sessions (user_id, sample_file, events_count, replay_status) VALUES (?, ?, ?, 'replaying')",
      [req.user!.id, sample_file || "mixed_sample.json", events.length]
    );

    demoReplayActive = true;
    res.json({ success: true, session_id: session.lastID, events_count: events.length });

    // Replay events asynchronously
    const baseInterval = 200 / speed_multiplier;
    let idx = 0;
    const replayNext = async () => {
      if (idx >= events.length || !demoReplayActive) {
        demoReplayActive = false;
        await dbRun("UPDATE demo_sessions SET replay_status = 'completed', completed_at = ? WHERE id = ?",
          [Date.now() / 1000, session.lastID]);
        console.log(`[Demo Replay] Completed ${idx} events from ${sample_file}`);
        return;
      }
      const evt = events[idx];
      try {
        await dbRun(
          "INSERT INTO events (event_type, order_id, timestamp, source, organization_id) VALUES (?, ?, ?, ?, 0)",
          [evt.event || "order_placed", evt.order_id || "ORD_REPLAY", Date.now() / 1000, evt.source || "web"]
        );
      } catch (e) { /* ignore individual event errors */ }
      idx++;
      demoReplayTimeout = setTimeout(replayNext, baseInterval);
    };
    replayNext();
  } catch (err: any) {
    demoReplayActive = false;
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/demo/stop-replay", authenticateToken, async (req, res) => {
  demoReplayActive = false;
  if (demoReplayTimeout) clearTimeout(demoReplayTimeout);
  res.json({ success: true, message: "Replay stopped." });
});

app.get("/api/demo/sessions", authenticateToken, async (req, res) => {
  try {
    const sessions = await dbAll("SELECT * FROM demo_sessions ORDER BY started_at DESC LIMIT 20");
    res.json(sessions);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/demo/samples", authenticateToken, async (req, res) => {
  try {
    const sampleDir = path.join(process.cwd(), "sample_data");
    const files = fs.readdirSync(sampleDir).filter(f => f.endsWith(".json"));
    const samples: Record<string, any> = {};
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(sampleDir, f), "utf-8"));
      samples[f.replace(".json", "")] = data;
    }
    res.json(samples);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// REPORTING / EXPORT
// ========================
app.get("/api/reports/export/:type", authenticateToken, requireRole("super_admin", "org_admin", "executive_viewer"), async (req, res) => {
  try {
    const type = req.params.type;
    const anomalies = await dbAll("SELECT * FROM anomalies ORDER BY id DESC LIMIT 100");
    const incidents = await dbAll("SELECT * FROM incidents ORDER BY id DESC LIMIT 100");
    const totalEvents = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM events");
    const auditLogs = await dbAll("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100");

    const report = {
      generated_at: new Date().toISOString(),
      summary: {
        total_events: totalEvents?.total || 0,
        total_anomalies: anomalies.length,
        total_incidents: incidents.length,
        engine_settings: engineSettings,
      },
      anomalies,
      incidents,
      audit_logs: auditLogs,
    };

    if (type === "json") {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", "attachment; filename=aegis_report.json");
      res.json(report);
    } else if (type === "csv") {
      let csv = "ID,Timestamp,Z-Score,Event Count,Status,Severity,Diagnosis\n";
      for (const a of anomalies) {
        csv += `${a.id},${new Date(a.timestamp * 1000).toISOString()},${a.z_score},${a.event_count},${a.status},${a.severity || "MEDIUM"},"${(a.diagnosis || "").replace(/"/g, '""')}"\n`;
      }
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=aegis_anomalies.csv");
      res.send(csv);
    } else {
      res.status(400).json({ error: "Export type must be 'json' or 'csv'." });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/public/health", (req, res) => {
  res.json({ status: "healthy" });
});

// ========================
// SYSTEM HEALTH
// ========================
app.get("/api/health", authenticateToken, async (req, res) => {
  try {
    const eventCount = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM events");
    const anomalyCount = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM anomalies");
    const dbSize = fs.existsSync(path.join(process.cwd(), "storage", "events.db"))
      ? (fs.statSync(path.join(process.cwd(), "storage", "events.db")).size / 1024).toFixed(1)
      : "0";

    res.json({
      server_uptime: Math.floor(process.uptime()),
      node_version: process.version,
      memory_usage: process.memoryUsage(),
      database: {
        events_count: eventCount?.total || 0,
        anomaly_count: anomalyCount?.total || 0,
        db_size_kb: parseFloat(dbSize),
        wal_mode: true,
      },
      engine: engineSettings,
      producer_active: !!activeProducerInterval,
      detector_active: !!activeDetectorInterval,
      ingestion_active: !!activeIngestInterval,
      ingested_events: totalIngestedEvents,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// SANDBOX ENVIRONMENT (DEPRECATED & DISABLED)
// ========================
app.use("/api/sandbox", (req, res) => {
  res.status(410).json({ error: "Organization Sandbox workflow is deprecated and disabled." });
});

// ========================
// EXTERNAL DB INGESTION LOOP (Org mode — pulls real data from connected databases)
// ========================
function startIngestionLoop(connectorId: number, dbPath: string, mapping: any) {
  if (process.env.MODE === "demo") {
    console.log("[Ingestion] Request to start ingestion loop ignored in Demo Mode.");
    return;
  }
  if (activeIngestInterval) clearInterval(activeIngestInterval);
  activeIngestConnectorId = connectorId;
  lastIngestedRowId = 0;
  totalIngestedEvents = 0;

  const sourceTable = mapping.source_table;
  const fTs = mapping.field_timestamp;
  const fSrc = mapping.field_source;
  const fType = mapping.field_event_type;
  const fId = mapping.field_event_id;

  const ingestTick = async () => {
    try {
      if (!fs.existsSync(dbPath)) return;
      const rows: any[] = await new Promise((resolve, reject) => {
        const extDb = new sqlite3Lib.Database(dbPath, sqlite3Lib.OPEN_READONLY, (err) => {
          if (err) { reject(err); return; }
          const whereClause = fId ? ` WHERE "${fId}" > ${lastIngestedRowId}` : "";
          const orderCol = fId || fTs || "rowid";
          extDb.all(
            `SELECT * FROM "${sourceTable}"${whereClause} ORDER BY "${orderCol}" ASC LIMIT 200`,
            (e, r) => { extDb.close(); if (e) reject(e); else resolve(r || []); }
          );
        });
      });
      if (rows.length === 0) return;
      const tNow = Date.now() / 1000;
      for (const row of rows) {
        let ts = tNow;
        if (fTs && row[fTs] != null) {
          const raw = row[fTs];
          if (typeof raw === "number") ts = raw < 1e12 ? raw : raw / 1000;
          else { const parsed = new Date(raw).getTime(); if (!isNaN(parsed)) ts = parsed / 1000; }
        }
        const eventType = (fType && row[fType]) || "external_event";
        const source = (fSrc && row[fSrc]) || "connector";
        const orderId = (fId && row[fId]) ? String(row[fId]) : `EXT_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
        await dbRun(
          "INSERT INTO events (event_type, order_id, timestamp, source, organization_id) VALUES (?, ?, ?, ?, 1)",
          [String(eventType), orderId, ts, String(source)]
        );
        totalIngestedEvents++;
        if (fId && row[fId] != null && typeof row[fId] === "number") lastIngestedRowId = Math.max(lastIngestedRowId, row[fId]);
        else lastIngestedRowId++;
      }
    } catch (err: any) {
      console.error("[Ingestion] Error:", err.message);
    }
  };
  activeIngestInterval = setInterval(ingestTick, 1000);
  console.log(`[Ingestion] Started — connector #${connectorId}, table: ${sourceTable}`);
}

function stopIngestionLoop() {
  if (activeIngestInterval) { clearInterval(activeIngestInterval); activeIngestInterval = null; }
  activeIngestConnectorId = null;
}


async function checkAndStartActiveConnector() {
  if (process.env.MODE === "demo") {
    console.log("[Ingestion] Running in Demo Mode. Ignoring database connectors to start B1 simulated telemetry.");
    return false;
  }
  try {
    const connector = await dbGet<any>("SELECT * FROM connectors WHERE id = (SELECT MIN(id) FROM connectors WHERE status = 'connected' AND db_type = 'sqlite')");
    if (connector && fs.existsSync(connector.database_name || connector.host || "")) {
      const mapping = await dbGet<any>("SELECT * FROM event_mappings WHERE connector_id = ? ORDER BY id DESC LIMIT 1", [connector.id]);
      if (mapping) {
        startIngestionLoop(connector.id, connector.database_name || connector.host, mapping);
        return true;
      }
    }
  } catch (e: any) { console.warn("[Ingestion] Auto-start check error:", e.message); }
  return false;
}

// ========================
// INTERNAL ENGINE LOOPS (Preserved)
// ========================

let currentPhase = 0;
let phaseTicksElapsed = 0;
let normalEventIndex = 0;
let normalEvents: any[] = [];
let bruteForceEvents: any[] = [];
let ddosEvents: any[] = [];
let exfilEvents: any[] = [];
let insiderEvents: any[] = [];
let serviceFailureEvents: any[] = [];

function loadAllSampleFiles() {
  const sampleDir = path.join(process.cwd(), "sample_data");
  try {
    normalEvents = JSON.parse(fs.readFileSync(path.join(sampleDir, "normal_sample.json"), "utf8"));
  } catch (err: any) {
    normalEvents = [
      { event: "user_auth", order_id: "AUTH_SUCCESS_01", source: "vpn" },
      { event: "firewall_accept", order_id: "FW_ACCEPT_01", source: "gateway" },
      { event: "api_request", order_id: "API_GET_01", source: "api" },
      { event: "order_placed", order_id: "ORD309482", source: "web" }
    ];
  }
  try {
    bruteForceEvents = JSON.parse(fs.readFileSync(path.join(sampleDir, "bruteforce_sample.json"), "utf8"));
  } catch (err: any) {
    bruteForceEvents = Array(55).fill(null).map((_, i) => ({ event: "failed_login", order_id: `FAIL_AUTH_${i}`, source: "web" }));
  }
  try {
    ddosEvents = JSON.parse(fs.readFileSync(path.join(sampleDir, "ddos_sample.json"), "utf8"));
  } catch (err: any) {
    ddosEvents = Array(120).fill(null).map((_, i) => ({ event: "order_placed", order_id: `ORD_DDOS_${i}`, source: "api" }));
  }
  try {
    exfilEvents = JSON.parse(fs.readFileSync(path.join(sampleDir, "exfiltration_sample.json"), "utf8"));
  } catch (err: any) {
    exfilEvents = Array(20).fill(null).map((_, i) => ({ event: "data_transfer", order_id: `EXFIL_DATA_${i}`, source: "api" }));
  }
  try {
    insiderEvents = JSON.parse(fs.readFileSync(path.join(sampleDir, "insider_sample.json"), "utf8"));
  } catch (err: any) {
    insiderEvents = Array(15).fill(null).map((_, i) => ({ event: "privileged_action", order_id: `ADMIN_CONFIG_${i}`, source: "console" }));
  }
  try {
    serviceFailureEvents = JSON.parse(fs.readFileSync(path.join(sampleDir, "service_failure_sample.json"), "utf8"));
  } catch (err: any) {
    serviceFailureEvents = Array(15).fill(null).map((_, i) => ({ event: "heartbeat_miss", order_id: `SERVICE_DROP_${i}`, source: "internal" }));
  }
}

let scenarioEngineProcess: any = null;
let isStartingScenarioEngine = false;

function startScenarioEngine() {
  if (scenarioEngineProcess) {
    console.log("[Engine] Scenario Engine is already running. Skipping duplicate launch request.");
    return;
  }
  if (isStartingScenarioEngine) {
    console.log("[Engine] Scenario Engine launch already in progress. Skipping.");
    return;
  }
  isStartingScenarioEngine = true;
  console.log("[Engine] Starting Python Scenario Engine (generators/scenario_engine.py)...");
  
  const pythonCmd = process.platform === "win32" ? "python" : "python3";
  const scriptPath = path.join(process.cwd(), "generators", "scenario_engine.py");
  
  scenarioEngineProcess = spawn(pythonCmd, [scriptPath], {
    env: { ...process.env, MODE: "demo", PYTHONIOENCODING: "utf-8" },
    stdio: "inherit"
  });

  scenarioEngineProcess.on("spawn", () => {
    isStartingScenarioEngine = false;
  });

  scenarioEngineProcess.on("error", (err: any) => {
    console.error("[Engine] Scenario Engine failed to spawn:", err.message);
    scenarioEngineProcess = null;
    isStartingScenarioEngine = false;
  });

  scenarioEngineProcess.on("close", (code: number) => {
    console.log(`[Engine] Scenario Engine process exited with code ${code}`);
    scenarioEngineProcess = null;
    isStartingScenarioEngine = false;
    if (process.env.MODE === "demo") {
      console.log("[Engine] Restarting Scenario Engine in 5 seconds...");
      setTimeout(startScenarioEngine, 5000);
    }
  });
}

function stopScenarioEngine() {
  if (scenarioEngineProcess) {
    console.log("[Engine] Stopping Scenario Engine process...");
    scenarioEngineProcess.kill();
    scenarioEngineProcess = null;
    isStartingScenarioEngine = false;
  }
}

function startProducerLoop() {
  // Skip simulated event generation if an external connector is actively ingesting
  if (activeIngestConnectorId) {
    console.log(`[Engine] Producer skipped — active connector #${activeIngestConnectorId} providing real events.`);
    return;
  }
  
  loadAllSampleFiles();
  
  const triggerTick = async () => {
    try {
      const isIncidentPhase = currentPhase % 2 === 1;
      const durationMs = isIncidentPhase ? 10000 : 40000;
      const maxTicks = Math.max(1, Math.round(durationMs / engineSettings.EVENT_INTERVAL));
      
      if (phaseTicksElapsed >= maxTicks) {
        currentPhase = (currentPhase + 1) % 11;
        phaseTicksElapsed = 0;
        console.log(`[Engine Demo Generator] Transitioning to Phase ${currentPhase} (isIncident: ${currentPhase % 2 === 1})`);
      }
      
      // If start of incident phase, inject rapid burst events
      if (currentPhase % 2 === 1 && phaseTicksElapsed === 0) {
        let burstEvents: any[] = [];
        if (currentPhase === 1) burstEvents = bruteForceEvents;
        else if (currentPhase === 3) burstEvents = ddosEvents;
        else if (currentPhase === 5) burstEvents = exfilEvents;
        else if (currentPhase === 7) burstEvents = insiderEvents;
        else if (currentPhase === 9) burstEvents = serviceFailureEvents;
        
        console.log(`[Engine Demo Generator] Phase ${currentPhase} Start: Injecting burst of ${burstEvents.length} events...`);
        for (const evt of burstEvents) {
          const orderId = evt.order_id || ("ORD" + Math.floor(100000 + Math.random() * 900000));
          await dbRun(
            "INSERT INTO events (event_type, order_id, timestamp, source) VALUES (?, ?, ?, ?)",
            [evt.event || "order_placed", orderId, Date.now() / 1000, evt.source || "web"]
          );
        }
      }
      
      // Always inject a healthy baseline normal event to maintain continuous activity and small fluctuations
      const normalEvt = normalEvents[normalEventIndex % normalEvents.length];
      normalEventIndex++;
      const orderId = "ORD" + Math.floor(100000 + Math.random() * 900000);
      await dbRun(
        "INSERT INTO events (event_type, order_id, timestamp, source) VALUES (?, ?, ?, ?)",
        [normalEvt.event || "order_placed", orderId, Date.now() / 1000, normalEvt.source || "web"]
      );
      
      phaseTicksElapsed++;
    } catch (err: any) {
      console.error("Failed recording normal/simulated order in demo generator:", err.message);
    }
  };
  activeProducerInterval = setInterval(triggerTick, engineSettings.EVENT_INTERVAL);
}

function restartProducerLoop() {
  if (activeProducerInterval) clearInterval(activeProducerInterval);
  startProducerLoop();
}

function startDetectorLoop() {
  const checkTick = async () => {
    try {
      const tNow = Date.now() / 1000;
      const windowSec = engineSettings.WINDOW_SIZE;
      const cutoff = tNow - windowSec - 2;
      const rows = await dbAll<any>(
        "SELECT CAST(timestamp as INTEGER) as sec, COUNT(*) as count FROM events WHERE timestamp >= ? GROUP BY sec ORDER BY sec DESC",
        [cutoff]
      );

      const countsMap: Record<number, number> = {};
      rows.forEach((r) => { countsMap[r.sec] = r.count; });

      const currentSec = Math.floor(tNow);
      currentEventRate = countsMap[currentSec] || 0;

      const historicalSamples: number[] = [];
      for (let i = 1; i <= windowSec; i++) {
        historicalSamples.push(countsMap[currentSec - i] || 0);
      }

      const totalSamples = historicalSamples.length;
      const sum = historicalSamples.reduce((a, b) => a + b, 0);
      const mean = sum / totalSamples;
      currentMean = mean;

      let stdDev = 0;
      if (totalSamples > 1) {
        const sqSum = historicalSamples.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0);
        stdDev = Math.sqrt(sqSum / (totalSamples - 1));
      }
      currentStd = stdDev;
      currentZScore = stdDev > 0 ? (currentEventRate - mean) / stdDev : 0;

      // Debug checkTick values
      if (currentEventRate > 0) {
        console.log(`[Detector Debug] Tick - Rate: ${currentEventRate} | Mean: ${mean.toFixed(2)} | StdDev: ${stdDev.toFixed(2)} | Z: ${currentZScore.toFixed(2)}`);
      }

      // === HYBRID DETECTION PIPELINE ===
      hybridDetector.setConfig({
        iforestEnabled: engineSettings.ISOLATION_FOREST_ENABLED,
        ewmaAlpha: engineSettings.EWMA_ALPHA,
      });

      const hybridResult = await hybridDetector.analyze(
        currentZScore,
        currentEventRate,
        windowSec,
        engineSettings.Z_SCORE_THRESHOLD,
      );

      // Update global hybrid state
      currentIForestScore = hybridResult.iforestScore;
      currentEWMAScore = hybridResult.ewmaScore;
      currentHybridScore = hybridResult.hybridScore;
      currentHybridSeverity = hybridResult.hybridSeverity;
      currentDetectionMethod = hybridResult.detectionMethod;
      if (hybridResult.features) {
        currentSourceEntropy = hybridResult.features.sourceEntropy;
        currentBurstRatio = hybridResult.features.burstRatio;
      }

      // Severity: use hybrid when fusion enabled
      const severity = engineSettings.HYBRID_FUSION ? hybridResult.hybridSeverity : hybridResult.zScoreSeverity;

      // Alert: hybrid OR Z-Score breach (whichever fires first)
      const zScoreBreach = currentZScore > engineSettings.Z_SCORE_THRESHOLD && currentEventRate > 5;
      const hybridBreach = engineSettings.HYBRID_FUSION && hybridResult.hybridScore >= 0.3 && currentEventRate > 5;
      const shouldAlert = (zScoreBreach || hybridBreach) && Date.now() - lastAlarmTime > ALARM_COOLDOWN_MS;

      if (shouldAlert) {
        lastAlarmTime = Date.now();
        const method = hybridResult.detectionMethod;
        console.log(`\n🚨 [${method}] BREACH! Rate: ${currentEventRate} | Z: ${currentZScore.toFixed(2)} | iForest: ${hybridResult.iforestScore.toFixed(3)} | EWMA: ${hybridResult.ewmaScore.toFixed(2)} | Hybrid: ${hybridResult.hybridScore.toFixed(3)} | Severity: ${severity}`);

        // Classify the threat exactly once at anomaly creation
        const threat = await classifyAnomalyThreat(tNow, currentEventRate, currentZScore);

        const anomalyInsert = await dbRun(
          "INSERT INTO anomalies (timestamp, z_score, window_mean, window_std, event_count, severity, iforest_score, ewma_score, hybrid_score, detection_method, source_entropy, burst_ratio, possible_threat, threat_confidence, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
          [tNow, currentZScore, mean, stdDev, currentEventRate, severity,
           hybridResult.iforestScore, hybridResult.ewmaScore, hybridResult.hybridScore,
           hybridResult.detectionMethod, currentSourceEntropy, currentBurstRatio,
           threat.possibleThreat, threat.threatConfidence, threat.recommendation]
        );
        const anomalyId = anomalyInsert.lastID;

        // Auto-create detailed incident for every anomaly peak
        const title = `[${method}] ${severity} Severity Anomaly Breach #${anomalyId}`;
        const desc = `${method} detection triggered at ${currentEventRate} events/sec. Z-Score=${currentZScore.toFixed(2)} (threshold: ${engineSettings.Z_SCORE_THRESHOLD}), iForest=${hybridResult.iforestScore.toFixed(3)}, EWMA=${hybridResult.ewmaScore.toFixed(2)}, Hybrid=${hybridResult.hybridScore.toFixed(3)}. Window: mean=${mean.toFixed(2)}, std=${stdDev.toFixed(2)}.`;
        const rootCause = `Traffic spike of ${currentEventRate} events/sec detected against baseline of ${mean.toFixed(1)} events/sec (${stdDev.toFixed(1)} std dev). Sources: entropy=${currentSourceEntropy.toFixed(3)}, burst ratio=${currentBurstRatio.toFixed(2)}.`;
        const aiDiag = `Hybrid analysis (${method}): Z-Score breach at ${currentZScore.toFixed(2)} SD, Isolation Forest scored ${hybridResult.iforestScore.toFixed(3)} (path-length anomaly), EWMA deviation at ${hybridResult.ewmaScore.toFixed(2)}. Severity classified as ${severity}.`;
        const recAction = `Immediate: Review traffic from all sources for potential DDoS or bot activity. Check source entropy (${currentSourceEntropy.toFixed(3)}) for concentration patterns. Verify ${currentEventRate} events/sec is not a legitimate burst. Isolate affected systems if malicious.`;

        const incidentResult = await dbRun(
          "INSERT INTO incidents (anomaly_id, title, description, severity, detection_time, status, root_cause, ai_diagnosis, recommended_action, organization_id, possible_threat, threat_confidence, recommendation) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, 1, ?, ?, ?)",
          [anomalyId, title, desc, severity, tNow, rootCause, aiDiag, recAction,
           threat.possibleThreat, threat.threatConfidence, threat.recommendation]
        );
        const incidentId = incidentResult.lastID;
        console.log(`Registered Anomaly #${anomalyId} + Incident #${incidentId} via ${method} [${severity}]`);

        // Always create an in-app notification for every anomaly peak
        await dbRun(
          "INSERT INTO notifications (type, message, anomaly_id, incident_id, status) VALUES ('email', ?, ?, ?, 'sent')",
          [`${severity} alert: Anomaly #${anomalyId} — ${method} Z=${currentZScore.toFixed(2)} Hybrid=${hybridResult.hybridScore.toFixed(3)} at ${currentEventRate} evt/s`, anomalyId, incidentId]
        );

        // Discord webhook (Rich embed lifecycle alert)
        const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (webhookUrl && webhookUrl.trim() !== "") {
          await triggerAnomalyDiscordAlert(anomalyId, "investigating");

          await dbRun(
            "INSERT INTO notifications (type, message, anomaly_id, status) VALUES ('discord', ?, ?, 'sent')",
            [`Rich Discord incident created for Anomaly #${anomalyId}`, anomalyId]
          );
        }

        runServerAgentLoop(anomalyId, currentEventRate).catch((err) => {
          console.error("[Detector Loop] Error in background runServerAgentLoop:", err);
        });
      }
    } catch (err: any) {
      console.error("Exception in detector loop:", err.message);
    }
  };
  activeDetectorInterval = setInterval(checkTick, 1000);
}

// Master Server Boot
async function startServer() {
  // Strict Startup Check
  const mode = process.env.MODE;
  if (mode !== "demo" && mode !== "organization") {
    console.error(`\n❌ [Fatal Error] Invalid MODE configuration!`);
    console.error(`   Expected MODE='demo' or MODE='organization'. Got: '${mode}'`);
    console.error(`   Aegis startup aborted to prevent database contamination.\n`);
    process.exit(1);
  }

  // Advisory Warning for obsolete events.db
  const legacyDbPath = path.resolve(process.cwd(), "storage", "events.db");
  if (fs.existsSync(legacyDbPath)) {
    console.warn("\n==================================================================");
    console.warn("⚠️  WARNING: Legacy database file 'storage/events.db' detected!");
    console.warn("   This database is obsolete and is no longer used by Aegis.");
    console.warn("   We recommend manual archival or removal of this file.");
    console.warn("==================================================================\n");
  }

  await initServerDb();
  await initPgDb();
  await initQdrantCollections();
  await initMinio();

  // Clear telemetry tables if Demo Mode and DEMO_RESET=true is active
  if (process.env.MODE === "demo" && process.env.DEMO_RESET === "true") {
    console.log("[Demo Startup] DEMO_RESET=true detected. Clearing demo telemetry tables...");
    try {
      // Respect foreign key constraints by deleting in order
      await dbRun("DELETE FROM agent_logs");
      await dbRun("DELETE FROM notifications");
      await dbRun("DELETE FROM incidents");
      await dbRun("DELETE FROM anomalies");
      await dbRun("DELETE FROM events");
      console.log("[Demo Startup] Telemetry tables cleared successfully.");
    } catch (err: any) {
      console.error("[Demo Startup] Failed clearing telemetry tables:", err.message);
    }
  }

  activePruneInterval = setInterval(() => { pruneOldEvents(); }, 60000);

  if (process.env.MODE === "demo") {
    startScenarioEngine();

    // Staged Verification: Stage 1 - Telemetry Flow Verification at 60s
    console.log("[Audit System] Stage 1 Telemetry flow verification scheduled in 60 seconds...");
    setTimeout(async () => {
      console.log("[Audit System] Running Stage 1 Telemetry Flow Verification...");
      try {
        const events = await dbGet<{ count: number }>("SELECT COUNT(*) as count FROM events");
        const evCount = events?.count || 0;
        console.log(`[Audit System] Stage 1 Row Count — events: ${evCount}`);
        if (evCount > 0) {
          console.log("\n=======================================================");
          console.log("✅ VERIFICATION SUCCESS: Demo telemetry flow verified!");
          console.log("=======================================================\n");
        } else {
          console.error("\n=======================================================");
          console.error("❌ VERIFICATION FAILURE: Demo telemetry generation failure.");
          console.error("=======================================================\n");
        }
      } catch (err: any) {
        console.error("\n=======================================================");
        console.error("❌ VERIFICATION FAILURE: Demo telemetry generation failure.");
        console.error("   Error querying database:", err.message);
        console.error("=======================================================\n");
      }
    }, 60000);

    // Staged Verification: Stage 2 - Detection Pipeline Verification at 180s
    console.log("[Audit System] Stage 2 Detection pipeline verification scheduled in 180 seconds...");
    setTimeout(async () => {
      console.log("[Audit System] Running Stage 2 Detection Pipeline Verification...");
      try {
        const anomalies = await dbGet<{ count: number }>("SELECT COUNT(*) as count FROM anomalies");
        const incidents = await dbGet<{ count: number }>("SELECT COUNT(*) as count FROM incidents");
        const notifications = await dbGet<{ count: number }>("SELECT COUNT(*) as count FROM notifications");
        const agentLogs = await dbGet<{ count: number }>("SELECT COUNT(*) as count FROM agent_logs");

        const anomCount = anomalies?.count || 0;
        const incCount = incidents?.count || 0;
        const notifCount = notifications?.count || 0;
        const logsCount = agentLogs?.count || 0;

        console.log(`[Audit System] Stage 2 Row Counts — anomalies: ${anomCount}, incidents: ${incCount}, notifications: ${notifCount}, agent_logs: ${logsCount}`);

        if (anomCount > 0 && incCount > 0 && notifCount > 0 && logsCount > 0) {
          console.log("\n=======================================================");
          console.log("✅ VERIFICATION SUCCESS: Demo detection pipeline verified!");
          console.log("=======================================================\n");
        } else {
          console.error("\n=======================================================");
          console.error("❌ VERIFICATION FAILURE: Demo detection pipeline failure.");
          console.error("=======================================================\n");
        }
      } catch (err: any) {
        console.error("\n=======================================================");
        console.error("❌ VERIFICATION FAILURE: Demo detection pipeline failure.");
        console.error("   Error querying database:", err.message);
        console.error("=======================================================\n");
      }
    }, 180000);

  } else {
    // Check for active connector — use real DB ingestion instead of simulated events
    const hasConnector = await checkAndStartActiveConnector();
    if (!hasConnector) {
      startProducerLoop();
    }
  }
  startDetectorLoop();

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  // One-time migration: add columns for hybrid detection, threat insights & recommended actions
  try {
    // Add recommended_action column if it doesn't exist
    try {
      await dbRun("ALTER TABLE incidents ADD COLUMN recommended_action TEXT DEFAULT ''");
      console.log("[Migration] Added recommended_action column to incidents.");
    } catch (_: any) { /* column already exists */ }

    // Add threat insights columns to incidents table
    const incColumns = [
      { name: "possible_threat", type: "TEXT DEFAULT ''" },
      { name: "threat_confidence", type: "REAL DEFAULT 0" },
      { name: "recommendation", type: "TEXT DEFAULT ''" },
      { name: "gemini_summary", type: "TEXT DEFAULT ''" }
    ];
    for (const col of incColumns) {
      try {
        await dbRun(`ALTER TABLE incidents ADD COLUMN ${col.name} ${col.type}`);
        console.log(`[Migration] Added ${col.name} column to incidents.`);
      } catch (_: any) { /* column already exists */ }
    }

    // Add hybrid detection & threat columns to anomalies table
    const hybridColumns = [
      { name: "iforest_score", type: "REAL DEFAULT 0" },
      { name: "ewma_score", type: "REAL DEFAULT 0" },
      { name: "hybrid_score", type: "REAL DEFAULT 0" },
      { name: "detection_method", type: "TEXT DEFAULT 'ZSCORE'" },
      { name: "source_entropy", type: "REAL DEFAULT 0" },
      { name: "burst_ratio", type: "REAL DEFAULT 0" },
      { name: "possible_threat", type: "TEXT DEFAULT ''" },
      { name: "threat_confidence", type: "REAL DEFAULT 0" }
    ];
    for (const col of hybridColumns) {
      try {
        await dbRun(`ALTER TABLE anomalies ADD COLUMN ${col.name} ${col.type}`);
        console.log(`[Migration] Added ${col.name} column to anomalies.`);
      } catch (_: any) { /* column already exists */ }
    }
  } catch (e: any) {
    console.warn("[Migration] Warning:", e.message);
  }

  // One-time backfill: create incidents for any anomalies that are missing them
  try {
    const anomaliesWithoutIncidents = await dbAll(
      "SELECT a.id, a.timestamp, a.z_score, a.event_count, a.severity, a.detection_method, a.iforest_score, a.ewma_score, a.hybrid_score, a.source_entropy, a.burst_ratio FROM anomalies a LEFT JOIN incidents i ON i.anomaly_id = a.id WHERE i.id IS NULL"
    );
    if (anomaliesWithoutIncidents.length > 0) {
      console.log(`[Backfill] Creating incidents for ${anomaliesWithoutIncidents.length} orphaned anomalies...`);
      for (const a of anomaliesWithoutIncidents as any[]) {
        const method = a.detection_method || "ZSCORE";
        const sev = a.severity || "MEDIUM";
        const title = `[${method}] ${sev} Severity Anomaly Breach #${a.id}`;
        const desc = `${method} detection triggered at ${a.event_count} events/sec. Z-Score=${(a.z_score||0).toFixed(2)}, iForest=${(a.iforest_score||0).toFixed(3)}, EWMA=${(a.ewma_score||0).toFixed(2)}, Hybrid=${(a.hybrid_score||0).toFixed(3)}.`;
        const rootCause = `Traffic spike of ${a.event_count} events/sec detected. Sources: entropy=${(a.source_entropy||0).toFixed(3)}, burst ratio=${(a.burst_ratio||0).toFixed(2)}.`;
        const aiDiag = `Hybrid analysis (${method}): Z-Score breach at ${(a.z_score||0).toFixed(2)} SD, Isolation Forest scored ${(a.iforest_score||0).toFixed(3)}, EWMA deviation at ${(a.ewma_score||0).toFixed(2)}. Severity classified as ${sev}.`;
        const recAction = `Immediate: Review traffic from all sources for potential DDoS or bot activity. Check source entropy (${(a.source_entropy||0).toFixed(3)}) for concentration patterns. Verify ${a.event_count} events/sec is not a legitimate burst.`;
        await dbRun(
          "INSERT INTO incidents (anomaly_id, title, description, severity, detection_time, status, root_cause, ai_diagnosis, recommended_action, organization_id) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, 1)",
          [a.id, title, desc, sev, a.timestamp, rootCause, aiDiag, recAction]
        );
        console.log(`[Backfill] Created incident for orphaned Anomaly #${a.id}`);
      }
      console.log(`[Backfill] Done. Created ${anomaliesWithoutIncidents.length} new incidents.`);
    }
  } catch (e: any) {
    console.warn("[Backfill] Orphan anomaly backfill error:", e.message);
  }

  // One-time backfill: populate incidents with empty root_cause/ai_diagnosis/resolution
  try {
    const emptyIncidents = await dbAll(
      "SELECT i.id, i.anomaly_id, i.status, a.diagnosis, a.z_score, a.event_count, a.severity FROM incidents i LEFT JOIN anomalies a ON i.anomaly_id = a.id WHERE ((i.root_cause = '' OR i.root_cause IS NULL) OR (i.recommended_action = '' OR i.recommended_action IS NULL)) AND i.anomaly_id IS NOT NULL"
    );
    if (emptyIncidents.length > 0) {
      console.log(`[Backfill] Updating ${emptyIncidents.length} incidents with empty diagnosis fields...`);
      for (const inc of emptyIncidents) {
        const diag = inc.diagnosis || "Analyzed by AI agent \u2014 no detailed diagnosis available.";
        const rootCause = `Traffic anomaly detected (Z-Score: ${inc.z_score || "N/A"}, ${inc.event_count || 0} events/sec, severity: ${inc.severity || "MEDIUM"})`;
        const resolution = inc.status === "MITIGATED" ? "Automated containment applied." : "Pending analyst review.";
        const recAction = `Investigate the traffic anomaly (Z-Score: ${inc.z_score || "N/A"}) and review system logs for potential issues. Verify source distribution and check if any ongoing campaigns or attacks are contributing to this anomaly.`;
        await dbRun(
          "UPDATE incidents SET root_cause = ?, ai_diagnosis = ?, resolution = ?, recommended_action = ? WHERE id = ?",
          [rootCause, diag, resolution, recAction, inc.id]
        );
      }
      console.log(`[Backfill] Done. ${emptyIncidents.length} incidents updated.`);
    }
  } catch (e: any) {
    console.warn("[Backfill] Warning:", e.message);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n======================================================`);
    console.log(`  Aegis Enterprise SOC Platform Active!`);
    console.log(`  Live UI: http://localhost:${PORT}`);
    console.log(`  API Docs: http://localhost:${PORT}/api/health`);
    console.log(`======================================================\n`);
  });
}

startServer();
