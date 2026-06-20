import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { pgQuery } from '../pg_db.js';
import { authenticateToken, requireRole, AuthenticatedRequest } from '../auth_middleware.js';
import { ingestDocument } from './langchain_service.js';
import { uploadToMinio } from './minio_service.js';
import { querySecurityCopilot } from './langchain_service.js';
import { dbRun, dbGet } from '../server_db.js';

export const copilotRouter = Router();
const upload = multer({ storage: multer.memoryStorage() });

// 1. Auth Endpoint: Login
copilotRouter.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: "Email and password are required." });
      return;
    }

    const userCheck = await pgQuery("SELECT * FROM users WHERE email = $1", [email.trim().toLowerCase()]);
    if (userCheck.rows.length === 0) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    const user = userCheck.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || "dev-secret-key",
      { expiresIn: "2h" }
    );
    const refreshToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || "dev-secret-key",
      { expiresIn: "7d" }
    );

    res.json({ token, refreshToken, role: user.role, email: user.email });
  } catch (err: any) {
    res.status(500).json({ error: "Internal server error: " + err.message });
  }
});

// 2. Chat Endpoints: Retrieve Sessions
copilotRouter.get("/sessions", authenticateToken, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const sessions = await pgQuery("SELECT * FROM chat_sessions WHERE user_id = $1 ORDER BY created_at DESC", [userId]);
    res.json(sessions.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Create Chat Session
copilotRouter.post("/sessions", authenticateToken, async (req: AuthenticatedRequest, res) => {
  try {
    const userId = req.user!.id;
    const { title } = req.body;
    const sessionRes = await pgQuery(
      "INSERT INTO chat_sessions (user_id, title) VALUES ($1, $2) RETURNING *",
      [userId, title || "New Investigation Session"]
    );
    res.status(201).json(sessionRes.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Get Messages in Session
copilotRouter.get("/sessions/:id/messages", authenticateToken, async (req, res) => {
  try {
    const sessionId = parseInt(req.params.id);
    const messages = await pgQuery("SELECT * FROM chat_messages WHERE session_id = $1 ORDER BY created_at ASC", [sessionId]);
    res.json(messages.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Ask Security Copilot (RAG Injected chatbot)
copilotRouter.post("/chat", authenticateToken, async (req: AuthenticatedRequest, res) => {
  try {
    const { session_id, message, anomaly_id } = req.body;
    const userId = req.user!.id;
    const ipAddress = req.ip || "127.0.0.1";

    if (!session_id || !message) {
      res.status(400).json({ error: "session_id and message are required." });
      return;
    }

    // Grab incident context if anomaly_id is provided
    let incidentContext = "";
    if (anomaly_id) {
      try {
        const incident = await dbGet("SELECT * FROM incidents WHERE anomaly_id = ?", [anomaly_id]);
        if (incident) {
          incidentContext = `Incident Title: ${incident.title}\nSeverity: ${incident.severity}\nDescription: ${incident.description}\nRoot Cause: ${incident.root_cause}`;
        }
      } catch (_) {}
    }

    const response = await querySecurityCopilot(message, session_id, userId, ipAddress, incidentContext);
    
    // If action required, log a staged alert requiring approval
    if (response.requires_action && response.pending_action) {
      const target = response.pending_action.target;
      const desc = `Copilot suggested blocking traffic from source: '${target}' based on user query: "${message}"`;
      
      const alertInsert = await pgQuery(
        "INSERT INTO alerts (severity, source, description, status, requires_approval, pending_action) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        ["HIGH", target, desc, "PENDING_APPROVAL", true, JSON.stringify(response.pending_action)]
      );
      
      res.json({
        ...response,
        alert_id: alertInsert.rows[0].id
      });
      return;
    }

    res.json(response);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Responsible AI human-in-the-loop: Approve staged alert mitigation
copilotRouter.post("/actions/approve", authenticateToken, requireRole("Admin", "SOC Analyst"), async (req: AuthenticatedRequest, res) => {
  try {
    const { alert_id } = req.body;
    const userId = req.user!.id;
    const ipAddress = req.ip || "127.0.0.1";

    if (!alert_id) {
      res.status(400).json({ error: "alert_id is required." });
      return;
    }

    const alertCheck = await pgQuery("SELECT * FROM alerts WHERE id = $1 AND status = $2", [alert_id, "PENDING_APPROVAL"]);
    if (alertCheck.rows.length === 0) {
      res.status(404).json({ error: "Pending approval alert not found or already processed." });
      return;
    }

    const alert = alertCheck.rows[0];
    const pendingAction = alert.pending_action;

    // Apply the mitigation actions inside SQLite core tables
    if (pendingAction && pendingAction.type === "BLOCK_IP") {
      const source = pendingAction.target;
      console.log(`[Human-In-The-Loop Approved] Blocking source '${source}' via Copilot...`);

      // Update SQLite to show that the system has mitigated active incidents
      try {
        await dbRun(
          "UPDATE incidents SET status = 'MITIGATED', resolution = ?, updated_at = ? WHERE status = 'OPEN'",
          [`Mitigation executed manually by Analyst. Blocked source: ${source}`, Date.now() / 1000]
        );
        await dbRun("UPDATE anomalies SET status = 'Mitigated' WHERE status = 'Open'");
      } catch (sqErr: any) {
        console.warn("[SQLite Sync Warning] Failed to update SQLite details:", sqErr.message);
      }
    }

    // Update alert status
    await pgQuery("UPDATE alerts SET status = $1 WHERE id = $2", ["MITIGATED", alert_id]);

    // Insert action audit log
    const auditRes = await pgQuery(
      "INSERT INTO audit_logs (user_id, action, resource, ip_address, prompt, retrieved_documents, llm_response, approval_granted) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
      [userId, "ACTION_APPROVAL", `ALERT_${alert_id}`, ipAddress, `Approved blocking action on staged alert #${alert_id}`, JSON.stringify([]), "Action applied successfully", true]
    );

    res.json({ status: "MITIGATED", audit_log_id: auditRes.rows[0].id });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Document Ingestion API
copilotRouter.post("/documents/upload", authenticateToken, requireRole("Admin", "SOC Analyst"), upload.single("file"), async (req: AuthenticatedRequest, res) => {
  try {
    const file = req.file;
    const userId = req.user!.id;
    if (!file) {
      res.status(400).json({ error: "No file uploaded." });
      return;
    }

    console.log(`[MinIO/RAG Ingestion] Uploading document: ${file.originalname} (${file.size} bytes)...`);

    // 1. Upload to MinIO object storage
    const storagePath = await uploadToMinio(file.originalname, file.buffer, file.size);

    // 2. Save metadata to PostgreSQL in PROCESSING state
    const docRes = await pgQuery(
      "INSERT INTO documents (filename, storage_path, uploaded_by, status) VALUES ($1, $2, $3, $4) RETURNING *",
      [file.originalname, storagePath, userId, "PROCESSING"]
    );
    const docId = docRes.rows[0].id;

    // 3. Chunk & Index into Qdrant collections asynchronously
    const textContent = file.buffer.toString("utf-8");
    
    ingestDocument(file.originalname, textContent)
      .then(async (chunksCount) => {
        console.log(`[RAG Indexer] Successfully indexed document ${file.originalname} into Qdrant. Total chunks: ${chunksCount}`);
        await pgQuery("UPDATE documents SET status = $1 WHERE id = $2", ["INDEXED", docId]);
      })
      .catch(async (ingestErr) => {
        console.error(`[RAG Indexer Error] Ingestion failed for ${file.originalname}:`, ingestErr.message);
        await pgQuery("UPDATE documents SET status = $1 WHERE id = $2", ["FAILED", docId]);
      });

    res.status(202).json({
      message: "Document upload accepted. Processing background index task...",
      document: docRes.rows[0]
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Audit logs API
copilotRouter.get("/audit_logs", authenticateToken, requireRole("Admin", "Auditor"), async (req, res) => {
  try {
    const logs = await pgQuery("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100");
    res.json(logs.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 6. Alerts API
copilotRouter.get("/alerts", authenticateToken, async (req, res) => {
  try {
    const list = await pgQuery("SELECT * FROM alerts ORDER BY created_at DESC");
    res.json(list.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Documents List API
copilotRouter.get("/documents", authenticateToken, async (req, res) => {
  try {
    const docs = await pgQuery("SELECT * FROM documents ORDER BY uploaded_at DESC");
    res.json(docs.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default copilotRouter;
