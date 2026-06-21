import "dotenv/config";
import path from "path";
import fs from "fs";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";

// Early validation of MODE to prevent raw stack trace throws during ESM import hoisting
const dbCheckMode = process.env.MODE;
if (process.env.NODE_ENV !== "test" && dbCheckMode !== "demo" && dbCheckMode !== "organization") {
  console.error(`\n❌ [Fatal Error] Invalid MODE configuration!`);
  console.error(`   Expected MODE='demo' or MODE='organization'. Got: '${dbCheckMode}'`);
  console.error(`   Aegis startup aborted to prevent database contamination.\n`);
  process.exit(1);
}


export function getActiveTelemetryDatabase(): string {
  const mode = process.env.MODE;
  if (mode === "demo") {
    return "events_demo.db";
  } else if (mode === "organization") {
    return "events_org.db";
  } else if (process.env.NODE_ENV === "test" && process.env.SQLITE_DB) {
    return path.basename(process.env.SQLITE_DB);
  } else {
    throw new Error("Invalid MODE. Expected 'demo' or 'organization'. Got: " + mode);
  }
}

export function getAbsoluteTelemetryDbPath(): string {
  const mode = process.env.MODE;
  if (mode === "demo") {
    return path.resolve(process.cwd(), "storage", "events_demo.db");
  } else if (mode === "organization") {
    return path.resolve(process.cwd(), "storage", "events_org.db");
  }
  if (process.env.NODE_ENV === "test" && process.env.SQLITE_DB) {
    const rawPath = process.env.SQLITE_DB;
    return path.isAbsolute(rawPath) ? rawPath : path.resolve(process.cwd(), rawPath);
  }
  throw new Error("Invalid MODE. Expected 'demo' or 'organization'. Got: " + mode);
}

export function getAbsoluteCoreDbPath(): string {
  return path.resolve(process.cwd(), "storage", "core.db");
}

export function getActiveDatabase(): string {
  return getActiveTelemetryDatabase();
}

export function getAbsoluteDbPath(): string {
  return getAbsoluteTelemetryDbPath();
}

const TELEMETRY_DB_PATH = getAbsoluteTelemetryDbPath();
const CORE_DB_PATH = getAbsoluteCoreDbPath();

const DB_DIR = path.dirname(CORE_DB_PATH);

// Ensure storage directory exists
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

// Establish core and telemetry SQLite connections
const coreDbConn = new sqlite3.Database(CORE_DB_PATH, (err) => {
  if (err) {
    console.error(`Failed to connect to core SQLite ${path.basename(CORE_DB_PATH)}:`, err);
  } else {
    coreDbConn.run("PRAGMA journal_mode=WAL;");
    coreDbConn.run("PRAGMA synchronous=NORMAL;");
    coreDbConn.run("PRAGMA foreign_keys=ON;");
    coreDbConn.run("PRAGMA busy_timeout = 30000;");
  }
});

const telemetryDbConn = new sqlite3.Database(TELEMETRY_DB_PATH, (err) => {
  if (err) {
    console.error(`Failed to connect to telemetry SQLite ${path.basename(TELEMETRY_DB_PATH)}:`, err);
  } else {
    telemetryDbConn.run("PRAGMA journal_mode=WAL;");
    telemetryDbConn.run("PRAGMA synchronous=NORMAL;");
    telemetryDbConn.run("PRAGMA foreign_keys=ON;");
    telemetryDbConn.run("PRAGMA busy_timeout = 30000;");
  }
});

// Telemetry tables for routing
const TELEMETRY_TABLES = ["events", "anomalies", "incidents", "notifications", "agent_logs"];

function getDbConn(sql: string): sqlite3.Database {
  const sqlLower = sql.toLowerCase();
  for (const table of TELEMETRY_TABLES) {
    if (new RegExp(`\\b${table}\\b`).test(sqlLower)) {
      return telemetryDbConn;
    }
  }
  return coreDbConn;
}

// SQLite interface wrapper executing insertions
export const dbRun = (sql: string, params: any[] = []): Promise<{ lastID: number; changes: number }> => {
  return new Promise((resolve, reject) => {
    const db = getDbConn(sql);
    db.run(sql, params, function (err) {
      if (err) {
        reject(err);
      } else {
        resolve({ lastID: this.lastID, changes: this.changes });
      }
    });
  });
};

// SQLite interface wrapper executing batch queries
export const dbAll = <T = any>(sql: string, params: any[] = []): Promise<T[]> => {
  return new Promise((resolve, reject) => {
    const db = getDbConn(sql);
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows as T[]);
      }
    });
  });
};

// SQLite interface wrapper executing batch queries on a read-only database connection
export const dbAllReadOnly = <T = any>(sql: string, params: any[] = []): Promise<T[]> => {
  return new Promise((resolve, reject) => {
    const isTelemetry = getDbConn(sql) === telemetryDbConn;
    const dbPath = isTelemetry ? TELEMETRY_DB_PATH : CORE_DB_PATH;
    const roDb = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
      if (err) {
        reject(err);
        return;
      }
      roDb.run("PRAGMA busy_timeout = 30000;", (pragmaErr) => {
        if (pragmaErr) {
          roDb.close();
          reject(pragmaErr);
          return;
        }
        roDb.all(sql, params, (queryErr, rows) => {
          roDb.close();
          if (queryErr) {
            reject(queryErr);
          } else {
            resolve(rows as T[]);
          }
        });
      });
    });
  });
};

// SQLite interface wrapper executing single queries
export const dbGet = <T = any>(sql: string, params: any[] = []): Promise<T | undefined> => {
  return new Promise((resolve, reject) => {
    const db = getDbConn(sql);
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row as T | undefined);
      }
    });
  });
};


// SQLite Schema initialization
export async function initServerDb(): Promise<void> {
  const initCore = (): Promise<void> => {
    return new Promise((resolve, reject) => {
      coreDbConn.serialize(() => {
        // 1. Organizations Table (multi-tenant)
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at REAL DEFAULT (strftime('%s','now')),
            status TEXT DEFAULT 'active'
          )
        `, (err) => { if (err) return reject(err); });

        // 2. Users Table (JWT + bcrypt)
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('super_admin','org_admin','soc_analyst','executive_viewer','demo_admin','demo_analyst','demo_viewer')),
            organization_id INTEGER DEFAULT NULL,
            email TEXT DEFAULT '',
            mode TEXT DEFAULT 'org' CHECK(mode IN ('demo','org')),
            created_at REAL DEFAULT (strftime('%s','now')),
            last_login REAL DEFAULT NULL,
            status TEXT DEFAULT 'active',
            FOREIGN KEY(organization_id) REFERENCES organizations(id)
          )
        `, (err) => { if (err) return reject(err); });

        // 7. Audit Logs Table
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT NULL,
            username TEXT DEFAULT 'system',
            action TEXT NOT NULL,
            resource TEXT DEFAULT '',
            details TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            timestamp REAL DEFAULT (strftime('%s','now')),
            organization_id INTEGER DEFAULT 1
          )
        `, (err) => { if (err) return reject(err); });

        // 9. Connectors Table (database connector framework)
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS connectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            db_type TEXT NOT NULL CHECK(db_type IN ('sqlite','postgresql','mysql','sqlserver','mongodb')),
            host TEXT DEFAULT 'localhost',
            port INTEGER DEFAULT 5432,
            username TEXT DEFAULT '',
            password_encrypted TEXT DEFAULT '',
            database_name TEXT DEFAULT '',
            connection_string TEXT DEFAULT '',
            status TEXT DEFAULT 'disconnected' CHECK(status IN ('connected','disconnected','error')),
            organization_id INTEGER DEFAULT 1,
            created_at REAL DEFAULT (strftime('%s','now')),
            last_tested REAL DEFAULT NULL
          )
        `, (err) => { if (err) return reject(err); });

        // 10. Connector Schemas Cache (discovered tables/collections)
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS connector_schemas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id INTEGER NOT NULL,
            schema_name TEXT DEFAULT '',
            table_name TEXT NOT NULL,
            columns TEXT DEFAULT '[]',
            row_count INTEGER DEFAULT 0,
            discovered_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY(connector_id) REFERENCES connectors(id)
          )
        `, (err) => { if (err) return reject(err); });

        // 11. Event Mappings (normalization rules per connector)
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS event_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id INTEGER NOT NULL,
            source_table TEXT NOT NULL,
            field_event_id TEXT DEFAULT '',
            field_timestamp TEXT DEFAULT '',
            field_source TEXT DEFAULT '',
            field_event_type TEXT DEFAULT '',
            field_user TEXT DEFAULT '',
            field_source_ip TEXT DEFAULT '',
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY(connector_id) REFERENCES connectors(id)
          )
        `, (err) => { if (err) return reject(err); });

        // 12. Demo Sessions (track replay sessions)
        coreDbConn.run(`
          CREATE TABLE IF NOT EXISTS demo_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sample_file TEXT DEFAULT '',
            events_count INTEGER DEFAULT 0,
            replay_status TEXT DEFAULT 'idle' CHECK(replay_status IN ('idle','replaying','completed','error')),
            started_at REAL DEFAULT (strftime('%s','now')),
            completed_at REAL DEFAULT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
          )
        `, (err) => {
          if (err) return reject(err);
          console.log(`Core metadata database schemas configured.`);
          resolve();
        });
      });
    });
  };

  const initTelemetry = (): Promise<void> => {
    return new Promise((resolve, reject) => {
      telemetryDbConn.serialize(() => {
        // 3. Events Table
        telemetryDbConn.run(`
          CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            order_id TEXT,
            timestamp REAL,
            source TEXT,
            organization_id INTEGER DEFAULT 1,
            formatted_time TEXT GENERATED ALWAYS AS (datetime(timestamp, 'unixepoch'))
          )
        `, (err) => { if (err) return reject(err); });

        // 4. Anomalies Table
        telemetryDbConn.run(`
          CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            z_score REAL,
            window_mean REAL,
            window_std REAL,
            event_count INTEGER,
            status TEXT DEFAULT 'Pending Mitigation',
            diagnosis TEXT DEFAULT 'No analysis yet.',
            severity TEXT DEFAULT 'MEDIUM' CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            iforest_score REAL DEFAULT 0,
            ewma_score REAL DEFAULT 0,
            hybrid_score REAL DEFAULT 0,
            detection_method TEXT DEFAULT 'ZSCORE',
            source_entropy REAL DEFAULT 0,
            burst_ratio REAL DEFAULT 0,
            organization_id INTEGER DEFAULT 1,
            possible_threat TEXT DEFAULT '',
            threat_confidence REAL DEFAULT 0,
            recommendation TEXT DEFAULT '',
            formatted_time TEXT GENERATED ALWAYS AS (datetime(timestamp, 'unixepoch'))
          )
        `, (err) => { if (err) return reject(err); });

        // 5. Agent Trace Logs Table
        telemetryDbConn.run(`
          CREATE TABLE IF NOT EXISTS agent_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id INTEGER,
            timestamp REAL,
            step INTEGER,
            type TEXT,
            content TEXT,
            formatted_time TEXT GENERATED ALWAYS AS (datetime(timestamp, 'unixepoch')),
            FOREIGN KEY(anomaly_id) REFERENCES anomalies(id)
          )
        `, (err) => { if (err) return reject(err); });

        // 6. Incidents Table (incident management)
        telemetryDbConn.run(`
          CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id INTEGER DEFAULT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'OPEN' CHECK(status IN ('OPEN','INVESTIGATING','MITIGATED','CLOSED')),
            severity TEXT DEFAULT 'MEDIUM' CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            detection_time REAL,
            root_cause TEXT DEFAULT '',
            ai_diagnosis TEXT DEFAULT '',
            analyst_notes TEXT DEFAULT '',
            resolution TEXT DEFAULT '',
            recommended_action TEXT DEFAULT '',
            assigned_to INTEGER DEFAULT NULL,
            created_by INTEGER DEFAULT NULL,
            organization_id INTEGER DEFAULT 1,
            possible_threat TEXT DEFAULT '',
            threat_confidence REAL DEFAULT 0,
            recommendation TEXT DEFAULT '',
            gemini_summary TEXT DEFAULT '',
            discord_message_id TEXT DEFAULT NULL,
            discord_channel_id TEXT DEFAULT NULL,
            mitigation_summary TEXT DEFAULT '',
            agent_summary TEXT DEFAULT '',
            resolution_status TEXT DEFAULT '',
            created_at REAL DEFAULT (strftime('%s','now')),
            updated_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY(anomaly_id) REFERENCES anomalies(id)
          )
        `, (err) => { if (err) return reject(err); });

        // 8. Notifications Table
        telemetryDbConn.run(`
          CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL CHECK(type IN ('discord','email','slack','teams','telegram')),
            channel TEXT DEFAULT '',
            message TEXT NOT NULL,
            status TEXT DEFAULT 'sent' CHECK(status IN ('sent','failed','pending')),
            anomaly_id INTEGER DEFAULT NULL,
            incident_id INTEGER DEFAULT NULL,
            organization_id INTEGER DEFAULT 1,
            created_at REAL DEFAULT (strftime('%s','now'))
          )
        `, (err) => { if (err) return reject(err); });

        // Conditionally create enterprise sandbox tables only in Organization Mode
        if (process.env.MODE === "organization") {
          const sandboxTables = [
            "authentication_logs",
            "firewall_logs",
            "vpn_logs",
            "network_events",
            "application_logs"
          ];
          sandboxTables.forEach((tbl, idx) => {
            telemetryDbConn.run(`
              CREATE TABLE IF NOT EXISTS "${tbl}" (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time REAL NOT NULL,
                event_type TEXT NOT NULL,
                event_source TEXT,
                user_name TEXT,
                source_ip TEXT,
                department TEXT,
                status TEXT,
                details TEXT,
                reference_id TEXT,
                amount REAL DEFAULT 0,
                endpoint TEXT,
                http_method TEXT,
                severity_level TEXT DEFAULT 'LOW',
                table_name TEXT DEFAULT '${tbl}'
              )
            `, (err) => {
              if (err) return reject(err);
              if (idx === sandboxTables.length - 1) {
                runMigrationsAndResolve();
              }
            });
          });
        } else {
          runMigrationsAndResolve();
        }

        function runMigrationsAndResolve() {
          // Safe migrations for anomalies table
          const anomaliesCols = [
            { name: "possible_threat", type: "TEXT DEFAULT ''" },
            { name: "threat_confidence", type: "REAL DEFAULT 0" },
            { name: "recommendation", type: "TEXT DEFAULT ''" }
          ];
          for (const col of anomaliesCols) {
            telemetryDbConn.run(`ALTER TABLE anomalies ADD COLUMN ${col.name} ${col.type}`, (alterErr) => {});
          }

          // Safe migrations for incidents table
          const incidentsCols = [
            { name: "possible_threat", type: "TEXT DEFAULT ''" },
            { name: "threat_confidence", type: "REAL DEFAULT 0" },
            { name: "recommendation", type: "TEXT DEFAULT ''" },
            { name: "gemini_summary", type: "TEXT DEFAULT ''" },
            { name: "discord_message_id", type: "TEXT DEFAULT NULL" },
            { name: "discord_channel_id", type: "TEXT DEFAULT NULL" },
            { name: "mitigation_summary", type: "TEXT DEFAULT ''" },
            { name: "agent_summary", type: "TEXT DEFAULT ''" },
            { name: "resolution_status", type: "TEXT DEFAULT ''" }
          ];
          for (const col of incidentsCols) {
            telemetryDbConn.run(`ALTER TABLE incidents ADD COLUMN ${col.name} ${col.type}`, (alterErr) => {});
          }

          telemetryDbConn.run("SELECT 1", (err) => {
            if (err) {
              reject(err);
            } else {
              console.log(`Telemetry database SQLite ${path.basename(TELEMETRY_DB_PATH)} configured.`);
              resolve();
            }
          });
        }
      });
    });
  };

  await initCore();
  await initTelemetry();
  await seedDefaultData();
}

// Seed default organization and users on first run
async function seedDefaultData(): Promise<void> {
  try {
    // Check if default org exists
    const org = await dbGet<{ id: number }>("SELECT id FROM organizations WHERE id = 1");
    if (!org) {
      await dbRun("INSERT INTO organizations (id, name, description) VALUES (1, 'Default Organization', 'Primary tenant organization')");
      console.log("Seeded default organization.");
    }

    // Check if any users exist
    const userCount = await dbGet<{ total: number }>("SELECT COUNT(*) as total FROM users");
    if (!userCount || userCount.total === 0) {
      const salt = bcrypt.genSaltSync(10);
      const users = [
        { username: "superadmin", password: "admin123", role: "super_admin", org_id: null, mode: "org" },
        { username: "admin", password: "admin123", role: "org_admin", org_id: 1, mode: "org" },
        { username: "analyst", password: "analyst123", role: "soc_analyst", org_id: 1, mode: "org" },
        { username: "viewer", password: "viewer123", role: "executive_viewer", org_id: 1, mode: "org" },
        { username: "demo_admin", password: "demo123", role: "demo_admin", org_id: null, mode: "demo" },
        { username: "demo_analyst", password: "demo123", role: "demo_analyst", org_id: null, mode: "demo" },
        { username: "demo_viewer", password: "demo123", role: "demo_viewer", org_id: null, mode: "demo" },
      ];
      for (const u of users) {
        const hash = bcrypt.hashSync(u.password, salt);
        await dbRun(
          "INSERT INTO users (username, password_hash, role, organization_id, mode) VALUES (?, ?, ?, ?, ?)",
          [u.username, hash, u.role, u.org_id, u.mode]
        );
      }
      console.log("Seeded 7 default users (4 org + 3 demo).");
    }
  } catch (err: any) {
    console.error("Seed data error:", err.message);
  }
}

// Keep SQLite DB clean by pruning older entries
export async function pruneOldEvents(): Promise<void> {
  let eventRetentionSec = parseInt(process.env.RETENTION_SECONDS || "600") || 600;
  if (process.env.EVENT_RETENTION_DAYS) {
    const days = parseInt(process.env.EVENT_RETENTION_DAYS);
    if (!isNaN(days)) {
      eventRetentionSec = days * 24 * 3600;
    }
  }

  let anomalyRetentionSec = 180 * 24 * 3600; // default 180 days
  if (process.env.ANOMALY_RETENTION_DAYS) {
    const days = parseInt(process.env.ANOMALY_RETENTION_DAYS);
    if (!isNaN(days)) {
      anomalyRetentionSec = days * 24 * 3600;
    }
  }

  let incidentRetentionSec = 365 * 24 * 3600; // default 365 days
  if (process.env.INCIDENT_RETENTION_DAYS) {
    const days = parseInt(process.env.INCIDENT_RETENTION_DAYS);
    if (!isNaN(days)) {
      incidentRetentionSec = days * 24 * 3600;
    }
  }

  const nowSec = Date.now() / 1000;
  const eventCutoff = nowSec - eventRetentionSec;
  const anomalyCutoff = nowSec - anomalyRetentionSec;
  const incidentCutoff = nowSec - incidentRetentionSec;

  try {
    const resEvents = await dbRun("DELETE FROM events WHERE timestamp < ?", [eventCutoff]);
    if (resEvents && resEvents.changes && resEvents.changes > 0) {
      console.log(`Pruned ${resEvents.changes} historical events to optimize SQLite storage.`);
    }

    const resAnomalies = await dbRun("DELETE FROM anomalies WHERE timestamp < ?", [anomalyCutoff]);
    if (resAnomalies && resAnomalies.changes && resAnomalies.changes > 0) {
      console.log(`Pruned ${resAnomalies.changes} historical anomalies.`);
    }

    const resIncidents = await dbRun("DELETE FROM incidents WHERE detection_time < ?", [incidentCutoff]);
    if (resIncidents && resIncidents.changes && resIncidents.changes > 0) {
      console.log(`Pruned ${resIncidents.changes} historical incidents.`);
    }
  } catch (err: any) {
    console.error("Failed to prune SQLite historical entries:", err.message);
  }
}
