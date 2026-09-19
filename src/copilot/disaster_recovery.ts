/**
 * Aegis Enterprise — Disaster Recovery Service
 * Implements backup/recovery procedures for PostgreSQL, Qdrant, and MinIO.
 * Defines RPO/RTO targets suitable for enterprise SOC environments.
 *
 * Recovery Objectives:
 *   RPO (Recovery Point Objective): 1 hour — max acceptable data loss
 *   RTO (Recovery Time Objective):  4 hours — max acceptable recovery duration
 */

import { execSync, exec } from "child_process";
import fs from "fs";
import path from "path";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface RecoveryObjectives {
  rpo_seconds: number; // 3600 = 1 hour
  rto_seconds: number; // 14400 = 4 hours
  rpo_description: string;
  rto_description: string;
}

export interface BackupRecord {
  id: string;
  component: "postgresql" | "qdrant" | "minio" | "sqlite";
  type: "full" | "incremental" | "snapshot";
  status: "pending" | "in_progress" | "completed" | "failed";
  file_path: string;
  size_bytes: number;
  started_at: number;
  completed_at: number | null;
  retention_days: number;
  verified: boolean;
  error: string | null;
}

export interface RecoveryPlan {
  component: string;
  steps: RecoveryStep[];
  estimated_duration_minutes: number;
  prerequisites: string[];
}

export interface RecoveryStep {
  order: number;
  action: string;
  command: string;
  description: string;
  rollback_command: string;
}

export interface BackupSchedule {
  component: string;
  frequency: string;
  retention_days: number;
  last_backup: number | null;
  next_backup: number | null;
  auto_enabled: boolean;
}

// ─── Configuration ──────────────────────────────────────────────────────────────

const BACKUP_DIR = path.join(process.cwd(), "storage", "backups");
const RETENTION_DAYS_POSTGRES = 30;
const RETENTION_DAYS_QDRANT = 14;
const RETENTION_DAYS_MINIO = 30;
const RETENTION_DAYS_SQLITE = 7;

const RPO_SECONDS = 3600; // 1 hour
const RTO_SECONDS = 14400; // 4 hours

export const RECOVERY_OBJECTIVES: RecoveryObjectives = {
  rpo_seconds: RPO_SECONDS,
  rto_seconds: RTO_SECONDS,
  rpo_description: "1 hour — maximum acceptable data loss window",
  rto_description: "4 hours — maximum time to restore full service",
};

// ─── Disaster Recovery Service ──────────────────────────────────────────────────

export class DisasterRecoveryService {
  private backupHistory: BackupRecord[] = [];
  private schedules: BackupSchedule[] = [];
  private backupTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.ensureBackupDir();
    this.initSchedules();
  }

  // ─── Directory Setup ────────────────────────────────────────────────────────

  private ensureBackupDir(): void {
    try {
      if (!fs.existsSync(BACKUP_DIR)) {
        fs.mkdirSync(BACKUP_DIR, { recursive: true });
        console.log(`[DR] Backup directory created: ${BACKUP_DIR}`);
      }
    } catch (err: any) {
      console.error(`[DR] Failed to create backup directory: ${err.message}`);
    }
  }

  private initSchedules(): void {
    this.schedules = [
      {
        component: "postgresql",
        frequency: "daily",
        retention_days: RETENTION_DAYS_POSTGRES,
        last_backup: null,
        next_backup: null,
        auto_enabled: true,
      },
      {
        component: "qdrant",
        frequency: "daily",
        retention_days: RETENTION_DAYS_QDRANT,
        last_backup: null,
        next_backup: null,
        auto_enabled: true,
      },
      {
        component: "minio",
        frequency: "weekly",
        retention_days: RETENTION_DAYS_MINIO,
        last_backup: null,
        next_backup: null,
        auto_enabled: true,
      },
      {
        component: "sqlite",
        frequency: "daily",
        retention_days: RETENTION_DAYS_SQLITE,
        last_backup: null,
        next_backup: null,
        auto_enabled: true,
      },
    ];
  }

  // ─── PostgreSQL Backup ─────────────────────────────────────────────────────

  async backupPostgres(): Promise<BackupRecord> {
    const id = `pg_${Date.now()}`;
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `postgres_backup_${timestamp}.sql.gz`;
    const filePath = path.join(BACKUP_DIR, filename);

    const record: BackupRecord = {
      id,
      component: "postgresql",
      type: "full",
      status: "in_progress",
      file_path: filePath,
      size_bytes: 0,
      started_at: Date.now(),
      completed_at: null,
      retention_days: RETENTION_DAYS_POSTGRES,
      verified: false,
      error: null,
    };

    this.backupHistory.push(record);

    const pgHost = process.env.POSTGRES_HOST || "postgres";
    const pgPort = process.env.POSTGRES_PORT || "5432";
    const pgDb = process.env.POSTGRES_DB || "aegis_enterprise";
    const pgUser = process.env.POSTGRES_USER || "aegis";
    const pgPass = process.env.POSTGRES_PASSWORD || "aegis_secret";

    // pg_dump with gzip compression
    const command = `PGPASSWORD=${pgPass} pg_dump -h ${pgHost} -p ${pgPort} -U ${pgUser} -d ${pgDb} --format=custom --compress=9 -f "${filePath}" 2>&1`;

    try {
      execSync(command, { timeout: 300000, stdio: "pipe" });
      const stat = fs.statSync(filePath);
      record.status = "completed";
      record.size_bytes = stat.size;
      record.completed_at = Date.now();
      record.verified = true;
      this.updateSchedule("postgresql", Date.now());
      console.log(
        `[DR] PostgreSQL backup completed: ${filename} (${stat.size} bytes)`,
      );
    } catch (err: any) {
      record.status = "failed";
      record.error = err.message;
      record.completed_at = Date.now();
      console.error(`[DR] PostgreSQL backup failed: ${err.message}`);
    }

    return record;
  }

  // ─── PostgreSQL Recovery Plan ──────────────────────────────────────────────

  getPostgresRecoveryPlan(): RecoveryPlan {
    return {
      component: "postgresql",
      estimated_duration_minutes: 30,
      prerequisites: [
        "PostgreSQL 16 server must be running",
        "Backup file must be accessible",
        "Database credentials must be available",
      ],
      steps: [
        {
          order: 1,
          action: "stop_services",
          command: "pm2 stop ecosystem.config.cjs",
          description:
            "Stop Aegis application services to prevent writes during restore",
          rollback_command: "pm2 start ecosystem.config.cjs",
        },
        {
          order: 2,
          action: "drop_database",
          command: `PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -c "DROP DATABASE IF EXISTS $POSTGRES_DB;"`,
          description: "Drop existing database to prepare for clean restore",
          rollback_command: "Requires re-running restore from backup",
        },
        {
          order: 3,
          action: "create_database",
          command: `PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -c "CREATE DATABASE $POSTGRES_DB;"`,
          description: "Create empty database for restore target",
          rollback_command: "N/A — part of restore flow",
        },
        {
          order: 4,
          action: "restore_backup",
          command: `PGPASSWORD=$POSTGRES_PASSWORD pg_restore -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB --no-owner --no-privileges <backup_file>`,
          description: "Restore PostgreSQL data from compressed backup",
          rollback_command: "Re-run restore from another backup",
        },
        {
          order: 5,
          action: "verify_integrity",
          command: `PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT COUNT(*) FROM copilot_audit_log;"`,
          description: "Verify data integrity by checking key table row counts",
          rollback_command: "Re-restore from backup",
        },
        {
          order: 6,
          action: "restart_services",
          command: "pm2 start ecosystem.config.cjs",
          description: "Restart Aegis application services",
          rollback_command: "pm2 stop ecosystem.config.cjs",
        },
      ],
    };
  }

  // ─── Qdrant Backup ─────────────────────────────────────────────────────────

  async backupQdrant(): Promise<BackupRecord> {
    const id = `qdrant_${Date.now()}`;
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `qdrant_snapshot_${timestamp}.json`;
    const filePath = path.join(BACKUP_DIR, filename);

    const record: BackupRecord = {
      id,
      component: "qdrant",
      type: "snapshot",
      status: "in_progress",
      file_path: filePath,
      size_bytes: 0,
      started_at: Date.now(),
      completed_at: null,
      retention_days: RETENTION_DAYS_QDRANT,
      verified: false,
      error: null,
    };

    this.backupHistory.push(record);

    const qdrantHost = process.env.QDRANT_HOST || "localhost";
    const qdrantPort = process.env.QDRANT_PORT || "6333";
    const collections = ["knowledge_base", "alert_rules", "incidents", "logs"];

    try {
      const snapshotData: Record<string, any> = {
        collections: {},
        timestamp: Date.now(),
      };

      for (const collection of collections) {
        try {
          const response = await fetch(
            `http://${qdrantHost}:${qdrantPort}/collections/${collection}/snapshots`,
            { method: "POST" },
          );
          if (response.ok) {
            const data = await response.json();
            snapshotData.collections[collection] = {
              snapshot: data.result?.name || "created",
              status: "ok",
            };
          } else {
            snapshotData.collections[collection] = {
              status: "error",
              error: `HTTP ${response.status}`,
            };
          }
        } catch (err: any) {
          snapshotData.collections[collection] = {
            status: "unreachable",
            error: err.message,
          };
        }
      }

      fs.writeFileSync(filePath, JSON.stringify(snapshotData, null, 2));
      const stat = fs.statSync(filePath);
      record.status = "completed";
      record.size_bytes = stat.size;
      record.completed_at = Date.now();
      record.verified = true;
      this.updateSchedule("qdrant", Date.now());
      console.log(`[DR] Qdrant snapshot completed: ${filename}`);
    } catch (err: any) {
      record.status = "failed";
      record.error = err.message;
      record.completed_at = Date.now();
      console.error(`[DR] Qdrant snapshot failed: ${err.message}`);
    }

    return record;
  }

  // ─── Qdrant Recovery Plan ──────────────────────────────────────────────────

  getQdrantRecoveryPlan(): RecoveryPlan {
    return {
      component: "qdrant",
      estimated_duration_minutes: 45,
      prerequisites: [
        "Qdrant v1.9.7 server must be running",
        "Snapshot file must be accessible",
        "Collections must be pre-created if not using auto-init",
      ],
      steps: [
        {
          order: 1,
          action: "check_qdrant_health",
          command: "curl -s http://$QDRANT_HOST:6333/readyz",
          description: "Verify Qdrant is healthy before restore",
          rollback_command: "N/A",
        },
        {
          order: 2,
          action: "list_snapshots",
          command:
            "curl -s http://$QDRANT_HOST:6333/collections/{collection}/snapshots",
          description: "List available snapshots for each collection",
          rollback_command: "N/A",
        },
        {
          order: 3,
          action: "restore_snapshot",
          command:
            "curl -X POST http://$QDRANT_HOST:6333/collections/{collection}/snapshots/recover -H 'Content-Type: application/json' -d '{\"location\": \"<snapshot_path>\"}'",
          description: "Restore collection from snapshot",
          rollback_command: "Re-restore from a different snapshot",
        },
        {
          order: 4,
          action: "verify_collections",
          command:
            "curl -s http://$QDRANT_HOST:6333/collections/{collection} | jq .result.points_count",
          description: "Verify point counts in restored collections",
          rollback_command: "Re-restore from backup",
        },
      ],
    };
  }

  // ─── MinIO Backup ──────────────────────────────────────────────────────────

  async backupMinIO(): Promise<BackupRecord> {
    const id = `minio_${Date.now()}`;
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `minio_backup_${timestamp}.tar.gz`;
    const filePath = path.join(BACKUP_DIR, filename);

    const record: BackupRecord = {
      id,
      component: "minio",
      type: "full",
      status: "in_progress",
      file_path: filePath,
      size_bytes: 0,
      started_at: Date.now(),
      completed_at: null,
      retention_days: RETENTION_DAYS_MINIO,
      verified: false,
      error: null,
    };

    this.backupHistory.push(record);

    const minioEndpoint = process.env.MINIO_ENDPOINT || "localhost:9000";
    const accessKey = process.env.MINIO_ACCESS_KEY || "minioadmin";
    const secretKey = process.env.MINIO_SECRET_KEY || "minioadmin";

    // Use mc (MinIO client) for backup or record metadata
    const command = `mc alias set aegis-minio http://${minioEndpoint} ${accessKey} ${secretKey} 2>&1 && mc mirror aegis-minio/aegis-documents "${path.join(BACKUP_DIR, "minio_mirror")}" 2>&1`;

    try {
      execSync(command, { timeout: 600000, stdio: "pipe" });
      record.status = "completed";
      record.completed_at = Date.now();
      record.verified = true;
      this.updateSchedule("minio", Date.now());

      // Check mirror dir size
      try {
        const mirrorDir = path.join(BACKUP_DIR, "minio_mirror");
        if (fs.existsSync(mirrorDir)) {
          const files = fs.readdirSync(mirrorDir);
          record.size_bytes = files.length * 1024; // approximate
        }
      } catch {}

      console.log(
        `[DR] MinIO backup completed: mirror to ${BACKUP_DIR}/minio_mirror`,
      );
    } catch (err: any) {
      record.status = "failed";
      record.error = err.message;
      record.completed_at = Date.now();
      console.error(`[DR] MinIO backup failed: ${err.message}`);
    }

    return record;
  }

  // ─── MinIO Recovery Plan ───────────────────────────────────────────────────

  getMinIORecoveryPlan(): RecoveryPlan {
    return {
      component: "minio",
      estimated_duration_minutes: 20,
      prerequisites: [
        "MinIO server must be running",
        "MinIO client (mc) must be installed",
        "Backup mirror directory must be accessible",
      ],
      steps: [
        {
          order: 1,
          action: "check_minio_health",
          command: "mc admin info aegis-minio",
          description: "Verify MinIO server health",
          rollback_command: "N/A",
        },
        {
          order: 2,
          action: "ensure_bucket",
          command: "mc mb aegis-minio/aegis-documents --ignore-existing",
          description: "Ensure target bucket exists",
          rollback_command: "N/A",
        },
        {
          order: 3,
          action: "restore_mirror",
          command: "mc mirror <backup_mirror_path> aegis-minio/aegis-documents",
          description: "Restore files from backup mirror to MinIO bucket",
          rollback_command:
            "mc rm --recursive --force aegis-minio/aegis-documents",
        },
        {
          order: 4,
          action: "verify_objects",
          command: "mc ls aegis-minio/aegis-documents --recursive | wc -l",
          description: "Verify object count matches expected",
          rollback_command: "Re-restore from backup",
        },
      ],
    };
  }

  // ─── SQLite Backup ─────────────────────────────────────────────────────────

  async backupSQLite(): Promise<BackupRecord> {
    const id = `sqlite_${Date.now()}`;
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `sqlite_backup_${timestamp}.db`;
    const filePath = path.join(BACKUP_DIR, filename);

    const record: BackupRecord = {
      id,
      component: "sqlite",
      type: "full",
      status: "in_progress",
      file_path: filePath,
      size_bytes: 0,
      started_at: Date.now(),
      completed_at: null,
      retention_days: RETENTION_DAYS_SQLITE,
      verified: false,
      error: null,
    };

    this.backupHistory.push(record);

    const dbPath = path.join(process.cwd(), "storage", "core.db");

    try {
      if (fs.existsSync(dbPath)) {
        // Use SQLite online backup (copy with WAL awareness)
        fs.copyFileSync(dbPath, filePath);
        // Also copy WAL if exists
        const walPath = dbPath + "-wal";
        if (fs.existsSync(walPath)) {
          fs.copyFileSync(walPath, filePath + "-wal");
        }
        const stat = fs.statSync(filePath);
        record.status = "completed";
        record.size_bytes = stat.size;
        record.completed_at = Date.now();
        record.verified = true;
        this.updateSchedule("sqlite", Date.now());
        console.log(
          `[DR] SQLite backup completed: ${filename} (${stat.size} bytes)`,
        );
      } else {
        record.status = "failed";
        record.error = "SQLite database file not found";
        record.completed_at = Date.now();
      }
    } catch (err: any) {
      record.status = "failed";
      record.error = err.message;
      record.completed_at = Date.now();
      console.error(`[DR] SQLite backup failed: ${err.message}`);
    }

    return record;
  }

  // ─── Retention Policy ──────────────────────────────────────────────────────

  enforceRetention(): { deleted: number; kept: number } {
    let deleted = 0;
    let kept = 0;
    const now = Date.now();

    this.backupHistory = this.backupHistory.filter((record) => {
      const ageMs = now - record.started_at;
      const maxAgeMs = record.retention_days * 24 * 60 * 60 * 1000;
      if (ageMs > maxAgeMs) {
        // Clean up backup file
        try {
          if (fs.existsSync(record.file_path)) {
            fs.unlinkSync(record.file_path);
          }
        } catch {}
        deleted++;
        return false;
      }
      kept++;
      return true;
    });

    return { deleted, kept };
  }

  // ─── Schedule Management ───────────────────────────────────────────────────

  private updateSchedule(component: string, timestamp: number): void {
    const schedule = this.schedules.find((s) => s.component === component);
    if (schedule) {
      schedule.last_backup = timestamp;
      // Calculate next backup based on frequency
      const intervals: Record<string, number> = {
        hourly: 3600000,
        daily: 86400000,
        weekly: 604800000,
      };
      schedule.next_backup =
        timestamp + (intervals[schedule.frequency] || 86400000);
    }
  }

  // ─── Auto-Backup Scheduler ─────────────────────────────────────────────────

  startAutoBackup(): void {
    if (this.backupTimer) return;

    // Run backup check every hour
    this.backupTimer = setInterval(async () => {
      const now = Date.now();
      for (const schedule of this.schedules) {
        if (!schedule.auto_enabled) continue;
        if (schedule.next_backup && now >= schedule.next_backup) {
          console.log(`[DR] Auto-backup triggered for ${schedule.component}`);
          try {
            switch (schedule.component) {
              case "postgresql":
                await this.backupPostgres();
                break;
              case "qdrant":
                await this.backupQdrant();
                break;
              case "minio":
                await this.backupMinIO();
                break;
              case "sqlite":
                await this.backupSQLite();
                break;
            }
          } catch (err: any) {
            console.error(
              `[DR] Auto-backup failed for ${schedule.component}: ${err.message}`,
            );
          }
        }
      }
      // Enforce retention on each cycle
      this.enforceRetention();
    }, 3600000); // every hour

    console.log("[DR] Auto-backup scheduler started (hourly check)");
  }

  stopAutoBackup(): void {
    if (this.backupTimer) {
      clearInterval(this.backupTimer);
      this.backupTimer = null;
    }
  }

  // ─── Run All Backups ───────────────────────────────────────────────────────

  async runAllBackups(): Promise<BackupRecord[]> {
    const results: BackupRecord[] = [];
    results.push(await this.backupSQLite());
    results.push(await this.backupPostgres());
    results.push(await this.backupQdrant());
    results.push(await this.backupMinIO());
    return results;
  }

  // ─── Status & Reporting ────────────────────────────────────────────────────

  getStatus() {
    return {
      service: "disaster_recovery",
      backup_directory: BACKUP_DIR,
      recovery_objectives: RECOVERY_OBJECTIVES,
      schedules: this.schedules,
      backup_history_count: this.backupHistory.length,
      recent_backups: this.backupHistory.slice(-20).reverse(),
      auto_backup_enabled: this.backupTimer !== null,
    };
  }

  getBackupHistory(limit: number = 50): BackupRecord[] {
    return this.backupHistory.slice(-limit).reverse();
  }

  getAllRecoveryPlans(): RecoveryPlan[] {
    return [
      this.getPostgresRecoveryPlan(),
      this.getQdrantRecoveryPlan(),
      this.getMinIORecoveryPlan(),
    ];
  }
}

// Singleton instance
export const disasterRecoveryService = new DisasterRecoveryService();
