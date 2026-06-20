import pg from 'pg';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';

const { Pool } = pg;

const pgUrl = process.env.PG_URL || "postgresql://aegis_user:aegis_pass@localhost:5432/aegis_db";

export const pgPool = new Pool({
  connectionString: pgUrl,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

export async function pgQuery<T = any>(text: string, params: any[] = []): Promise<pg.QueryResult<T>> {
  const start = Date.now();
  try {
    const res = await pgPool.query(text, params);
    const duration = Date.now() - start;
    return res;
  } catch (err: any) {
    console.error('[Postgres Query Error]', err.message);
    throw err;
  }
}

export async function initPgDb() {
  console.log("[Postgres Startup] Connecting to PostgreSQL database...");
  try {
    // Probe database connection
    await pgQuery("SELECT 1");
  } catch (err: any) {
    console.warn("[Postgres Warning] Could not connect to PostgreSQL. Enterprise Copilot features may degrade. Error:", err.message);
    return;
  }

  try {
    const migrationPath = path.resolve(process.cwd(), "db", "pg_migrations", "001_init_schemas.sql");
    if (fs.existsSync(migrationPath)) {
      const sql = fs.readFileSync(migrationPath, "utf-8");
      // Execute the migration DDL file
      await pgQuery(sql);
      console.log("[Postgres Startup] Database schema initialized successfully via migration script.");
    } else {
      console.error("[Postgres Startup Error] Migration file not found at:", migrationPath);
    }

    // Seed default users if users table is empty
    const adminCheck = await pgQuery("SELECT COUNT(*) as count FROM users");
    const count = parseInt(adminCheck.rows[0].count || "0");
    if (count === 0) {
      const adminHash = await bcrypt.hash("admin123", 10);
      await pgQuery(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
        ["admin@aegis.com", adminHash, "Admin"]
      );
      console.log("[Postgres Startup] Seeded default Admin user: admin@aegis.com / admin123");

      const analystHash = await bcrypt.hash("analyst123", 10);
      await pgQuery(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
        ["analyst@aegis.com", analystHash, "SOC Analyst"]
      );
      console.log("[Postgres Startup] Seeded default Analyst user: analyst@aegis.com / analyst123");

      const auditorHash = await bcrypt.hash("auditor123", 10);
      await pgQuery(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
        ["auditor@aegis.com", auditorHash, "Auditor"]
      );
      console.log("[Postgres Startup] Seeded default Auditor user: auditor@aegis.com / auditor123");

      const viewerHash = await bcrypt.hash("viewer123", 10);
      await pgQuery(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)",
        ["viewer@aegis.com", viewerHash, "Viewer"]
      );
      console.log("[Postgres Startup] Seeded default Viewer user: viewer@aegis.com / viewer123");
    }
  } catch (err: any) {
    console.error("[Postgres Startup Error] Schema initialization failed:", err.message);
  }
}
export default pgPool;
