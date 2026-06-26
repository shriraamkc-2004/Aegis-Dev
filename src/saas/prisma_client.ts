/**
 * Aegis Phase 3A — Prisma Client Singleton
 * Provides a shared PrismaClient instance for PostgreSQL SaaS operations.
 * Falls back gracefully when PostgreSQL is unreachable (SQLite continues independently).
 *
 * Prisma 7.x: uses @prisma/adapter-pg driver adapter instead of datasource URL.
 */

import { PrismaClient } from "../generated/prisma/index.js";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";

let prismaInstance: PrismaClient | null = null;

function buildDatabaseUrl(): string {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
  const host = process.env.POSTGRES_HOST || "localhost";
  const port = process.env.POSTGRES_PORT || "5432";
  const db = process.env.POSTGRES_DB || "aegis_enterprise";
  const user = process.env.POSTGRES_USER || "aegis";
  const password = process.env.POSTGRES_PASSWORD || "aegis_secret";
  return `postgresql://${user}:${password}@${host}:${port}/${db}?schema=public`;
}

export function getPrismaClient(): PrismaClient {
  if (!prismaInstance) {
    const connStr = buildDatabaseUrl();
    console.log("PRISMA CLIENT: Connecting to", connStr);
    const pool = new pg.Pool({ connectionString: connStr });
    const adapter = new PrismaPg(pool);
    console.log("PRISMA CLIENT: Created adapter:", adapter ? typeof adapter : "undefined", adapter);
    prismaInstance = new PrismaClient({
      adapter,
      log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
    });
  }
  return prismaInstance;
}

/**
 * Test PostgreSQL connectivity. Returns true if connected, false otherwise.
 * Used by health monitor and startup checks.
 */
export async function isPostgresConnected(): Promise<boolean> {
  try {
    const prisma = getPrismaClient();
    await prisma.$queryRawUnsafe("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

/**
 * Gracefully disconnect Prisma on shutdown.
 */
export async function disconnectPrisma(): Promise<void> {
  if (prismaInstance) {
    await prismaInstance.$disconnect();
    prismaInstance = null;
  }
}
