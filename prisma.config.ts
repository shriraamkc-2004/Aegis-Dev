import "dotenv/config";
import { defineConfig } from "prisma/config";

// Construct DATABASE_URL from existing POSTGRES_* env vars if DATABASE_URL is not set
function buildDatabaseUrl(): string {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL;
  const host = process.env.POSTGRES_HOST || "localhost";
  const port = process.env.POSTGRES_PORT || "5432";
  const db = process.env.POSTGRES_DB || "aegis_enterprise";
  const user = process.env.POSTGRES_USER || "aegis";
  const password = process.env.POSTGRES_PASSWORD || "aegis_secret";
  return `postgresql://${user}:${password}@${host}:${port}/${db}?schema=public`;
}

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url: buildDatabaseUrl(),
  },
});
