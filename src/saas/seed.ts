/**
 * Aegis Phase 3A — SuperAdmin Bootstrap Seed Script
 * Creates default SuperAdmin from environment variables on first deployment.
 * Run: npx tsx src/saas/seed.ts
 */

import "dotenv/config";
import bcrypt from "bcryptjs";
import { getPrismaClient, isPostgresConnected } from "./prisma_client.js";

export async function seedSuperAdmin(): Promise<void> {
  if (process.env.MODE === "demo") {
    console.log("[Seed] Skipping SuperAdmin PostgreSQL seeding in Demo Mode.");
    return;
  }

  const connected = await isPostgresConnected();
  if (!connected) {
    console.warn("[Seed] PostgreSQL unavailable. Skipping SuperAdmin seed.");
    return;
  }

  const prisma = getPrismaClient();

  // Check if any SuperAdmin already exists
  const existingAdmin = await prisma.user.findFirst({
    where: { role: "super_admin" },
  });

  if (existingAdmin) {
    console.log("[Seed] SuperAdmin already exists. Skipping seed.");
    return;
  }

  // Read credentials from environment variables — NEVER hardcode
  const email = process.env.SUPERADMIN_EMAIL;
  const password = process.env.SUPERADMIN_PASSWORD;

  if (!email || !password) {
    console.warn("[Seed] SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD not set. Skipping seed.");
    console.warn("[Seed] Set these in your .env file to auto-create a SuperAdmin.");
    return;
  }

  if (password.length < 8) {
    console.error("[Seed] SUPERADMIN_PASSWORD must be at least 8 characters. Skipping seed.");
    return;
  }

  // Create default organization if none exists
  let defaultOrg = await prisma.organization.findFirst({ orderBy: { id: "asc" } });
  if (!defaultOrg) {
    defaultOrg = await prisma.organization.create({
      data: {
        name: "Default Organization",
        slug: "default",
      },
    });
    console.log("[Seed] Created default organization.");
  }

  // Create SuperAdmin
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);

  const admin = await prisma.user.create({
    data: {
      email: email.toLowerCase().trim(),
      password_hash: hash,
      first_name: "Super",
      last_name: "Admin",
      role: "super_admin",
      is_active: true,
      email_verified: true, // Auto-verify the SuperAdmin
    } as any,
  });

  console.log(`[Seed] SuperAdmin created: ${admin.email} (ID: ${admin.id})`);

  // Create audit log entry
  await prisma.auditLog.create({
    data: {
      user_id: admin.id,
      action: "SEED_SUPERADMIN",
      resource: "system",
      ip_address: "system",
    },
  });
}

// Allow running directly: npx tsx src/saas/seed.ts
if (process.argv[1]?.includes("seed")) {
  seedSuperAdmin()
    .then(() => {
      console.log("[Seed] Done.");
      process.exit(0);
    })
    .catch((err) => {
      console.error("[Seed] Failed:", err);
      process.exit(1);
    });
}
