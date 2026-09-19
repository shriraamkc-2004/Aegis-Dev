/**
 * Aegis Phase 3A — User Management Service
 * Full CRUD + invite, activate, deactivate, soft delete for multi-tenant users.
 */

import bcrypt from "bcryptjs";
import crypto from "crypto";
import { getPrismaClient, isPostgresConnected } from "./prisma_client.js";
import type { SaasRole } from "./auth_service.js";

// ─── Permission Matrix ──────────────────────────────────────────────────────────

const ROLE_PERMISSIONS: Record<SaasRole, string[]> = {
  super_admin: ["*"], // Full system access
  org_admin: [
    "users:manage",
    "users:list",
    "users:invite",
    "users:activate",
    "users:deactivate",
    "organization:view",
    "organization:update",
    "alerts:view",
    "alerts:configure",
  ],
  soc_analyst: [
    "alerts:investigate",
    "alerts:view",
    "copilot:use",
    "incidents:update",
  ],
  executive_viewer: ["reports:view", "reports:export", "audit_logs:view"],
  demo_admin: ["dashboard:view", "alerts:view"],
  demo_analyst: ["dashboard:view", "alerts:view"],
  demo_viewer: ["dashboard:view"],
};

export function hasPermission(role: SaasRole, permission: string): boolean {
  const perms = ROLE_PERMISSIONS[role] || [];
  return perms.includes("*") || perms.includes(permission);
}

export function getPermissions(role: SaasRole): string[] {
  return ROLE_PERMISSIONS[role] || [];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────────

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .substring(0, 100);
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// ─── Create User ──────────────────────────────────────────────────────────────────

export async function createUser(data: {
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  role: SaasRole;
  organization_id?: number | null;
}): Promise<{ success: boolean; user?: any; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const prisma = getPrismaClient();

  const existing = await prisma.user.findUnique({
    where: { email: data.email.toLowerCase().trim() },
  });
  if (existing) return { success: false, error: "Email already registered." };

  if (data.password.length < 8)
    return { success: false, error: "Password must be at least 8 characters." };

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(data.password, salt);

  const user = await prisma.user.create({
    data: {
      email: data.email.toLowerCase().trim(),
      password_hash: hash,
      first_name: data.first_name || "",
      last_name: data.last_name || "",
      role: data.role,
      organization_id: data.organization_id || null,
      email_verified: false,
      is_active: true,
    } as any,
    select: {
      id: true,
      email: true,
      first_name: true,
      last_name: true,
      role: true,
      organization_id: true,
      is_active: true,
      email_verified: true,
      created_at: true,
    },
  });

  return { success: true, user };
}

// ─── Invite User (generates invite token, sends email in production) ─────────────

export async function inviteUser(data: {
  email: string;
  first_name?: string;
  last_name?: string;
  role: SaasRole;
  organization_id: number;
  invited_by: number;
  ipAddress?: string;
}): Promise<{ success: boolean; token?: string; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const prisma = getPrismaClient();

  const existing = await prisma.user.findUnique({
    where: { email: data.email.toLowerCase().trim() },
  });
  if (existing) return { success: false, error: "Email already registered." };

  // Create user with a random password (they'll reset via invite link)
  const tempPassword = crypto.randomBytes(16).toString("hex");
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(tempPassword, salt);

  const user = await prisma.user.create({
    data: {
      email: data.email.toLowerCase().trim(),
      password_hash: hash,
      first_name: data.first_name || "",
      last_name: data.last_name || "",
      role: data.role,
      organization_id: data.organization_id,
      email_verified: false,
      is_active: true,
    } as any,
  });

  // Create a password reset token as the invite token
  const tokenRaw = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(tokenRaw);

  await prisma.passwordResetToken.create({
    data: {
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    },
  });

  // Dev mode: log invitation notice without leaking secret token
  if (process.env.NODE_ENV !== "production") {
    console.log(`[Invite] User invitation created`);
  }

  await prisma.auditLog.create({
    data: {
      user_id: data.invited_by,
      organization_id: data.organization_id,
      action: "INVITE_USER",
      resource: "users",
      ip_address: data.ipAddress || "",
    },
  });

  return { success: true };
}

// ─── List Users ───────────────────────────────────────────────────────────────────

export async function listUsers(
  organizationId: number | null,
  isSuperAdmin: boolean,
): Promise<any[]> {
  const connected = await isPostgresConnected();
  if (!connected) return [];

  const prisma = getPrismaClient();

  if (isSuperAdmin) {
    return prisma.user.findMany({
      select: {
        id: true,
        email: true,
        first_name: true,
        last_name: true,
        role: true,
        organization_id: true,
        is_active: true,
        email_verified: true,
        created_at: true,
        updated_at: true,
        organization: { select: { name: true, slug: true } },
      },
      orderBy: { id: "asc" },
    });
  }

  return prisma.user.findMany({
    where: { organization_id: organizationId },
    select: {
      id: true,
      email: true,
      first_name: true,
      last_name: true,
      role: true,
      organization_id: true,
      is_active: true,
      email_verified: true,
      created_at: true,
      updated_at: true,
    },
    orderBy: { id: "asc" },
  });
}

// ─── Get User ─────────────────────────────────────────────────────────────────────

export async function getUser(userId: number): Promise<any | null> {
  const connected = await isPostgresConnected();
  if (!connected) return null;

  const prisma = getPrismaClient();
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      first_name: true,
      last_name: true,
      role: true,
      organization_id: true,
      is_active: true,
      email_verified: true,
      created_at: true,
      updated_at: true,
      organization: { select: { id: true, name: true, slug: true } },
    },
  });
}

// ─── Update User ──────────────────────────────────────────────────────────────────

export async function updateUser(
  userId: number,
  data: {
    first_name?: string;
    last_name?: string;
    role?: SaasRole;
    organization_id?: number | null;
  },
  updatedBy: number,
  ipAddress?: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return { success: false, error: "User not found." };

  await prisma.user.update({
    where: { id: userId },
    data: {
      ...(data.first_name !== undefined && { first_name: data.first_name }),
      ...(data.last_name !== undefined && { last_name: data.last_name }),
      ...(data.role !== undefined && { role: data.role }),
      ...(data.organization_id !== undefined && {
        organization_id: data.organization_id,
      }),
    } as any,
  });

  await prisma.auditLog.create({
    data: {
      user_id: updatedBy,
      organization_id: user.organization_id,
      action: "UPDATE_USER",
      resource: "users",
      ip_address: ipAddress || "",
    },
  });

  return { success: true };
}

// ─── Activate User ────────────────────────────────────────────────────────────────

export async function activateUser(
  userId: number,
  activatedBy: number,
  ipAddress?: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const prisma = getPrismaClient();
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return { success: false, error: "User not found." };
  if (user.is_active)
    return { success: false, error: "User is already active." };

  await prisma.user.update({
    where: { id: userId },
    data: { is_active: true },
  });

  await prisma.auditLog.create({
    data: {
      user_id: activatedBy,
      organization_id: user.organization_id,
      action: "ACTIVATE_USER",
      resource: "users",
      ip_address: ipAddress || "",
    },
  });

  return { success: true };
}

// ─── Deactivate User ──────────────────────────────────────────────────────────────

export async function deactivateUser(
  userId: number,
  deactivatedBy: number,
  ipAddress?: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const prisma = getPrismaClient();
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return { success: false, error: "User not found." };
  if (!user.is_active)
    return { success: false, error: "User is already deactivated." };
  if (user.role === "super_admin")
    return { success: false, error: "Cannot deactivate a SuperAdmin." };

  await prisma.user.update({
    where: { id: userId },
    data: { is_active: false },
  });

  // Invalidate all refresh tokens
  await prisma.refreshToken.deleteMany({ where: { user_id: userId } });

  await prisma.auditLog.create({
    data: {
      user_id: deactivatedBy,
      organization_id: user.organization_id,
      action: "DEACTIVATE_USER",
      resource: "users",
      ip_address: ipAddress || "",
    },
  });

  return { success: true };
}

// ─── Soft Delete User ─────────────────────────────────────────────────────────────

export async function deleteUser(
  userId: number,
  deletedBy: number,
  ipAddress?: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const prisma = getPrismaClient();
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return { success: false, error: "User not found." };
  if (user.role === "super_admin")
    return { success: false, error: "Cannot delete a SuperAdmin." };

  // Soft delete: deactivate + anonymize email
  await prisma.user.update({
    where: { id: userId },
    data: {
      is_active: false,
      email: `deleted_${userId}_${Date.now()}@deleted.local`,
      first_name: "Deleted",
      last_name: "User",
      password_hash: "DELETED",
    },
  });

  // Invalidate all tokens
  await prisma.refreshToken.deleteMany({ where: { user_id: userId } });
  await prisma.passwordResetToken.deleteMany({ where: { user_id: userId } });
  await prisma.emailVerificationToken.deleteMany({
    where: { user_id: userId },
  });

  await prisma.auditLog.create({
    data: {
      user_id: deletedBy,
      organization_id: user.organization_id,
      action: "DELETE_USER",
      resource: "users",
      ip_address: ipAddress || "",
    },
  });

  return { success: true };
}
