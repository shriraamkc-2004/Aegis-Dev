/**
 * Aegis Phase 3A — Organization Management Service
 * CRUD operations for multi-tenant organizations.
 */

import bcrypt from "bcryptjs";
import { isPostgresConnected, getPrismaClient } from "./prisma_client.js";
import { OrganizationRepository } from "../repositories/index.js";
import {
  sendWelcomeEmail,
  sendEmailVerification,
} from "../services/email_service.js";

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .substring(0, 100);
}

// ─── Create Organization ──────────────────────────────────────────────────────────

export async function createOrganization(data: {
  name: string;
  slug?: string;
}): Promise<{ success: boolean; organization?: any; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const slug = data.slug || slugify(data.name);

  const existing = await OrganizationRepository.findBySlug(slug);
  if (existing)
    return { success: false, error: "Organization slug already exists." };

  const org = await OrganizationRepository.create({ name: data.name, slug });

  return { success: true, organization: org };
}

// ─── Self-Registration (Public SaaS Signup) ───────────────────────────────────

/**
 * Allows a new company to sign up for Aegis without a super_admin.
 * Creates the organization and the initial org_admin user atomically.
 * On success, dispatches a welcome email and email verification.
 */
export async function selfRegisterOrganization(data: {
  orgName: string;
  adminFirstName: string;
  adminLastName: string;
  adminEmail: string;
  adminPassword: string;
}): Promise<{
  success: boolean;
  organization?: any;
  user?: any;
  error?: string;
}> {
  const connected = await isPostgresConnected();
  if (!connected)
    return {
      success: false,
      error: "Database unavailable. Please try again shortly.",
    };

  if (!data.orgName || data.orgName.trim().length < 2) {
    return {
      success: false,
      error: "Organization name must be at least 2 characters.",
    };
  }
  if (!data.adminEmail || !data.adminEmail.includes("@")) {
    return { success: false, error: "A valid admin email is required." };
  }
  if (!data.adminPassword || data.adminPassword.length < 8) {
    return { success: false, error: "Password must be at least 8 characters." };
  }

  const prisma = getPrismaClient();
  const slug = slugify(data.orgName);

  // Check for slug collision
  const existingOrg = await OrganizationRepository.findBySlug(slug);
  if (existingOrg) {
    return {
      success: false,
      error:
        "An organization with that name already exists. Please choose a different name.",
    };
  }

  // Check for email collision
  const existingUser = await prisma.user.findUnique({
    where: { email: data.adminEmail.toLowerCase().trim() },
  });
  if (existingUser) {
    return {
      success: false,
      error: "An account with that email already exists.",
    };
  }

  const salt = bcrypt.genSaltSync(12);
  const passwordHash = bcrypt.hashSync(data.adminPassword, salt);
  const username = data.adminEmail
    .toLowerCase()
    .split("@")[0]
    .replace(/[^a-z0-9]/g, "");

  // Atomic transaction: create org + admin user together
  let org: any;
  let adminUser: any;

  try {
    await prisma.$transaction(async (tx) => {
      org = await tx.organization.create({
        data: { name: data.orgName.trim(), slug, status: "active" },
      });

      adminUser = await tx.user.create({
        data: {
          organization_id: org.id,
          username: `${username}_${org.id}`, // ensure uniqueness
          email: data.adminEmail.toLowerCase().trim(),
          password_hash: passwordHash,
          first_name: data.adminFirstName.trim(),
          last_name: data.adminLastName.trim(),
          role: "org_admin",
          mode: "org",
          is_active: true,
          email_verified: false,
        },
      });

      // Audit the registration event
      await tx.auditLog.create({
        data: {
          organization_id: org.id,
          user_id: adminUser.id,
          username: adminUser.username,
          action: "ORG_SELF_REGISTERED",
          resource: "organization",
          details: `New SaaS organization registered: ${data.orgName}`,
        },
      });
    });
  } catch (err: any) {
    console.error(
      "[OrgService] Self-registration transaction failed:",
      err.message,
    );
    return { success: false, error: "Registration failed. Please try again." };
  }

  // Send emails (non-blocking, after transaction commits)
  sendWelcomeEmail({
    to: adminUser.email,
    firstName: adminUser.first_name,
    orgName: org.name,
  }).catch(() => {});

  // Generate + send email verification token
  try {
    const crypto = await import("crypto");
    const tokenRaw = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(tokenRaw)
      .digest("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await prisma.emailVerificationToken.create({
      data: {
        user_id: adminUser.id,
        token_hash: tokenHash,
        expires_at: expiresAt,
      },
    });

    sendEmailVerification({
      to: adminUser.email,
      firstName: adminUser.first_name,
      token: tokenRaw,
    }).catch(() => {});
  } catch {
    // Non-critical — user can request a new verification email later
  }

  // Strip sensitive fields before returning
  const { password_hash: _ph, ...safeUser } = adminUser;
  return { success: true, organization: org, user: safeUser };
}

// ─── Get Organization ─────────────────────────────────────────────────────────────

export async function getOrganization(id: number): Promise<any | null> {
  const connected = await isPostgresConnected();
  if (!connected) return null;

  return OrganizationRepository.findById(id);
}

// ─── Update Organization ──────────────────────────────────────────────────────────

export async function updateOrganization(
  id: number,
  data: { name?: string; slug?: string },
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const org = await OrganizationRepository.findById(id);
  if (!org) return { success: false, error: "Organization not found." };

  if (data.slug) {
    const existingSlug = await OrganizationRepository.findBySlug(data.slug);
    if (existingSlug && existingSlug.id !== id)
      return { success: false, error: "Slug already in use." };
  }

  await OrganizationRepository.update(id, {
    ...(data.name !== undefined && { name: data.name }),
    ...(data.slug !== undefined && { slug: data.slug }),
  });

  return { success: true };
}

// ─── List Organizations ───────────────────────────────────────────────────────────

export async function listOrganizations(): Promise<any[]> {
  const connected = await isPostgresConnected();
  if (!connected) return [];

  return OrganizationRepository.list();
}
