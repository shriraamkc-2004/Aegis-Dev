/**
 * Aegis Phase 3A — SaaS Authentication Service
 * JWT access/refresh tokens with rotation, password reset, email verification.
 * Uses Prisma (PostgreSQL) for SaaS entities, falls back to SQLite when PG is down.
 */

import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { getPrismaClient, isPostgresConnected } from "./prisma_client.js";
import type { Role } from "../generated/prisma/index.js";
import {
  sendPasswordResetEmail,
  sendEmailVerification,
} from "../services/email_service.js";

// ─── Config ──────────────────────────────────────────────────────────────────────

const JWT_SECRET =
  process.env.JWT_SECRET || "aegis-enterprise-secret-key-change-in-production";
const JWT_REFRESH_SECRET =
  process.env.JWT_REFRESH_SECRET || JWT_SECRET + "-refresh";
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || "15m";
const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(
  process.env.REFRESH_TOKEN_EXPIRY_DAYS || "7",
);
const PASSWORD_RESET_EXPIRY_HOURS = parseInt(
  process.env.PASSWORD_RESET_EXPIRY_HOURS || "1",
);
const EMAIL_VERIFY_EXPIRY_HOURS = parseInt(
  process.env.EMAIL_VERIFY_EXPIRY_HOURS || "24",
);
const EMAIL_VERIFICATION_REQUIRED =
  process.env.EMAIL_VERIFICATION_REQUIRED !== "false";

export type SaasRole = Role;

export interface SaasUser {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  role: SaasRole;
  organization_id: number | null;
  is_active: boolean;
  email_verified: boolean;
}

// ─── Token Utilities ─────────────────────────────────────────────────────────────

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function generateSecureToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function generateAccessToken(user: SaasUser): string {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      organization_id: user.organization_id,
      type: "access",
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY as any },
  );
}

export function generateRefreshTokenString(): string {
  return generateSecureToken();
}

// ─── Login ───────────────────────────────────────────────────────────────────────

export async function loginUser(
  email: string,
  password: string,
  ipAddress: string,
): Promise<
  | { accessToken: string; refreshToken: string; user: SaasUser }
  | { error: string; status: number }
> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return {
      error: "PostgreSQL unavailable. SaaS authentication requires PostgreSQL.",
      status: 503,
    };
  }

  const prisma = getPrismaClient();

  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase().trim() },
    include: { organization: true },
  });

  if (!user) {
    return { error: "Invalid email or password.", status: 401 };
  }

  if (!user.is_active) {
    return {
      error: "Account is deactivated. Contact your administrator.",
      status: 403,
    };
  }

  if (EMAIL_VERIFICATION_REQUIRED && !user.email_verified) {
    return {
      error:
        "Email not verified. Please check your inbox for a verification link.",
      status: 403,
    };
  }

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) {
    return { error: "Invalid email or password.", status: 401 };
  }

  const saasUser: SaasUser = {
    id: user.id,
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name,
    role: user.role,
    organization_id: user.organization_id,
    is_active: user.is_active,
    email_verified: user.email_verified,
  };

  const accessToken = generateAccessToken(saasUser);
  const refreshTokenRaw = generateRefreshTokenString();
  const refreshTokenHash = hashToken(refreshTokenRaw);

  const expiresAt = new Date(
    Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
  );

  await prisma.refreshToken.create({
    data: {
      user_id: user.id,
      token_hash: refreshTokenHash,
      expires_at: expiresAt,
    },
  });

  // Audit log
  await prisma.auditLog.create({
    data: {
      user_id: user.id,
      organization_id: user.organization_id,
      action: "LOGIN",
      resource: "auth",
      ip_address: ipAddress,
    },
  });

  return { accessToken, refreshToken: refreshTokenRaw, user: saasUser };
}

// ─── Refresh Token (with rotation) ───────────────────────────────────────────────

export async function refreshTokens(
  refreshToken: string,
  ipAddress: string,
): Promise<
  | { accessToken: string; refreshToken: string; user: SaasUser }
  | { error: string; status: number }
> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return { error: "PostgreSQL unavailable.", status: 503 };
  }

  const prisma = getPrismaClient();
  const tokenHash = hashToken(refreshToken);

  const stored = await prisma.refreshToken.findUnique({
    where: { token_hash: tokenHash },
    include: { user: true },
  });

  if (!stored) {
    return { error: "Invalid refresh token.", status: 401 };
  }

  if (stored.expires_at < new Date()) {
    // Expired — delete and invalidate all user tokens
    await prisma.refreshToken.deleteMany({
      where: { user_id: stored.user_id },
    });
    return {
      error: "Refresh token expired. Please log in again.",
      status: 401,
    };
  }

  const user = stored.user;
  if (!user.is_active) {
    await prisma.refreshToken.deleteMany({ where: { user_id: user.id } });
    return { error: "Account deactivated.", status: 403 };
  }

  // Token rotation: delete old token, create new one
  await prisma.refreshToken.delete({ where: { id: stored.id } });

  const saasUser: SaasUser = {
    id: user.id,
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name,
    role: user.role,
    organization_id: user.organization_id,
    is_active: user.is_active,
    email_verified: user.email_verified,
  };

  const newAccessToken = generateAccessToken(saasUser);
  const newRefreshTokenRaw = generateRefreshTokenString();
  const newRefreshTokenHash = hashToken(newRefreshTokenRaw);
  const newExpiresAt = new Date(
    Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
  );

  await prisma.refreshToken.create({
    data: {
      user_id: user.id,
      token_hash: newRefreshTokenHash,
      expires_at: newExpiresAt,
    },
  });

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshTokenRaw,
    user: saasUser,
  };
}

// ─── Logout ──────────────────────────────────────────────────────────────────────

export async function logoutUser(
  userId: number,
  refreshToken?: string,
  ipAddress?: string,
): Promise<void> {
  const connected = await isPostgresConnected();
  if (!connected) return;

  const prisma = getPrismaClient();

  if (refreshToken) {
    const tokenHash = hashToken(refreshToken);
    await prisma.refreshToken.deleteMany({ where: { token_hash: tokenHash } });
  } else {
    // Invalidate all refresh tokens for this user
    await prisma.refreshToken.deleteMany({ where: { user_id: userId } });
  }

  await prisma.auditLog.create({
    data: {
      user_id: userId,
      action: "LOGOUT",
      resource: "auth",
      ip_address: ipAddress || "",
    },
  });
}

// ─── Forgot Password ─────────────────────────────────────────────────────────────

export async function forgotPassword(
  email: string,
  ipAddress: string,
): Promise<{ message: string }> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return { message: "If that email exists, a reset link has been sent." };
  }

  const prisma = getPrismaClient();
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase().trim() },
  });

  // Always return the same message to prevent email enumeration
  if (!user) {
    return { message: "If that email exists, a reset link has been sent." };
  }

  // Delete any existing reset tokens
  await prisma.passwordResetToken.deleteMany({ where: { user_id: user.id } });

  const tokenRaw = generateSecureToken();
  const tokenHash = hashToken(tokenRaw);
  const expiresAt = new Date(
    Date.now() + PASSWORD_RESET_EXPIRY_HOURS * 60 * 60 * 1000,
  );

  await prisma.passwordResetToken.create({
    data: {
      user_id: user.id,
      token_hash: tokenHash,
      expires_at: expiresAt,
    },
  });

  // Dispatch the password reset email (non-blocking)
  sendPasswordResetEmail({
    to: user.email,
    firstName: user.first_name || user.username,
    token: tokenRaw,
  }).catch((err) =>
    console.error("[Auth] Failed to send password reset email:", err),
  );

  await prisma.auditLog.create({
    data: {
      user_id: user.id,
      action: "FORGOT_PASSWORD",
      resource: "auth",
      ip_address: ipAddress,
    },
  });

  return { message: "If that email exists, a reset link has been sent." };
}

// ─── Reset Password ──────────────────────────────────────────────────────────────

export async function resetPassword(
  token: string,
  newPassword: string,
  ipAddress: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return { success: false, error: "PostgreSQL unavailable." };
  }

  const prisma = getPrismaClient();
  const tokenHash = hashToken(token);

  const resetRecord = await prisma.passwordResetToken.findUnique({
    where: { token_hash: tokenHash },
  });

  if (!resetRecord) {
    return { success: false, error: "Invalid or expired reset token." };
  }

  if (resetRecord.expires_at < new Date()) {
    await prisma.passwordResetToken.delete({ where: { id: resetRecord.id } });
    return {
      success: false,
      error: "Reset token has expired. Please request a new one.",
    };
  }

  if (newPassword.length < 8) {
    return { success: false, error: "Password must be at least 8 characters." };
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(newPassword, salt);

  await prisma.user.update({
    where: { id: resetRecord.user_id },
    data: { password_hash: hash },
  });

  // Delete the used reset token
  await prisma.passwordResetToken.delete({ where: { id: resetRecord.id } });

  // Invalidate all existing refresh tokens (force re-login)
  await prisma.refreshToken.deleteMany({
    where: { user_id: resetRecord.user_id },
  });

  await prisma.auditLog.create({
    data: {
      user_id: resetRecord.user_id,
      action: "RESET_PASSWORD",
      resource: "auth",
      ip_address: ipAddress,
    },
  });

  return { success: true };
}

// ─── Email Verification ──────────────────────────────────────────────────────────

export async function sendVerificationEmail(
  userId: number,
  ipAddress: string,
): Promise<{ success: boolean; error?: string; token?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return { success: false, error: "PostgreSQL unavailable." };
  }

  const prisma = getPrismaClient();
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    return { success: false, error: "User not found." };
  }

  if (user.email_verified) {
    return { success: false, error: "Email already verified." };
  }

  // Delete any existing verification tokens
  await prisma.emailVerificationToken.deleteMany({
    where: { user_id: userId },
  });

  const tokenRaw = generateSecureToken();
  const tokenHash = hashToken(tokenRaw);
  const expiresAt = new Date(
    Date.now() + EMAIL_VERIFY_EXPIRY_HOURS * 60 * 60 * 1000,
  );

  await prisma.emailVerificationToken.create({
    data: {
      user_id: userId,
      token_hash: tokenHash,
      expires_at: expiresAt,
    },
  });

  // Dispatch the verification email (non-blocking)
  sendEmailVerification({
    to: user.email,
    firstName: user.first_name || user.username,
    token: tokenRaw,
  }).catch((err) =>
    console.error("[Auth] Failed to send verification email:", err),
  );

  return { success: true };
}

export async function verifyEmail(
  token: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return { success: false, error: "PostgreSQL unavailable." };
  }

  const prisma = getPrismaClient();
  const tokenHash = hashToken(token);

  const verifyRecord = await prisma.emailVerificationToken.findUnique({
    where: { token_hash: tokenHash },
  });

  if (!verifyRecord) {
    return { success: false, error: "Invalid or expired verification token." };
  }

  if (verifyRecord.expires_at < new Date()) {
    await prisma.emailVerificationToken.delete({
      where: { id: verifyRecord.id },
    });
    return {
      success: false,
      error: "Verification token expired. Please request a new one.",
    };
  }

  await prisma.user.update({
    where: { id: verifyRecord.user_id },
    data: { email_verified: true },
  });

  await prisma.emailVerificationToken.delete({
    where: { id: verifyRecord.id },
  });

  await prisma.auditLog.create({
    data: {
      user_id: verifyRecord.user_id,
      action: "EMAIL_VERIFIED",
      resource: "auth",
    },
  });

  return { success: true };
}

// ─── Change Password (authenticated) ─────────────────────────────────────────────

export async function changePassword(
  userId: number,
  currentPassword: string,
  newPassword: string,
  ipAddress: string,
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) {
    return { success: false, error: "PostgreSQL unavailable." };
  }

  const prisma = getPrismaClient();
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    return { success: false, error: "User not found." };
  }

  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return { success: false, error: "Current password is incorrect." };
  }

  if (newPassword.length < 8) {
    return {
      success: false,
      error: "New password must be at least 8 characters.",
    };
  }

  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(newPassword, salt);

  await prisma.user.update({
    where: { id: userId },
    data: { password_hash: hash },
  });

  // Invalidate all refresh tokens
  await prisma.refreshToken.deleteMany({ where: { user_id: userId } });

  await prisma.auditLog.create({
    data: {
      user_id: userId,
      action: "CHANGE_PASSWORD",
      resource: "auth",
      ip_address: ipAddress,
    },
  });

  return { success: true };
}
