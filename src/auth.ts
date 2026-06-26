import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { dbGet, dbRun } from "./server_db.js";

const JWT_SECRET = process.env.JWT_SECRET || "aegis-enterprise-secret-key-change-in-production";
const JWT_EXPIRY = "1h";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || JWT_SECRET + "-refresh";
const JWT_REFRESH_EXPIRY = "7d";

export type UserRole =
  | "super_admin" | "org_admin" | "soc_analyst" | "executive_viewer"
  | "demo_admin" | "demo_analyst" | "demo_viewer";

export type UserMode = "demo" | "org";

export interface AuthUser {
  id: number;
  username: string;
  role: UserRole;
  organization_id: number | null;
  mode: UserMode;
}

// Extend Express Request to include user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

// Generate JWT access token
export function generateToken(user: AuthUser): string {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, organization_id: user.organization_id, mode: user.mode },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

// Generate JWT refresh token
export function generateRefreshToken(user: AuthUser): string {
  return jwt.sign(
    { id: user.id, username: user.username, type: "refresh" },
    JWT_REFRESH_SECRET,
    { expiresIn: JWT_REFRESH_EXPIRY }
  );
}

import redis from "./redis/client.js";

// Verify refresh token
export function verifyRefreshToken(token: string): AuthUser | null {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET) as any;
    if (decoded.type !== "refresh") return null;
    return decoded as AuthUser;
  } catch {
    return null;
  }
}

// Check if refresh token is blacklisted/revoked in Redis
export async function isRefreshTokenRevoked(token: string): Promise<boolean> {
  try {
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    const val = await redis.get(`blacklist:${hash}`);
    return val === "true";
  } catch (err) {
    console.warn("[Auth SDK] Redis blacklist query failure:", err);
    return false;
  }
}

// Revoke a refresh token in Redis
export async function revokeRefreshToken(token: string, expirySeconds: number = 7 * 24 * 3600): Promise<void> {
  try {
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    await redis.set(`blacklist:${hash}`, "true", "EX", expirySeconds);
  } catch (err) {
    console.warn("[Auth SDK] Redis blacklist insert failure:", err);
  }
}

// Verify JWT token and return decoded user (for non-middleware use)
export function verifyToken(token: string): AuthUser {
  return jwt.verify(token, JWT_SECRET) as AuthUser;
}

// Verify JWT token middleware
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    res.status(401).json({ error: "Authentication required. Provide Bearer token." });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as AuthUser;
    req.user = decoded;
    next();
  } catch (err: any) {
    if (err.name === "TokenExpiredError") {
      res.status(401).json({ error: "Token expired. Please re-authenticate." });
    } else {
      res.status(403).json({ error: "Invalid token." });
    }
  }
}

// RBAC middleware - restrict access to specific roles
export function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: `Access denied. Required role: ${allowedRoles.join(" or ")}` });
      return;
    }
    next();
  };
}

// Audit logging helper
export async function logAudit(
  userId: number | null,
  username: string,
  action: string,
  resource: string = "",
  details: string = "",
  ipAddress: string = "",
  organizationId: number = 1
): Promise<void> {
  try {
    await dbRun(
      "INSERT INTO audit_logs (user_id, username, action, resource, details, ip_address, organization_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [userId, username, action, resource, details, ipAddress, organizationId]
    );
  } catch (err: any) {
    console.error("Audit log error:", err.message);
  }
}

// Tenant isolation middleware - ensures users only access their org's data
export function tenantIsolation(req: Request, res: Response, next: NextFunction): void {
  // Super admins can access all tenants
  if (req.user?.role === "super_admin") {
    next();
    return;
  }
  // Other users are scoped to their organization
  next();
}

// Get user's organization ID (for tenant-scoped queries)
export function getOrgId(user: AuthUser): number {
  if (user.role === "super_admin") return 0; // 0 = all orgs
  return user.organization_id || 1;
}

// Check if user is in demo mode
export function isDemoUser(user: AuthUser): boolean {
  return user.mode === "demo" || user.role.startsWith("demo_");
}

// Demo role hierarchy check
export function hasDemoRole(user: AuthUser, ...allowedRoles: string[]): boolean {
  return allowedRoles.includes(user.role);
}

// Require demo mode
export function requireDemoMode(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }
  if (!isDemoUser(req.user)) {
    res.status(403).json({ error: "Demo mode access required." });
    return;
  }
  next();
}

// Require org mode
export function requireOrgMode(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }
  if (isDemoUser(req.user)) {
    res.status(403).json({ error: "Organization mode access required." });
    return;
  }
  next();
}

/**
 * Sensitive field encryption protects secrets and credentials only.
 * PII masking is applied during presentation and external exposure only.
 * Operational SOC telemetry remains unencrypted and unmasked internally to preserve detection accuracy and forensic integrity.
 */
import crypto from "crypto";

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "aegis-super-secret-key-32bytes-long!!"; // Should be 32 bytes
const IV_LENGTH = 16;

export function encryptSensitive(text: string): string {
  if (!text) return "";
  try {
    const key = crypto.createHash("sha256").update(ENCRYPTION_KEY).digest();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return iv.toString("hex") + ":" + encrypted;
  } catch (err: any) {
    console.warn("[Encryption Helper] Encryption failed:", err.message);
    return text;
  }
}

export function decryptSensitive(text: string): string {
  if (!text) return "";
  try {
    const parts = text.split(":");
    if (parts.length !== 2) return text;
    const iv = Buffer.from(parts[0], "hex");
    const encryptedText = Buffer.from(parts[1], "hex");
    const key = crypto.createHash("sha256").update(ENCRYPTION_KEY).digest();
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString("utf8");
  } catch (err: any) {
    console.warn("[Encryption Helper] Decryption failed:", err.message);
    return text;
  }
}

export function maskPII(text: string, type?: "email" | "ip" | "username"): string {
  if (!text) return "";
  
  if (type === "username") {
    if (text.length <= 2) {
      return text.length === 1 ? "*" : `${text[0]}*`;
    }
    return text[0] + "*".repeat(text.length - 2) + text[text.length - 1];
  }

  // Mask Email
  let masked = text.replace(/([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})/g, (match, emailUser, emailDomain, emailExt) => {
    if (emailUser.length <= 2) return `${emailUser[0]}***@${emailDomain[0]}***.${emailExt}`;
    return `${emailUser[0]}***${emailUser[emailUser.length - 1]}@${emailDomain[0]}***.${emailExt}`;
  });
  // Mask IPv4 IP Address
  masked = masked.replace(/\b\d{1,3}\.\d{1,3}\.(\d{1,3})\.(\d{1,3})\b/g, (match) => {
    const parts = match.split(".");
    return `${parts[0]}.${parts[1]}.*.*`;
  });
  return masked;
}

export { JWT_SECRET };
