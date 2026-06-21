/**
 * Aegis Phase 3A — SaaS API Routes
 * Registers all Phase 3A endpoints on the existing Express app.
 * Preserves all existing routes — adds new auth, user, and org endpoints.
 */

import { Router } from "express";
import rateLimit from "express-rate-limit";
import { authenticateToken, requireRole, logAudit, getOrgId, maskPII } from "../auth.js";
import {
  loginUser, refreshTokens, logoutUser,
  forgotPassword, resetPassword,
  sendVerificationEmail, verifyEmail, changePassword,
} from "./auth_service.js";
import {
  createUser, inviteUser, listUsers, getUser, updateUser,
  activateUser, deactivateUser, deleteUser,
  hasPermission, getPermissions,
} from "./user_service.js";
import {
  createOrganization, getOrganization, updateOrganization, listOrganizations,
} from "./org_service.js";
import type { SaasRole } from "./auth_service.js";

export const saasRouter = Router();

// ─── Rate Limiters ────────────────────────────────────────────────────────────────

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many authentication attempts. Please try again later." },
});

const resetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many password reset requests. Please try again later." },
});

// ─── Role mapping: existing SQLite roles → Phase 3A SaaS roles ───────────────────

const ROLE_MAP: Record<string, SaasRole> = {
  super_admin: "super_admin",
  org_admin: "org_admin",
  soc_analyst: "soc_analyst",
  executive_viewer: "executive_viewer",
  demo_admin: "demo_admin",
  demo_analyst: "demo_analyst",
  demo_viewer: "demo_viewer",
};

function mapRole(sqliteRole: string): SaasRole {
  return ROLE_MAP[sqliteRole] || "demo_viewer";
}

// ─── Auth Endpoints ───────────────────────────────────────────────────────────────

// POST /api/saas/auth/login
saasRouter.post("/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: "Email and password are required." });
      return;
    }
    const result = await loginUser(email, password, req.ip || "");
    if ("error" in result) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: "Authentication failed." });
  }
});

// POST /api/saas/auth/refresh
saasRouter.post("/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400).json({ error: "Refresh token is required." });
      return;
    }
    const result = await refreshTokens(refreshToken, req.ip || "");
    if ("error" in result) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: "Token refresh failed." });
  }
});

// POST /api/saas/auth/logout
saasRouter.post("/auth/logout", authenticateToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    await logoutUser(req.user!.id, refreshToken, req.ip || "");
    res.json({ message: "Logged out successfully." });
  } catch (err: any) {
    res.status(500).json({ error: "Logout failed." });
  }
});

// POST /api/saas/auth/forgot-password
saasRouter.post("/auth/forgot-password", resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      res.status(400).json({ error: "Email is required." });
      return;
    }
    const result = await forgotPassword(email, req.ip || "");
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: "Request failed." });
  }
});

// POST /api/saas/auth/reset-password
saasRouter.post("/auth/reset-password", resetLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
      res.status(400).json({ error: "Token and new password are required." });
      return;
    }
    const result = await resetPassword(token, newPassword, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "Password reset successfully." });
  } catch (err: any) {
    res.status(500).json({ error: "Password reset failed." });
  }
});

// POST /api/saas/auth/verify-email
saasRouter.post("/auth/verify-email", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      res.status(400).json({ error: "Verification token is required." });
      return;
    }
    const result = await verifyEmail(token);
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "Email verified successfully." });
  } catch (err: any) {
    res.status(500).json({ error: "Verification failed." });
  }
});

// POST /api/saas/auth/resend-verification
saasRouter.post("/auth/resend-verification", authenticateToken, async (req, res) => {
  try {
    const result = await sendVerificationEmail(req.user!.id, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "Verification email sent.", token: result.token });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to send verification email." });
  }
});

// POST /api/saas/auth/change-password
saasRouter.post("/auth/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: "Current and new password are required." });
      return;
    }
    const result = await changePassword(req.user!.id, currentPassword, newPassword, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "Password changed successfully." });
  } catch (err: any) {
    res.status(500).json({ error: "Password change failed." });
  }
});

// ─── User Management Endpoints ────────────────────────────────────────────────────

// GET /api/saas/users
saasRouter.get("/users", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:list") && !hasPermission(saasRole, "users:manage")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const isSuperAdmin = req.user!.role === "super_admin";
    const orgId = req.user!.organization_id;
    const users = await listUsers(orgId, isSuperAdmin);
    // Mask PII
    const masked = users.map((u: any) => ({
      ...u,
      email: maskPII(u.email, "email"),
    }));
    res.json(masked);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/saas/users
saasRouter.post("/users", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:manage")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const { email, password, first_name, last_name, role, organization_id } = req.body;
    if (!email || !password || !role) {
      res.status(400).json({ error: "email, password, and role are required." });
      return;
    }
    const orgId = req.user!.role === "super_admin" ? (organization_id || null) : req.user!.organization_id;
    const result = await createUser({
      email, password, first_name, last_name,
      role: role as SaasRole,
      organization_id: orgId,
    });
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    await logAudit(req.user!.id, req.user!.username, "CREATE_USER", "users", `Created SaaS user: ${email}`, req.ip || "", getOrgId(req.user!));
    res.status(201).json(result.user);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/saas/users/invite
saasRouter.post("/users/invite", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:invite")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const { email, first_name, last_name, role } = req.body;
    if (!email || !role) {
      res.status(400).json({ error: "email and role are required." });
      return;
    }
    const result = await inviteUser({
      email, first_name, last_name,
      role: role as SaasRole,
      organization_id: req.user!.organization_id || 1,
      invited_by: req.user!.id,
      ipAddress: req.ip || "",
    });
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.status(201).json({ message: "Invitation sent.", token: result.token });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/saas/users/:id
saasRouter.get("/users/:id", authenticateToken, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const user = await getUser(userId);
    if (!user) {
      res.status(404).json({ error: "User not found." });
      return;
    }
    // Tenant isolation: non-superadmin can only view users in their org
    if (req.user!.role !== "super_admin" && user.organization_id !== req.user!.organization_id) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    res.json({ ...user, email: maskPII(user.email, "email") });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/saas/users/:id
saasRouter.patch("/users/:id", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:manage")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const userId = parseInt(req.params.id);
    const result = await updateUser(userId, req.body, req.user!.id, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "User updated." });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/saas/users/:id/activate
saasRouter.patch("/users/:id/activate", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:activate")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const result = await activateUser(parseInt(req.params.id), req.user!.id, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "User activated." });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/saas/users/:id/deactivate
saasRouter.patch("/users/:id/deactivate", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:deactivate")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const result = await deactivateUser(parseInt(req.params.id), req.user!.id, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "User deactivated." });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/saas/users/:id
saasRouter.delete("/users/:id", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "users:manage")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const result = await deleteUser(parseInt(req.params.id), req.user!.id, req.ip || "");
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "User deleted." });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/saas/roles
saasRouter.get("/roles", authenticateToken, (_req, res) => {
  const roles = Object.keys(ROLE_MAP).map(r => ({
    key: r,
    saas_role: ROLE_MAP[r],
    permissions: getPermissions(ROLE_MAP[r]),
  }));
  res.json(roles);
});

// ─── Organization Endpoints ───────────────────────────────────────────────────────

// GET /api/saas/organizations
saasRouter.get("/organizations", authenticateToken, async (req, res) => {
  try {
    if (req.user!.role !== "super_admin") {
      res.status(403).json({ error: "SuperAdmin access required." });
      return;
    }
    const orgs = await listOrganizations();
    res.json(orgs);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/saas/organizations
saasRouter.post("/organizations", authenticateToken, async (req, res) => {
  try {
    if (req.user!.role !== "super_admin") {
      res.status(403).json({ error: "SuperAdmin access required." });
      return;
    }
    const { name, slug } = req.body;
    if (!name) {
      res.status(400).json({ error: "Organization name is required." });
      return;
    }
    const result = await createOrganization({ name, slug });
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    await logAudit(req.user!.id, req.user!.username, "CREATE_ORG", "organizations", `Created org: ${name}`, req.ip || "", 1);
    res.status(201).json(result.organization);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/saas/organizations/:id
saasRouter.get("/organizations/:id", authenticateToken, async (req, res) => {
  try {
    const orgId = parseInt(req.params.id);
    // Tenant isolation: non-superadmin can only view their own org
    if (req.user!.role !== "super_admin" && req.user!.organization_id !== orgId) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const org = await getOrganization(orgId);
    if (!org) {
      res.status(404).json({ error: "Organization not found." });
      return;
    }
    res.json(org);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/saas/organizations/:id
saasRouter.patch("/organizations/:id", authenticateToken, async (req, res) => {
  try {
    const saasRole = mapRole(req.user!.role);
    if (!hasPermission(saasRole, "organization:update")) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const orgId = parseInt(req.params.id);
    if (req.user!.role !== "super_admin" && req.user!.organization_id !== orgId) {
      res.status(403).json({ error: "Access denied." });
      return;
    }
    const result = await updateOrganization(orgId, req.body);
    if (!result.success) {
      res.status(400).json({ error: result.error });
      return;
    }
    res.json({ message: "Organization updated." });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/saas/audit-logs
saasRouter.get("/audit-logs", authenticateToken, async (req, res) => {
  try {
    const { isPostgresConnected } = await import("./prisma_client.js");
    const connected = await isPostgresConnected();
    if (!connected) {
      res.status(503).json({ error: "PostgreSQL unavailable." });
      return;
    }
    const { getPrismaClient } = await import("./prisma_client.js");
    const prisma = getPrismaClient();
    const limit = parseInt(req.query.limit as string) || 100;

    const where = req.user!.role === "super_admin"
      ? {}
      : { organization_id: req.user!.organization_id };

    const logs = await prisma.auditLog.findMany({
      where,
      orderBy: { timestamp: "desc" },
      take: limit,
      include: {
        user: { select: { email: true, first_name: true, last_name: true } },
      },
    });
    res.json(logs);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
