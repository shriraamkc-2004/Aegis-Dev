/**
 * Aegis SaaS — Tenant Guard Middleware
 *
 * Enforces strict per-tenant data isolation on every authenticated API request.
 *
 * How it works:
 *  1. Extracts `organization_id` from the validated JWT (populated by `authenticateToken`)
 *  2. Injects it as `req.tenantId` for all downstream route handlers
 *  3. Provides helper `assertTenant()` to throw if a route forgets to guard
 *
 * Rules:
 *  - `super_admin` bypasses the tenant check (they operate across all orgs)
 *  - All other roles MUST have an `organization_id` or the request is rejected
 */

import type { Request, Response, NextFunction } from "express";

// ─── Augment Express Request ────────────────────────────────────────────────────

declare global {
  namespace Express {
    interface Request {
      /** The organization_id of the authenticated tenant (null for super_admin) */
      tenantId: number | null;
      /** Whether the current user is a super_admin (cross-tenant access) */
      isSuperAdmin: boolean;
    }
  }
}

// ─── Tenant Guard Middleware ────────────────────────────────────────────────────

/**
 * Must be placed AFTER `authenticateToken` so that `req.user` is populated.
 *
 * Usage in Express:
 *   router.use(authenticateToken, tenantGuard);
 *   router.get("/incidents", (req, res) => {
 *     const orgId = req.tenantId; // safe — guaranteed to be set or request was rejected
 *   });
 */
export function tenantGuard(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const user = (req as any).user;

  if (!user) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  // super_admin has cross-tenant visibility
  if (user.role === "super_admin") {
    req.tenantId = null;
    req.isSuperAdmin = true;
    return next();
  }

  // All other roles must belong to an organization
  if (!user.organization_id) {
    res.status(403).json({
      error:
        "Your account is not associated with any organization. Contact your administrator.",
    });
    return;
  }

  req.tenantId = user.organization_id as number;
  req.isSuperAdmin = false;
  next();
}

// ─── Scoped Tenant Guard ────────────────────────────────────────────────────────

/**
 * Use this variant when a route must ONLY be accessed by members of a specific
 * organization (blocks super_admin from accidentally operating in the wrong context
 * without explicit org selection).
 *
 * Pass `allowedRoles` to further restrict which roles inside the org can access.
 */
export function scopedTenantGuard(allowedRoles?: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = (req as any).user;

    if (!user) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }

    if (!user.organization_id) {
      res.status(403).json({ error: "No organization context." });
      return;
    }

    if (allowedRoles && !allowedRoles.includes(user.role)) {
      res.status(403).json({
        error: `Access denied. Required roles: ${allowedRoles.join(", ")}.`,
      });
      return;
    }

    req.tenantId = user.organization_id as number;
    req.isSuperAdmin = false;
    next();
  };
}

// ─── assertTenant Helper ────────────────────────────────────────────────────────

/**
 * Runtime assertion for use inside route handlers.
 * Throws a 500 if `tenantGuard` was somehow not applied before this route.
 *
 * Usage:
 *   const orgId = assertTenant(req);
 *   const incidents = await db.query("SELECT * FROM incidents WHERE org_id = $1", [orgId]);
 */
export function assertTenant(req: Request): number {
  if (req.isSuperAdmin) {
    throw new Error(
      "assertTenant() called on a super_admin request. Use req.tenantId with null check instead.",
    );
  }
  if (req.tenantId === null || req.tenantId === undefined) {
    throw new Error(
      "tenantGuard middleware was not applied before this route. Missing organization_id.",
    );
  }
  return req.tenantId;
}

/**
 * Returns the tenant filter clause for Prisma queries.
 * For super_admin: returns {} (no filter — sees all orgs).
 * For org users: returns { organization_id: tenantId }.
 */
export function tenantFilter(req: Request): { organization_id?: number } {
  if (req.isSuperAdmin) return {};
  return { organization_id: req.tenantId! };
}
