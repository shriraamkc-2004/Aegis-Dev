/**
 * Aegis Enterprise - Rate Limiter Middleware
 * Role-based and endpoint-based memory rate limiting for API protection.
 */
import rateLimit from "express-rate-limit";
import { Request, Response, NextFunction } from "express";

// Role-based rate limits (requests per 15-minute window)
const ROLE_LIMITS: Record<string, { windowMs: number; max: number }> = {
  super_admin: { windowMs: 15 * 60 * 1000, max: 10000 },
  org_admin: { windowMs: 15 * 60 * 1000, max: 5000 },
  soc_analyst: { windowMs: 15 * 60 * 1000, max: 3000 },
  executive_viewer: { windowMs: 15 * 60 * 1000, max: 1000 },
  demo_admin: { windowMs: 15 * 60 * 1000, max: 2000 },
  demo_analyst: { windowMs: 15 * 60 * 1000, max: 1000 },
  demo_viewer: { windowMs: 15 * 60 * 1000, max: 500 },
};

// Endpoint-specific overrides
const ENDPOINT_LIMITS: Record<string, { windowMs: number; max: number }> = {
  "/api/auth/login": { windowMs: 15 * 60 * 1000, max: 10 },
  "/api/auth/register": { windowMs: 60 * 60 * 1000, max: 5 },
  "/api/auth/forgot-password": { windowMs: 60 * 60 * 1000, max: 3 },
  "/api/events/ingest": { windowMs: 60 * 1000, max: 1000 },
  "/api/copilot/chat": { windowMs: 60 * 1000, max: 30 },
};

// Create role-based rate limiter
export function createRoleBasedLimiter() {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    if (!user) return next();

    const limits = ROLE_LIMITS[user.role] || ROLE_LIMITS.executive_viewer;

    rateLimit({
      windowMs: limits.windowMs,
      max: limits.max,
      message: {
        error: "Too many requests, please try again later.",
        retryAfter: Math.ceil(limits.windowMs / 1000),
      },
      standardHeaders: true,
      legacyHeaders: false,
    })(req, res, next);
  };
}

// Create endpoint-specific rate limiter
export function createEndpointLimiter(endpoint: string) {
  const limits = ENDPOINT_LIMITS[endpoint];
  if (!limits) {
    return (req: Request, res: Response, next: NextFunction) => next();
  }

  return rateLimit({
    windowMs: limits.windowMs,
    max: limits.max,
    message: {
      error: "Too many requests to this endpoint, please try again later.",
      retryAfter: Math.ceil(limits.windowMs / 1000),
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
}

// Global rate limiter (fallback for unauthenticated requests)
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // 200 requests per window
  message: {
    error: "Too many requests, please slow down.",
    retryAfter: 900,
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for authentication endpoints
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 attempts per window
  message: {
    error: "Too many authentication attempts, please try again later.",
    retryAfter: 900,
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful logins
});

// API limiter for high-volume endpoints
export const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1000, // 1000 requests per minute
  message: {
    error: "API rate limit exceeded.",
    retryAfter: 60,
  },
  standardHeaders: true,
  legacyHeaders: false,
});
