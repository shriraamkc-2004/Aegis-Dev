/**
 * Aegis Enterprise — API Ingress Gateway Middleware
 *
 * Manages token verification, rate limiting, and routes screening at API boundary.
 */

import { Request, Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";

// Rate limiting middleware using Node memory store (migratable to Redis)
export const gatewayRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5000, // Limit each IP to 5000 requests per window to accommodate real-time SOC dashboard telemetry
  message: {
    error: "Too many requests to Aegis Gateway, please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Enterprise Access Log Gateway middleware
 */
export function gatewayLoggingMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  console.log(
    `[API Gateway Log] ${new Date().toISOString()} | ${req.method} ${req.originalUrl} | IP: ${ip}`,
  );
  next();
}
