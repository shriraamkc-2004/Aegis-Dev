/**
 * Aegis Enterprise - Redis-Backed Rate Limiter
 * Role-based rate limiting for API protection
 */
import rateLimit from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { Request, Response, NextFunction } from 'express';
import redis from '../redis/client';

// Role-based rate limits (requests per window)
const ROLE_LIMITS = {
  super_admin: { windowMs: 15 * 60 * 1000, max: 10000 },
  org_admin: { windowMs: 15 * 60 * 1000, max: 5000 },
  soc_analyst: { windowMs: 15 * 60 * 1000, max: 3000 },
  executive_viewer: { windowMs: 15 * 60 * 1000, max: 1000 },
  demo_admin: { windowMs: 15 * 60 * 1000, max: 2000 },
  demo_analyst: { windowMs: 15 * 60 * 1000, max: 1000 },
  demo_viewer: { windowMs: 15 * 60 * 1000, max: 500 }
};

// Endpoint-specific overrides
const ENDPOINT_LIMITS = {
  '/api/auth/login': { windowMs: 15 * 60 * 1000, max: 10 },
  '/api/auth/register': { windowMs: 60 * 60 * 1000, max: 5 },
  '/api/auth/forgot-password': { windowMs: 60 * 60 * 1000, max: 3 },
  '/api/events/ingest': { windowMs: 60 * 1000, max: 1000 },
  '/api/copilot/chat': { windowMs: 60 * 1000, max: 30 }
};

// Type-safe sendCommand wrapper for rate-limit-redis
const sendCommand: any = (...args: string[]) => (redis as any).call(...args);

// Create role-based rate limiter
export function createRoleBasedLimiter() {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    if (!user) return next();
    
    const limits = ROLE_LIMITS[user.role] || ROLE_LIMITS.executive_viewer;
    
    const limiter = rateLimit({
      store: new RedisStore({
        sendCommand,
        prefix: `rate_limit:${user.id}:`
      }),
      windowMs: limits.windowMs,
      max: limits.max,
      message: {
        error: 'Too many requests, please try again later.',
        retryAfter: Math.ceil(limits.windowMs / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      skipSuccessfulRequests: false,
      skipFailedRequests: false
    });
    
    limiter(req, res, next);
  };
}

// Create endpoint-specific rate limiter
export function createEndpointLimiter(endpoint: string) {
  const limits = ENDPOINT_LIMITS[endpoint as keyof typeof ENDPOINT_LIMITS];
  if (!limits) {
    return (req: Request, res: Response, next: NextFunction) => next();
  }
  
  const limiter = rateLimit({
    store: new RedisStore({
      sendCommand,
      prefix: `rate_limit:${endpoint}:`
    }),
    windowMs: limits.windowMs,
    max: limits.max,
    message: {
      error: 'Too many requests to this endpoint, please try again later.',
      retryAfter: Math.ceil(limits.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false
  });
  
  return limiter;
}

// Global rate limiter (fallback for unauthenticated requests)
export const globalLimiter = rateLimit({
  store: new RedisStore({
    sendCommand,
    prefix: 'rate_limit:global:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: {
    error: 'Too many requests, please slow down.',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false
});

// Strict limiter for authentication endpoints
export const authLimiter = rateLimit({
  store: new RedisStore({
    sendCommand,
    prefix: 'rate_limit:auth:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per window
  message: {
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // Don't count successful logins
});

// API limiter for high-volume endpoints
export const apiLimiter = rateLimit({
  store: new RedisStore({
    sendCommand,
    prefix: 'rate_limit:api:'
  }),
  windowMs: 60 * 1000, // 1 minute
  max: 1000, // 1000 requests per minute
  message: {
    error: 'API rate limit exceeded.',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false
});