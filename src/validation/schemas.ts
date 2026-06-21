/**
 * Aegis Enterprise - Input Validation Schemas with Zod
 * Comprehensive validation for all API endpoints
 */
import { z } from 'zod';

// ─── Authentication Schemas ────────────────────────────────────────────────────

export const loginSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters')
});

export const registerSchema = z.object({
  org_name: z.string()
    .min(1, 'Organization name is required')
    .max(255, 'Organization name too long'),
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters'),
  email: z.string()
    .email('Invalid email address')
    .max(255, 'Email too long')
    .optional()
    .or(z.literal(''))
});

export const changePasswordSchema = z.object({
  current_password: z.string().min(1, 'Current password is required'),
  new_password: z.string()
    .min(8, 'New password must be at least 8 characters')
    .max(128, 'New password must be less than 128 characters')
    .regex(/[A-Z]/, 'New password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'New password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'New password must contain at least one number')
});

// ─── Event Schemas ─────────────────────────────────────────────────────────────

export const eventSchema = z.object({
  event_type: z.string()
    .min(1, 'Event type is required')
    .max(100, 'Event type too long'),
  source: z.string()
    .min(1, 'Source is required')
    .max(255, 'Source too long'),
  timestamp: z.number()
    .positive('Timestamp must be positive')
    .max(Date.now() / 1000 + 3600, 'Timestamp too far in the future'),
  organization_id: z.number()
    .int('Organization ID must be an integer')
    .positive('Organization ID must be positive')
    .optional(),
  raw_data: z.record(z.string(), z.unknown()).optional()
});

export const batchEventSchema = z.array(eventSchema)
  .min(1, 'At least one event is required')
  .max(1000, 'Maximum 1000 events per batch');

// ─── Anomaly Schemas ───────────────────────────────────────────────────────────

export const anomalyUpdateSchema = z.object({
  status: z.enum(['PENDING', 'INVESTIGATING', 'MITIGATED', 'CLOSED'])
    .optional(),
  diagnosis: z.string()
    .max(5000, 'Diagnosis too long')
    .optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    .optional(),
  recommendation: z.string()
    .max(2000, 'Recommendation too long')
    .optional()
});

// ─── Incident Schemas ──────────────────────────────────────────────────────────

export const incidentCreateSchema = z.object({
  title: z.string()
    .min(1, 'Title is required')
    .max(500, 'Title too long'),
  description: z.string()
    .max(5000, 'Description too long')
    .optional(),
  anomaly_id: z.number()
    .int('Anomaly ID must be an integer')
    .positive('Anomaly ID must be positive')
    .optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    .default('MEDIUM'),
  assigned_to: z.number()
    .int('User ID must be an integer')
    .positive('User ID must be positive')
    .optional()
});

export const incidentUpdateSchema = z.object({
  status: z.enum(['OPEN', 'INVESTIGATING', 'MITIGATED', 'CLOSED'])
    .optional(),
  title: z.string()
    .min(1, 'Title is required')
    .max(500, 'Title too long')
    .optional(),
  description: z.string()
    .max(5000, 'Description too long')
    .optional(),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    .optional(),
  analyst_notes: z.string()
    .max(5000, 'Notes too long')
    .optional(),
  resolution: z.string()
    .max(5000, 'Resolution too long')
    .optional(),
  assigned_to: z.number()
    .int('User ID must be an integer')
    .positive('User ID must be positive')
    .optional()
});

// ─── Connector Schemas ─────────────────────────────────────────────────────────

export const connectorSchema = z.object({
  name: z.string()
    .min(1, 'Connector name is required')
    .max(255, 'Connector name too long'),
  db_type: z.enum(['sqlite', 'postgresql', 'mysql', 'sqlserver', 'mongodb']),
  host: z.string()
    .max(255, 'Host too long')
    .optional()
    .or(z.literal('')),
  port: z.number()
    .int('Port must be an integer')
    .min(1, 'Port must be positive')
    .max(65535, 'Port too large')
    .optional(),
  username: z.string()
    .max(255, 'Username too long')
    .optional()
    .or(z.literal('')),
  password: z.string()
    .max(255, 'Password too long')
    .optional()
    .or(z.literal('')),
  database_name: z.string()
    .max(255, 'Database name too long')
    .optional()
    .or(z.literal('')),
  connection_string: z.string()
    .max(1000, 'Connection string too long')
    .optional()
    .or(z.literal(''))
});

// ─── Copilot Schemas ───────────────────────────────────────────────────────────

export const copilotChatSchema = z.object({
  message: z.string()
    .min(1, 'Message is required')
    .max(4000, 'Message too long'),
  assistant: z.enum(['analyst', 'audit', 'documentation', 'incident'])
    .default('analyst'),
  session_id: z.number()
    .int('Session ID must be an integer')
    .positive('Session ID must be positive')
    .optional()
});

export const copilotSessionSchema = z.object({
  assistant: z.enum(['analyst', 'audit', 'documentation', 'incident'])
    .default('analyst'),
  title: z.string()
    .max(500, 'Title too long')
    .optional()
});

// ─── User Management Schemas ───────────────────────────────────────────────────

export const userCreateSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username must be less than 50 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),
  email: z.string()
    .email('Invalid email address')
    .max(255, 'Email too long'),
  role: z.enum(['org_admin', 'soc_analyst', 'executive_viewer'])
    .default('soc_analyst'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password must be less than 128 characters')
});

export const userUpdateSchema = z.object({
  email: z.string()
    .email('Invalid email address')
    .max(255, 'Email too long')
    .optional(),
  role: z.enum(['org_admin', 'soc_analyst', 'executive_viewer'])
    .optional(),
  is_active: z.boolean().optional()
});

// ─── Engine Configuration Schemas ──────────────────────────────────────────────

export const engineSettingsSchema = z.object({
  WINDOW_SIZE: z.number()
    .int('Window size must be an integer')
    .min(30, 'Window size must be at least 30 seconds')
    .max(300, 'Window size must be at most 300 seconds')
    .optional(),
  EVENT_INTERVAL: z.number()
    .int('Event interval must be an integer')
    .min(50, 'Event interval must be at least 50ms')
    .max(1000, 'Event interval must be at most 1000ms')
    .optional(),
  ZSCORE_THRESHOLD: z.number()
    .min(1.5, 'Z-score threshold must be at least 1.5')
    .max(6.0, 'Z-score threshold must be at most 6.0')
    .optional(),
  EWMA_ALPHA: z.number()
    .min(0.01, 'EWMA alpha must be at least 0.01')
    .max(1.0, 'EWMA alpha must be at most 1.0')
    .optional(),
  IFOREST_ENABLED: z.boolean().optional(),
  HYBRID_FUSION: z.boolean().optional()
});

// ─── Export validation middleware helper ───────────────────────────────────────

export function validateRequest(schema: z.ZodSchema) {
  return (req: any, res: any, next: Function) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          error: 'Validation failed',
          details: error.issues.map(e => ({
            field: e.path.join('.'),
            message: e.message
          }))
        });
      } else {
        next(error);
      }
    }
  };
}