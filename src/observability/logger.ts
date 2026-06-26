/**
 * Aegis Enterprise - Observability Logger & Request ID Middleware
 * Implements structured JSON logging and trace propagation.
 */
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

export interface LogMetadata {
  traceId?: string;
  requestId?: string;
  userId?: number;
  orgId?: number;
  [key: string]: any;
}

export function logStructured(level: 'info' | 'warn' | 'error', message: string, meta: LogMetadata = {}) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta
  };
  console.log(JSON.stringify(logEntry));
}

// Middleware to inject Request ID and Trace ID and log HTTP requests
export function requestLoggerMiddleware(req: Request, res: Response, next: NextFunction) {
  const requestId = (req.headers['x-request-id'] as string) || uuidv4();
  const traceId = (req.headers['x-trace-id'] as string) || uuidv4();

  // Attach to request object
  (req as any).requestId = requestId;
  (req as any).traceId = traceId;

  // Add headers to response
  res.setHeader('x-request-id', requestId);
  res.setHeader('x-trace-id', traceId);

  const startTime = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const user = (req as any).user;
    const userId = user?.id;
    const orgId = user?.organization_id;

    logStructured('info', `${req.method} ${req.originalUrl} - ${res.statusCode}`, {
      requestId,
      traceId,
      userId,
      orgId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      durationMs: duration
    });
  });

  next();
}
