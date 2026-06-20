import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// Extend Express Request type
export interface AuthenticatedRequest extends Request {
  user?: {
    id: number;
    email: string;
    role: 'Admin' | 'SOC Analyst' | 'Auditor' | 'Viewer';
  };
}

// Validates Bearer JWT header token
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Access denied. No token provided." });
    return;
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "dev-secret-key") as any;
    (req as AuthenticatedRequest).user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token." });
  }
}

// Restricts access to matching security profiles
export function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    if (!user) {
      res.status(401).json({ error: "Unauthorized. Authentication required." });
      return;
    }
    if (!allowedRoles.includes(user.role)) {
      res.status(403).json({ error: "Forbidden. Insufficient permissions." });
      return;
    }
    next();
  };
}
