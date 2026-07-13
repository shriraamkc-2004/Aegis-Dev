/**
 * Aegis Enterprise — AI Session Manager
 *
 * Implements a memory boundary to prevent cross-tenant session data contamination.
 * Stores conversation history in memory with explicit tenant validation.
 */

import { logStructured } from "../observability/logger.js";

export interface ChatMessage {
  role: "user" | "model";
  content: string;
  timestamp: number;
}

export interface SessionContext {
  session_id: string;
  tenant_id: number;
  messages: ChatMessage[];
  last_activity: number;
}

export class AISessionManager {
  private sessions: Map<string, SessionContext> = new Map();

  /**
   * Retrieve session messages. Validates tenant identity to enforce isolation.
   */
  getSession(sessionId: string, tenantId: number): ChatMessage[] {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return [];
    }

    // Security Boundary check: Cross-tenant session access prevention
    if (session.tenant_id !== tenantId) {
      logStructured(
        "error",
        "[AISessionManager] CRITICAL: Access denied to session of another tenant",
        {
          sessionId,
          attemptedTenantId: tenantId,
          actualTenantId: session.tenant_id,
        },
      );
      throw new Error("Session access denied: Tenant mismatch.");
    }

    session.last_activity = Date.now();
    return session.messages;
  }

  /**
   * Append a message to the session. Validates tenant identity.
   */
  appendMessage(
    sessionId: string,
    tenantId: number,
    role: "user" | "model",
    content: string,
  ): void {
    let session = this.sessions.get(sessionId);

    if (!session) {
      session = {
        session_id: sessionId,
        tenant_id: tenantId,
        messages: [],
        last_activity: Date.now(),
      };
      this.sessions.set(sessionId, session);
    }

    // Security Boundary check
    if (session.tenant_id !== tenantId) {
      logStructured(
        "error",
        "[AISessionManager] CRITICAL: Session injection attempt blocked",
        {
          sessionId,
          attemptedTenantId: tenantId,
          actualTenantId: session.tenant_id,
        },
      );
      throw new Error("Session update denied: Tenant mismatch.");
    }

    session.messages.push({
      role,
      content,
      timestamp: Date.now(),
    });

    // Prune very old sessions or messages to avoid memory leak DoS
    if (session.messages.length > 50) {
      session.messages.shift(); // Keep window small
    }
    session.last_activity = Date.now();
  }

  /**
   * Clear session.
   */
  clearSession(sessionId: string, tenantId: number): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      if (session.tenant_id !== tenantId) {
        throw new Error("Session clearance denied: Tenant mismatch.");
      }
      this.sessions.delete(sessionId);
    }
  }

  /**
   * Purge sessions inactive for more than 1 hour.
   */
  purgeExpiredSessions(): void {
    const now = Date.now();
    const expiryWindow = 60 * 60 * 1000; // 1 hour
    for (const [sid, sess] of this.sessions.entries()) {
      if (now - sess.last_activity > expiryWindow) {
        this.sessions.delete(sid);
      }
    }
  }
}

export const aiSessionManager = new AISessionManager();
