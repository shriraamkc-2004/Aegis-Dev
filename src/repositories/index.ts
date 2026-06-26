/**
 * Aegis Enterprise SOC Platform - Repositories
 * Centralized data access layer encapsulating Prisma (PostgreSQL) operations.
 */

import { getPrismaClient } from "../saas/prisma_client.js";

// Helper helper to get database client
function db() {
  return getPrismaClient();
}

// 1. Organization Repository
export class OrganizationRepository {
  static async create(data: { name: string; slug: string; description?: string }) {
    return db().organization.create({ data });
  }

  static async findById(id: number) {
    return db().organization.findUnique({
      where: { id },
      include: { _count: { select: { users: true } } },
    });
  }

  static async findBySlug(slug: string) {
    return db().organization.findUnique({ where: { slug } });
  }

  static async update(id: number, data: { name?: string; slug?: string; description?: string }) {
    return db().organization.update({ where: { id }, data });
  }

  static async list() {
    return db().organization.findMany({
      include: { _count: { select: { users: true } } },
      orderBy: { id: "asc" },
    });
  }
}

// 2. User Repository
export class UserRepository {
  static async create(data: {
    username: string;
    email?: string;
    password_hash: string;
    role: any;
    organization_id?: number;
    is_active?: boolean;
    email_verified?: boolean;
  }) {
    return db().user.create({ data });
  }

  static async findById(id: number, orgId?: number) {
    return db().user.findFirst({
      where: {
        id,
        ...(orgId !== undefined && { organization_id: orgId }),
      },
      include: { organization: true },
    });
  }

  static async findByEmail(email: string) {
    return db().user.findUnique({
      where: { email: email.toLowerCase().trim() },
      include: { organization: true },
    });
  }

  static async findByUsername(username: string) {
    return db().user.findUnique({
      where: { username: username.toLowerCase().trim() },
      include: { organization: true },
    });
  }

  static async update(id: number, data: any, orgId?: number) {
    // Ensure tenant isolation
    const user = await this.findById(id, orgId);
    if (!user) throw new Error("User not found or access denied.");
    return db().user.update({ where: { id }, data });
  }

  static async delete(id: number, orgId?: number) {
    const user = await this.findById(id, orgId);
    if (!user) throw new Error("User not found or access denied.");
    return db().user.delete({ where: { id } });
  }

  static async list(orgId?: number) {
    return db().user.findMany({
      where: {
        ...(orgId !== undefined && { organization_id: orgId }),
      },
      include: { organization: true },
      orderBy: { id: "asc" },
    });
  }
}

// 3. Event Repository
export class EventRepository {
  static async create(data: {
    event_type: string;
    source: string;
    timestamp: Date;
    organization_id: number;
    raw_data?: any;
  }) {
    return db().telemetryEvent.create({ data });
  }

  static async findMany(orgId: number, cutoff: Date) {
    return db().telemetryEvent.findMany({
      where: {
        organization_id: orgId,
        timestamp: { gte: cutoff },
      },
    });
  }
}

// 4. Alert Repository (represented by anomalies in schema)
export class AlertRepository {
  static async create(data: {
    organization_id: number;
    timestamp: Date;
    z_score: number;
    iforest_score: number;
    ewma_score: number;
    hybrid_score: number;
    severity: string;
    event_count: number;
    source_entropy: number;
    burst_ratio: number;
    status: string;
    diagnosis: string;
    possible_threat?: string;
    threat_confidence?: number;
    recommendation?: string;
    detection_method: string;
  }) {
    return db().anomaly.create({ data });
  }

  static async findById(id: bigint, orgId: number) {
    return db().anomaly.findFirst({
      where: {
        id,
        organization_id: orgId,
      },
    });
  }

  static async update(id: bigint, orgId: number, data: any) {
    return db().anomaly.updateMany({
      where: { id, organization_id: orgId },
      data,
    });
  }
}

// 5. Incident Repository
export class IncidentRepository {
  static async create(data: {
    organization_id: number;
    anomaly_id?: bigint;
    title: string;
    description?: string;
    status?: string;
    severity?: string;
    detection_time: Date;
    root_cause?: string;
    ai_diagnosis?: string;
    recommended_action?: string;
  }) {
    return db().incident.create({ data });
  }

  static async findById(id: bigint, orgId: number) {
    return db().incident.findFirst({
      where: { id, organization_id: orgId },
      include: { anomaly: true },
    });
  }

  static async update(id: bigint, orgId: number, data: any) {
    return db().incident.updateMany({
      where: { id, organization_id: orgId },
      data,
    });
  }
}

// 6. Threat Repository (Classification results mapped to anomalies/incidents metadata)
export class ThreatRepository {
  static async updateThreatIntel(anomalyId: bigint, orgId: number, data: {
    possible_threat: string;
    threat_confidence: number;
    recommendation: string;
  }) {
    return db().anomaly.updateMany({
      where: { id: anomalyId, organization_id: orgId },
      data,
    });
  }
}

// 7. Audit Repository
export class AuditRepository {
  static async log(data: {
    organization_id?: number;
    user_id?: number;
    username: string;
    action: string;
    resource: string;
    details?: string;
    ip_address: string;
  }) {
    return db().auditLog.create({ data });
  }

  static async list(orgId?: number) {
    return db().auditLog.findMany({
      where: {
        ...(orgId !== undefined && { organization_id: orgId }),
      },
      orderBy: { timestamp: "desc" },
    });
  }
}

// 8. Knowledge Repository (represented by chat messages/sessions in vector store context)
export class KnowledgeRepository {
  static async getChatSession(id: number, orgId: number) {
    return db().chatSession.findFirst({
      where: { id, organization_id: orgId },
      include: { messages: true },
    });
  }
}

// 9. Policy Repository (represented by connectors configuration mapping metadata)
export class PolicyRepository {
  static async listConnectors(orgId: number) {
    return db().connector.findMany({
      where: { organization_id: orgId },
    });
  }
}

// 10. Notification Repository
export class NotificationRepository {
  static async findMany(orgId: number) {
    return db().chatMessage.findMany({
      where: { session: { organization_id: orgId } },
    });
  }
}
