/**
 * Aegis Enterprise — Prompt Registry Service
 * Manages prompt templates with versioning, rollback, and governance review.
 */

import { dbRun, dbAll, dbGet } from "../server_db.js";

// ─── Types ──────────────────────────────────────────────────────────────────────

export interface PromptEntry {
  id?: number;
  tenant_id: number;
  name: string;
  version: number;
  category:
    "general" | "analyst" | "audit" | "documentation" | "incident" | "system";
  prompt_template: string;
  system_hint: string;
  variables: Record<string, string>;
  is_active: boolean;
  governance_reviewed: boolean;
  reviewed_by: number | null;
  created_by: number | null;
  created_at?: number;
  updated_at?: number;
}

export interface PromptVersion {
  version: number;
  prompt_template: string;
  system_hint: string;
  is_active: boolean;
  governance_reviewed: boolean;
  created_at: number;
}

// ─── Default Prompt Templates ───────────────────────────────────────────────────

export const DEFAULT_PROMPTS: Omit<
  PromptEntry,
  "id" | "created_at" | "updated_at"
>[] = [
  {
    tenant_id: 1,
    name: "analyst_system",
    version: 1,
    category: "analyst",
    prompt_template:
      "You are the Aegis Analyst Assistant. Help SOC analysts understand anomalies, " +
      "explain severity decisions, recommend mitigations, and guide investigations. " +
      "Always reference specific data points and retrieved evidence. " +
      "CRITICAL SAFETY LIMITS: " +
      "1. ONLY reference facts present in the Evidence Bundle. " +
      "2. NEVER speculate or invent CVEs, MITRE techniques, IPs, or threat actors. " +
      "3. Cite all sources explicitly.",
    system_hint: "Analyst persona active. Cite all sources.",
    variables: {},
    is_active: true,
    governance_reviewed: true,
    reviewed_by: null,
    created_by: null,
  },
  {
    tenant_id: 1,
    name: "audit_system",
    version: 1,
    category: "audit",
    prompt_template:
      "You are the Aegis Audit Assistant. Summarize audit findings, highlight critical risks, " +
      "and recommend OWASP Top 10 improvements. Cite specific evidence from audit logs. " +
      "CRITICAL SAFETY LIMITS: " +
      "1. ONLY reference facts present in the Evidence Bundle. " +
      "2. NEVER speculate or invent CVEs, MITRE techniques, IPs, or threat actors. " +
      "3. Cite all sources explicitly.",
    system_hint: "Audit persona active. Focus on compliance.",
    variables: {},
    is_active: true,
    governance_reviewed: true,
    reviewed_by: null,
    created_by: null,
  },
  {
    tenant_id: 1,
    name: "documentation_system",
    version: 1,
    category: "documentation",
    prompt_template:
      "You are the Aegis Documentation Assistant. Explain system architecture, workflows, " +
      "setup procedures, and operational guides. Reference documentation sources explicitly. " +
      "CRITICAL SAFETY LIMITS: " +
      "1. ONLY reference facts present in the Evidence Bundle. " +
      "2. NEVER speculate or invent CVEs, MITRE techniques, IPs, or threat actors. " +
      "3. Cite all sources explicitly.",
    system_hint: "Documentation persona active. Be precise.",
    variables: {},
    is_active: true,
    governance_reviewed: true,
    reviewed_by: null,
    created_by: null,
  },
  {
    tenant_id: 1,
    name: "incident_system",
    version: 1,
    category: "incident",
    prompt_template:
      "You are the Aegis Incident Intelligence Assistant. Retrieve similar historical incidents, " +
      "summarize previous investigations, and recommend next steps based on lessons learned. " +
      "CRITICAL SAFETY LIMITS: " +
      "1. ONLY reference facts present in the Evidence Bundle. " +
      "2. NEVER speculate or invent CVEs, MITRE techniques, IPs, or threat actors. " +
      "3. Cite all sources explicitly.",
    system_hint: "Incident persona active. Reference historical data.",
    variables: {},
    is_active: true,
    governance_reviewed: true,
    reviewed_by: null,
    created_by: null,
  },
  {
    tenant_id: 1,
    name: "react_agent",
    version: 1,
    category: "system",
    prompt_template:
      "You are the autonomous Aegis ReAct AI Agent. Your objective is investigate and solve Anomaly ID #{{anomalyId}} using our local tool server.\n" +
      "Available tools metadata:\n{{mcpToolsDesc}}\n\n" +
      "You MUST proceed strictly by outputting steps in the following formatting block:\n" +
      "Thought: <what you are reasoning>\n" +
      'Action: <json representation of tool call, e.g. {"name": "query_database", "arguments": {"sql_query": "SELECT ..."}} >\n' +
      "Observation: <this will be provided in the next turn>\n\n" +
      "When the issue is resolved or you are summarizing, output:\n" +
      "Final Response: <your ultimate diagnosis and security mitigation summary>\n\n" +
      'IMPORTANT: Do not duplicate or combine blocks. Exit immediately when producing a "Final Response:".\n' +
      "Begin by inspecting recent event rates with a SELECT query via query_database.",
    system_hint: "ReAct agent persona active. Enforce ReAct format rules.",
    variables: {},
    is_active: true,
    governance_reviewed: true,
    reviewed_by: null,
    created_by: null,
  },
];

// ─── Prompt Registry Service ────────────────────────────────────────────────────

export class PromptRegistryService {
  private inMemoryStore: Map<string, PromptEntry[]> = new Map();

  constructor() {
    // Initialize with defaults in memory
    for (const prompt of DEFAULT_PROMPTS) {
      const key = `${prompt.tenant_id}:${prompt.name}`;
      if (!this.inMemoryStore.has(key)) {
        this.inMemoryStore.set(key, []);
      }
      this.inMemoryStore.get(key)!.push({ ...prompt });
    }
  }

  // ─── Create / Update ──────────────────────────────────────────────────────

  async createPrompt(entry: PromptEntry): Promise<PromptEntry> {
    const key = `${entry.tenant_id}:${entry.name}`;
    const existing = this.inMemoryStore.get(key) || [];
    const maxVersion = existing.reduce((max, e) => Math.max(max, e.version), 0);
    const newEntry = { ...entry, version: maxVersion + 1 };

    // Deactivate all previous versions
    for (const e of existing) {
      e.is_active = false;
    }
    newEntry.is_active = true;

    existing.push(newEntry);
    this.inMemoryStore.set(key, existing);

    return newEntry;
  }

  async updatePrompt(
    tenantId: number,
    name: string,
    updates: Partial<PromptEntry>,
    userId: number,
  ): Promise<PromptEntry | null> {
    const key = `${tenantId}:${name}`;
    const versions = this.inMemoryStore.get(key);
    if (!versions || versions.length === 0) return null;

    // Create new version
    const latest = versions[versions.length - 1];
    const newVersion = await this.createPrompt({
      ...latest,
      ...updates,
      tenant_id: tenantId,
      name,
      version: latest.version + 1,
      is_active: true,
      created_by: userId,
    });

    return newVersion;
  }

  // ─── Retrieval ────────────────────────────────────────────────────────────

  async getActivePrompt(
    tenantId: number,
    name: string,
  ): Promise<PromptEntry | null> {
    const key = `${tenantId}:${name}`;
    const versions = this.inMemoryStore.get(key);
    if (!versions) return null;
    return (
      versions.find((v) => v.is_active) || versions[versions.length - 1] || null
    );
  }

  async getPromptVersions(
    tenantId: number,
    name: string,
  ): Promise<PromptVersion[]> {
    const key = `${tenantId}:${name}`;
    const versions = this.inMemoryStore.get(key) || [];
    return versions.map((v) => ({
      version: v.version,
      prompt_template: v.prompt_template,
      system_hint: v.system_hint,
      is_active: v.is_active,
      governance_reviewed: v.governance_reviewed,
      created_at: v.created_at || Date.now(),
    }));
  }

  async getAllPrompts(tenantId: number): Promise<PromptEntry[]> {
    const results: PromptEntry[] = [];
    for (const [key, versions] of this.inMemoryStore.entries()) {
      if (key.startsWith(`${tenantId}:`)) {
        const active = versions.find((v) => v.is_active);
        if (active) results.push(active);
      }
    }
    return results;
  }

  // ─── Rollback ─────────────────────────────────────────────────────────────

  async rollbackToVersion(
    tenantId: number,
    name: string,
    targetVersion: number,
    userId: number,
  ): Promise<PromptEntry | null> {
    const key = `${tenantId}:${name}`;
    const versions = this.inMemoryStore.get(key);
    if (!versions) return null;

    const target = versions.find((v) => v.version === targetVersion);
    if (!target) return null;

    // Deactivate all
    for (const v of versions) v.is_active = false;

    // Create new version based on target
    const rolledBack = await this.createPrompt({
      ...target,
      is_active: true,
      created_by: userId,
    });

    return rolledBack;
  }

  // ─── Governance Review ────────────────────────────────────────────────────

  async markGovernanceReviewed(
    tenantId: number,
    name: string,
    reviewerId: number,
  ): Promise<boolean> {
    const key = `${tenantId}:${name}`;
    const versions = this.inMemoryStore.get(key);
    if (!versions) return false;

    const active = versions.find((v) => v.is_active);
    if (!active) return false;

    active.governance_reviewed = true;
    active.reviewed_by = reviewerId;
    return true;
  }

  // ─── Health ───────────────────────────────────────────────────────────────

  getStatus() {
    return {
      total_prompts: this.inMemoryStore.size,
      total_versions: Array.from(this.inMemoryStore.values()).reduce(
        (sum, v) => sum + v.length,
        0,
      ),
    };
  }
}

// Singleton instance
export const promptRegistry = new PromptRegistryService();
