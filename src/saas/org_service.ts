/**
 * Aegis Phase 3A — Organization Management Service
 * CRUD operations for multi-tenant organizations.
 */

import { isPostgresConnected } from "./prisma_client.js";
import { OrganizationRepository } from "../repositories/index.js";

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .substring(0, 100);
}

// ─── Create Organization ──────────────────────────────────────────────────────────

export async function createOrganization(data: {
  name: string;
  slug?: string;
}): Promise<{ success: boolean; organization?: any; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const slug = data.slug || slugify(data.name);

  const existing = await OrganizationRepository.findBySlug(slug);
  if (existing) return { success: false, error: "Organization slug already exists." };

  const org = await OrganizationRepository.create({ name: data.name, slug });

  return { success: true, organization: org };
}

// ─── Get Organization ─────────────────────────────────────────────────────────────

export async function getOrganization(id: number): Promise<any | null> {
  const connected = await isPostgresConnected();
  if (!connected) return null;

  return OrganizationRepository.findById(id);
}

// ─── Update Organization ──────────────────────────────────────────────────────────

export async function updateOrganization(
  id: number,
  data: { name?: string; slug?: string }
): Promise<{ success: boolean; error?: string }> {
  const connected = await isPostgresConnected();
  if (!connected) return { success: false, error: "PostgreSQL unavailable." };

  const org = await OrganizationRepository.findById(id);
  if (!org) return { success: false, error: "Organization not found." };

  if (data.slug) {
    const existingSlug = await OrganizationRepository.findBySlug(data.slug);
    if (existingSlug && existingSlug.id !== id) return { success: false, error: "Slug already in use." };
  }

  await OrganizationRepository.update(id, {
    ...(data.name !== undefined && { name: data.name }),
    ...(data.slug !== undefined && { slug: data.slug }),
  });

  return { success: true };
}

// ─── List Organizations ───────────────────────────────────────────────────────────

export async function listOrganizations(): Promise<any[]> {
  const connected = await isPostgresConnected();
  if (!connected) return [];

  return OrganizationRepository.list();
}
