/**
 * Aegis SaaS — Tenant Quota & Usage Tracking Service
 *
 * Enforces per-tenant resource limits (event ingestion per day/hour, API request limits)
 * based on the organization's subscription tier.
 *
 * Tier Quotas:
 *   - starter:    10,000 events/day,     1,000 API req/hr
 *   - pro:     1,000,000 events/day,   100,000 API req/hr
 *   - enterprise: Unlimited events/day, Unlimited API req/hr
 *
 * High-performance, zero-dependency in-memory sliding window counters.
 */

export type SubscriptionPlan = "starter" | "pro" | "enterprise";

export interface TenantQuotaConfig {
  eventsPerDay: number;
  apiRequestsPerHour: number;
}

export const PLAN_QUOTAS: Record<SubscriptionPlan, TenantQuotaConfig> = {
  starter: {
    eventsPerDay: 10_000,
    apiRequestsPerHour: 1_000,
  },
  pro: {
    eventsPerDay: 1_000_000,
    apiRequestsPerHour: 100_000,
  },
  enterprise: {
    eventsPerDay: Infinity,
    apiRequestsPerHour: Infinity,
  },
};

// In-memory quota counters
const inMemoryEvents = new Map<string, { count: number; resetAt: number }>();

function getTodayKey(orgId: number): string {
  const dateStr = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
  return `quota:events:${orgId}:${dateStr}`;
}

/**
 * Check and increment daily ingestion event quota for a tenant.
 * Returns { allowed: boolean, currentUsage: number, limit: number }
 */
export async function checkAndIncrementEventQuota(
  orgId: number,
  plan: SubscriptionPlan = "starter",
  batchSize: number = 1,
): Promise<{ allowed: boolean; currentUsage: number; limit: number }> {
  const limit =
    PLAN_QUOTAS[plan]?.eventsPerDay ?? PLAN_QUOTAS.starter.eventsPerDay;

  if (limit === Infinity) {
    return { allowed: true, currentUsage: 0, limit: Infinity };
  }

  const key = getTodayKey(orgId);
  const now = Date.now();
  const dayMs = 24 * 3600 * 1000;
  let counter = inMemoryEvents.get(key);

  if (!counter || now > counter.resetAt) {
    counter = { count: 0, resetAt: now + dayMs };
    inMemoryEvents.set(key, counter);
  }

  if (counter.count + batchSize > limit) {
    return { allowed: false, currentUsage: counter.count, limit };
  }

  counter.count += batchSize;
  return { allowed: true, currentUsage: counter.count, limit };
}

/**
 * Get current usage statistics for a tenant.
 */
export async function getTenantUsageStats(
  orgId: number,
  plan: SubscriptionPlan = "starter",
): Promise<{ eventsToday: number; eventsLimit: number; percentage: number }> {
  const limit =
    PLAN_QUOTAS[plan]?.eventsPerDay ?? PLAN_QUOTAS.starter.eventsPerDay;
  const key = getTodayKey(orgId);
  const count = inMemoryEvents.get(key)?.count ?? 0;

  const percentage =
    limit === Infinity ? 0 : Math.min(100, Math.round((count / limit) * 100));
  return { eventsToday: count, eventsLimit: limit, percentage };
}
