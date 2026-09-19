/**
 * Aegis Enterprise — In-Memory High-Performance Cache Utility
 * Provides TTL-aware caching for high-frequency query results.
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const memoryStore = new Map<string, CacheEntry<any>>();

export async function getCached<T>(key: string): Promise<T | null> {
  const entry = memoryStore.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    memoryStore.delete(key);
    return null;
  }
  return entry.value;
}

export async function setCached<T>(
  key: string,
  value: T,
  ttlSeconds = 30,
): Promise<void> {
  memoryStore.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
}

export async function invalidateCache(key: string): Promise<void> {
  memoryStore.delete(key);
}

export async function invalidatePattern(pattern: string): Promise<void> {
  const regexStr = pattern.replace(/\*/g, ".*");
  const regex = new RegExp(`^${regexStr}$`);
  for (const key of memoryStore.keys()) {
    if (regex.test(key)) {
      memoryStore.delete(key);
    }
  }
}
