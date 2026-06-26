/**
 * Aegis Enterprise - Redis Caching Utility
 * Provides helpers to cache high-frequency query results.
 */
import redis from './client.js';

export async function getCached<T>(key: string): Promise<T | null> {
  try {
    const data = await redis.get(key);
    if (!data) return null;
    return JSON.parse(data);
  } catch (err) {
    console.error(`[Redis Cache] GET error for key ${key}:`, err);
    return null;
  }
}

export async function setCached<T>(key: string, value: T, ttlSeconds = 30): Promise<void> {
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  } catch (err) {
    console.error(`[Redis Cache] SET error for key ${key}:`, err);
  }
}

export async function invalidateCache(key: string): Promise<void> {
  try {
    await redis.del(key);
  } catch (err) {
    console.error(`[Redis Cache] DEL error for key ${key}:`, err);
  }
}

export async function invalidatePattern(pattern: string): Promise<void> {
  try {
    const keys = await redis.keys(pattern);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } catch (err) {
    console.error(`[Redis Cache] Pattern DEL error for pattern ${pattern}:`, err);
  }
}
