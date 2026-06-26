import { getCached, setCached, invalidateCache } from '../../src/redis/cache.js';

// Mock the redis client
jest.mock('../../src/redis/client.js', () => {
  const store = new Map();
  return {
    __esModule: true,
    default: {
      get: jest.fn().mockImplementation(async (key) => store.get(key) || null),
      set: jest.fn().mockImplementation(async (key, val) => {
        store.set(key, val);
        return 'OK';
      }),
      del: jest.fn().mockImplementation(async (...keys) => {
        let count = 0;
        for (const k of keys) {
          if (store.delete(k)) count++;
        }
        return count;
      }),
      keys: jest.fn().mockImplementation(async (pattern) => {
        return Array.from(store.keys());
      })
    }
  };
});

describe('Redis Cache Helpers', () => {
  it('should cache and retrieve items correctly', async () => {
    const data = { foo: 'bar' };
    await setCached('test-key', data, 10);
    const retrieved = await getCached<typeof data>('test-key');
    expect(retrieved).toEqual(data);
  });

  it('should return null for non-existent key', async () => {
    const retrieved = await getCached('non-existent');
    expect(retrieved).toBeNull();
  });

  it('should invalidate key correctly', async () => {
    await setCached('invalidate-key', 'some-value');
    await invalidateCache('invalidate-key');
    const retrieved = await getCached('invalidate-key');
    expect(retrieved).toBeNull();
  });
});
