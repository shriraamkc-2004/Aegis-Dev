/**
 * Aegis Enterprise — In-Memory State Client (Redis Alternative)
 * Provides a stubbed client to prevent connection errors when running in standalone mode.
 */

export const mockRedisClient = {
  status: "ready",
  get: async (_key: string) => null,
  set: async (_key: string, _val: string, ..._args: any[]) => "OK",
  del: async (..._keys: string[]) => 1,
  keys: async (_pattern: string) => [],
  incrby: async (_key: string, amount: number) => amount,
  decrby: async (_key: string, amount: number) => amount,
  expire: async (_key: string, _seconds: number) => 1,
  ping: async () => "PONG",
  on: () => {},
};

export async function checkRedisHealth(): Promise<boolean> {
  return true;
}

export default mockRedisClient as any;
