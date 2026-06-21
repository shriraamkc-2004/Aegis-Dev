/**
 * Aegis Enterprise - Test Setup
 * Global test configuration, fixtures, and utilities
 */
import { PrismaClient } from '../src/generated/prisma/index.js';
import bcrypt from 'bcryptjs';

// Create test database instance using adapter pattern (Prisma v7)
const prisma = new PrismaClient({
  log: ['error'],
});

// Test user fixtures
export const testUsers = {
  superAdmin: {
    username: 'test_super_admin',
    email: 'superadmin@test.com',
    password: 'Test123!',
    role: 'super_admin' as const
  },
  orgAdmin: {
    username: 'test_org_admin',
    email: 'orgadmin@test.com',
    password: 'Test123!',
    role: 'org_admin' as const
  },
  socAnalyst: {
    username: 'test_soc_analyst',
    email: 'analyst@test.com',
    password: 'Test123!',
    role: 'soc_analyst' as const
  },
  viewer: {
    username: 'test_viewer',
    email: 'viewer@test.com',
    password: 'Test123!',
    role: 'executive_viewer' as const
  },
  demoAdmin: {
    username: 'test_demo_admin',
    email: 'demoadmin@test.com',
    password: 'Test123!',
    role: 'demo_admin' as const
  }
};

// Test organization fixture
export const testOrganization = {
  name: 'Test Organization',
  slug: 'test-org',
  description: 'Test organization for automated tests'
};

// Helper to create test user
export async function createTestUser(userData: any) {
  const hashedPassword = await bcrypt.hash(userData.password, 10);
  return prisma.user.create({
    data: {
      username: userData.username,
      email: userData.email,
      password_hash: hashedPassword,
      role: userData.role,
      is_active: true,
      email_verified: true
    }
  });
}

// Helper to create test organization
export async function createTestOrganization() {
  return prisma.organization.create({
    data: testOrganization
  });
}

// Helper to create test telemetry events
export async function createTestEvents(count: number, organizationId: number) {
  const events = [];
  const now = Date.now() / 1000;
  
  for (let i = 0; i < count; i++) {
    events.push({
      event_type: ['user_auth', 'api_request', 'order_placed', 'data_transfer'][Math.floor(Math.random() * 4)],
      source: ['web', 'api', 'vpn', 'gateway'][Math.floor(Math.random() * 4)],
      timestamp: new Date((now - Math.random() * 3600) * 1000), // Last hour
      organization_id: organizationId
    });
  }
  
  return prisma.telemetryEvent.createMany({
    data: events
  });
}

// Helper to create test anomaly
export async function createTestAnomaly(organizationId: number, overrides = {}) {
  return prisma.anomaly.create({
    data: {
      organization_id: organizationId,
      timestamp: new Date(),
      z_score: 4.5,
      iforest_score: 0.6,
      ewma_score: 2.1,
      hybrid_score: 0.55,
      severity: 'HIGH',
      event_count: 150,
      source_entropy: 3.2,
      burst_ratio: 2.5,
      status: 'PENDING',
      diagnosis: 'Test anomaly for automated testing',
      detection_method: 'HYBRID',
      ...overrides
    }
  });
}

// Helper to create test incident
export async function createTestIncident(organizationId: number, anomalyId?: bigint, overrides = {}) {
  return prisma.incident.create({
    data: {
      organization_id: organizationId,
      anomaly_id: anomalyId,
      title: 'Test Incident',
      description: 'This is a test incident for automated testing',
      status: 'OPEN',
      severity: 'HIGH',
      detection_time: new Date(),
      ...overrides
    }
  });
}

// Clean up test data
export async function cleanupTestData() {
  // Delete in reverse order of dependencies
  await prisma.chatMessage.deleteMany();
  await prisma.chatSession.deleteMany();
  await prisma.incident.deleteMany();
  await prisma.anomaly.deleteMany();
  await prisma.telemetryEvent.deleteMany();
  await prisma.auditLog.deleteMany();
  await prisma.connector.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.user.deleteMany();
  await prisma.organization.deleteMany();
}

// Clean Redis test keys (conditional on Redis being available)
export async function cleanupRedis() {
  try {
    const { default: redis } = await import('../src/redis/client');
    const keys = await redis.keys('test:*');
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } catch {
    // Redis not available — skip cleanup
  }
}

// Global setup
beforeAll(async () => {
  console.log('🧪 Starting test suite...');
  
  // Connect to database
  await prisma.$connect();
  
  // Clean up any existing test data
  await cleanupTestData();
  await cleanupRedis();
  
  console.log('✅ Test environment ready');
});

// Global teardown
afterAll(async () => {
  console.log('🧹 Cleaning up test environment...');
  
  // Clean up test data
  await cleanupTestData();
  await cleanupRedis();
  
  // Disconnect from database
  await prisma.$disconnect();
  
  // Close Redis connection (best-effort)
  try {
    const { default: redis } = await import('../src/redis/client');
    await redis.quit();
  } catch {
    // Redis not available
  }
  
  console.log('✅ Test environment cleaned up');
});

// Reset database between tests
beforeEach(async () => {
  await cleanupTestData();
  await cleanupRedis();
});

// Export Prisma client for use in tests
export { prisma };