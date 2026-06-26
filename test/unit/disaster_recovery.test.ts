import { disasterRecoveryService } from "../../src/copilot/disaster_recovery.js";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

// Mock child_process execSync
jest.mock("child_process", () => ({
  execSync: jest.fn().mockImplementation(() => "Mock output"),
  exec: jest.fn()
}));

// Mock fs methods to avoid writing actual files in unit tests
jest.mock("fs", () => {
  const original = jest.requireActual("fs");
  return {
    ...original,
    existsSync: jest.fn().mockImplementation((p) => {
      if (p.includes("core.db")) return true;
      return false;
    }),
    mkdirSync: jest.fn(),
    writeFileSync: jest.fn(),
    copyFileSync: jest.fn(),
    statSync: jest.fn().mockReturnValue({ size: 1024 }),
    unlinkSync: jest.fn()
  };
});

describe("Disaster Recovery Service", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should initialize default backup schedules", () => {
    const status = disasterRecoveryService.getStatus();
    expect(status.service).toBe("disaster_recovery");
    expect(status.schedules.length).toBe(4);
    
    const postgresSchedule = status.schedules.find(s => s.component === "postgresql");
    expect(postgresSchedule).toBeDefined();
    expect(postgresSchedule?.frequency).toBe("daily");
  });

  it("should support SQLite backup procedure", async () => {
    const record = await disasterRecoveryService.backupSQLite();
    expect(record.status).toBe("completed");
    expect(record.component).toBe("sqlite");
    expect(record.verified).toBe(true);
    expect(fs.copyFileSync).toHaveBeenCalled();
  });

  it("should support PostgreSQL backup procedure", async () => {
    const record = await disasterRecoveryService.backupPostgres();
    expect(record.status).toBe("completed");
    expect(record.component).toBe("postgresql");
    expect(record.verified).toBe(true);
    expect(execSync).toHaveBeenCalled();
  });

  it("should retrieve recovery plans for all key databases", () => {
    const plans = disasterRecoveryService.getAllRecoveryPlans();
    expect(plans.length).toBe(3);
    
    const postgresPlan = plans.find(p => p.component === "postgresql");
    expect(postgresPlan).toBeDefined();
    expect(postgresPlan?.steps.length).toBeGreaterThan(0);
  });

  it("should enforce backup retention policies correctly", () => {
    const result = disasterRecoveryService.enforceRetention();
    expect(result.kept).toBeDefined();
    expect(result.deleted).toBeDefined();
  });
});
