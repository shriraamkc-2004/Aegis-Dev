/**
 * Aegis Enterprise - Jest Configuration
 * Comprehensive testing setup for unit, integration, and E2E tests
 */
import type { Config } from "jest";

const config: Config = {
  // Preset for TypeScript
  preset: "ts-jest",

  // Test environment
  testEnvironment: "node",

  // Root directory for tests
  roots: ["<rootDir>/test"],

  // Test file pattern
  testMatch: ["<rootDir>/test/**/*.test.ts", "<rootDir>/test/**/*.spec.ts"],

  // Module file extensions
  moduleFileExtensions: ["ts", "js", "json"],

  // Transform settings
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: {
          sourceMap: true,
          inlineSourceMap: true,
          esModuleInterop: true,
          allowSyntheticDefaultImports: true,
          resolveJsonModule: true,
        },
      },
    ],
  },

  // Coverage settings
  collectCoverageFrom: [
    "src/**/*.{ts,tsx}",
    "!src/**/*.d.ts",
    "!src/generated/**",
    "!src/**/*.test.ts",
    "!src/**/*.spec.ts",
  ],

  // Coverage directory
  coverageDirectory: "coverage",

  // Coverage thresholds (aiming for 80%+)
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },

  // Coverage report
  coverageReporters: ["text", "text-summary", "lcov", "html"],

  // Test results reporter
  // testResultsProcessor: 'jest-stare',

  // Verbose output
  verbose: true,

  // Force exit (prevent hanging)
  forceExit: true,

  // Detect open handles
  detectOpenHandles: true,

  // Clear mocks between tests
  clearMocks: true,

  // Reset modules between tests
  resetModules: true,

  // Setup files
  setupFilesAfterEnv: ["<rootDir>/test/setup.ts"],

  // Test timeout (30 seconds)
  testTimeout: 30000,

  // Max workers
  maxWorkers: 4,

  // Watch path ignore pattern
  watchPathIgnorePatterns: ["node_modules", "dist", "coverage"],

  // Module name mapper
  moduleNameMapper: {
    "^(\\.\\.?/.*)\\.js$": "$1",
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};

export default config;
