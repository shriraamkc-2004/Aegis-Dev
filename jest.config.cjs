module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ["**/test/unit/**/*.test.ts"],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: {
        sourceMap: true,
        inlineSourceMap: true,
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        resolveJsonModule: true
      }
    }]
  },
  moduleNameMapper: {
    "^uuid$": "<rootDir>/test/mocks/uuid.ts",
    "^(\\.\\.?/.*)\\.js$": "$1",
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};
