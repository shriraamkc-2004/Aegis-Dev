import config from "./jest.config.ts";

export default {
  ...config,
  testResultsProcessor: undefined,
  setupFilesAfterEnv: [],
  testRegex: undefined,
  testMatch: ["**/test/unit/**/*.test.ts"],
  moduleNameMapper: {
    "^uuid$": "<rootDir>/test/mocks/uuid.ts",
    "^(\\.\\.?/.*)\\.js$": "$1",
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};
