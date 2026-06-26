import config from './jest.config.ts';

export default {
  ...config,
  testResultsProcessor: undefined,
  setupFilesAfterEnv: []
};
