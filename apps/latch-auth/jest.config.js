// latch-apps/apps/latch-auth/jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: process.env.JEST_JUNIT_OUTPUT_DIR || 'latch-auth-ci-artifacts',
        outputName: process.env.JEST_JUNIT_OUTPUT_NAME || 'junit.xml',
      },
    ],
  ],
  coverageDirectory: 'latch-auth-ci-artifacts/coverage',
  collectCoverageFrom: ['src/**/*.ts'],
};
