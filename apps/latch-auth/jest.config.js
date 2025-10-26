// latch-apps/apps/latch-auth/jest.config.js
const { createDefaultPreset } = require('ts-jest');

const preset = createDefaultPreset();

module.exports = {
  ...preset,
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: '<rootDir>/latch-auth-ci-artifacts',
        outputName: 'junit.xml',
      },
    ],
  ],
  collectCoverage: true,
  coverageDirectory: '<rootDir>/latch-auth-ci-artifacts/coverage',
  collectCoverageFrom: ['src/**/*.ts'],
  transformIgnorePatterns: ['node_modules'],
};