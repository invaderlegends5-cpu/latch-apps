// latch-apps/apps/latch-auth/jest.config.js
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
  
    // Add your source/test directories if not already defined
    roots: ['<rootDir>/src', '<rootDir>/test'],
  
    reporters: [
      'default',
      [
        'jest-junit',
        {
          outputDirectory: 'latch-auth-ci-artifacts',
          outputName: 'junit.xml',
        },
      ],
    ],
  
    // Optional but helps in CI readability
    coverageDirectory: 'latch-auth-ci-artifacts/coverage',
    collectCoverageFrom: ['src/**/*.ts'],
  };
  