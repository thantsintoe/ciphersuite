module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/**/*.test.ts'],
  collectCoverage: true,
  collectCoverageFrom: ['src/**/*.ts']
};
