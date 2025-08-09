/**
 * Jest Configuration for iSECTECH Protect
 * Production-grade testing setup for cybersecurity frontend
 */

const nextJest = require('next/jest');

const createJestConfig = nextJest({
  // Provide the path to your Next.js app to load next.config.js and .env files
  dir: './',
});

// Add any custom config to be passed to Jest
const customJestConfig = {
  // Test environment
  testEnvironment: 'jsdom',

  // Setup files
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],

  // Module paths
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/$1',
    '^@/app/(.*)$': '<rootDir>/app/$1',
    '^@/components/(.*)$': '<rootDir>/app/components/$1',
    '^@/lib/(.*)$': '<rootDir>/app/lib/$1',
    '^@/types/(.*)$': '<rootDir>/app/types/$1',
    '^@/hooks/(.*)$': '<rootDir>/app/lib/hooks/$1',
    '^@/utils/(.*)$': '<rootDir>/app/lib/utils/$1',
    '^@/store/(.*)$': '<rootDir>/app/lib/store/$1',
  },

  // Test file patterns
  testMatch: [
    '<rootDir>/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/**/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],

  // Test directories to ignore
  testPathIgnorePatterns: [
    '<rootDir>/.next/',
    '<rootDir>/node_modules/',
    '<rootDir>/build/',
    '<rootDir>/dist/',
    '<rootDir>/cypress/',
    '<rootDir>/playwright/',
  ],

  // Coverage configuration
  collectCoverageFrom: [
    'app/**/*.{js,jsx,ts,tsx}',
    '!app/**/*.d.ts',
    '!app/**/index.ts',
    '!app/**/index.tsx',
    '!app/layout.tsx',
    '!app/page.tsx',
    '!app/globals.css',
    '!**/*.stories.{js,jsx,ts,tsx}',
    '!**/node_modules/**',
  ],

  // Coverage thresholds for security components
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    // Higher thresholds for critical security components
    'app/components/alerts/**': {
      branches: 95,
      functions: 95,
      lines: 95,
      statements: 95,
    },
    'app/lib/store/**': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    'app/lib/store/auth.ts': {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
    'app/lib/utils/accessibility.ts': {
      branches: 98,
      functions: 98,
      lines: 98,
      statements: 98,
    },
    'app/lib/utils/security.ts': {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
    'app/components/layout/**': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85,
    },
  },

  // Coverage output
  coverageDirectory: '<rootDir>/coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json-summary', 'clover'],

  // Test timeout for security operations
  testTimeout: 30000,

  // Transform configuration
  transform: {
    '^.+\\.(js|jsx|ts|tsx)$': ['babel-jest', { presets: ['next/babel'] }],
  },

  // Module file extensions
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json'],

  // Global test setup
  globalSetup: '<rootDir>/__tests__/setup/global-setup.ts',
  globalTeardown: '<rootDir>/__tests__/setup/global-teardown.ts',

  // Test reporter configuration
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: './test-results',
        outputName: 'jest-results.xml',
        classNameTemplate: '{classname}',
        titleTemplate: '{title}',
        ancestorSeparator: ' › ',
        usePathForSuiteName: true,
      },
    ],
    [
      'jest-html-reporters',
      {
        publicPath: './test-results',
        filename: 'jest-report.html',
        expand: true,
      },
    ],
  ],

  // Verbose output for security testing
  verbose: true,

  // Security-specific test environment variables
  setupFiles: ['<rootDir>/__tests__/setup/env-setup.ts'],

  // Mock configuration for external dependencies
  moduleNameMapping: {
    ...require('./jest.moduleNameMapping.js'),
  },
};

// createJestConfig is exported this way to ensure that next/jest can load the Next.js config which is async
module.exports = createJestConfig(customJestConfig);
