/**
 * Storybook Configuration for iSECTECH Protect
 * Production-grade component documentation and testing
 */

import type { StorybookConfig } from '@storybook/nextjs';
import path from 'path';

const config: StorybookConfig = {
  stories: ['../app/components/**/*.stories.@(js|jsx|ts|tsx|mdx)', '../stories/**/*.stories.@(js|jsx|ts|tsx|mdx)'],

  addons: [
    '@storybook/addon-links',
    '@storybook/addon-essentials',
    '@storybook/addon-interactions',
    '@storybook/addon-a11y',
    '@storybook/addon-coverage',
    {
      name: '@storybook/addon-docs',
      options: {
        configureJSX: true,
      },
    },
  ],

  framework: {
    name: '@storybook/nextjs',
    options: {},
  },

  typescript: {
    check: false,
    reactDocgen: 'react-docgen-typescript',
    reactDocgenTypescriptOptions: {
      shouldExtractLiteralValuesFromEnum: true,
      propFilter: (prop) => (prop.parent ? !/node_modules/.test(prop.parent.fileName) : true),
    },
  },

  webpackFinal: async (config) => {
    // Add aliases for imports
    if (config.resolve) {
      config.resolve.alias = {
        ...config.resolve.alias,
        '@': path.resolve(__dirname, '../'),
        '@/app': path.resolve(__dirname, '../app'),
        '@/components': path.resolve(__dirname, '../app/components'),
        '@/lib': path.resolve(__dirname, '../app/lib'),
        '@/types': path.resolve(__dirname, '../app/types'),
        '@/utils': path.resolve(__dirname, '../app/lib/utils'),
        '@/hooks': path.resolve(__dirname, '../app/lib/hooks'),
        '@/store': path.resolve(__dirname, '../app/lib/store'),
      };
    }

    return config;
  },

  features: {
    buildStoriesJson: true,
    interactionsDebugger: true,
  },

  docs: {
    autodocs: 'tag',
  },

  staticDirs: ['../public'],

  core: {
    disableTelemetry: true,
  },

  // Security-focused build configuration
  managerHead: (head) => `
    ${head}
    <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https:; font-src 'self' data:;">
  `,
};

export default config;
