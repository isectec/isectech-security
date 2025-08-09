/**
 * Storybook Preview Configuration for iSECTECH Protect
 * Global settings for component stories
 */

import { CssBaseline } from '@mui/material';
import { ThemeProvider } from '@mui/material/styles';
import type { Preview } from '@storybook/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import React from 'react';
import '../app/globals.css';
import { theme } from '../app/providers/theme-provider';

// Create a QueryClient for stories
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      gcTime: 0,
    },
  },
});

// Global decorators
const withTheme = (Story: any) => {
  return React.createElement(ThemeProvider, { theme }, React.createElement(CssBaseline), React.createElement(Story));
};

const withQueryClient = (Story: any) => {
  return React.createElement(QueryClientProvider, { client: queryClient }, React.createElement(Story));
};

const preview: Preview = {
  parameters: {
    actions: { argTypesRegex: '^on[A-Z].*' },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/,
      },
      expanded: true,
    },
    docs: {
      extractComponentDescription: (component, { notes }) => {
        if (notes) {
          return typeof notes === 'string' ? notes : notes.markdown || notes.text;
        }
        return null;
      },
    },

    // Accessibility testing configuration
    a11y: {
      config: {
        rules: [
          {
            id: 'color-contrast',
            enabled: true,
          },
          {
            id: 'aria-valid-attr',
            enabled: true,
          },
          {
            id: 'aria-required-attr',
            enabled: true,
          },
          {
            id: 'keyboard-navigation',
            enabled: true,
          },
        ],
        tags: ['wcag2a', 'wcag2aa', 'wcag21aa', 'section508'],
      },
      options: {
        checks: { 'color-contrast': { options: { noScroll: true } } },
        restoreScroll: true,
      },
    },

    // Layout configuration
    layout: 'fullscreen',

    // Viewport configuration for security dashboard testing
    viewport: {
      viewports: {
        securityAnalyst: {
          name: 'Security Analyst (1920x1080)',
          styles: {
            width: '1920px',
            height: '1080px',
          },
        },
        soc: {
          name: 'SOC Display (2560x1440)',
          styles: {
            width: '2560px',
            height: '1440px',
          },
        },
        mobile: {
          name: 'Mobile Security (375x812)',
          styles: {
            width: '375px',
            height: '812px',
          },
        },
        tablet: {
          name: 'Tablet Security (768x1024)',
          styles: {
            width: '768px',
            height: '1024px',
          },
        },
      },
      defaultViewport: 'securityAnalyst',
    },

    // Background configuration
    backgrounds: {
      default: 'dark',
      values: [
        {
          name: 'dark',
          value: '#0a0e1a',
        },
        {
          name: 'light',
          value: '#ffffff',
        },
        {
          name: 'soc-dark',
          value: '#1a1a2e',
        },
      ],
    },
  },

  decorators: [withQueryClient, withTheme],

  // Global types for story args
  argTypes: {
    // Security-specific arg types
    severity: {
      control: {
        type: 'select',
        options: ['low', 'medium', 'high', 'critical'],
      },
    },
    threatLevel: {
      control: {
        type: 'select',
        options: ['minimal', 'low', 'medium', 'high', 'critical'],
      },
    },
    complianceStatus: {
      control: {
        type: 'select',
        options: ['compliant', 'non-compliant', 'pending', 'unknown'],
      },
    },
    userRole: {
      control: {
        type: 'select',
        options: ['viewer', 'analyst', 'admin', 'super-admin'],
      },
    },
  },

  // Global args
  args: {
    // Default security context
    userRole: 'analyst',
    tenantId: 'default-tenant',
    darkMode: true,
  },
};

export default preview;
