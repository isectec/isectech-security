/**
 * Theme Provider for iSECTECH Protect
 * Material-UI theme configuration tailored for cybersecurity dashboard
 */

'use client';

import React, { useMemo } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import type { Theme, ThemeOptions } from '@mui/material/styles';
import { useAppStore, appSelectors } from '@/lib/store';

// Emotion cache for styled-components
const cache = createCache({
  key: 'isectech',
  prepend: true,
});

// iSECTECH Brand Colors
const brandColors = {
  primary: {
    50: '#e8f4f8',
    100: '#c5e3ee',
    200: '#9ed0e2',
    300: '#76bdd6',
    400: '#58aece',
    500: '#3a9fc5',
    600: '#3497bf',
    700: '#2c8cb7',
    800: '#2482af',
    900: '#1770a1',
  },
  secondary: {
    50: '#fdf2e8',
    100: '#f9dfc6',
    200: '#f5caa0',
    300: '#f1b579',
    400: '#eea55c',
    500: '#eb9540',
    600: '#e98d3a',
    700: '#e68232',
    800: '#e3782a',
    900: '#de671c',
  },
  error: {
    50: '#ffebee',
    100: '#ffcdd2',
    200: '#ef9a9a',
    300: '#e57373',
    400: '#ef5350',
    500: '#f44336',
    600: '#e53935',
    700: '#d32f2f',
    800: '#c62828',
    900: '#b71c1c',
  },
  warning: {
    50: '#fffbf0',
    100: '#fff4d9',
    200: '#ffecb3',
    300: '#ffe082',
    400: '#ffd54f',
    500: '#ffca28',
    600: '#ffb300',
    700: '#ff8f00',
    800: '#ff6f00',
    900: '#ff3d00',
  },
  success: {
    50: '#e8f5e8',
    100: '#c8e6c9',
    200: '#a5d6a7',
    300: '#81c784',
    400: '#66bb6a',
    500: '#4caf50',
    600: '#43a047',
    700: '#388e3c',
    800: '#2e7d32',
    900: '#1b5e20',
  },
  info: {
    50: '#e3f2fd',
    100: '#bbdefb',
    200: '#90caf9',
    300: '#64b5f6',
    400: '#42a5f5',
    500: '#2196f3',
    600: '#1e88e5',
    700: '#1976d2',
    800: '#1565c0',
    900: '#0d47a1',
  },
};

// Security-specific color palette
const securityColors = {
  threat: {
    critical: '#d32f2f',
    high: '#f57c00',
    medium: '#fbc02d',
    low: '#388e3c',
    info: '#1976d2',
  },
  clearance: {
    topSecret: '#b71c1c',
    secret: '#e65100',
    confidential: '#f57f17',
    unclassified: '#2e7d32',
  },
  status: {
    online: '#4caf50',
    offline: '#f44336',
    warning: '#ff9800',
    maintenance: '#9c27b0',
  },
  network: {
    internal: '#1976d2',
    external: '#d32f2f',
    dmz: '#ff9800',
    trusted: '#4caf50',
  },
};

// Light theme configuration
const lightThemeOptions: ThemeOptions = {
  palette: {
    mode: 'light',
    primary: brandColors.primary,
    secondary: brandColors.secondary,
    error: brandColors.error,
    warning: brandColors.warning,
    success: brandColors.success,
    info: brandColors.info,
    background: {
      default: '#fafafa',
      paper: '#ffffff',
    },
    text: {
      primary: 'rgba(0, 0, 0, 0.87)',
      secondary: 'rgba(0, 0, 0, 0.6)',
      disabled: 'rgba(0, 0, 0, 0.38)',
    },
    divider: 'rgba(0, 0, 0, 0.12)',
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.125rem',
      fontWeight: 600,
      lineHeight: 1.2,
    },
    h2: {
      fontSize: '1.875rem',
      fontWeight: 600,
      lineHeight: 1.3,
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 600,
      lineHeight: 1.3,
    },
    h4: {
      fontSize: '1.25rem',
      fontWeight: 600,
      lineHeight: 1.4,
    },
    h5: {
      fontSize: '1.125rem',
      fontWeight: 600,
      lineHeight: 1.4,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 600,
      lineHeight: 1.5,
    },
    body1: {
      fontSize: '1rem',
      lineHeight: 1.5,
    },
    body2: {
      fontSize: '0.875rem',
      lineHeight: 1.43,
    },
    caption: {
      fontSize: '0.75rem',
      lineHeight: 1.33,
      fontWeight: 400,
    },
    overline: {
      fontSize: '0.75rem',
      lineHeight: 2.66,
      fontWeight: 500,
      textTransform: 'uppercase',
    },
  },
  shape: {
    borderRadius: 8,
  },
  spacing: 8,
  shadows: [
    'none',
    '0px 2px 1px -1px rgba(0,0,0,0.2),0px 1px 1px 0px rgba(0,0,0,0.14),0px 1px 3px 0px rgba(0,0,0,0.12)',
    '0px 3px 1px -2px rgba(0,0,0,0.2),0px 2px 2px 0px rgba(0,0,0,0.14),0px 1px 5px 0px rgba(0,0,0,0.12)',
    '0px 3px 3px -2px rgba(0,0,0,0.2),0px 3px 4px 0px rgba(0,0,0,0.14),0px 1px 8px 0px rgba(0,0,0,0.12)',
    '0px 2px 4px -1px rgba(0,0,0,0.2),0px 4px 5px 0px rgba(0,0,0,0.14),0px 1px 10px 0px rgba(0,0,0,0.12)',
    '0px 3px 5px -1px rgba(0,0,0,0.2),0px 5px 8px 0px rgba(0,0,0,0.14),0px 1px 14px 0px rgba(0,0,0,0.12)',
    '0px 3px 5px -1px rgba(0,0,0,0.2),0px 6px 10px 0px rgba(0,0,0,0.14),0px 1px 18px 0px rgba(0,0,0,0.12)',
    '0px 4px 5px -2px rgba(0,0,0,0.2),0px 7px 10px 1px rgba(0,0,0,0.14),0px 2px 16px 1px rgba(0,0,0,0.12)',
    '0px 5px 5px -3px rgba(0,0,0,0.2),0px 8px 10px 1px rgba(0,0,0,0.14),0px 3px 14px 2px rgba(0,0,0,0.12)',
    '0px 5px 6px -3px rgba(0,0,0,0.2),0px 9px 12px 1px rgba(0,0,0,0.14),0px 3px 16px 2px rgba(0,0,0,0.12)',
    '0px 6px 6px -3px rgba(0,0,0,0.2),0px 10px 14px 1px rgba(0,0,0,0.14),0px 4px 18px 3px rgba(0,0,0,0.12)',
    '0px 6px 7px -4px rgba(0,0,0,0.2),0px 11px 15px 1px rgba(0,0,0,0.14),0px 4px 20px 3px rgba(0,0,0,0.12)',
    '0px 7px 8px -4px rgba(0,0,0,0.2),0px 12px 17px 2px rgba(0,0,0,0.14),0px 5px 22px 4px rgba(0,0,0,0.12)',
    '0px 7px 8px -4px rgba(0,0,0,0.2),0px 13px 19px 2px rgba(0,0,0,0.14),0px 5px 24px 4px rgba(0,0,0,0.12)',
    '0px 7px 9px -4px rgba(0,0,0,0.2),0px 14px 21px 2px rgba(0,0,0,0.14),0px 5px 26px 4px rgba(0,0,0,0.12)',
    '0px 8px 9px -5px rgba(0,0,0,0.2),0px 15px 22px 2px rgba(0,0,0,0.14),0px 6px 28px 5px rgba(0,0,0,0.12)',
    '0px 8px 10px -5px rgba(0,0,0,0.2),0px 16px 24px 2px rgba(0,0,0,0.14),0px 6px 30px 5px rgba(0,0,0,0.12)',
    '0px 8px 11px -5px rgba(0,0,0,0.2),0px 17px 26px 2px rgba(0,0,0,0.14),0px 6px 32px 5px rgba(0,0,0,0.12)',
    '0px 9px 11px -5px rgba(0,0,0,0.2),0px 18px 28px 2px rgba(0,0,0,0.14),0px 7px 34px 6px rgba(0,0,0,0.12)',
    '0px 9px 12px -6px rgba(0,0,0,0.2),0px 19px 29px 2px rgba(0,0,0,0.14),0px 7px 36px 6px rgba(0,0,0,0.12)',
    '0px 10px 13px -6px rgba(0,0,0,0.2),0px 20px 31px 3px rgba(0,0,0,0.14),0px 8px 38px 7px rgba(0,0,0,0.12)',
    '0px 10px 13px -6px rgba(0,0,0,0.2),0px 21px 33px 3px rgba(0,0,0,0.14),0px 8px 40px 7px rgba(0,0,0,0.12)',
    '0px 10px 14px -6px rgba(0,0,0,0.2),0px 22px 35px 3px rgba(0,0,0,0.14),0px 8px 42px 7px rgba(0,0,0,0.12)',
    '0px 11px 14px -7px rgba(0,0,0,0.2),0px 23px 36px 3px rgba(0,0,0,0.14),0px 9px 44px 8px rgba(0,0,0,0.12)',
    '0px 11px 15px -7px rgba(0,0,0,0.2),0px 24px 38px 3px rgba(0,0,0,0.14),0px 9px 46px 8px rgba(0,0,0,0.12)',
  ],
};

// Dark theme configuration
const darkThemeOptions: ThemeOptions = {
  ...lightThemeOptions,
  palette: {
    mode: 'dark',
    primary: {
      ...brandColors.primary,
      main: brandColors.primary[300],
    },
    secondary: {
      ...brandColors.secondary,
      main: brandColors.secondary[300],
    },
    error: {
      ...brandColors.error,
      main: brandColors.error[300],
    },
    warning: {
      ...brandColors.warning,
      main: brandColors.warning[300],
    },
    success: {
      ...brandColors.success,
      main: brandColors.success[300],
    },
    info: {
      ...brandColors.info,
      main: brandColors.info[300],
    },
    background: {
      default: '#0a0e1a',
      paper: '#1a1f2e',
    },
    text: {
      primary: 'rgba(255, 255, 255, 0.87)',
      secondary: 'rgba(255, 255, 255, 0.6)',
      disabled: 'rgba(255, 255, 255, 0.38)',
    },
    divider: 'rgba(255, 255, 255, 0.12)',
  },
};

// Component style overrides
const componentOverrides = (theme: Theme) => ({
  MuiCssBaseline: {
    styleOverrides: {
      body: {
        scrollbarWidth: 'thin',
        scrollbarColor: theme.palette.divider + ' transparent',
        '&::-webkit-scrollbar': {
          width: '6px',
          height: '6px',
        },
        '&::-webkit-scrollbar-track': {
          background: 'transparent',
        },
        '&::-webkit-scrollbar-thumb': {
          backgroundColor: theme.palette.divider,
          borderRadius: '3px',
          '&:hover': {
            backgroundColor: theme.palette.text.disabled,
          },
        },
      },
    },
  },
  MuiCard: {
    styleOverrides: {
      root: {
        borderRadius: theme.spacing(2),
        boxShadow: theme.shadows[1],
        '&:hover': {
          boxShadow: theme.shadows[4],
        },
        transition: theme.transitions.create(['box-shadow', 'transform'], {
          duration: theme.transitions.duration.short,
        }),
      },
    },
  },
  MuiButton: {
    styleOverrides: {
      root: {
        borderRadius: theme.spacing(1),
        textTransform: 'none',
        fontWeight: 600,
        fontSize: '0.875rem',
        padding: theme.spacing(1, 2),
      },
      containedPrimary: {
        boxShadow: 'none',
        '&:hover': {
          boxShadow: theme.shadows[2],
        },
      },
    },
  },
  MuiChip: {
    styleOverrides: {
      root: {
        borderRadius: theme.spacing(1),
        fontWeight: 500,
      },
      colorPrimary: {
        backgroundColor: theme.palette.primary.main,
        color: theme.palette.primary.contrastText,
      },
      colorSecondary: {
        backgroundColor: theme.palette.secondary.main,
        color: theme.palette.secondary.contrastText,
      },
    },
  },
  MuiAppBar: {
    styleOverrides: {
      root: {
        backgroundColor: theme.palette.background.paper,
        color: theme.palette.text.primary,
        boxShadow: 'none',
        borderBottom: `1px solid ${theme.palette.divider}`,
      },
    },
  },
  MuiDrawer: {
    styleOverrides: {
      paper: {
        borderRight: `1px solid ${theme.palette.divider}`,
        backgroundColor: theme.palette.background.paper,
      },
    },
  },
  MuiTableHead: {
    styleOverrides: {
      root: {
        backgroundColor: theme.palette.mode === 'dark' 
          ? 'rgba(255, 255, 255, 0.05)' 
          : 'rgba(0, 0, 0, 0.02)',
      },
    },
  },
  MuiTableCell: {
    styleOverrides: {
      head: {
        fontWeight: 600,
        fontSize: '0.875rem',
        color: theme.palette.text.secondary,
      },
    },
  },
});

// Create theme instances
function createISECTechTheme(mode: 'light' | 'dark'): Theme {
  const baseTheme = createTheme(mode === 'dark' ? darkThemeOptions : lightThemeOptions);
  
  return createTheme(baseTheme, {
    components: componentOverrides(baseTheme),
    // Add custom security-related properties
    palette: {
      ...baseTheme.palette,
      security: securityColors,
    },
  });
}

declare module '@mui/material/styles' {
  interface Palette {
    security: typeof securityColors;
  }

  interface PaletteOptions {
    security?: typeof securityColors;
  }
}

interface ISECTechThemeProviderProps {
  children: React.ReactNode;
}

export function ISECTechThemeProvider({ children }: ISECTechThemeProviderProps) {
  const theme = useAppStore(appSelectors.theme);

  const muiTheme = useMemo(() => {
    const mode = theme === 'auto' 
      ? (typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
      : theme;
    
    return createISECTechTheme(mode);
  }, [theme]);

  return (
    <CacheProvider value={cache}>
      <ThemeProvider theme={muiTheme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </CacheProvider>
  );
}

export default ISECTechThemeProvider;