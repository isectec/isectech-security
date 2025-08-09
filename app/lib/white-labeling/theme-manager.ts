/**
 * Theme Manager for iSECTECH Protect White-Labeling
 * Production-grade theme management system with real-time updates and caching
 */

import { createTheme, Theme } from '@mui/material/styles';
import type { 
  ColorPalette, 
  ColorScheme, 
  TypographyTheme, 
  ThemeConfiguration, 
  BrandAsset,
  ThemeVariables,
  DEFAULT_COLOR_PALETTE,
  DEFAULT_TYPOGRAPHY_SCALE
} from '@/types/white-labeling';

export class ThemeManager {
  private static instance: ThemeManager;
  private themeCache = new Map<string, Theme>();
  private configCache = new Map<string, ThemeConfiguration>();
  private cssVariablesCache = new Map<string, ThemeVariables>();
  
  private constructor() {}

  public static getInstance(): ThemeManager {
    if (!ThemeManager.instance) {
      ThemeManager.instance = new ThemeManager();
    }
    return ThemeManager.instance;
  }

  /**
   * Generate Material-UI theme from white-label configuration
   */
  public generateTheme(
    config: ThemeConfiguration, 
    mode: 'light' | 'dark' = 'light'
  ): Theme {
    const cacheKey = `${config.id}-${mode}-${config.version}`;
    
    if (this.themeCache.has(cacheKey)) {
      return this.themeCache.get(cacheKey)!;
    }

    const colorPalette = mode === 'light' ? config.colorScheme.light : config.colorScheme.dark;
    const typography = config.typography;

    const theme = createTheme({
      palette: {
        mode,
        primary: {
          main: colorPalette.primary,
          dark: colorPalette.primaryDark,
          light: colorPalette.primaryLight,
        },
        secondary: {
          main: colorPalette.secondary,
          dark: colorPalette.secondaryDark,
          light: colorPalette.secondaryLight,
        },
        error: {
          main: colorPalette.error,
        },
        warning: {
          main: colorPalette.warning,
        },
        info: {
          main: colorPalette.info,
        },
        success: {
          main: colorPalette.success,
        },
        background: {
          default: colorPalette.background,
          paper: colorPalette.surface,
        },
        text: {
          primary: colorPalette.text.primary,
          secondary: colorPalette.text.secondary,
          disabled: colorPalette.text.disabled,
        },
        divider: colorPalette.divider,
      },
      typography: {
        fontFamily: this.buildFontFamilyString(typography.fontFamily),
        h1: {
          fontSize: typography.scale.h1.fontSize,
          fontWeight: typography.scale.h1.fontWeight,
          lineHeight: typography.scale.h1.lineHeight,
          letterSpacing: typography.scale.h1.letterSpacing,
        },
        h2: {
          fontSize: typography.scale.h2.fontSize,
          fontWeight: typography.scale.h2.fontWeight,
          lineHeight: typography.scale.h2.lineHeight,
          letterSpacing: typography.scale.h2.letterSpacing,
        },
        h3: {
          fontSize: typography.scale.h3.fontSize,
          fontWeight: typography.scale.h3.fontWeight,
          lineHeight: typography.scale.h3.lineHeight,
          letterSpacing: typography.scale.h3.letterSpacing,
        },
        h4: {
          fontSize: typography.scale.h4.fontSize,
          fontWeight: typography.scale.h4.fontWeight,
          lineHeight: typography.scale.h4.lineHeight,
          letterSpacing: typography.scale.h4.letterSpacing,
        },
        h5: {
          fontSize: typography.scale.h5.fontSize,
          fontWeight: typography.scale.h5.fontWeight,
          lineHeight: typography.scale.h5.lineHeight,
          letterSpacing: typography.scale.h5.letterSpacing,
        },
        h6: {
          fontSize: typography.scale.h6.fontSize,
          fontWeight: typography.scale.h6.fontWeight,
          lineHeight: typography.scale.h6.lineHeight,
          letterSpacing: typography.scale.h6.letterSpacing,
        },
        body1: {
          fontSize: typography.scale.body1.fontSize,
          fontWeight: typography.scale.body1.fontWeight,
          lineHeight: typography.scale.body1.lineHeight,
          letterSpacing: typography.scale.body1.letterSpacing,
        },
        body2: {
          fontSize: typography.scale.body2.fontSize,
          fontWeight: typography.scale.body2.fontWeight,
          lineHeight: typography.scale.body2.lineHeight,
          letterSpacing: typography.scale.body2.letterSpacing,
        },
        caption: {
          fontSize: typography.scale.caption.fontSize,
          fontWeight: typography.scale.caption.fontWeight,
          lineHeight: typography.scale.caption.lineHeight,
          letterSpacing: typography.scale.caption.letterSpacing,
        },
        button: {
          fontSize: typography.scale.button.fontSize,
          fontWeight: typography.scale.button.fontWeight,
          lineHeight: typography.scale.button.lineHeight,
          letterSpacing: typography.scale.button.letterSpacing,
          textTransform: typography.scale.button.textTransform || 'uppercase',
        },
      },
      shape: {
        borderRadius: 8,
      },
      components: {
        MuiAppBar: {
          styleOverrides: {
            root: {
              backgroundColor: colorPalette.primary,
              color: colorPalette.text.primary,
            },
          },
        },
        MuiButton: {
          styleOverrides: {
            root: {
              borderRadius: 8,
              textTransform: typography.scale.button.textTransform || 'uppercase',
            },
          },
        },
        MuiCard: {
          styleOverrides: {
            root: {
              borderRadius: 12,
              boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
            },
          },
        },
        MuiChip: {
          styleOverrides: {
            root: {
              borderRadius: 16,
            },
          },
        },
      },
    });

    // Cache the generated theme
    this.themeCache.set(cacheKey, theme);
    return theme;
  }

  /**
   * Generate CSS variables for custom styling
   */
  public generateCssVariables(config: ThemeConfiguration, mode: 'light' | 'dark' = 'light'): ThemeVariables {
    const cacheKey = `${config.id}-${mode}-variables-${config.version}`;
    
    if (this.cssVariablesCache.has(cacheKey)) {
      return this.cssVariablesCache.get(cacheKey)!;
    }

    const colorPalette = mode === 'light' ? config.colorScheme.light : config.colorScheme.dark;
    const typography = config.typography;

    const variables: ThemeVariables = {
      // Color variables
      '--color-primary': colorPalette.primary,
      '--color-primary-dark': colorPalette.primaryDark,
      '--color-primary-light': colorPalette.primaryLight,
      '--color-secondary': colorPalette.secondary,
      '--color-secondary-dark': colorPalette.secondaryDark,
      '--color-secondary-light': colorPalette.secondaryLight,
      '--color-accent': colorPalette.accent,
      '--color-accent-dark': colorPalette.accentDark,
      '--color-accent-light': colorPalette.accentLight,
      '--color-success': colorPalette.success,
      '--color-warning': colorPalette.warning,
      '--color-error': colorPalette.error,
      '--color-info': colorPalette.info,
      '--color-background': colorPalette.background,
      '--color-surface': colorPalette.surface,
      '--color-text-primary': colorPalette.text.primary,
      '--color-text-secondary': colorPalette.text.secondary,
      '--color-text-disabled': colorPalette.text.disabled,
      '--color-border': colorPalette.border,
      '--color-divider': colorPalette.divider,

      // Typography variables
      '--font-family': this.buildFontFamilyString(typography.fontFamily),
      '--font-size-h1': typography.scale.h1.fontSize,
      '--font-weight-h1': typography.scale.h1.fontWeight,
      '--line-height-h1': typography.scale.h1.lineHeight,
      '--font-size-h2': typography.scale.h2.fontSize,
      '--font-weight-h2': typography.scale.h2.fontWeight,
      '--line-height-h2': typography.scale.h2.lineHeight,
      '--font-size-h3': typography.scale.h3.fontSize,
      '--font-weight-h3': typography.scale.h3.fontWeight,
      '--line-height-h3': typography.scale.h3.lineHeight,
      '--font-size-h4': typography.scale.h4.fontSize,
      '--font-weight-h4': typography.scale.h4.fontWeight,
      '--line-height-h4': typography.scale.h4.lineHeight,
      '--font-size-h5': typography.scale.h5.fontSize,
      '--font-weight-h5': typography.scale.h5.fontWeight,
      '--line-height-h5': typography.scale.h5.lineHeight,
      '--font-size-h6': typography.scale.h6.fontSize,
      '--font-weight-h6': typography.scale.h6.fontWeight,
      '--line-height-h6': typography.scale.h6.lineHeight,
      '--font-size-body1': typography.scale.body1.fontSize,
      '--font-weight-body1': typography.scale.body1.fontWeight,
      '--line-height-body1': typography.scale.body1.lineHeight,
      '--font-size-body2': typography.scale.body2.fontSize,
      '--font-weight-body2': typography.scale.body2.fontWeight,
      '--line-height-body2': typography.scale.body2.lineHeight,
      '--font-size-caption': typography.scale.caption.fontSize,
      '--font-weight-caption': typography.scale.caption.fontWeight,
      '--line-height-caption': typography.scale.caption.lineHeight,
      '--font-size-button': typography.scale.button.fontSize,
      '--font-weight-button': typography.scale.button.fontWeight,
      '--line-height-button': typography.scale.button.lineHeight,

      // Asset URLs
      '--logo-primary-url': config.assets['logo-primary']?.url || '',
      '--logo-secondary-url': config.assets['logo-secondary']?.url || '',
      '--favicon-url': config.assets['favicon']?.url || '',
      '--background-url': config.assets['background']?.url || '',
    };

    // Cache the variables
    this.cssVariablesCache.set(cacheKey, variables);
    return variables;
  }

  /**
   * Apply CSS variables to document root
   */
  public applyCssVariables(variables: ThemeVariables): void {
    const root = document.documentElement;
    
    Object.entries(variables).forEach(([key, value]) => {
      root.style.setProperty(key, String(value));
    });
  }

  /**
   * Load and apply web fonts
   */
  public async loadWebFonts(config: ThemeConfiguration): Promise<void> {
    const typography = config.typography;
    
    if (typography.fontFamily.webFont) {
      const { provider, url, weights } = typography.fontFamily.webFont;
      
      switch (provider) {
        case 'google':
          await this.loadGoogleFont(typography.fontFamily.name, weights);
          break;
        case 'adobe':
          await this.loadAdobeFont(url);
          break;
        case 'custom':
          await this.loadCustomFont(url, typography.fontFamily.name);
          break;
      }
    }
  }

  /**
   * Get asset URL with CDN optimization
   */
  public getAssetUrl(asset: BrandAsset | null, fallback?: string): string {
    if (!asset) return fallback || '';
    
    // Add CDN parameters for optimization
    const url = new URL(asset.url);
    url.searchParams.set('v', asset.version);
    
    // Add image optimization parameters
    if (asset.format === 'png' || asset.format === 'jpg' || asset.format === 'webp') {
      url.searchParams.set('format', 'auto');
      url.searchParams.set('quality', '85');
    }
    
    return url.toString();
  }

  /**
   * Validate theme configuration
   */
  public validateConfiguration(config: Partial<ThemeConfiguration>): { 
    isValid: boolean; 
    errors: string[]; 
    warnings: string[]; 
  } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate color scheme
    if (config.colorScheme) {
      const lightPalette = config.colorScheme.light;
      const darkPalette = config.colorScheme.dark;
      
      // Check color contrast ratios
      if (lightPalette) {
        const contrastRatio = this.getContrastRatio(lightPalette.text.primary, lightPalette.background);
        if (contrastRatio < 4.5) {
          warnings.push('Light theme text contrast ratio is below WCAG AA standard (4.5:1)');
        }
      }
      
      if (darkPalette) {
        const contrastRatio = this.getContrastRatio(darkPalette.text.primary, darkPalette.background);
        if (contrastRatio < 4.5) {
          warnings.push('Dark theme text contrast ratio is below WCAG AA standard (4.5:1)');
        }
      }
    }

    // Validate typography
    if (config.typography) {
      const typography = config.typography;
      
      // Check for required font properties
      if (!typography.fontFamily.name) {
        errors.push('Font family name is required');
      }
      
      // Validate font sizes
      const fontSizes = [
        typography.scale.h1.fontSize,
        typography.scale.body1.fontSize,
        typography.scale.caption.fontSize,
      ];
      
      if (fontSizes.some(size => !size || parseFloat(size) <= 0)) {
        errors.push('All font sizes must be positive values');
      }
    }

    // Validate assets
    if (config.assets) {
      Object.entries(config.assets).forEach(([type, asset]) => {
        if (asset && !asset.url) {
          errors.push(`Asset ${type} is missing URL`);
        }
        
        if (asset && asset.fileSize > (5 * 1024 * 1024)) { // 5MB
          warnings.push(`Asset ${type} is larger than recommended size (5MB)`);
        }
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Clear theme caches
   */
  public clearCache(): void {
    this.themeCache.clear();
    this.configCache.clear();
    this.cssVariablesCache.clear();
  }

  /**
   * Build font family string with fallbacks
   */
  private buildFontFamilyString(fontFamily: any): string {
    const name = fontFamily.name;
    const fallbacks = fontFamily.fallback || ['Arial', 'sans-serif'];
    
    return [name, ...fallbacks]
      .map(font => font.includes(' ') ? `"${font}"` : font)
      .join(', ');
  }

  /**
   * Load Google Font
   */
  private async loadGoogleFont(fontName: string, weights: number[]): Promise<void> {
    const weightsStr = weights.join(',');
    const url = `https://fonts.googleapis.com/css2?family=${fontName.replace(' ', '+')}:wght@${weightsStr}&display=swap`;
    
    const link = document.createElement('link');
    link.href = url;
    link.rel = 'stylesheet';
    
    return new Promise((resolve, reject) => {
      link.onload = () => resolve();
      link.onerror = reject;
      document.head.appendChild(link);
    });
  }

  /**
   * Load Adobe Font
   */
  private async loadAdobeFont(url: string): Promise<void> {
    const link = document.createElement('link');
    link.href = url;
    link.rel = 'stylesheet';
    
    return new Promise((resolve, reject) => {
      link.onload = () => resolve();
      link.onerror = reject;
      document.head.appendChild(link);
    });
  }

  /**
   * Load Custom Font
   */
  private async loadCustomFont(url: string, fontName: string): Promise<void> {
    const fontFace = new FontFace(fontName, `url(${url})`);
    
    try {
      await fontFace.load();
      document.fonts.add(fontFace);
    } catch (error) {
      console.error('Failed to load custom font:', error);
      throw error;
    }
  }

  /**
   * Calculate color contrast ratio
   */
  private getContrastRatio(color1: string, color2: string): number {
    const luminance1 = this.getLuminance(color1);
    const luminance2 = this.getLuminance(color2);
    
    const lighter = Math.max(luminance1, luminance2);
    const darker = Math.min(luminance1, luminance2);
    
    return (lighter + 0.05) / (darker + 0.05);
  }

  /**
   * Get relative luminance of a color
   */
  private getLuminance(color: string): number {
    const rgb = this.hexToRgb(color);
    if (!rgb) return 0;
    
    const { r, g, b } = rgb;
    
    const [rs, gs, bs] = [r, g, b].map(c => {
      c = c / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });
    
    return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
  }

  /**
   * Convert hex color to RGB
   */
  private hexToRgb(hex: string): { r: number; g: number; b: number } | null {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16),
    } : null;
  }
}

// Export singleton instance
export const themeManager = ThemeManager.getInstance();