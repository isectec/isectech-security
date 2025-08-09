/**
 * Accessibility Testing Infrastructure for iSECTECH Protect
 * Production-grade testing utilities for WCAG 2.1 AA compliance
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { accessibilityUtils, a11yTesting, CONTRAST_RATIOS } from './accessibility';

// Accessibility violation types
export interface AccessibilityViolation {
  id: string;
  element: HTMLElement;
  type: 'error' | 'warning' | 'info';
  wcagLevel: 'A' | 'AA' | 'AAA';
  rule: string;
  description: string;
  impact: 'critical' | 'serious' | 'moderate' | 'minor';
  selector: string;
  help: string;
  helpUrl?: string;
}

// Test suite configuration
export interface AccessibilityTestConfig {
  includeA: boolean;
  includeAA: boolean;
  includeAAA: boolean;
  tags: string[];
  exclude: string[];
  timeout: number;
}

// Default configuration for security-focused testing
export const DEFAULT_A11Y_CONFIG: AccessibilityTestConfig = {
  includeA: true,
  includeAA: true,
  includeAAA: false, // Focus on AA compliance
  tags: ['wcag2a', 'wcag2aa', 'wcag21aa', 'section508', 'best-practice'],
  exclude: [
    'color-contrast', // We handle this with our custom implementation
  ],
  timeout: 10000,
};

// Security-specific accessibility rules
export const SECURITY_A11Y_RULES = {
  // Alert accessibility
  alertAnnouncement: {
    rule: 'security-alert-announcement',
    description: 'Security alerts must be announced to screen readers',
    wcagLevel: 'AA' as const,
    check: (element: HTMLElement): boolean => {
      if (element.getAttribute('role') === 'alert') {
        return !!(element.getAttribute('aria-live') || element.getAttribute('aria-atomic'));
      }
      return true;
    },
  },

  // Security data labeling
  securityDataLabeling: {
    rule: 'security-data-labeling',
    description: 'Security metrics and data must have descriptive labels',
    wcagLevel: 'AA' as const,
    check: (element: HTMLElement): boolean => {
      const securityDataSelectors = [
        '[data-security-metric]',
        '[data-threat-level]',
        '[data-compliance-score]',
        '.security-metric',
        '.threat-indicator',
      ];

      if (securityDataSelectors.some((selector) => element.matches(selector))) {
        return a11yTesting.hasProperLabeling(element);
      }
      return true;
    },
  },

  // Keyboard navigation for security controls
  securityControlKeyboard: {
    rule: 'security-control-keyboard',
    description: 'Security controls must be keyboard accessible',
    wcagLevel: 'AA' as const,
    check: (element: HTMLElement): boolean => {
      const securityControlSelectors = [
        '[data-security-action]',
        '.security-button',
        '.threat-action',
        '.alert-action',
      ];

      if (securityControlSelectors.some((selector) => element.matches(selector))) {
        return a11yTesting.isKeyboardAccessible(element);
      }
      return true;
    },
  },

  // High contrast for security status
  securityStatusContrast: {
    rule: 'security-status-contrast',
    description: 'Security status indicators must have sufficient contrast',
    wcagLevel: 'AA' as const,
    check: (element: HTMLElement): boolean => {
      const statusSelectors = ['.security-status', '.threat-level', '.compliance-status', '[data-status]'];

      if (statusSelectors.some((selector) => element.matches(selector))) {
        return a11yTesting.hasSufficientContrast(element);
      }
      return true;
    },
  },
};

// Accessibility testing hook
export function useAccessibilityTesting(config: Partial<AccessibilityTestConfig> = {}) {
  const [violations, setViolations] = useState<AccessibilityViolation[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [lastTestTime, setLastTestTime] = useState<Date | null>(null);
  const configRef = useRef({ ...DEFAULT_A11Y_CONFIG, ...config });

  const runCustomSecurityTests = useCallback((container: HTMLElement): AccessibilityViolation[] => {
    const securityViolations: AccessibilityViolation[] = [];

    // Get all elements in container
    const allElements = container.querySelectorAll('*');

    Object.entries(SECURITY_A11Y_RULES).forEach(([ruleKey, rule]) => {
      allElements.forEach((element) => {
        if (!rule.check(element as HTMLElement)) {
          securityViolations.push({
            id: `security-${ruleKey}-${Date.now()}-${Math.random()}`,
            element: element as HTMLElement,
            type: 'error',
            wcagLevel: rule.wcagLevel,
            rule: rule.rule,
            description: rule.description,
            impact: 'serious',
            selector: getElementSelector(element as HTMLElement),
            help: `Fix ${rule.description.toLowerCase()}`,
            helpUrl: `https://www.w3.org/WAI/WCAG21/Understanding/`,
          });
        }
      });
    });

    return securityViolations;
  }, []);

  const runAccessibilityTest = useCallback(
    async (element?: HTMLElement) => {
      setIsRunning(true);
      const testTarget = element || document.body;

      try {
        // Run custom security-specific tests
        const securityViolations = runCustomSecurityTests(testTarget);

        // Simulate axe-core-like testing (in production, use actual axe-core)
        const standardViolations = await runStandardAccessibilityTests(testTarget, configRef.current);

        const allViolations = [...securityViolations, ...standardViolations];
        setViolations(allViolations);
        setLastTestTime(new Date());

        return allViolations;
      } catch (error) {
        console.error('Accessibility test failed:', error);
        return [];
      } finally {
        setIsRunning(false);
      }
    },
    [runCustomSecurityTests]
  );

  // Auto-run tests on DOM changes (debounced)
  useEffect(() => {
    if (typeof window === 'undefined') return;

    let timeoutId: NodeJS.Timeout;

    const observer = new MutationObserver(() => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        runAccessibilityTest();
      }, 1000); // Debounce DOM changes
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['aria-label', 'aria-labelledby', 'aria-describedby', 'role'],
    });

    return () => {
      observer.disconnect();
      clearTimeout(timeoutId);
    };
  }, [runAccessibilityTest]);

  return {
    violations,
    isRunning,
    lastTestTime,
    runTest: runAccessibilityTest,
    getViolationsByLevel: (level: 'A' | 'AA' | 'AAA') => violations.filter((v) => v.wcagLevel === level),
    getViolationsByImpact: (impact: AccessibilityViolation['impact']) => violations.filter((v) => v.impact === impact),
    getCriticalViolations: () => violations.filter((v) => v.impact === 'critical' || v.impact === 'serious'),
  };
}

// Mock standard accessibility testing (replace with axe-core in production)
async function runStandardAccessibilityTests(
  element: HTMLElement,
  config: AccessibilityTestConfig
): Promise<AccessibilityViolation[]> {
  const violations: AccessibilityViolation[] = [];

  // Color contrast testing
  const elementsWithText = element.querySelectorAll('*');
  elementsWithText.forEach((el) => {
    const htmlEl = el as HTMLElement;
    const computedStyle = getComputedStyle(htmlEl);
    const hasText = htmlEl.textContent && htmlEl.textContent.trim().length > 0;

    if (hasText) {
      const color = computedStyle.color;
      const backgroundColor = computedStyle.backgroundColor;

      if (color && backgroundColor && backgroundColor !== 'rgba(0, 0, 0, 0)') {
        const contrast = accessibilityUtils.checkContrast(color, backgroundColor);
        const fontSize = parseFloat(computedStyle.fontSize);
        const isLargeText = fontSize >= 18 || (fontSize >= 14 && computedStyle.fontWeight >= '700');
        const requiredRatio = isLargeText ? CONTRAST_RATIOS.AA_LARGE : CONTRAST_RATIOS.AA_NORMAL;

        if (contrast < requiredRatio) {
          violations.push({
            id: `contrast-${Date.now()}-${Math.random()}`,
            element: htmlEl,
            type: 'error',
            wcagLevel: 'AA',
            rule: 'color-contrast',
            description: `Element has insufficient color contrast ratio of ${contrast.toFixed(
              2
            )}:1 (minimum required: ${requiredRatio}:1)`,
            impact: contrast < 3 ? 'critical' : 'serious',
            selector: getElementSelector(htmlEl),
            help: 'Ensure all text elements have sufficient color contrast',
            helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/contrast-minimum.html',
          });
        }
      }
    }
  });

  // Missing labels
  const formControls = element.querySelectorAll('input, select, textarea, button');
  formControls.forEach((control) => {
    const htmlControl = control as HTMLElement;
    if (!a11yTesting.hasProperLabeling(htmlControl)) {
      violations.push({
        id: `label-${Date.now()}-${Math.random()}`,
        element: htmlControl,
        type: 'error',
        wcagLevel: 'A',
        rule: 'label',
        description: 'Form control missing accessible label',
        impact: 'critical',
        selector: getElementSelector(htmlControl),
        help: 'Ensure all form controls have accessible labels',
        helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/labels-or-instructions.html',
      });
    }
  });

  // Missing keyboard access
  const interactiveElements = element.querySelectorAll('button, a, input, select, textarea, [onclick], [tabindex]');
  interactiveElements.forEach((interactive) => {
    const htmlInteractive = interactive as HTMLElement;
    if (!a11yTesting.isKeyboardAccessible(htmlInteractive)) {
      violations.push({
        id: `keyboard-${Date.now()}-${Math.random()}`,
        element: htmlInteractive,
        type: 'error',
        wcagLevel: 'A',
        rule: 'keyboard',
        description: 'Interactive element not keyboard accessible',
        impact: 'serious',
        selector: getElementSelector(htmlInteractive),
        help: 'Ensure all interactive elements are keyboard accessible',
        helpUrl: 'https://www.w3.org/WAI/WCAG21/Understanding/keyboard.html',
      });
    }
  });

  return violations;
}

// Get CSS selector for element
function getElementSelector(element: HTMLElement): string {
  if (element.id) {
    return `#${element.id}`;
  }

  if (element.className) {
    const classes = element.className.split(' ').filter((c) => c.trim());
    if (classes.length > 0) {
      return `${element.tagName.toLowerCase()}.${classes[0]}`;
    }
  }

  return element.tagName.toLowerCase();
}

// Accessibility test reporter
export function generateAccessibilityReport(violations: AccessibilityViolation[]) {
  const report = {
    timestamp: new Date().toISOString(),
    summary: {
      total: violations.length,
      critical: violations.filter((v) => v.impact === 'critical').length,
      serious: violations.filter((v) => v.impact === 'serious').length,
      moderate: violations.filter((v) => v.impact === 'moderate').length,
      minor: violations.filter((v) => v.impact === 'minor').length,
    },
    byWCAGLevel: {
      A: violations.filter((v) => v.wcagLevel === 'A').length,
      AA: violations.filter((v) => v.wcagLevel === 'AA').length,
      AAA: violations.filter((v) => v.wcagLevel === 'AAA').length,
    },
    violations: violations.map((v) => ({
      rule: v.rule,
      impact: v.impact,
      wcagLevel: v.wcagLevel,
      description: v.description,
      selector: v.selector,
      help: v.help,
    })),
  };

  return report;
}

// Development component for accessibility debugging
export function AccessibilityDebugPanel() {
  const { violations, isRunning, runTest, getCriticalViolations } = useAccessibilityTesting();
  const [showDetails, setShowDetails] = useState(false);

  if (process.env.NODE_ENV !== 'development') {
    return null;
  }

  const criticalViolations = getCriticalViolations();

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 20,
        right: 20,
        background: '#fff',
        border: '2px solid #d32f2f',
        borderRadius: '8px',
        padding: '12px',
        maxWidth: '300px',
        zIndex: 9999,
        fontSize: '14px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
      }}
    >
      <div style={{ fontWeight: 'bold', marginBottom: '8px' }}>🔍 Accessibility Monitor</div>

      <div style={{ marginBottom: '8px' }}>
        Total violations: <strong>{violations.length}</strong>
        <br />
        Critical: <strong style={{ color: '#d32f2f' }}>{criticalViolations.length}</strong>
      </div>

      <button
        onClick={() => runTest()}
        disabled={isRunning}
        style={{
          background: '#1976d2',
          color: 'white',
          border: 'none',
          padding: '6px 12px',
          borderRadius: '4px',
          cursor: isRunning ? 'not-allowed' : 'pointer',
          marginRight: '8px',
        }}
      >
        {isRunning ? 'Testing...' : 'Run Test'}
      </button>

      <button
        onClick={() => setShowDetails(!showDetails)}
        style={{
          background: '#666',
          color: 'white',
          border: 'none',
          padding: '6px 12px',
          borderRadius: '4px',
          cursor: 'pointer',
        }}
      >
        {showDetails ? 'Hide' : 'Show'} Details
      </button>

      {showDetails && violations.length > 0 && (
        <div style={{ marginTop: '12px', maxHeight: '200px', overflow: 'auto' }}>
          {violations.slice(0, 10).map((violation, index) => (
            <div
              key={violation.id}
              style={{
                padding: '8px',
                margin: '4px 0',
                border: '1px solid #ddd',
                borderRadius: '4px',
                fontSize: '12px',
              }}
            >
              <div style={{ fontWeight: 'bold', color: getImpactColor(violation.impact) }}>
                {violation.rule} ({violation.impact})
              </div>
              <div>{violation.description}</div>
              <div style={{ color: '#666', fontSize: '10px' }}>{violation.selector}</div>
            </div>
          ))}
          {violations.length > 10 && (
            <div style={{ textAlign: 'center', color: '#666' }}>... and {violations.length - 10} more</div>
          )}
        </div>
      )}
    </div>
  );
}

function getImpactColor(impact: AccessibilityViolation['impact']): string {
  switch (impact) {
    case 'critical':
      return '#d32f2f';
    case 'serious':
      return '#f57c00';
    case 'moderate':
      return '#fbc02d';
    case 'minor':
      return '#388e3c';
    default:
      return '#666';
  }
}
