/**
 * Security Testing Utilities for iSECTECH Protect
 * Production-grade security-focused testing helpers
 */

import { render, RenderOptions, RenderResult } from '@testing-library/react';
import { ReactElement } from 'react';
import { axe, toHaveNoViolations } from 'jest-axe';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@mui/material/styles';
import { CssBaseline } from '@mui/material';
import { theme } from '@/app/providers/theme-provider';

// Extend Jest matchers
expect.extend(toHaveNoViolations);

// Security test context provider
const SecurityTestProvider = ({ children }: { children: React.ReactNode }) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
    },
  });

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </QueryClientProvider>
  );
};

// Custom render function with security context
export function renderWithSecurityContext(ui: ReactElement, options?: Omit<RenderOptions, 'wrapper'>): RenderResult {
  return render(ui, {
    wrapper: SecurityTestProvider,
    ...options,
  });
}

// Accessibility testing utilities
export const accessibilityUtils = {
  /**
   * Run comprehensive accessibility tests on a component
   */
  async testAccessibility(container: HTMLElement, options?: any) {
    const results = await axe(container, {
      rules: {
        // Security-specific accessibility rules
        'aria-required-attr': { enabled: true },
        'aria-valid-attr': { enabled: true },
        'aria-valid-attr-value': { enabled: true },
        'color-contrast': { enabled: true },
        'keyboard-navigation': { enabled: true },
        'focus-management': { enabled: true },
        ...options?.rules,
      },
      tags: ['wcag2a', 'wcag2aa', 'wcag21aa', 'section508', ...(options?.tags || [])],
    });

    expect(results).toHaveNoViolations();
    return results;
  },

  /**
   * Test keyboard navigation for security components
   */
  async testKeyboardNavigation(container: HTMLElement) {
    const user = userEvent.setup();
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    // Test tab navigation through all focusable elements
    for (const element of Array.from(focusableElements)) {
      await user.tab();
      expect(document.activeElement).toBe(element);
    }

    // Test reverse tab navigation
    for (let i = focusableElements.length - 1; i >= 0; i--) {
      await user.tab({ shift: true });
      expect(document.activeElement).toBe(focusableElements[i]);
    }
  },

  /**
   * Test screen reader announcements
   */
  testScreenReaderAnnouncements(container: HTMLElement) {
    const liveRegions = container.querySelectorAll('[aria-live]');
    const alerts = container.querySelectorAll('[role="alert"]');
    const status = container.querySelectorAll('[role="status"]');

    return {
      liveRegions: Array.from(liveRegions),
      alerts: Array.from(alerts),
      status: Array.from(status),
      hasAnnouncements: liveRegions.length > 0 || alerts.length > 0 || status.length > 0,
    };
  },

  /**
   * Test color contrast for security indicators
   */
  testColorContrast(container: HTMLElement) {
    const elements = container.querySelectorAll('*');
    const contrastIssues: Element[] = [];

    elements.forEach((element) => {
      const styles = window.getComputedStyle(element);
      const textColor = styles.color;
      const backgroundColor = styles.backgroundColor;

      // Check if element has text and colors
      if (element.textContent?.trim() && textColor && backgroundColor) {
        // This is a simplified check - in real tests you'd use a proper contrast checker
        if (textColor === backgroundColor) {
          contrastIssues.push(element);
        }
      }
    });

    return {
      hasContrastIssues: contrastIssues.length > 0,
      issues: contrastIssues,
    };
  },
};

// Security event testing utilities
export const securityEventUtils = {
  /**
   * Create mock security events for testing
   */
  createMockSecurityEvent(overrides = {}) {
    return {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date().toISOString(),
      type: 'threat_detected',
      severity: 'high',
      source: 'network_monitoring',
      title: 'Suspicious Network Activity',
      description: 'Unusual traffic pattern detected from external IP',
      status: 'active',
      tags: ['network', 'suspicious'],
      metadata: {
        source_ip: '192.168.1.100',
        destination_ip: '10.0.0.1',
        protocol: 'TCP',
        port: 443,
        bytes_transferred: 1024,
      },
      ...overrides,
    };
  },

  /**
   * Create mock threat intelligence data
   */
  createMockThreatIntel(overrides = {}) {
    return {
      id: Math.random().toString(36).substr(2, 9),
      indicator: '192.168.1.100',
      type: 'ip',
      confidence: 'high',
      tags: ['malware', 'botnet'],
      source: 'threat_feed',
      created: new Date().toISOString(),
      ttl: 86400,
      ...overrides,
    };
  },

  /**
   * Create mock vulnerability data
   */
  createMockVulnerability(overrides = {}) {
    return {
      id: Math.random().toString(36).substr(2, 9),
      cve_id: 'CVE-2024-0001',
      title: 'Remote Code Execution Vulnerability',
      description: 'Critical vulnerability allowing remote code execution',
      severity: 'critical',
      cvss_score: 9.8,
      affected_systems: ['web-server-01', 'api-gateway'],
      status: 'open',
      discovered: new Date().toISOString(),
      ...overrides,
    };
  },

  /**
   * Create mock compliance data
   */
  createMockComplianceData(overrides = {}) {
    return {
      id: Math.random().toString(36).substr(2, 9),
      framework: 'SOC2',
      control: 'CC6.1',
      status: 'compliant',
      last_assessed: new Date().toISOString(),
      evidence: 'Automated scan results',
      ...overrides,
    };
  },
};

// Performance testing utilities
export const performanceUtils = {
  /**
   * Measure component render performance
   */
  measureRenderPerformance(renderFn: () => void) {
    const start = performance.now();
    renderFn();
    const end = performance.now();
    return end - start;
  },

  /**
   * Test memory usage during component lifecycle
   */
  measureMemoryUsage(testFn: () => void) {
    if (!('memory' in performance)) {
      console.warn('Performance memory API not available');
      return null;
    }

    const initialMemory = (performance as any).memory.usedJSHeapSize;
    testFn();
    const finalMemory = (performance as any).memory.usedJSHeapSize;

    return {
      initial: initialMemory,
      final: finalMemory,
      difference: finalMemory - initialMemory,
    };
  },

  /**
   * Test component mounting/unmounting performance
   */
  async measureMountingPerformance(component: ReactElement, iterations = 10) {
    const times: number[] = [];

    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      const { unmount } = renderWithSecurityContext(component);
      const mountTime = performance.now() - start;

      const unmountStart = performance.now();
      unmount();
      const unmountTime = performance.now() - unmountStart;

      times.push(mountTime, unmountTime);
    }

    return {
      averageMountTime: times.filter((_, i) => i % 2 === 0).reduce((a, b) => a + b) / iterations,
      averageUnmountTime: times.filter((_, i) => i % 2 === 1).reduce((a, b) => a + b) / iterations,
      totalTime: times.reduce((a, b) => a + b),
    };
  },
};

// User interaction testing utilities
export const interactionUtils = {
  /**
   * Simulate security analyst workflows
   */
  async simulateAnalystWorkflow(container: HTMLElement) {
    const user = userEvent.setup();

    // Simulate reviewing alerts
    const alertElements = container.querySelectorAll('[data-testid*="alert"]');
    for (const alert of Array.from(alertElements)) {
      await user.click(alert as HTMLElement);
      // Wait for any async operations
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Simulate filtering/searching
    const searchInput = container.querySelector('input[type="search"]') as HTMLInputElement;
    if (searchInput) {
      await user.type(searchInput, 'high severity');
      await user.keyboard('{Enter}');
    }

    // Simulate bulk actions
    const checkboxes = container.querySelectorAll('input[type="checkbox"]');
    for (const checkbox of Array.from(checkboxes).slice(0, 3)) {
      await user.click(checkbox as HTMLElement);
    }
  },

  /**
   * Test emergency response workflows
   */
  async simulateEmergencyResponse(container: HTMLElement) {
    const user = userEvent.setup();

    // Look for emergency/critical action buttons
    const emergencyButtons = container.querySelectorAll(
      '[data-severity="critical"], [data-priority="high"], [aria-label*="emergency"]'
    );

    for (const button of Array.from(emergencyButtons)) {
      await user.click(button as HTMLElement);
      // Verify rapid response capabilities
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  },

  /**
   * Test multi-tenant context switching
   */
  async simulateTenantSwitching(container: HTMLElement) {
    const user = userEvent.setup();

    const tenantSelector = container.querySelector('[data-testid="tenant-selector"]');
    if (tenantSelector) {
      await user.click(tenantSelector as HTMLElement);

      // Select different tenant
      const tenantOptions = container.querySelectorAll('[data-testid^="tenant-option"]');
      if (tenantOptions.length > 1) {
        await user.click(tenantOptions[1] as HTMLElement);
      }
    }
  },
};

// Security-specific test assertions
export const securityAssertions = {
  /**
   * Assert component has proper security attributes
   */
  expectSecureComponent(element: HTMLElement) {
    expect(element).toHaveAttribute('data-security-level');
    expect(element).toHaveAttribute('role');

    // Check for XSS protection
    if (element.innerHTML) {
      expect(element.innerHTML).not.toContain('<script>');
      expect(element.innerHTML).not.toContain('javascript:');
    }
  },

  /**
   * Assert sensitive data is properly masked
   */
  expectSensitiveDataMasked(container: HTMLElement) {
    const sensitivePatterns = [
      /\d{4}-\d{4}-\d{4}-\d{4}/, // Credit card
      /\d{3}-\d{2}-\d{4}/, // SSN
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, // Email (should be masked in logs)
    ];

    const text = container.textContent || '';
    sensitivePatterns.forEach((pattern) => {
      const matches = text.match(pattern);
      if (matches) {
        // If sensitive data is found, it should be masked
        expect(matches[0]).toMatch(/\*+/);
      }
    });
  },

  /**
   * Assert proper error handling
   */
  expectSecureErrorHandling(errorElement: HTMLElement) {
    const errorText = errorElement.textContent || '';

    // Should not expose sensitive system information
    expect(errorText).not.toContain('database');
    expect(errorText).not.toContain('server');
    expect(errorText).not.toContain('internal');
    expect(errorText).not.toContain('sql');

    // Should provide user-friendly messages
    expect(errorText.length).toBeGreaterThan(10);
  },

  /**
   * Assert CSRF protection
   */
  expectCSRFProtection(form: HTMLFormElement) {
    const csrfToken = form.querySelector('input[name="_token"], input[name="csrf_token"]');
    expect(csrfToken).toBeInTheDocument();
    expect(csrfToken).toHaveAttribute('type', 'hidden');
  },
};

// Mock data generators
export const mockDataGenerators = {
  /**
   * Generate realistic security dashboard data
   */
  generateDashboardData() {
    return {
      alerts: Array.from({ length: 25 }, (_, i) =>
        securityEventUtils.createMockSecurityEvent({
          id: `alert-${i}`,
          severity: ['critical', 'high', 'medium', 'low'][i % 4],
        })
      ),
      threats: Array.from({ length: 15 }, (_, i) =>
        securityEventUtils.createMockThreatIntel({
          id: `threat-${i}`,
          confidence: ['high', 'medium', 'low'][i % 3],
        })
      ),
      vulnerabilities: Array.from({ length: 10 }, (_, i) =>
        securityEventUtils.createMockVulnerability({
          id: `vuln-${i}`,
          severity: ['critical', 'high', 'medium'][i % 3],
        })
      ),
      compliance: Array.from({ length: 20 }, (_, i) =>
        securityEventUtils.createMockComplianceData({
          id: `compliance-${i}`,
          status: ['compliant', 'non-compliant', 'pending'][i % 3],
        })
      ),
    };
  },

  /**
   * Generate time-series data for charts
   */
  generateTimeSeriesData(days = 30) {
    const data = [];
    const now = new Date();

    for (let i = days; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);

      data.push({
        timestamp: date.toISOString(),
        alerts: Math.floor(Math.random() * 100),
        threats: Math.floor(Math.random() * 50),
        incidents: Math.floor(Math.random() * 10),
        compliance_score: Math.floor(Math.random() * 100),
      });
    }

    return data;
  },
};

// Export all utilities
export { renderWithSecurityContext as render, userEvent, axe };
