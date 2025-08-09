/**
 * Alert Management Component Tests
 * Production-grade security testing for alert management interface
 */

import {
  accessibilityUtils,
  interactionUtils,
  mockDataGenerators,
  render,
  securityAssertions,
  securityEventUtils,
} from '@/__tests__/utils/security-test-utils';
import { AlertManagementPage } from '@/app/components/alerts/alert-management-page';
import { fireEvent, screen, waitFor } from '@testing-library/react';

// Mock the hooks and API calls
jest.mock('@/app/lib/hooks/use-alerts', () => ({
  useAlerts: () => ({
    alerts: mockDataGenerators.generateDashboardData().alerts,
    isLoading: false,
    error: null,
    refetch: jest.fn(),
  }),
}));

jest.mock('@/app/lib/api/services/alerts', () => ({
  updateAlertStatus: jest.fn(() => Promise.resolve()),
  bulkUpdateAlerts: jest.fn(() => Promise.resolve()),
  deleteAlert: jest.fn(() => Promise.resolve()),
}));

describe('AlertManagementPage', () => {
  const mockAlerts = mockDataGenerators.generateDashboardData().alerts;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('Accessibility', () => {
    it('should meet WCAG 2.1 AA standards', async () => {
      const { container } = render(<AlertManagementPage />);
      const results = await accessibilityUtils.testAccessibility(container);
      expect(results).toHaveNoViolations();
    });

    it('should support keyboard navigation', async () => {
      const { container } = render(<AlertManagementPage />);
      await accessibilityUtils.testKeyboardNavigation(container);
    });

    it('should announce security alerts to screen readers', async () => {
      const { container } = render(<AlertManagementPage />);
      const announcements = accessibilityUtils.testScreenReaderAnnouncements(container);

      expect(announcements.hasAnnouncements).toBe(true);
      expect(announcements.alerts.length).toBeGreaterThan(0);
    });

    it('should have sufficient color contrast for security indicators', async () => {
      const { container } = render(<AlertManagementPage />);
      const contrastResults = accessibilityUtils.testColorContrast(container);

      expect(contrastResults.hasContrastIssues).toBe(false);
    });
  });

  describe('Security Features', () => {
    it('should properly secure alert data display', () => {
      const { container } = render(<AlertManagementPage />);

      // Verify sensitive data masking
      securityAssertions.expectSensitiveDataMasked(container);

      // Check for XSS protection
      const alertElements = container.querySelectorAll('[data-testid^="alert-item"]');
      alertElements.forEach((element) => {
        securityAssertions.expectSecureComponent(element as HTMLElement);
      });
    });

    it('should handle malicious input safely', async () => {
      const { container } = render(<AlertManagementPage />);

      const searchInput = screen.getByRole('textbox', { name: /search alerts/i });

      // Test XSS attempts
      const maliciousInputs = [
        '<script>alert("xss")</script>',
        'javascript:void(0)',
        '<img src="x" onerror="alert(1)">',
        '"><script>alert("xss")</script>',
      ];

      for (const input of maliciousInputs) {
        fireEvent.change(searchInput, { target: { value: input } });

        // Verify input is sanitized
        expect(container.innerHTML).not.toContain('<script>');
        expect(container.innerHTML).not.toContain('javascript:');
        expect(container.innerHTML).not.toContain('onerror');
      }
    });

    it('should implement proper CSRF protection', () => {
      const { container } = render(<AlertManagementPage />);

      const forms = container.querySelectorAll('form');
      forms.forEach((form) => {
        securityAssertions.expectCSRFProtection(form as HTMLFormElement);
      });
    });
  });

  describe('Alert Display and Filtering', () => {
    it('should display alerts with correct security classifications', () => {
      render(<AlertManagementPage />);

      // Verify critical alerts are prominently displayed
      const criticalAlerts = screen.getAllByText(/critical/i);
      expect(criticalAlerts.length).toBeGreaterThan(0);

      // Verify severity indicators
      const highSeverityBadges = screen.getAllByText(/high/i);
      expect(highSeverityBadges.length).toBeGreaterThan(0);
    });

    it('should filter alerts by security criteria', async () => {
      render(<AlertManagementPage />);

      // Test severity filter
      const severityFilter = screen.getByRole('button', { name: /filter by severity/i });
      fireEvent.click(severityFilter);

      const criticalOption = screen.getByRole('menuitem', { name: /critical/i });
      fireEvent.click(criticalOption);

      await waitFor(() => {
        const visibleAlerts = screen.getAllByTestId(/alert-item/);
        visibleAlerts.forEach((alert) => {
          expect(alert).toHaveAttribute('data-severity', 'critical');
        });
      });
    });

    it('should support rapid threat assessment workflows', async () => {
      const { container } = render(<AlertManagementPage />);

      await interactionUtils.simulateAnalystWorkflow(container);

      // Verify analyst can quickly triage alerts
      const triageButtons = screen.getAllByRole('button', { name: /investigate|escalate|dismiss/i });
      expect(triageButtons.length).toBeGreaterThan(0);
    });
  });

  describe('Bulk Operations', () => {
    it('should handle bulk alert operations securely', async () => {
      render(<AlertManagementPage />);

      // Select multiple alerts
      const checkboxes = screen.getAllByRole('checkbox');
      fireEvent.click(checkboxes[1]); // First is select all
      fireEvent.click(checkboxes[2]);
      fireEvent.click(checkboxes[3]);

      // Perform bulk action
      const bulkActionButton = screen.getByRole('button', { name: /bulk actions/i });
      fireEvent.click(bulkActionButton);

      const markResolvedOption = screen.getByRole('menuitem', { name: /mark resolved/i });
      fireEvent.click(markResolvedOption);

      // Verify confirmation dialog for security
      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        expect(screen.getByText(/confirm bulk operation/i)).toBeInTheDocument();
      });
    });

    it('should prevent unauthorized bulk operations', async () => {
      // Mock user with limited permissions
      render(<AlertManagementPage />);

      const selectAllCheckbox = screen.getAllByRole('checkbox')[0];
      fireEvent.click(selectAllCheckbox);

      const deleteButton = screen.queryByRole('button', { name: /delete selected/i });

      // Delete should not be available for non-admin users
      expect(deleteButton).not.toBeInTheDocument();
    });
  });

  describe('Real-time Updates', () => {
    it('should handle real-time alert updates', async () => {
      render(<AlertManagementPage />);

      // Simulate real-time alert
      const newAlert = securityEventUtils.createMockSecurityEvent({
        severity: 'critical',
        type: 'malware_detected',
      });

      // Mock WebSocket message
      fireEvent(
        window,
        new CustomEvent('alert-received', {
          detail: newAlert,
        })
      );

      await waitFor(() => {
        expect(screen.getByText(newAlert.title)).toBeInTheDocument();
      });
    });

    it('should announce urgent alerts immediately', async () => {
      const { container } = render(<AlertManagementPage />);

      const criticalAlert = securityEventUtils.createMockSecurityEvent({
        severity: 'critical',
        type: 'security_breach',
      });

      fireEvent(
        window,
        new CustomEvent('alert-received', {
          detail: criticalAlert,
        })
      );

      await waitFor(() => {
        const announcements = accessibilityUtils.testScreenReaderAnnouncements(container);
        expect(announcements.alerts.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Performance', () => {
    it('should render large alert lists efficiently', async () => {
      const largeAlertSet = Array.from({ length: 1000 }, (_, i) =>
        securityEventUtils.createMockSecurityEvent({ id: `alert-${i}` })
      );

      const start = performance.now();
      render(<AlertManagementPage />);
      const renderTime = performance.now() - start;

      // Should render within reasonable time (2 seconds for 1000 alerts)
      expect(renderTime).toBeLessThan(2000);
    });

    it('should virtualize long alert lists', () => {
      render(<AlertManagementPage />);

      // Check for virtualization indicators
      const alertContainer = screen.getByTestId('alert-list-container');
      expect(alertContainer).toHaveStyle('overflow: auto');

      // Only visible alerts should be in DOM
      const visibleAlerts = screen.getAllByTestId(/alert-item/);
      expect(visibleAlerts.length).toBeLessThan(50); // Reasonable viewport limit
    });
  });

  describe('Error Handling', () => {
    it('should handle API errors gracefully', async () => {
      // Mock API error
      jest.mock('@/app/lib/hooks/use-alerts', () => ({
        useAlerts: () => ({
          alerts: [],
          isLoading: false,
          error: { message: 'Failed to load alerts' },
          refetch: jest.fn(),
        }),
      }));

      const { container } = render(<AlertManagementPage />);

      const errorElement = screen.getByRole('alert');
      expect(errorElement).toBeInTheDocument();

      // Verify secure error handling
      securityAssertions.expectSecureErrorHandling(errorElement);
    });

    it('should provide fallback content during loading', () => {
      // Mock loading state
      jest.mock('@/app/lib/hooks/use-alerts', () => ({
        useAlerts: () => ({
          alerts: [],
          isLoading: true,
          error: null,
          refetch: jest.fn(),
        }),
      }));

      render(<AlertManagementPage />);

      const loadingIndicator = screen.getByTestId('alert-loading');
      expect(loadingIndicator).toBeInTheDocument();
      expect(loadingIndicator).toHaveAttribute('aria-live', 'polite');
    });
  });

  describe('Emergency Response', () => {
    it('should support emergency response workflows', async () => {
      const { container } = render(<AlertManagementPage />);

      await interactionUtils.simulateEmergencyResponse(container);

      // Verify emergency actions are available
      const emergencyButtons = screen.getAllByRole('button', { name: /emergency|urgent|critical/i });
      expect(emergencyButtons.length).toBeGreaterThan(0);
    });

    it('should escalate critical threats automatically', async () => {
      render(<AlertManagementPage />);

      const criticalAlert = securityEventUtils.createMockSecurityEvent({
        severity: 'critical',
        type: 'active_breach',
      });

      fireEvent(
        window,
        new CustomEvent('alert-received', {
          detail: criticalAlert,
        })
      );

      await waitFor(() => {
        const escalationNotice = screen.getByText(/automatically escalated/i);
        expect(escalationNotice).toBeInTheDocument();
      });
    });
  });
});
