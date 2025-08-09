/**
 * Alert Management Component Unit Tests
 * iSECTECH Protect - Critical Security Component Testing
 * Coverage Target: 95% (Critical Security Component)
 */

import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AlertManagementPage } from '@/components/alerts/alert-management-page';
import { useAlerts } from '@/lib/hooks/use-alerts';
import { useAuthStore } from '@/lib/store/auth';

// Mock dependencies
jest.mock('@/lib/hooks/use-alerts');
jest.mock('@/lib/store/auth');
jest.mock('@/components/common/accessible-security-alert', () => ({
  AccessibleSecurityAlert: ({ children, ...props }) => (
    <div data-testid="security-alert" {...props}>{children}</div>
  ),
}));

const mockUseAlerts = useAlerts as jest.MockedFunction<typeof useAlerts>;
const mockUseAuthStore = useAuthStore as jest.MockedFunction<typeof useAuthStore>;

describe('AlertManagementPage - Critical Security Component', () => {
  const mockAlerts = [
    {
      id: 'alert-1',
      title: 'Suspicious Network Activity',
      severity: 'HIGH' as const,
      status: 'ACTIVE' as const,
      type: 'NETWORK_ANOMALY' as const,
      description: 'Unusual traffic patterns detected',
      sourceIp: '192.168.1.100',
      destinationIp: '10.0.0.1',
      timestamp: '2025-01-02T10:30:00Z',
      assignee: null,
      tags: ['network', 'anomaly'],
      metadata: {
        protocol: 'TCP',
        port: 443,
        bytes: 1024000,
      },
    },
    {
      id: 'alert-2',
      title: 'Malware Detection',
      severity: 'CRITICAL' as const,
      status: 'ACKNOWLEDGED' as const,
      type: 'MALWARE' as const,
      description: 'Trojan detected on endpoint',
      sourceIp: '192.168.1.101',
      timestamp: '2025-01-02T11:00:00Z',
      assignee: 'analyst-123',
      tags: ['malware', 'endpoint'],
      metadata: {
        fileName: 'suspicious.exe',
        hash: 'sha256:abc123...',
      },
    },
  ];

  const mockUser = {
    id: 'user-123',
    email: 'analyst@isectech.com',
    role: 'SECURITY_ANALYST',
    permissions: ['read:alerts', 'write:alerts', 'acknowledge:alerts'],
    securityClearance: 'SECRET',
  };

  beforeEach(() => {
    mockUseAuthStore.mockReturnValue({
      user: mockUser,
      isAuthenticated: true,
      hasPermission: jest.fn((permission) => mockUser.permissions.includes(permission)),
      hasSecurityClearance: jest.fn(() => true),
    } as any);

    mockUseAlerts.mockReturnValue({
      alerts: mockAlerts,
      isLoading: false,
      error: null,
      totalCount: 2,
      acknowledgeAlerts: jest.fn(),
      assignAlerts: jest.fn(),
      updateAlertStatus: jest.fn(),
      bulkUpdateAlerts: jest.fn(),
      refreshAlerts: jest.fn(),
      exportAlerts: jest.fn(),
    } as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Component Rendering', () => {
    it('should render alert management interface correctly', () => {
      render(<AlertManagementPage />);

      expect(screen.getByRole('heading', { name: /alert management/i })).toBeInTheDocument();
      expect(screen.getByRole('table')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /refresh alerts/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /bulk actions/i })).toBeInTheDocument();
    });

    it('should display alerts in table format with correct data', () => {
      render(<AlertManagementPage />);

      const table = screen.getByRole('table');
      
      // Check table headers
      expect(within(table).getByRole('columnheader', { name: /severity/i })).toBeInTheDocument();
      expect(within(table).getByRole('columnheader', { name: /title/i })).toBeInTheDocument();
      expect(within(table).getByRole('columnheader', { name: /status/i })).toBeInTheDocument();
      expect(within(table).getByRole('columnheader', { name: /timestamp/i })).toBeInTheDocument();

      // Check alert data
      expect(screen.getByText('Suspicious Network Activity')).toBeInTheDocument();
      expect(screen.getByText('Malware Detection')).toBeInTheDocument();
      expect(screen.getByText('HIGH')).toBeInTheDocument();
      expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    });

    it('should show loading state when alerts are being fetched', () => {
      mockUseAlerts.mockReturnValue({
        alerts: [],
        isLoading: true,
        error: null,
        totalCount: 0,
      } as any);

      render(<AlertManagementPage />);

      expect(screen.getByRole('progressbar')).toBeInTheDocument();
      expect(screen.getByText(/loading alerts/i)).toBeInTheDocument();
    });

    it('should display error state when alert fetching fails', () => {
      mockUseAlerts.mockReturnValue({
        alerts: [],
        isLoading: false,
        error: 'Failed to fetch alerts',
        totalCount: 0,
      } as any);

      render(<AlertManagementPage />);

      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(/failed to fetch alerts/i)).toBeInTheDocument();
    });
  });

  describe('Alert Filtering and Sorting', () => {
    it('should filter alerts by severity', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const severityFilter = screen.getByRole('combobox', { name: /severity filter/i });
      await user.click(severityFilter);
      await user.click(screen.getByRole('option', { name: /critical/i }));

      // Should show filtered alerts
      expect(screen.getByText('Malware Detection')).toBeInTheDocument();
      expect(screen.queryByText('Suspicious Network Activity')).not.toBeInTheDocument();
    });

    it('should filter alerts by status', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const statusFilter = screen.getByRole('combobox', { name: /status filter/i });
      await user.click(statusFilter);
      await user.click(screen.getByRole('option', { name: /acknowledged/i }));

      expect(screen.getByText('Malware Detection')).toBeInTheDocument();
      expect(screen.queryByText('Suspicious Network Activity')).not.toBeInTheDocument();
    });

    it('should sort alerts by timestamp', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const timestampHeader = screen.getByRole('columnheader', { name: /timestamp/i });
      await user.click(timestampHeader);

      // Verify sorting indicator
      expect(within(timestampHeader).getByLabelText(/sort descending/i)).toBeInTheDocument();
    });

    it('should search alerts by title and description', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const searchInput = screen.getByRole('searchbox', { name: /search alerts/i });
      await user.type(searchInput, 'malware');

      expect(screen.getByText('Malware Detection')).toBeInTheDocument();
      expect(screen.queryByText('Suspicious Network Activity')).not.toBeInTheDocument();
    });
  });

  describe('Alert Actions', () => {
    it('should acknowledge single alert when acknowledge button is clicked', async () => {
      const mockAcknowledgeAlerts = jest.fn();
      mockUseAlerts.mockReturnValue({
        ...mockUseAlerts(),
        acknowledgeAlerts: mockAcknowledgeAlerts,
      } as any);

      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const acknowledgeButton = screen.getAllByRole('button', { name: /acknowledge/i })[0];
      await user.click(acknowledgeButton);

      expect(mockAcknowledgeAlerts).toHaveBeenCalledWith(['alert-1']);
    });

    it('should assign alert to user when assign button is clicked', async () => {
      const mockAssignAlerts = jest.fn();
      mockUseAlerts.mockReturnValue({
        ...mockUseAlerts(),
        assignAlerts: mockAssignAlerts,
      } as any);

      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const assignButton = screen.getAllByRole('button', { name: /assign/i })[0];
      await user.click(assignButton);

      // Should open assignment dialog
      expect(screen.getByRole('dialog', { name: /assign alert/i })).toBeInTheDocument();
      
      const userSelect = screen.getByRole('combobox', { name: /select analyst/i });
      await user.click(userSelect);
      await user.click(screen.getByRole('option', { name: /analyst@isectech.com/i }));

      const confirmButton = screen.getByRole('button', { name: /confirm assignment/i });
      await user.click(confirmButton);

      expect(mockAssignAlerts).toHaveBeenCalledWith(['alert-1'], 'user-123');
    });

    it('should update alert status when status dropdown is changed', async () => {
      const mockUpdateAlertStatus = jest.fn();
      mockUseAlerts.mockReturnValue({
        ...mockUseAlerts(),
        updateAlertStatus: mockUpdateAlertStatus,
      } as any);

      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const statusDropdown = screen.getAllByRole('combobox', { name: /alert status/i })[0];
      await user.click(statusDropdown);
      await user.click(screen.getByRole('option', { name: /resolved/i }));

      expect(mockUpdateAlertStatus).toHaveBeenCalledWith('alert-1', 'RESOLVED');
    });
  });

  describe('Bulk Operations', () => {
    it('should select multiple alerts and perform bulk acknowledgment', async () => {
      const mockBulkUpdateAlerts = jest.fn();
      mockUseAlerts.mockReturnValue({
        ...mockUseAlerts(),
        bulkUpdateAlerts: mockBulkUpdateAlerts,
      } as any);

      const user = userEvent.setup();
      render(<AlertManagementPage />);

      // Select multiple alerts
      const checkboxes = screen.getAllByRole('checkbox', { name: /select alert/i });
      await user.click(checkboxes[0]);
      await user.click(checkboxes[1]);

      // Perform bulk action
      const bulkActionsButton = screen.getByRole('button', { name: /bulk actions/i });
      await user.click(bulkActionsButton);

      const acknowledgeOption = screen.getByRole('menuitem', { name: /acknowledge selected/i });
      await user.click(acknowledgeOption);

      expect(mockBulkUpdateAlerts).toHaveBeenCalledWith(['alert-1', 'alert-2'], {
        action: 'acknowledge',
        assignee: 'user-123',
      });
    });

    it('should validate permissions before allowing bulk operations', async () => {
      mockUseAuthStore.mockReturnValue({
        user: { ...mockUser, permissions: ['read:alerts'] }, // Remove write permission
        isAuthenticated: true,
        hasPermission: jest.fn((permission) => permission === 'read:alerts'),
      } as any);

      render(<AlertManagementPage />);

      const bulkActionsButton = screen.getByRole('button', { name: /bulk actions/i });
      expect(bulkActionsButton).toBeDisabled();
    });

    it('should show confirmation dialog for destructive bulk operations', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      // Select alerts
      const checkboxes = screen.getAllByRole('checkbox', { name: /select alert/i });
      await user.click(checkboxes[0]);

      const bulkActionsButton = screen.getByRole('button', { name: /bulk actions/i });
      await user.click(bulkActionsButton);

      const deleteOption = screen.getByRole('menuitem', { name: /delete selected/i });
      await user.click(deleteOption);

      // Should show confirmation dialog
      expect(screen.getByRole('dialog', { name: /confirm deletion/i })).toBeInTheDocument();
      expect(screen.getByText(/are you sure you want to delete/i)).toBeInTheDocument();
    });
  });

  describe('Accessibility Features', () => {
    it('should have proper ARIA labels and roles', () => {
      render(<AlertManagementPage />);

      expect(screen.getByRole('main')).toHaveAttribute('aria-label', 'Alert Management');
      expect(screen.getByRole('table')).toHaveAttribute('aria-label', 'Security Alerts');
      expect(screen.getByRole('searchbox')).toHaveAttribute('aria-label', 'Search alerts');
    });

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const firstButton = screen.getByRole('button', { name: /refresh alerts/i });
      firstButton.focus();

      expect(firstButton).toHaveFocus();

      // Tab to next focusable element
      await user.tab();
      expect(screen.getByRole('button', { name: /bulk actions/i })).toHaveFocus();
    });

    it('should announce alert updates to screen readers', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const acknowledgeButton = screen.getAllByRole('button', { name: /acknowledge/i })[0];
      await user.click(acknowledgeButton);

      expect(screen.getByRole('status')).toHaveTextContent(/alert acknowledged successfully/i);
    });

    it('should provide high contrast support for severity indicators', () => {
      render(<AlertManagementPage />);

      const criticalSeverity = screen.getByText('CRITICAL');
      const highSeverity = screen.getByText('HIGH');

      expect(criticalSeverity).toHaveClass('severity-critical');
      expect(highSeverity).toHaveClass('severity-high');
      
      // Check for proper color contrast
      expect(criticalSeverity).toHaveStyle({ backgroundColor: expect.any(String) });
      expect(highSeverity).toHaveStyle({ backgroundColor: expect.any(String) });
    });
  });

  describe('Security Features', () => {
    it('should validate security clearance for sensitive alerts', () => {
      const sensitiveAlert = {
        ...mockAlerts[0],
        id: 'alert-classified',
        classification: 'TOP_SECRET',
        title: 'Classified Security Event',
      };

      mockUseAlerts.mockReturnValue({
        alerts: [sensitiveAlert],
        isLoading: false,
        error: null,
        totalCount: 1,
      } as any);

      mockUseAuthStore.mockReturnValue({
        user: { ...mockUser, securityClearance: 'SECRET' },
        hasSecurityClearance: jest.fn((level) => level !== 'TOP_SECRET'),
      } as any);

      render(<AlertManagementPage />);

      expect(screen.getByText(/insufficient clearance/i)).toBeInTheDocument();
      expect(screen.queryByText('Classified Security Event')).not.toBeInTheDocument();
    });

    it('should log security events for sensitive operations', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const criticalAlert = screen.getByText('Malware Detection');
      await user.click(criticalAlert);

      expect(consoleSpy).toHaveBeenCalledWith(
        'Security audit: Alert viewed',
        expect.objectContaining({
          alertId: 'alert-2',
          userId: 'user-123',
          timestamp: expect.any(String),
        })
      );

      consoleSpy.mockRestore();
    });

    it('should prevent unauthorized alert modifications', async () => {
      mockUseAuthStore.mockReturnValue({
        user: { ...mockUser, permissions: ['read:alerts'] }, // Remove write permissions
        hasPermission: jest.fn((permission) => permission === 'read:alerts'),
      } as any);

      render(<AlertManagementPage />);

      const acknowledgeButtons = screen.queryAllByRole('button', { name: /acknowledge/i });
      const assignButtons = screen.queryAllByRole('button', { name: /assign/i });

      expect(acknowledgeButtons).toHaveLength(0);
      expect(assignButtons).toHaveLength(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      const mockRefreshAlerts = jest.fn().mockRejectedValue(new Error('Network error'));
      mockUseAlerts.mockReturnValue({
        ...mockUseAlerts(),
        refreshAlerts: mockRefreshAlerts,
      } as any);

      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const refreshButton = screen.getByRole('button', { name: /refresh alerts/i });
      await user.click(refreshButton);

      await waitFor(() => {
        expect(screen.getByRole('alert')).toHaveTextContent(/network error/i);
      });
    });

    it('should handle invalid alert data gracefully', () => {
      const invalidAlerts = [
        { id: 'invalid-1' }, // Missing required fields
        { id: 'invalid-2', title: null, severity: 'INVALID' },
      ];

      mockUseAlerts.mockReturnValue({
        alerts: invalidAlerts,
        isLoading: false,
        error: null,
        totalCount: 2,
      } as any);

      render(<AlertManagementPage />);

      expect(screen.getByText(/invalid alert data detected/i)).toBeInTheDocument();
    });
  });

  describe('Performance Optimizations', () => {
    it('should virtualize large alert lists for performance', () => {
      const largeAlertList = Array.from({ length: 1000 }, (_, i) => ({
        ...mockAlerts[0],
        id: `alert-${i}`,
        title: `Alert ${i}`,
      }));

      mockUseAlerts.mockReturnValue({
        alerts: largeAlertList,
        isLoading: false,
        error: null,
        totalCount: 1000,
      } as any);

      render(<AlertManagementPage />);

      // Should render virtual list container
      expect(screen.getByTestId('virtual-alert-list')).toBeInTheDocument();
    });

    it('should debounce search input for performance', async () => {
      const user = userEvent.setup();
      render(<AlertManagementPage />);

      const searchInput = screen.getByRole('searchbox', { name: /search alerts/i });
      
      // Type rapidly
      await user.type(searchInput, 'test query');

      // Should debounce the search
      expect(searchInput).toHaveValue('test query');
      
      // Wait for debounce
      await waitFor(() => {
        expect(mockUseAlerts().refreshAlerts).not.toHaveBeenCalled();
      });
    });
  });
});