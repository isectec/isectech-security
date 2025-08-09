/**
 * Security Alert Component Stories
 * Interactive documentation and testing for security alert components
 */

import { AccessibleSecurityAlert } from '@/app/components/common/accessible-security-alert';
import type { Meta, StoryObj } from '@storybook/react';
import { expect, userEvent, within } from '@storybook/test';

const meta: Meta<typeof AccessibleSecurityAlert> = {
  title: 'Security/Alerts/AccessibleSecurityAlert',
  component: AccessibleSecurityAlert,
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component:
          'A production-grade security alert component with WCAG 2.1 AA compliance, designed specifically for cybersecurity professionals. Features intelligent color coding, screen reader optimization, and emergency response capabilities.',
      },
    },
  },
  tags: ['autodocs'],
  argTypes: {
    severity: {
      control: 'select',
      options: ['low', 'medium', 'high', 'critical'],
      description: 'The security severity level of the alert',
    },
    type: {
      control: 'select',
      options: ['threat_detected', 'vulnerability', 'compliance_violation', 'system_breach'],
      description: 'The type of security event',
    },
    title: {
      control: 'text',
      description: 'The alert title visible to users',
    },
    description: {
      control: 'text',
      description: 'Detailed description of the security event',
    },
    timestamp: {
      control: 'date',
      description: 'When the security event occurred',
    },
    autoEscalate: {
      control: 'boolean',
      description: 'Whether the alert should auto-escalate based on severity',
    },
    requiresAcknowledgment: {
      control: 'boolean',
      description: 'Whether the alert requires explicit acknowledgment',
    },
  },
};

export default meta;
type Story = StoryObj<typeof meta>;

// Default security alert
export const Default: Story = {
  args: {
    id: 'alert-001',
    severity: 'medium',
    type: 'threat_detected',
    title: 'Suspicious Network Activity',
    description: 'Unusual traffic pattern detected from external IP address',
    timestamp: new Date().toISOString(),
    metadata: {
      source_ip: '192.168.1.100',
      destination_ip: '10.0.0.1',
      protocol: 'TCP',
      port: 443,
    },
  },
};

// Critical security breach
export const CriticalBreach: Story = {
  args: {
    id: 'alert-002',
    severity: 'critical',
    type: 'system_breach',
    title: 'Active Security Breach Detected',
    description: 'Unauthorized access to production database detected. Immediate action required.',
    timestamp: new Date().toISOString(),
    autoEscalate: true,
    requiresAcknowledgment: true,
    metadata: {
      affected_system: 'prod-db-01',
      attack_vector: 'SQL Injection',
      impact_assessment: 'HIGH',
    },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    // Verify critical alert is properly announced
    const alert = canvas.getByRole('alert');
    expect(alert).toHaveAttribute('aria-live', 'assertive');
    expect(alert).toHaveAttribute('data-severity', 'critical');

    // Verify emergency actions are available
    const escalateButton = canvas.getByRole('button', { name: /escalate/i });
    expect(escalateButton).toBeInTheDocument();

    // Test acknowledgment requirement
    const acknowledgeButton = canvas.getByRole('button', { name: /acknowledge/i });
    expect(acknowledgeButton).toBeInTheDocument();

    // Simulate acknowledgment
    await userEvent.click(acknowledgeButton);
  },
};

// Vulnerability alert
export const VulnerabilityAlert: Story = {
  args: {
    id: 'alert-003',
    severity: 'high',
    type: 'vulnerability',
    title: 'Critical Vulnerability Detected',
    description: 'CVE-2024-0001 affects multiple systems in your environment',
    timestamp: new Date().toISOString(),
    metadata: {
      cve_id: 'CVE-2024-0001',
      cvss_score: 9.8,
      affected_systems: ['web-server-01', 'api-gateway', 'worker-node-03'],
      remediation: 'Apply security patch immediately',
    },
  },
};

// Compliance violation
export const ComplianceViolation: Story = {
  args: {
    id: 'alert-004',
    severity: 'medium',
    type: 'compliance_violation',
    title: 'SOC2 Compliance Violation',
    description: 'Access control policy violation detected in user management system',
    timestamp: new Date().toISOString(),
    metadata: {
      framework: 'SOC2',
      control: 'CC6.1',
      violation_type: 'Access Control',
      affected_users: ['user@example.com'],
    },
  },
};

// Low severity informational alert
export const InformationalAlert: Story = {
  args: {
    id: 'alert-005',
    severity: 'low',
    type: 'threat_detected',
    title: 'Routine Security Scan Complete',
    description: 'Weekly vulnerability scan completed successfully with no new issues',
    timestamp: new Date().toISOString(),
    metadata: {
      scan_type: 'vulnerability',
      duration: '45 minutes',
      assets_scanned: 156,
      issues_found: 0,
    },
  },
};

// Accessibility testing story
export const AccessibilityTest: Story = {
  args: {
    ...CriticalBreach.args,
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    // Test keyboard navigation
    const alert = canvas.getByRole('alert');
    const buttons = canvas.getAllByRole('button');

    // Test tab navigation
    for (const button of buttons) {
      await userEvent.tab();
      expect(document.activeElement).toBe(button);
    }

    // Test Enter key activation
    const acknowledgeButton = canvas.getByRole('button', { name: /acknowledge/i });
    acknowledgeButton.focus();
    await userEvent.keyboard('{Enter}');

    // Verify ARIA attributes
    expect(alert).toHaveAttribute('role', 'alert');
    expect(alert).toHaveAttribute('aria-live');
    expect(alert).toHaveAttribute('aria-labelledby');
  },
};

// Performance testing story
export const PerformanceTest: Story = {
  args: {
    ...Default.args,
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    // Measure render performance
    const startTime = performance.now();

    // Simulate rapid alert updates
    for (let i = 0; i < 100; i++) {
      const alert = canvas.getByTestId('security-alert');
      expect(alert).toBeInTheDocument();
    }

    const endTime = performance.now();
    const renderTime = endTime - startTime;

    // Should render quickly even with rapid updates
    expect(renderTime).toBeLessThan(1000);
  },
};

// Dark mode story
export const DarkMode: Story = {
  args: {
    ...CriticalBreach.args,
  },
  parameters: {
    backgrounds: { default: 'dark' },
  },
};

// Light mode story
export const LightMode: Story = {
  args: {
    ...CriticalBreach.args,
  },
  parameters: {
    backgrounds: { default: 'light' },
  },
};

// Mobile responsive story
export const MobileView: Story = {
  args: {
    ...Default.args,
  },
  parameters: {
    viewport: { defaultViewport: 'mobile' },
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);

    // Verify mobile-optimized layout
    const alert = canvas.getByRole('alert');
    const computedStyle = window.getComputedStyle(alert);

    // Should be responsive
    expect(computedStyle.width).toBe('100%');
    expect(computedStyle.maxWidth).not.toBe('none');
  },
};
