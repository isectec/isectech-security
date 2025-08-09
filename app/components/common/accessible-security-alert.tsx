/**
 * Accessible Security Alert Component for iSECTECH Protect
 * WCAG 2.1 AA compliant security alert component with screen reader support
 */

'use client';

import {
  ACCESSIBLE_SECURITY_COLORS,
  SECURITY_ARIA_ROLES,
  accessibilityUtils,
  useFocusManagement,
  useScreenReader,
} from '@/lib/utils/accessibility';
import {
  Close as CloseIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Security as SecurityIcon,
  Shield as ShieldIcon,
  CheckCircle as SuccessIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { Alert, AlertTitle, Box, IconButton, Snackbar } from '@mui/material';
import React, { useEffect, useRef } from 'react';

export interface AccessibleSecurityAlertProps {
  // Alert content
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success';
  title: string;
  message?: string;

  // Security-specific properties
  alertType?: 'threat' | 'vulnerability' | 'compliance' | 'incident' | 'system';
  threatLevel?: number;
  timestamp?: Date;
  source?: string;

  // Accessibility properties
  announceImmediately?: boolean;
  persistent?: boolean;
  focusOnMount?: boolean;

  // Interaction
  onClose?: () => void;
  onAcknowledge?: () => void;
  onEscalate?: () => void;

  // Display
  open?: boolean;
  autoHideDuration?: number;
  variant?: 'filled' | 'outlined' | 'standard';
}

const SecurityIconMap = {
  critical: ErrorIcon,
  high: WarningIcon,
  medium: WarningIcon,
  low: InfoIcon,
  info: InfoIcon,
  success: SuccessIcon,
} as const;

const ThreatIconMap = {
  threat: SecurityIcon,
  vulnerability: ShieldIcon,
  compliance: SuccessIcon,
  incident: ErrorIcon,
  system: InfoIcon,
} as const;

export function AccessibleSecurityAlert({
  severity,
  title,
  message,
  alertType = 'system',
  threatLevel,
  timestamp,
  source,
  announceImmediately = true,
  persistent = false,
  focusOnMount = false,
  onClose,
  onAcknowledge,
  onEscalate,
  open = true,
  autoHideDuration = persistent ? null : severity === 'critical' ? 10000 : 6000,
  variant = 'filled',
}: AccessibleSecurityAlertProps) {
  const alertRef = useRef<HTMLDivElement>(null);
  const { announce, announceSecurityAlert } = useScreenReader();
  const { saveFocus, restoreFocus } = useFocusManagement();

  // Generate accessible labels and descriptions
  const alertId = `security-alert-${Date.now()}`;
  const ariaLabel = accessibilityUtils.createSecurityAnnouncement(
    severity as 'critical' | 'high' | 'medium' | 'low',
    title,
    message,
    timestamp
  );

  const threatDescription = threatLevel ? accessibilityUtils.describeThreatLevel(threatLevel) : '';

  const timestampDescription = timestamp ? accessibilityUtils.formatSecurityTimestamp(timestamp) : '';

  // Get appropriate colors for accessibility
  const colors = ACCESSIBLE_SECURITY_COLORS[severity] || ACCESSIBLE_SECURITY_COLORS.unknown;

  // Select appropriate icons
  const SecurityIconComponent = SecurityIconMap[severity];
  const ThreatIconComponent = ThreatIconMap[alertType];

  // Announce alert to screen readers
  useEffect(() => {
    if (open && announceImmediately) {
      announceSecurityAlert(severity as 'critical' | 'high' | 'medium' | 'low', title, message);
    }
  }, [open, announceImmediately, severity, title, message, announceSecurityAlert]);

  // Focus management
  useEffect(() => {
    if (open && focusOnMount && alertRef.current) {
      saveFocus();
      alertRef.current.focus();

      return () => {
        restoreFocus();
      };
    }
  }, [open, focusOnMount, saveFocus, restoreFocus]);

  // Keyboard event handling
  const handleKeyDown = (event: React.KeyboardEvent) => {
    switch (event.key) {
      case 'Escape':
        if (onClose) {
          event.preventDefault();
          onClose();
        }
        break;
      case 'a':
      case 'A':
        if (onAcknowledge && (event.ctrlKey || event.metaKey)) {
          event.preventDefault();
          onAcknowledge();
          announce('Security alert acknowledged', 'polite');
        }
        break;
      case 'e':
      case 'E':
        if (onEscalate && (event.ctrlKey || event.metaKey)) {
          event.preventDefault();
          onEscalate();
          announce('Security alert escalated', 'assertive');
        }
        break;
    }
  };

  const alertContent = (
    <Alert
      ref={alertRef}
      severity={
        severity === 'critical'
          ? 'error'
          : severity === 'high'
          ? 'warning'
          : severity === 'medium'
          ? 'warning'
          : severity === 'low'
          ? 'info'
          : severity
      }
      variant={variant}
      onClose={onClose}
      role={SECURITY_ARIA_ROLES.securityAlert}
      aria-live={severity === 'critical' ? 'assertive' : 'polite'}
      aria-atomic="true"
      aria-label={ariaLabel}
      aria-describedby={`${alertId}-description`}
      tabIndex={focusOnMount ? 0 : -1}
      onKeyDown={handleKeyDown}
      sx={{
        backgroundColor: colors.background,
        color: colors.text,
        '& .MuiAlert-icon': {
          color: colors.text,
        },
        '& .MuiAlert-action': {
          color: colors.text,
        },
        // High contrast mode support
        '@media (prefers-contrast: high)': {
          border: `2px solid ${colors.text}`,
          backgroundColor: severity === 'critical' ? '#000000' : colors.background,
          color: severity === 'critical' ? '#ffffff' : colors.text,
        },
        // Focus indicators
        '&:focus': {
          outline: `3px solid ${colors.text}`,
          outlineOffset: '2px',
        },
      }}
      icon={
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <SecurityIconComponent />
          {alertType !== 'system' && <ThreatIconComponent fontSize="small" />}
        </Box>
      }
      action={
        <Box sx={{ display: 'flex', gap: 0.5 }}>
          {onAcknowledge && (
            <IconButton
              size="small"
              aria-label="Acknowledge security alert (Ctrl+A)"
              onClick={onAcknowledge}
              sx={{ color: colors.text }}
              title="Acknowledge Alert (Ctrl+A)"
            >
              <CheckCircle fontSize="small" />
            </IconButton>
          )}
          {onEscalate && (
            <IconButton
              size="small"
              aria-label="Escalate security alert (Ctrl+E)"
              onClick={onEscalate}
              sx={{ color: colors.text }}
              title="Escalate Alert (Ctrl+E)"
            >
              <WarningIcon fontSize="small" />
            </IconButton>
          )}
          {onClose && (
            <IconButton
              size="small"
              aria-label="Close security alert (Escape)"
              onClick={onClose}
              sx={{ color: colors.text }}
              title="Close Alert (Escape)"
            >
              <CloseIcon fontSize="small" />
            </IconButton>
          )}
        </Box>
      }
    >
      <AlertTitle>
        {title}
        {threatLevel && (
          <Box component="span" sx={{ ml: 1, fontSize: '0.8em', fontWeight: 'normal' }} aria-label={threatDescription}>
            (Threat Level: {threatLevel})
          </Box>
        )}
      </AlertTitle>

      <Box id={`${alertId}-description`}>
        {message && (
          <Box component="p" sx={{ margin: 0, mb: 1 }}>
            {message}
          </Box>
        )}

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1, fontSize: '0.875em' }}>
          {source && (
            <Box component="span" aria-label={`Alert source: ${source}`}>
              <strong>Source:</strong> {source}
            </Box>
          )}

          {timestamp && (
            <Box component="span" aria-label={`Alert time: ${timestampDescription}`} title={timestampDescription}>
              <strong>Time:</strong> {timestamp.toLocaleTimeString()}
            </Box>
          )}

          {alertType !== 'system' && (
            <Box component="span" aria-label={`Alert type: ${alertType}`}>
              <strong>Type:</strong> {alertType.charAt(0).toUpperCase() + alertType.slice(1)}
            </Box>
          )}
        </Box>
      </Box>
    </Alert>
  );

  // For persistent alerts, render directly
  if (persistent) {
    return (
      <Box role="region" aria-label="Security Alerts">
        {open && alertContent}
      </Box>
    );
  }

  // For temporary alerts, use Snackbar
  return (
    <Snackbar
      open={open}
      autoHideDuration={autoHideDuration}
      onClose={onClose}
      anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      role="region"
      aria-label="Security Alert Notifications"
    >
      {alertContent}
    </Snackbar>
  );
}

export default AccessibleSecurityAlert;
