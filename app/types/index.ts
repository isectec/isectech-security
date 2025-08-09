/**
 * Type Definitions Index for iSECTECH Protect
 * Central export point for all TypeScript types
 */

// Re-export all types from individual modules
export * from './auth';
export * from './security';
export * from './common';
export * from './customer-success';
export * from './white-labeling';

// Type guards and utility functions
export function isApiSuccess<T>(response: import('./common').ApiResponse<T>): response is import('./common').ApiSuccess<T> {
  return response.success;
}

export function isApiFailure<T>(response: import('./common').ApiResponse<T>): response is import('./common').ApiFailure {
  return !response.success;
}

export function hasPermission(userPermissions: string[], requiredPermission: string): boolean {
  return userPermissions.includes(requiredPermission) || userPermissions.includes('*');
}

export function hasClearance(
  userClearance: import('./security').SecurityClearance,
  requiredClearance: import('./security').SecurityClearance
): boolean {
  const clearanceLevels = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
  const userLevel = clearanceLevels.indexOf(userClearance);
  const requiredLevel = clearanceLevels.indexOf(requiredClearance);
  return userLevel >= requiredLevel;
}

export function isExpired(date: Date): boolean {
  return new Date() > date;
}

export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

export function formatClearanceLevel(clearance: import('./security').SecurityClearance): string {
  switch (clearance) {
    case 'TOP_SECRET':
      return 'Top Secret';
    case 'SECRET':
      return 'Secret';
    case 'CONFIDENTIAL':
      return 'Confidential';
    case 'UNCLASSIFIED':
      return 'Unclassified';
    default:
      return clearance;
  }
}

export function formatUserRole(role: import('./security').UserRole): string {
  switch (role) {
    case 'SUPER_ADMIN':
      return 'Super Administrator';
    case 'TENANT_ADMIN':
      return 'Tenant Administrator';
    case 'SECURITY_ANALYST':
      return 'Security Analyst';
    case 'SOC_ANALYST':
      return 'SOC Analyst';
    case 'INCIDENT_RESPONDER':
      return 'Incident Responder';
    case 'COMPLIANCE_OFFICER':
      return 'Compliance Officer';
    case 'READ_ONLY':
      return 'Read Only';
    case 'CUSTOM':
      return 'Custom Role';
    default:
      return role;
  }
}

export function getSeverityColor(severity: import('./security').ThreatSeverity): string {
  switch (severity) {
    case 'CRITICAL':
      return '#d32f2f'; // Red
    case 'HIGH':
      return '#f57c00'; // Orange
    case 'MEDIUM':
      return '#fbc02d'; // Yellow
    case 'LOW':
      return '#388e3c'; // Green
    default:
      return '#757575'; // Gray
  }
}

export function getPriorityColor(priority: import('./security').AlertPriority): string {
  switch (priority) {
    case 'P1':
      return '#d32f2f'; // Red
    case 'P2':
      return '#f57c00'; // Orange
    case 'P3':
      return '#fbc02d'; // Yellow
    case 'P4':
      return '#388e3c'; // Green
    case 'P5':
      return '#757575'; // Gray
    default:
      return '#757575';
  }
}

export function formatRiskScore(score: number): { level: string; color: string; label: string } {
  if (score >= 80) {
    return { level: 'CRITICAL', color: '#d32f2f', label: 'Critical Risk' };
  } else if (score >= 60) {
    return { level: 'HIGH', color: '#f57c00', label: 'High Risk' };
  } else if (score >= 40) {
    return { level: 'MEDIUM', color: '#fbc02d', label: 'Medium Risk' };
  } else if (score >= 20) {
    return { level: 'LOW', color: '#388e3c', label: 'Low Risk' };
  } else {
    return { level: 'MINIMAL', color: '#4caf50', label: 'Minimal Risk' };
  }
}

export function calculateCompliancePercentage(controls: import('./security').ComplianceControl[]): number {
  if (controls.length === 0) return 0;
  
  const compliantControls = controls.filter(control => control.status === 'COMPLIANT').length;
  return Math.round((compliantControls / controls.length) * 100);
}

export function groupAssetsByType(assets: import('./security').Asset[]): Record<import('./security').AssetType, import('./security').Asset[]> {
  return assets.reduce((groups, asset) => {
    if (!groups[asset.type]) {
      groups[asset.type] = [];
    }
    groups[asset.type].push(asset);
    return groups;
  }, {} as Record<import('./security').AssetType, import('./security').Asset[]>);
}

export function filterBySecurityClearance<T extends { securityClearance: import('./security').SecurityClearance }>(
  items: T[],
  userClearance: import('./security').SecurityClearance
): T[] {
  return items.filter(item => hasClearance(userClearance, item.securityClearance));
}

export function filterByTenantId<T extends { tenantId: string }>(
  items: T[],
  tenantId: string
): T[] {
  return items.filter(item => item.tenantId === tenantId);
}

export function sortByDateDesc<T extends { createdAt: Date }>(items: T[]): T[] {
  return [...items].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
}

export function sortByDateAsc<T extends { createdAt: Date }>(items: T[]): T[] {
  return [...items].sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
}

export function debounce<T extends (...args: Parameters<T>) => ReturnType<T>>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout;
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

export function throttle<T extends (...args: Parameters<T>) => ReturnType<T>>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let lastCall = 0;
  return (...args: Parameters<T>) => {
    const now = Date.now();
    if (now - lastCall >= delay) {
      lastCall = now;
      func(...args);
    }
  };
}