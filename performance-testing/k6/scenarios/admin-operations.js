// k6 Admin Operations Test
// Load testing for administrative operations and system management

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { getTestConfig, getHttpParams, validateResponse, getThinkTime,
         authenticationFailures, concurrentUsers } from '../config/config.js';

// Test configuration
const testConfig = getTestConfig(__ENV.TEST_TYPE || 'baseline');
export const options = testConfig.options;

export default function adminOperations() {
  const env = testConfig.environment;
  const adminToken = env.auth.admin;
  
  if (!adminToken) {
    console.error('Admin token not provided for environment:', env.name);
    authenticationFailures.add(1);
    return;
  }

  concurrentUsers.add(1);

  group('Admin Authentication & Authorization', function() {
    // Admin profile verification
    const profileResponse = http.get(
      `${env.baseUrl}/api/auth/profile`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(profileResponse, 'admin/auth/profile')) {
      const profile = JSON.parse(profileResponse.body);
      check(profile, {
        'Admin has elevated permissions': (p) => 
          p.user.role === 'admin' || p.user.permissions?.includes('SYSTEM_ADMIN'),
        'Admin profile complete': (p) => p.user.id && p.user.email,
        'Admin session valid': (p) => p.session && p.session.expires_at
      });
    } else {
      authenticationFailures.add(1);
      return;
    }
  });

  sleep(getThinkTime('quickAction'));

  group('User Management Operations', function() {
    // List all users with pagination
    const usersResponse = http.get(
      `${env.baseUrl}/api/admin/users?page=1&limit=50&sort=created_desc&include=roles,permissions`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(usersResponse, 'admin/users/list')) {
      const users = JSON.parse(usersResponse.body);
      check(users, {
        'Users list properly paginated': (u) => u.data && u.pagination,
        'User records complete': (u) => u.data.length === 0 || 
          (u.data[0].id && u.data[0].email && u.data[0].roles),
        'User count reasonable': (u) => u.pagination.total < 10000 // Sanity check
      });
    }

    // Get user activity analytics
    const userAnalyticsResponse = http.get(
      `${env.baseUrl}/api/admin/analytics/user-activity?timeframe=7d&aggregation=daily`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(userAnalyticsResponse, 'admin/analytics/users')) {
      const analytics = JSON.parse(userAnalyticsResponse.body);
      check(analytics, {
        'User analytics available': (a) => a.timeline && Array.isArray(a.timeline),
        'Analytics have metrics': (a) => a.summary && typeof a.summary.total_logins === 'number',
        'Activity breakdown present': (a) => a.breakdown && a.breakdown.by_role
      });
    }

    // User role management
    const rolesResponse = http.get(
      `${env.baseUrl}/api/admin/roles?include=permissions`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(rolesResponse, 'admin/roles/list')) {
      const roles = JSON.parse(rolesResponse.body);
      check(roles, {
        'Roles properly structured': (r) => r.data && Array.isArray(r.data),
        'Roles have permissions': (r) => r.data.length === 0 || 
          (r.data[0].permissions && Array.isArray(r.data[0].permissions)),
        'Standard roles present': (r) => r.data.some(role => 
          ['admin', 'analyst', 'viewer'].includes(role.name))
      });
    }
  });

  sleep(getThinkTime('analysis'));

  group('System Configuration Management', function() {
    // System configuration overview
    const configResponse = http.get(
      `${env.baseUrl}/api/admin/config?category=all&format=summary`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(configResponse, 'admin/config/overview')) {
      const config = JSON.parse(configResponse.body);
      check(config, {
        'Config categories available': (c) => c.security && c.alerts && c.system,
        'Config validation status': (c) => typeof c.validation_status === 'object',
        'Last modified tracking': (c) => c.metadata && c.metadata.last_modified
      });
    }

    // Security settings verification
    const securityConfigResponse = http.get(
      `${env.baseUrl}/api/admin/config/security?include_policies=true`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(securityConfigResponse, 'admin/config/security')) {
      const secConfig = JSON.parse(securityConfigResponse.body);
      check(secConfig, {
        'Security policies loaded': (s) => s.policies && Array.isArray(s.policies),
        'Authentication config present': (s) => s.authentication && s.authentication.mfa_enabled,
        'Encryption settings valid': (s) => s.encryption && s.encryption.algorithms
      });
    }

    // Alert configuration management
    const alertConfigResponse = http.get(
      `${env.baseUrl}/api/admin/config/alerts?include_rules=true`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(alertConfigResponse, 'admin/config/alerts')) {
      const alertConfig = JSON.parse(alertConfigResponse.body);
      check(alertConfig, {
        'Alert rules configured': (a) => a.rules && Array.isArray(a.rules),
        'Notification settings valid': (a) => a.notifications && a.notifications.channels,
        'Escalation policies present': (a) => a.escalation && Array.isArray(a.escalation.policies)
      });
    }
  });

  sleep(getThinkTime('analysis'));

  group('System Health and Monitoring', function() {
    // Comprehensive system health check
    const healthResponse = http.get(
      `${env.baseUrl}/api/admin/health/detailed?include_metrics=true`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(healthResponse, 'admin/health/detailed')) {
      const health = JSON.parse(healthResponse.body);
      check(health, {
        'All services healthy': (h) => h.overall_status === 'healthy',
        'Component health tracked': (h) => h.components && Object.keys(h.components).length > 0,
        'Performance metrics included': (h) => h.metrics && h.metrics.response_times,
        'Database connectivity good': (h) => h.components.database?.status === 'healthy'
      });
    }

    // System resource utilization
    const resourcesResponse = http.get(
      `${env.baseUrl}/api/admin/system/resources?timeframe=1h&granularity=5m`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(resourcesResponse, 'admin/system/resources')) {
      const resources = JSON.parse(resourcesResponse.body);
      check(resources, {
        'CPU metrics available': (r) => r.cpu && typeof r.cpu.current === 'number',
        'Memory usage tracked': (r) => r.memory && r.memory.used && r.memory.total,
        'Disk space monitored': (r) => r.disk && Array.isArray(r.disk),
        'Network stats present': (r) => r.network && r.network.throughput
      });
    }

    // Active sessions monitoring
    const sessionsResponse = http.get(
      `${env.baseUrl}/api/admin/sessions/active?include_details=true`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(sessionsResponse, 'admin/sessions/active')) {
      const sessions = JSON.parse(sessionsResponse.body);
      check(sessions, {
        'Active sessions tracked': (s) => s.data && Array.isArray(s.data),
        'Session details complete': (s) => s.data.length === 0 || 
          (s.data[0].user_id && s.data[0].ip_address && s.data[0].last_activity),
        'Session count reasonable': (s) => s.total < 1000 // Sanity check
      });
    }
  });

  sleep(getThinkTime('analysis'));

  group('Audit and Compliance Operations', function() {
    // Security audit logs
    const auditResponse = http.get(
      `${env.baseUrl}/api/admin/audit-logs?timeframe=24h&limit=100&severity=high,critical`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(auditResponse, 'admin/audit-logs')) {
      const audit = JSON.parse(auditResponse.body);
      check(audit, {
        'Audit logs properly formatted': (a) => a.data && Array.isArray(a.data),
        'Audit entries complete': (a) => a.data.length === 0 || 
          (a.data[0].timestamp && a.data[0].action && a.data[0].user_id),
        'Audit integrity maintained': (a) => a.data.length === 0 || a.data[0].checksum
      });
    }

    // Compliance reporting
    const complianceResponse = http.get(
      `${env.baseUrl}/api/admin/compliance/status?frameworks=SOC2,ISO27001,GDPR`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(complianceResponse, 'admin/compliance/status')) {
      const compliance = JSON.parse(complianceResponse.body);
      check(compliance, {
        'Compliance frameworks tracked': (c) => c.frameworks && Object.keys(c.frameworks).length > 0,
        'Compliance scores available': (c) => Object.values(c.frameworks).every(f => 
          typeof f.score === 'number'),
        'Last assessment recorded': (c) => c.metadata && c.metadata.last_assessment
      });
    }

    // Generate compliance report
    const reportResponse = http.post(
      `${env.baseUrl}/api/admin/reports/compliance`,
      JSON.stringify({
        frameworks: ['SOC2', 'ISO27001'],
        timeframe: '30d',
        format: 'pdf',
        include_evidence: true
      }),
      getHttpParams(adminToken)
    );
    
    if (validateResponse(reportResponse, 'admin/reports/compliance', 202)) {
      const report = JSON.parse(reportResponse.body);
      check(report, {
        'Report generation initiated': (r) => r.job_id && r.status === 'processing',
        'Report includes metadata': (r) => r.estimated_completion && r.format === 'pdf'
      });
    }
  });

  sleep(getThinkTime('reporting'));

  group('Tenant and Multi-tenancy Management', function() {
    // Tenant overview
    const tenantsResponse = http.get(
      `${env.baseUrl}/api/admin/tenants?include=usage,billing&status=active`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(tenantsResponse, 'admin/tenants/list')) {
      const tenants = JSON.parse(tenantsResponse.body);
      check(tenants, {
        'Tenant data available': (t) => t.data && Array.isArray(t.data),
        'Tenant usage tracked': (t) => t.data.length === 0 || t.data[0].usage,
        'Billing info present': (t) => t.data.length === 0 || t.data[0].billing_status
      });
    }

    // Cross-tenant security monitoring
    const crossTenantResponse = http.get(
      `${env.baseUrl}/api/admin/security/cross-tenant?timeframe=24h&anomalies_only=true`,
      getHttpParams(adminToken)
    );
    
    if (validateResponse(crossTenantResponse, 'admin/security/cross-tenant')) {
      const crossTenant = JSON.parse(crossTenantResponse.body);
      check(crossTenant, {
        'Cross-tenant monitoring active': (c) => c.anomalies !== undefined,
        'Isolation verification': (c) => c.isolation_checks && c.isolation_checks.passed,
        'Data segregation healthy': (c) => !c.data_leakage_detected
      });
    }
  });

  sleep(getThinkTime('quickAction'));

  concurrentUsers.add(-1);
}

export function setup() {
  console.log(`Starting Admin Operations test on ${testConfig.environment.name} environment`);
  return { startTime: Date.now() };
}

export function teardown(data) {
  const duration = Date.now() - data.startTime;
  console.log(`Admin Operations test completed in ${duration}ms`);
}