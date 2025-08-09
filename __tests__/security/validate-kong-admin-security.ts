#!/usr/bin/env node
/**
 * Kong Admin API Security Validation
 * CRITICAL: Direct validation of emergency Kong Admin API security hardening
 */

import { EmergencyKongAdminSecurity, generateEmergencyKongConfig } from '../../api-gateway/security/emergency-kong-admin-security';

console.log('🔒 Kong Admin API Emergency Security Validation');
console.log('='.repeat(60));

// Initialize security system
const securitySystem = new EmergencyKongAdminSecurity({
  allowedSourceIPs: ['127.0.0.1', '192.168.1.0/24'],
  allowedClientCerts: ['valid-cert-data'],
  emergencyLockdownMode: true,
  maxConcurrentSessions: 2,
  sessionTimeoutMinutes: 15
});

let testsRun = 0;
let testsPassed = 0;
let testsFailed = 0;

function runTest(testName: string, testFn: () => boolean): void {
  testsRun++;
  console.log(`\n${testsRun}. Testing: ${testName}`);
  
  try {
    const result = testFn();
    if (result) {
      testsPassed++;
      console.log(`   ✅ PASSED`);
    } else {
      testsFailed++;
      console.log(`   ❌ FAILED`);
    }
  } catch (error) {
    testsFailed++;
    console.log(`   ❌ FAILED: ${error.message}`);
  }
}

// Test 1: Block dangerous configuration changes
runTest('Block dangerous configuration changes', () => {
  const dangerousRequest = {
    method: 'PUT',
    url: '/config',
    headers: { 
      'user-agent': 'malicious-client',
      'x-forwarded-proto': 'https'
    },
    sourceIP: '127.0.0.1',
    clientCert: 'valid-cert-data',
    body: {
      admin_listen: '0.0.0.0:8001', // Dangerous
      trusted_ips: ['0.0.0.0/0'] // Open access
    }
  };

  const result = securitySystem.validateAdminRequest(dangerousRequest);
  return !result.allowed && result.securityViolation?.includes('DANGEROUS');
});

// Test 2: Block unauthorized source IPs
runTest('Block unauthorized source IPs', () => {
  const unauthorizedRequest = {
    method: 'GET',
    url: '/status',
    headers: { 
      'user-agent': 'admin-client',
      'x-forwarded-proto': 'https'
    },
    sourceIP: '1.2.3.4', // Not in allowlist
    clientCert: 'valid-cert-data'
  };

  const result = securitySystem.validateAdminRequest(unauthorizedRequest);
  return !result.allowed && result.securityViolation === 'UNAUTHORIZED_ACCESS_ATTEMPT';
});

// Test 3: Allow authorized source IPs
runTest('Allow authorized source IPs', () => {
  const authorizedRequest = {
    method: 'GET',
    url: '/status',
    headers: { 
      'user-agent': 'admin-client',
      'x-forwarded-proto': 'https'
    },
    sourceIP: '127.0.0.1', // In allowlist
    clientCert: 'valid-cert-data'
  };

  const result = securitySystem.validateAdminRequest(authorizedRequest);
  return result.allowed;
});

// Test 4: Block requests without client certificates
runTest('Block requests without client certificates', () => {
  const noCertRequest = {
    method: 'GET',
    url: '/status',
    headers: { 
      'user-agent': 'admin-client',
      'x-forwarded-proto': 'https'
    },
    sourceIP: '127.0.0.1'
    // Missing clientCert
  };

  const result = securitySystem.validateAdminRequest(noCertRequest);
  return !result.allowed && result.securityViolation === 'MTLS_AUTHENTICATION_FAILURE';
});

// Test 5: Block write operations in lockdown mode
runTest('Block write operations in lockdown mode', () => {
  const writeRequest = {
    method: 'POST',
    url: '/services',
    headers: { 
      'user-agent': 'admin-client',
      'x-forwarded-proto': 'https'
    },
    sourceIP: '127.0.0.1',
    clientCert: 'valid-cert-data',
    body: { name: 'test-service' }
  };

  const result = securitySystem.validateAdminRequest(writeRequest);
  return !result.allowed && result.securityViolation?.includes('LOCKDOWN');
});

// Test 6: Require HTTPS protocol
runTest('Require HTTPS protocol', () => {
  const httpRequest = {
    method: 'GET',
    url: '/status',
    headers: { 
      'user-agent': 'admin-client',
      'x-forwarded-proto': 'http' // Not HTTPS
    },
    sourceIP: '127.0.0.1',
    clientCert: 'valid-cert-data'
  };

  const result = securitySystem.validateAdminRequest(httpRequest);
  return !result.allowed && result.securityViolation === 'SECURITY_HEADER_VIOLATION';
});

// Test 7: Generate secure Kong configuration
runTest('Generate secure Kong configuration', () => {
  const secureConfig = generateEmergencyKongConfig({
    allowedSourceIPs: ['127.0.0.1'],
    emergencyLockdownMode: true
  });

  return (
    secureConfig.hasOwnProperty('admin_listen') &&
    secureConfig.hasOwnProperty('admin_ssl_cert') &&
    secureConfig.hasOwnProperty('client_ssl') &&
    secureConfig['client_ssl'] === true &&
    secureConfig.hasOwnProperty('trusted_ips') &&
    Array.isArray(secureConfig['trusted_ips'])
  );
});

// Test 8: Security status reporting
runTest('Security status reporting', () => {
  const status = securitySystem.getSecurityStatus();
  
  return (
    status.hasOwnProperty('emergencyLockdownActive') &&
    status.hasOwnProperty('mtlsEnabled') &&
    status.hasOwnProperty('protectionLevel') &&
    status['protectionLevel'] === 'MAXIMUM'
  );
});

// Test 9: Handle malformed requests safely
runTest('Handle malformed requests safely', () => {
  const malformedRequests = [
    null,
    undefined,
    {},
    { method: 'GET' }, // Missing required fields
  ];

  let allBlocked = true;
  for (const request of malformedRequests) {
    try {
      const result = securitySystem.validateAdminRequest(request as any);
      if (result.allowed) {
        allBlocked = false;
        break;
      }
    } catch (error) {
      // Should not throw - should handle gracefully
      allBlocked = false;
      break;
    }
  }

  return allBlocked;
});

// Test 10: Performance validation
runTest('Performance validation (< 10ms per request)', () => {
  const testRequest = {
    method: 'GET',
    url: '/status',
    headers: { 
      'user-agent': 'performance-test',
      'x-forwarded-proto': 'https'
    },
    sourceIP: '127.0.0.1',
    clientCert: 'valid-cert-data'
  };

  const startTime = Date.now();
  
  for (let i = 0; i < 100; i++) {
    securitySystem.validateAdminRequest(testRequest);
  }

  const totalTime = Date.now() - startTime;
  const avgTimePerRequest = totalTime / 100;

  console.log(`   📊 Performance: ${avgTimePerRequest.toFixed(3)}ms per request`);
  return avgTimePerRequest < 10;
});

// Results summary
console.log('\n' + '='.repeat(60));
console.log('KONG ADMIN API SECURITY VALIDATION RESULTS');
console.log('='.repeat(60));
console.log(`Tests Run: ${testsRun}`);
console.log(`Tests Passed: ${testsPassed}`);
console.log(`Tests Failed: ${testsFailed}`);
console.log(`Success Rate: ${((testsPassed / testsRun) * 100).toFixed(1)}%`);

if (testsFailed === 0) {
  console.log('\n✅ ALL TESTS PASSED');
  console.log('🔒 Kong Admin API Emergency Security is READY for deployment');
  console.log('🚨 CVSS 9.6 Administrative System Takeover vulnerability BLOCKED');
  
  // Display security status
  const finalStatus = securitySystem.getSecurityStatus();
  console.log('\n📊 Final Security Status:');
  console.log(`   Emergency Lockdown: ${finalStatus.emergencyLockdownActive}`);
  console.log(`   mTLS Enabled: ${finalStatus.mtlsEnabled}`);
  console.log(`   Rate Limiting: ${finalStatus.rateLimitingEnabled}`);
  console.log(`   Protection Level: ${finalStatus.protectionLevel}`);
  console.log(`   Status: ${finalStatus.status}`);
  
  process.exit(0);
} else {
  console.log('\n❌ SOME TESTS FAILED');
  console.log('🚨 Kong Admin API security hardening needs review');
  process.exit(1);
}