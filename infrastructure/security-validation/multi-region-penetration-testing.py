#!/usr/bin/env python3
"""
Multi-Region Penetration Testing Framework
Production-grade security validation for multi-region infrastructure
Implements OWASP Testing Methodology and NIST Security Framework
"""

import asyncio
import ssl
import socket
import subprocess
import json
import logging
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import argparse
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID
import ipaddress


@dataclass
class SecurityTestResult:
    """Test result data structure"""
    test_name: str
    region: str
    endpoint: str
    status: str  # PASS, FAIL, WARNING, INFO
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description: str
    details: Dict[str, Any]
    remediation: str
    timestamp: datetime
    duration: float


@dataclass
class RegionConfig:
    """Multi-region configuration"""
    name: str
    primary_endpoint: str
    api_endpoints: List[str]
    load_balancer: str
    dns_records: List[str]
    expected_certificates: List[str]
    data_residency_zone: str
    compliance_requirements: List[str]


class SecurityLogger:
    """Centralized security logging"""
    
    def __init__(self, log_level: str = "INFO"):
        self.logger = logging.getLogger("SecurityValidator")
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(getattr(logging, log_level.upper()))
    
    def log_test_start(self, test_name: str, region: str, endpoint: str):
        self.logger.info(f"[{region}] Starting {test_name} for {endpoint}")
    
    def log_test_result(self, result: SecurityTestResult):
        level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH": logging.ERROR,
            "MEDIUM": logging.WARNING,
            "LOW": logging.INFO,
            "INFO": logging.INFO
        }.get(result.severity, logging.INFO)
        
        self.logger.log(level, 
            f"[{result.region}] {result.test_name}: {result.status} - {result.description}"
        )


class NetworkSecurityTester:
    """Network-level security testing"""
    
    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        
    async def test_ssl_configuration(self, region: RegionConfig, endpoint: str) -> SecurityTestResult:
        """Test SSL/TLS configuration and certificate validity"""
        test_name = "SSL/TLS Configuration Test"
        start_time = time.time()
        
        try:
            # Parse endpoint
            if "://" in endpoint:
                hostname = endpoint.split("://")[1].split("/")[0].split(":")[0]
                port = 443
                if ":" in endpoint.split("://")[1].split("/")[0]:
                    port = int(endpoint.split("://")[1].split("/")[0].split(":")[1])
            else:
                hostname = endpoint.split(":")[0]
                port = int(endpoint.split(":")[1]) if ":" in endpoint else 443
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Test SSL connection
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_obj = x509.load_der_x509_certificate(cert)
                    
                    # Certificate validation
                    issues = []
                    
                    # Check expiration
                    if cert_obj.not_valid_after < datetime.now(timezone.utc):
                        issues.append("Certificate expired")
                    elif (cert_obj.not_valid_after - datetime.now(timezone.utc)).days < 30:
                        issues.append("Certificate expires within 30 days")
                    
                    # Check signature algorithm
                    if cert_obj.signature_algorithm_oid._name in ['sha1WithRSAEncryption']:
                        issues.append("Weak signature algorithm (SHA1)")
                    
                    # Check key size
                    public_key = cert_obj.public_key()
                    if hasattr(public_key, 'key_size') and public_key.key_size < 2048:
                        issues.append(f"Weak key size: {public_key.key_size} bits")
                    
                    # Test cipher suites
                    cipher = ssock.cipher()
                    if cipher and cipher[1] < 128:
                        issues.append(f"Weak cipher key length: {cipher[1]} bits")
                    
                    # Test protocol version
                    if ssock.version() in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        issues.append(f"Deprecated protocol version: {ssock.version()}")
                    
                    status = "FAIL" if issues else "PASS"
                    severity = "HIGH" if any("expired" in issue for issue in issues) else "MEDIUM" if issues else "INFO"
                    
                    return SecurityTestResult(
                        test_name=test_name,
                        region=region.name,
                        endpoint=endpoint,
                        status=status,
                        severity=severity,
                        description=f"SSL/TLS validation: {len(issues)} issues found",
                        details={
                            "certificate_subject": cert_obj.subject.rfc4514_string(),
                            "certificate_issuer": cert_obj.issuer.rfc4514_string(),
                            "expires": cert_obj.not_valid_after.isoformat(),
                            "protocol_version": ssock.version(),
                            "cipher_suite": cipher,
                            "issues": issues
                        },
                        remediation="Update certificates, disable weak ciphers, enforce TLS 1.2+",
                        timestamp=datetime.now(timezone.utc),
                        duration=time.time() - start_time
                    )
                    
        except Exception as e:
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=endpoint,
                status="FAIL",
                severity="HIGH",
                description=f"SSL connection failed: {str(e)}",
                details={"error": str(e)},
                remediation="Fix SSL configuration and certificate issues",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )
    
    async def test_dns_security(self, region: RegionConfig) -> List[SecurityTestResult]:
        """Test DNS configuration and security"""
        results = []
        
        for dns_record in region.dns_records:
            test_name = "DNS Security Test"
            start_time = time.time()
            
            try:
                # DNS resolution test
                resolver = dns.resolver.Resolver()
                resolver.timeout = 10
                
                issues = []
                
                # Test A record
                try:
                    a_records = resolver.resolve(dns_record, 'A')
                    ip_addresses = [str(record) for record in a_records]
                    
                    # Check for private IP exposure
                    for ip in ip_addresses:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj.is_private:
                                issues.append(f"Private IP exposed in DNS: {ip}")
                        except ValueError:
                            pass
                            
                except Exception as e:
                    issues.append(f"A record resolution failed: {str(e)}")
                
                # Test DNSSEC
                try:
                    dnssec_records = resolver.resolve(dns_record, 'DNSKEY')
                    if not dnssec_records:
                        issues.append("DNSSEC not configured")
                except Exception:
                    issues.append("DNSSEC not configured")
                
                # Test CAA record
                try:
                    caa_records = resolver.resolve(dns_record, 'CAA')
                    if not caa_records:
                        issues.append("CAA record not configured")
                except Exception:
                    issues.append("CAA record not configured")
                
                status = "FAIL" if issues else "PASS"
                severity = "MEDIUM" if issues else "INFO"
                
                results.append(SecurityTestResult(
                    test_name=test_name,
                    region=region.name,
                    endpoint=dns_record,
                    status=status,
                    severity=severity,
                    description=f"DNS security validation: {len(issues)} issues found",
                    details={
                        "ip_addresses": ip_addresses if 'ip_addresses' in locals() else [],
                        "issues": issues
                    },
                    remediation="Configure DNSSEC, CAA records, and secure DNS settings",
                    timestamp=datetime.now(timezone.utc),
                    duration=time.time() - start_time
                ))
                
            except Exception as e:
                results.append(SecurityTestResult(
                    test_name=test_name,
                    region=region.name,
                    endpoint=dns_record,
                    status="FAIL",
                    severity="HIGH",
                    description=f"DNS test failed: {str(e)}",
                    details={"error": str(e)},
                    remediation="Fix DNS configuration",
                    timestamp=datetime.now(timezone.utc),
                    duration=time.time() - start_time
                ))
        
        return results


class ApplicationSecurityTester:
    """Application-level security testing"""
    
    def __init__(self, logger: SecurityLogger):
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'iSECTECH-Security-Scanner/1.0',
            'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
    
    async def test_security_headers(self, region: RegionConfig, endpoint: str) -> SecurityTestResult:
        """Test HTTP security headers"""
        test_name = "Security Headers Test"
        start_time = time.time()
        
        try:
            response = self.session.get(endpoint, timeout=30, verify=True, allow_redirects=True)
            
            required_headers = {
                'Strict-Transport-Security': 'HSTS header missing',
                'X-Content-Type-Options': 'Content-Type-Options header missing',
                'X-Frame-Options': 'X-Frame-Options header missing',
                'X-XSS-Protection': 'XSS-Protection header missing',
                'Content-Security-Policy': 'CSP header missing',
                'Referrer-Policy': 'Referrer-Policy header missing',
                'Permissions-Policy': 'Permissions-Policy header missing'
            }
            
            issues = []
            for header, message in required_headers.items():
                if header not in response.headers:
                    issues.append(message)
                elif header == 'Strict-Transport-Security':
                    # Validate HSTS header
                    hsts_value = response.headers[header]
                    if 'max-age' not in hsts_value.lower():
                        issues.append("HSTS header missing max-age directive")
                    elif int(hsts_value.split('max-age=')[1].split(';')[0]) < 31536000:
                        issues.append("HSTS max-age too low (should be >= 1 year)")
            
            # Check for information disclosure headers
            dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in dangerous_headers:
                if header in response.headers:
                    issues.append(f"Information disclosure header: {header}: {response.headers[header]}")
            
            status = "FAIL" if issues else "PASS"
            severity = "MEDIUM" if issues else "INFO"
            
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=endpoint,
                status=status,
                severity=severity,
                description=f"Security headers validation: {len(issues)} issues found",
                details={
                    "response_headers": dict(response.headers),
                    "status_code": response.status_code,
                    "issues": issues
                },
                remediation="Configure all required security headers with appropriate values",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )
            
        except Exception as e:
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=endpoint,
                status="FAIL",
                severity="HIGH",
                description=f"HTTP request failed: {str(e)}",
                details={"error": str(e)},
                remediation="Fix network connectivity and endpoint configuration",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )
    
    async def test_authentication_security(self, region: RegionConfig, endpoint: str) -> SecurityTestResult:
        """Test authentication and authorization security"""
        test_name = "Authentication Security Test"
        start_time = time.time()
        
        try:
            issues = []
            
            # Test for default credentials
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('root', 'root'),
                ('test', 'test')
            ]
            
            for username, password in default_creds:
                try:
                    auth_response = self.session.post(
                        f"{endpoint}/api/auth/login",
                        json={"username": username, "password": password},
                        timeout=10
                    )
                    if auth_response.status_code == 200:
                        issues.append(f"Default credentials accepted: {username}:{password}")
                except requests.exceptions.RequestException:
                    pass  # Expected for most endpoints
            
            # Test rate limiting
            auth_attempts = []
            for i in range(10):
                try:
                    auth_response = self.session.post(
                        f"{endpoint}/api/auth/login",
                        json={"username": "testuser", "password": "wrongpassword"},
                        timeout=5
                    )
                    auth_attempts.append(auth_response.status_code)
                except requests.exceptions.RequestException as e:
                    auth_attempts.append(str(e))
            
            # Check if rate limiting is in place
            if all(isinstance(code, int) and code != 429 for code in auth_attempts):
                issues.append("No rate limiting detected on authentication endpoint")
            
            # Test for session fixation
            try:
                # Get initial session
                initial_response = self.session.get(f"{endpoint}/", timeout=10)
                initial_cookies = self.session.cookies.get_dict()
                
                # Attempt login
                login_response = self.session.post(
                    f"{endpoint}/api/auth/login",
                    json={"username": "testuser", "password": "testpass"},
                    timeout=10
                )
                post_login_cookies = self.session.cookies.get_dict()
                
                # Check if session ID changed after login
                if initial_cookies == post_login_cookies and initial_cookies:
                    issues.append("Potential session fixation vulnerability")
                    
            except requests.exceptions.RequestException:
                pass  # Expected for endpoints without login
            
            status = "FAIL" if issues else "PASS"
            severity = "HIGH" if any("default credentials" in issue.lower() for issue in issues) else "MEDIUM" if issues else "INFO"
            
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=endpoint,
                status=status,
                severity=severity,
                description=f"Authentication security validation: {len(issues)} issues found",
                details={
                    "issues": issues,
                    "rate_limit_test": auth_attempts
                },
                remediation="Disable default credentials, implement rate limiting, prevent session fixation",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )
            
        except Exception as e:
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=endpoint,
                status="FAIL",
                severity="MEDIUM",
                description=f"Authentication test failed: {str(e)}",
                details={"error": str(e)},
                remediation="Review authentication endpoint configuration",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )


class DataResidencyValidator:
    """Data residency and compliance validation"""
    
    def __init__(self, logger: SecurityLogger):
        self.logger = logger
    
    async def test_data_residency_compliance(self, region: RegionConfig) -> SecurityTestResult:
        """Test data residency compliance"""
        test_name = "Data Residency Compliance Test"
        start_time = time.time()
        
        try:
            issues = []
            
            # Test each endpoint for data residency compliance
            for endpoint in region.api_endpoints:
                try:
                    # Make request with geo-location headers
                    headers = {
                        'X-Client-Region': region.data_residency_zone,
                        'X-Compliance-Check': 'data-residency'
                    }
                    
                    response = requests.get(f"{endpoint}/api/compliance/data-location", 
                                          headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Check if data is processed in correct region
                        processing_region = data.get('processing_region', 'unknown')
                        if processing_region != region.data_residency_zone:
                            issues.append(f"Data processed outside residency zone: {processing_region}")
                        
                        # Check storage location
                        storage_region = data.get('storage_region', 'unknown')
                        if storage_region != region.data_residency_zone:
                            issues.append(f"Data stored outside residency zone: {storage_region}")
                        
                    else:
                        issues.append(f"Data residency endpoint not accessible: {response.status_code}")
                        
                except requests.exceptions.RequestException as e:
                    issues.append(f"Failed to test data residency for {endpoint}: {str(e)}")
            
            # Test cross-region data leakage
            try:
                # Attempt to access data from different region
                other_regions = ['us-east-1', 'eu-west-1', 'ap-southeast-1']
                for test_region in other_regions:
                    if test_region != region.data_residency_zone:
                        headers = {'X-Client-Region': test_region}
                        response = requests.get(f"{region.primary_endpoint}/api/data/region-test",
                                              headers=headers, timeout=30)
                        
                        if response.status_code == 200:
                            data = response.json()
                            if data.get('accessible', False):
                                issues.append(f"Data accessible from unauthorized region: {test_region}")
            except requests.exceptions.RequestException:
                pass  # Expected if endpoint doesn't exist
            
            status = "FAIL" if issues else "PASS"
            severity = "CRITICAL" if any("outside residency zone" in issue for issue in issues) else "HIGH" if issues else "INFO"
            
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=region.primary_endpoint,
                status=status,
                severity=severity,
                description=f"Data residency compliance: {len(issues)} violations found",
                details={
                    "expected_zone": region.data_residency_zone,
                    "compliance_requirements": region.compliance_requirements,
                    "issues": issues
                },
                remediation="Ensure all data processing and storage occurs within designated region",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )
            
        except Exception as e:
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=region.primary_endpoint,
                status="FAIL",
                severity="HIGH",
                description=f"Data residency test failed: {str(e)}",
                details={"error": str(e)},
                remediation="Fix data residency compliance testing endpoint",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )


class CrossRegionIsolationTester:
    """Test cross-region isolation and data leakage prevention"""
    
    def __init__(self, logger: SecurityLogger):
        self.logger = logger
    
    async def test_region_isolation(self, regions: List[RegionConfig]) -> List[SecurityTestResult]:
        """Test isolation between regions"""
        results = []
        
        for source_region in regions:
            for target_region in regions:
                if source_region.name == target_region.name:
                    continue
                
                test_name = "Cross-Region Isolation Test"
                start_time = time.time()
                
                try:
                    issues = []
                    
                    # Test data access from different region
                    test_data_id = f"test-data-{secrets.token_hex(8)}"
                    
                    # Create test data in source region
                    try:
                        create_response = requests.post(
                            f"{source_region.primary_endpoint}/api/test-data",
                            json={
                                "id": test_data_id,
                                "data": "sensitive-test-data",
                                "region": source_region.data_residency_zone
                            },
                            timeout=30
                        )
                        
                        if create_response.status_code in [200, 201]:
                            # Try to access from target region
                            access_response = requests.get(
                                f"{target_region.primary_endpoint}/api/test-data/{test_data_id}",
                                timeout=30
                            )
                            
                            if access_response.status_code == 200:
                                issues.append(f"Cross-region data access possible from {target_region.name}")
                                
                    except requests.exceptions.RequestException:
                        pass  # Expected if endpoint doesn't exist
                    
                    # Test network connectivity between regions
                    try:
                        # This should fail or be restricted
                        direct_response = requests.get(
                            f"{source_region.primary_endpoint}/api/internal/region-status",
                            headers={'X-Source-Region': target_region.name},
                            timeout=30
                        )
                        
                        if direct_response.status_code == 200:
                            data = direct_response.json()
                            if data.get('internal_access_allowed', False):
                                issues.append("Internal region endpoints accessible externally")
                                
                    except requests.exceptions.RequestException:
                        pass  # Expected
                    
                    # Test session sharing between regions
                    try:
                        # Login to source region
                        login_response = requests.post(
                            f"{source_region.primary_endpoint}/api/auth/login",
                            json={"username": "test", "password": "test"},
                            timeout=10
                        )
                        
                        if login_response.status_code == 200:
                            session_cookie = login_response.cookies.get('session')
                            if session_cookie:
                                # Try to use session in target region
                                auth_check = requests.get(
                                    f"{target_region.primary_endpoint}/api/auth/check",
                                    cookies={'session': session_cookie},
                                    timeout=10
                                )
                                
                                if auth_check.status_code == 200:
                                    issues.append("Sessions shared across regions")
                                    
                    except requests.exceptions.RequestException:
                        pass  # Expected
                    
                    status = "FAIL" if issues else "PASS"
                    severity = "CRITICAL" if any("cross-region" in issue.lower() for issue in issues) else "HIGH" if issues else "INFO"
                    
                    results.append(SecurityTestResult(
                        test_name=test_name,
                        region=f"{source_region.name}->{target_region.name}",
                        endpoint=f"{source_region.primary_endpoint} -> {target_region.primary_endpoint}",
                        status=status,
                        severity=severity,
                        description=f"Region isolation test: {len(issues)} violations found",
                        details={
                            "source_region": source_region.name,
                            "target_region": target_region.name,
                            "issues": issues
                        },
                        remediation="Implement proper region isolation and access controls",
                        timestamp=datetime.now(timezone.utc),
                        duration=time.time() - start_time
                    ))
                    
                except Exception as e:
                    results.append(SecurityTestResult(
                        test_name=test_name,
                        region=f"{source_region.name}->{target_region.name}",
                        endpoint=f"{source_region.primary_endpoint} -> {target_region.primary_endpoint}",
                        status="FAIL",
                        severity="HIGH",
                        description=f"Region isolation test failed: {str(e)}",
                        details={"error": str(e)},
                        remediation="Fix region isolation testing framework",
                        timestamp=datetime.now(timezone.utc),
                        duration=time.time() - start_time
                    ))
        
        return results


class EncryptionValidator:
    """Test encryption in transit and at rest"""
    
    def __init__(self, logger: SecurityLogger):
        self.logger = logger
    
    async def test_encryption_in_transit(self, region: RegionConfig) -> List[SecurityTestResult]:
        """Test encryption in transit"""
        results = []
        
        for endpoint in region.api_endpoints:
            test_name = "Encryption in Transit Test"
            start_time = time.time()
            
            try:
                issues = []
                
                # Test HTTP vs HTTPS redirection
                if endpoint.startswith('https://'):
                    http_endpoint = endpoint.replace('https://', 'http://')
                    try:
                        http_response = requests.get(http_endpoint, timeout=30, allow_redirects=False)
                        if http_response.status_code not in [301, 302, 308]:
                            issues.append("HTTP not redirected to HTTPS")
                    except requests.exceptions.RequestException:
                        pass  # Expected if HTTP is blocked
                
                # Test TLS configuration
                try:
                    response = requests.get(endpoint, timeout=30)
                    
                    # Check if connection was secure
                    if not endpoint.startswith('https://'):
                        issues.append("Endpoint not using HTTPS")
                    
                    # Test for mixed content (if HTML response)
                    if 'text/html' in response.headers.get('content-type', ''):
                        if 'http://' in response.text and endpoint.startswith('https://'):
                            issues.append("Mixed content detected (HTTP resources in HTTPS page)")
                            
                except requests.exceptions.RequestException as e:
                    issues.append(f"Failed to test HTTPS endpoint: {str(e)}")
                
                # Test API encryption
                try:
                    # Test if API enforces encryption
                    api_response = requests.post(
                        f"{endpoint}/api/test-encryption",
                        json={"test": "sensitive-data"},
                        timeout=30
                    )
                    
                    if api_response.status_code == 200:
                        # Check response headers for encryption indicators
                        if 'X-Encryption-Status' not in api_response.headers:
                            issues.append("API encryption status not indicated")
                            
                except requests.exceptions.RequestException:
                    pass  # Expected if endpoint doesn't exist
                
                status = "FAIL" if issues else "PASS"
                severity = "HIGH" if any("not using https" in issue.lower() for issue in issues) else "MEDIUM" if issues else "INFO"
                
                results.append(SecurityTestResult(
                    test_name=test_name,
                    region=region.name,
                    endpoint=endpoint,
                    status=status,
                    severity=severity,
                    description=f"Encryption in transit: {len(issues)} issues found",
                    details={"issues": issues},
                    remediation="Enforce HTTPS, configure proper TLS, eliminate mixed content",
                    timestamp=datetime.now(timezone.utc),
                    duration=time.time() - start_time
                ))
                
            except Exception as e:
                results.append(SecurityTestResult(
                    test_name=test_name,
                    region=region.name,
                    endpoint=endpoint,
                    status="FAIL",
                    severity="HIGH",
                    description=f"Encryption test failed: {str(e)}",
                    details={"error": str(e)},
                    remediation="Fix encryption testing configuration",
                    timestamp=datetime.now(timezone.utc),
                    duration=time.time() - start_time
                ))
        
        return results
    
    async def test_encryption_at_rest(self, region: RegionConfig) -> SecurityTestResult:
        """Test encryption at rest"""
        test_name = "Encryption at Rest Test"
        start_time = time.time()
        
        try:
            issues = []
            
            # Test database encryption
            try:
                db_status_response = requests.get(
                    f"{region.primary_endpoint}/api/admin/database-encryption-status",
                    timeout=30
                )
                
                if db_status_response.status_code == 200:
                    db_data = db_status_response.json()
                    
                    if not db_data.get('encryption_enabled', False):
                        issues.append("Database encryption not enabled")
                    
                    encryption_algorithm = db_data.get('encryption_algorithm', '')
                    if encryption_algorithm.lower() not in ['aes-256', 'aes-256-gcm']:
                        issues.append(f"Weak database encryption algorithm: {encryption_algorithm}")
                        
                else:
                    issues.append("Cannot verify database encryption status")
                    
            except requests.exceptions.RequestException:
                issues.append("Database encryption status endpoint unavailable")
            
            # Test file storage encryption
            try:
                storage_response = requests.get(
                    f"{region.primary_endpoint}/api/admin/storage-encryption-status",
                    timeout=30
                )
                
                if storage_response.status_code == 200:
                    storage_data = storage_response.json()
                    
                    if not storage_data.get('encryption_enabled', False):
                        issues.append("File storage encryption not enabled")
                        
                    key_management = storage_data.get('key_management', '')
                    if 'kms' not in key_management.lower():
                        issues.append("Key management service not properly configured")
                        
                else:
                    issues.append("Cannot verify storage encryption status")
                    
            except requests.exceptions.RequestException:
                issues.append("Storage encryption status endpoint unavailable")
            
            status = "FAIL" if issues else "PASS"
            severity = "CRITICAL" if any("not enabled" in issue for issue in issues) else "HIGH" if issues else "INFO"
            
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=region.primary_endpoint,
                status=status,
                severity=severity,
                description=f"Encryption at rest: {len(issues)} issues found",
                details={"issues": issues},
                remediation="Enable database and storage encryption with strong algorithms",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )
            
        except Exception as e:
            return SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=region.primary_endpoint,
                status="FAIL",
                severity="HIGH",
                description=f"Encryption at rest test failed: {str(e)}",
                details={"error": str(e)},
                remediation="Fix encryption at rest testing configuration",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            )


class IAMAccessControlTester:
    """Test IAM and access control across regions"""
    
    def __init__(self, logger: SecurityLogger):
        self.logger = logger
    
    async def test_iam_controls(self, region: RegionConfig) -> List[SecurityTestResult]:
        """Test IAM and access controls"""
        results = []
        
        # Test privilege escalation
        test_name = "Privilege Escalation Test"
        start_time = time.time()
        
        try:
            issues = []
            
            # Test horizontal privilege escalation
            try:
                # Create low-privilege user context
                user_response = requests.post(
                    f"{region.primary_endpoint}/api/auth/test-user",
                    json={"role": "viewer"},
                    timeout=30
                )
                
                if user_response.status_code == 200:
                    user_token = user_response.json().get('token')
                    
                    # Try to access admin endpoints
                    admin_attempts = [
                        "/api/admin/users",
                        "/api/admin/config",
                        "/api/admin/logs"
                    ]
                    
                    for endpoint in admin_attempts:
                        admin_response = requests.get(
                            f"{region.primary_endpoint}{endpoint}",
                            headers={"Authorization": f"Bearer {user_token}"},
                            timeout=10
                        )
                        
                        if admin_response.status_code == 200:
                            issues.append(f"Privilege escalation possible: {endpoint}")
                            
            except requests.exceptions.RequestException:
                pass  # Expected if test endpoints don't exist
            
            # Test role-based access control
            try:
                roles_response = requests.get(
                    f"{region.primary_endpoint}/api/auth/roles",
                    timeout=30
                )
                
                if roles_response.status_code == 200:
                    roles_data = roles_response.json()
                    
                    # Check for overly permissive roles
                    for role in roles_data.get('roles', []):
                        permissions = role.get('permissions', [])
                        if '*' in permissions or 'admin:*' in permissions:
                            if role.get('name') not in ['super_admin', 'system_admin']:
                                issues.append(f"Overly permissive role: {role.get('name')}")
                                
            except requests.exceptions.RequestException:
                issues.append("Cannot verify role configuration")
            
            status = "FAIL" if issues else "PASS"
            severity = "HIGH" if any("escalation possible" in issue for issue in issues) else "MEDIUM" if issues else "INFO"
            
            results.append(SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=region.primary_endpoint,
                status=status,
                severity=severity,
                description=f"IAM privilege escalation test: {len(issues)} issues found",
                details={"issues": issues},
                remediation="Fix privilege escalation vulnerabilities and role permissions",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            ))
            
        except Exception as e:
            results.append(SecurityTestResult(
                test_name=test_name,
                region=region.name,
                endpoint=region.primary_endpoint,
                status="FAIL",
                severity="HIGH",
                description=f"IAM test failed: {str(e)}",
                details={"error": str(e)},
                remediation="Fix IAM testing configuration",
                timestamp=datetime.now(timezone.utc),
                duration=time.time() - start_time
            ))
        
        return results


class MultiRegionPenetrationTester:
    """Main penetration testing orchestrator"""
    
    def __init__(self, config_file: str, output_file: str = "security_report.json", log_level: str = "INFO"):
        self.logger = SecurityLogger(log_level)
        self.output_file = output_file
        
        # Initialize testers
        self.network_tester = NetworkSecurityTester(self.logger)
        self.app_tester = ApplicationSecurityTester(self.logger)
        self.data_tester = DataResidencyValidator(self.logger)
        self.isolation_tester = CrossRegionIsolationTester(self.logger)
        self.encryption_tester = EncryptionValidator(self.logger)
        self.iam_tester = IAMAccessControlTester(self.logger)
        
        # Load configuration
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        self.regions = [RegionConfig(**region) for region in config_data['regions']]
        self.test_config = config_data.get('test_config', {})
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests"""
        start_time = time.time()
        all_results = []
        
        self.logger.logger.info("Starting multi-region penetration testing...")
        
        # Test each region individually
        for region in self.regions:
            self.logger.logger.info(f"Testing region: {region.name}")
            
            region_tests = []
            
            # Network security tests
            for endpoint in region.api_endpoints:
                region_tests.append(self.network_tester.test_ssl_configuration(region, endpoint))
                region_tests.append(self.app_tester.test_security_headers(region, endpoint))
                region_tests.append(self.app_tester.test_authentication_security(region, endpoint))
            
            region_tests.extend(await self.network_tester.test_dns_security(region))
            region_tests.append(self.data_tester.test_data_residency_compliance(region))
            region_tests.extend(await self.encryption_tester.test_encryption_in_transit(region))
            region_tests.append(self.encryption_tester.test_encryption_at_rest(region))
            region_tests.extend(await self.iam_tester.test_iam_controls(region))
            
            # Run tests concurrently
            region_results = await asyncio.gather(*region_tests, return_exceptions=True)
            
            # Filter out exceptions and flatten results
            for result in region_results:
                if isinstance(result, Exception):
                    self.logger.logger.error(f"Test failed with exception: {result}")
                elif isinstance(result, list):
                    all_results.extend(result)
                else:
                    all_results.append(result)
        
        # Cross-region tests
        self.logger.logger.info("Running cross-region tests...")
        isolation_results = await self.isolation_tester.test_region_isolation(self.regions)
        all_results.extend(isolation_results)
        
        # Generate summary
        summary = self._generate_summary(all_results)
        
        # Save results
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration": time.time() - start_time,
            "regions_tested": [region.name for region in self.regions],
            "total_tests": len(all_results),
            "summary": summary,
            "results": [asdict(result) for result in all_results]
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.logger.info(f"Security testing completed. Report saved to: {self.output_file}")
        
        return report
    
    def _generate_summary(self, results: List[SecurityTestResult]) -> Dict[str, Any]:
        """Generate test summary"""
        total = len(results)
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        warnings = sum(1 for r in results if r.status == "WARNING")
        
        severity_counts = {}
        for result in results:
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1
        
        critical_issues = [r for r in results if r.severity == "CRITICAL"]
        high_issues = [r for r in results if r.severity == "HIGH"]
        
        return {
            "total_tests": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "pass_rate": f"{(passed/total*100):.1f}%" if total > 0 else "0%",
            "severity_breakdown": severity_counts,
            "critical_issues_count": len(critical_issues),
            "high_issues_count": len(high_issues),
            "top_critical_issues": [
                {"test": issue.test_name, "region": issue.region, "description": issue.description}
                for issue in critical_issues[:5]
            ],
            "top_high_issues": [
                {"test": issue.test_name, "region": issue.region, "description": issue.description}
                for issue in high_issues[:10]
            ]
        }


async def main():
    parser = argparse.ArgumentParser(description="Multi-Region Penetration Testing")
    parser.add_argument("--config", required=True, help="Configuration file path")
    parser.add_argument("--output", default="security_report.json", help="Output report file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config):
        print(f"Configuration file not found: {args.config}")
        sys.exit(1)
    
    tester = MultiRegionPenetrationTester(args.config, args.output, args.log_level)
    report = await tester.run_all_tests()
    
    # Print summary
    summary = report['summary']
    print(f"\n{'='*60}")
    print("SECURITY TESTING SUMMARY")
    print(f"{'='*60}")
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Passed: {summary['passed']} ({summary['pass_rate']})")
    print(f"Failed: {summary['failed']}")
    print(f"Critical Issues: {summary['critical_issues_count']}")
    print(f"High Issues: {summary['high_issues_count']}")
    
    if summary['critical_issues_count'] > 0:
        print(f"\nCRITICAL ISSUES:")
        for issue in summary['top_critical_issues']:
            print(f"  • [{issue['region']}] {issue['test']}: {issue['description']}")
    
    if summary['high_issues_count'] > 0:
        print(f"\nHIGH PRIORITY ISSUES:")
        for issue in summary['top_high_issues']:
            print(f"  • [{issue['region']}] {issue['test']}: {issue['description']}")
    
    # Exit with appropriate code
    if summary['critical_issues_count'] > 0:
        sys.exit(2)  # Critical issues found
    elif summary['high_issues_count'] > 0:
        sys.exit(1)  # High issues found
    else:
        sys.exit(0)  # All tests passed


if __name__ == "__main__":
    asyncio.run(main())