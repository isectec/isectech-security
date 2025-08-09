#!/usr/bin/env python3
"""
IAM and Access Control Testing Framework
Production-grade validation of identity and access management across regions
Implements OWASP ASVS and NIST access control standards
"""

import asyncio
import json
import logging
import time
import hashlib
import secrets
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import argparse
import sys
import os
from concurrent.futures import ThreadPoolExecutor
import requests
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


@dataclass
class AccessControlTest:
    """Access control test definition"""
    test_id: str
    test_name: str
    test_type: str  # RBAC, ABAC, PRIVILEGE_ESCALATION, SESSION_MANAGEMENT
    region: str
    endpoint: str
    user_context: Dict[str, Any]
    expected_access: bool
    resource_path: str
    http_method: str
    payload: Optional[Dict[str, Any]] = None


@dataclass
class AccessControlResult:
    """Access control test result"""
    test_id: str
    test_name: str
    region: str
    endpoint: str
    status: str  # PASS, FAIL, ERROR
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    actual_access: bool
    expected_access: bool
    response_code: int
    response_time: float
    vulnerability_type: Optional[str]
    evidence: Dict[str, Any]
    remediation: str
    timestamp: datetime


@dataclass
class UserContext:
    """User context for testing"""
    user_id: str
    username: str
    roles: List[str]
    permissions: List[str]
    attributes: Dict[str, Any]
    session_token: Optional[str] = None
    jwt_token: Optional[str] = None


class JWTTokenGenerator:
    """Generate JWT tokens for testing"""
    
    def __init__(self):
        # Generate test key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def generate_token(self, user_context: UserContext, expires_in: int = 3600) -> str:
        """Generate JWT token for user context"""
        now = datetime.utcnow()
        
        payload = {
            'sub': user_context.user_id,
            'username': user_context.username,
            'roles': user_context.roles,
            'permissions': user_context.permissions,
            'attributes': user_context.attributes,
            'iat': now,
            'exp': now + timedelta(seconds=expires_in),
            'iss': 'isectech-security-test',
            'aud': 'isectech-api'
        }
        
        # Sign with RS256
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        token = jwt.encode(
            payload, 
            private_key_pem, 
            algorithm='RS256',
            headers={'kid': 'test-key-1'}
        )
        
        return token
    
    def generate_malformed_token(self, user_context: UserContext) -> str:
        """Generate malformed token for testing"""
        # Create token with wrong signature
        payload = {
            'sub': user_context.user_id,
            'username': user_context.username,
            'roles': ['admin'],  # Escalated privileges
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        
        # Use different key to create invalid signature
        wrong_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        wrong_key_pem = wrong_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return jwt.encode(payload, wrong_key_pem, algorithm='RS256')
    
    def generate_expired_token(self, user_context: UserContext) -> str:
        """Generate expired token for testing"""
        payload = {
            'sub': user_context.user_id,
            'username': user_context.username,
            'roles': user_context.roles,
            'exp': datetime.utcnow() - timedelta(hours=1)  # Expired
        }
        
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return jwt.encode(payload, private_key_pem, algorithm='RS256')


class RBACTester:
    """Role-Based Access Control testing"""
    
    def __init__(self, logger: logging.Logger, token_generator: JWTTokenGenerator):
        self.logger = logger
        self.token_generator = token_generator
        self.session = requests.Session()
    
    async def test_role_based_access(self, test: AccessControlTest) -> AccessControlResult:
        """Test role-based access control"""
        start_time = time.time()
        
        try:
            # Generate token for user context
            user_context = UserContext(**test.user_context)
            token = self.token_generator.generate_token(user_context)
            
            # Make request with token
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'X-Test-ID': test.test_id
            }
            
            url = f"{test.endpoint}{test.resource_path}"
            
            if test.http_method == 'GET':
                response = self.session.get(url, headers=headers, timeout=30)
            elif test.http_method == 'POST':
                response = self.session.post(url, headers=headers, json=test.payload, timeout=30)
            elif test.http_method == 'PUT':
                response = self.session.put(url, headers=headers, json=test.payload, timeout=30)
            elif test.http_method == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {test.http_method}")
            
            actual_access = response.status_code < 400
            response_time = time.time() - start_time
            
            # Determine test result
            if actual_access == test.expected_access:
                status = "PASS"
                severity = "INFO"
                vulnerability_type = None
                remediation = "Access control working as expected"
            else:
                status = "FAIL"
                if actual_access and not test.expected_access:
                    # Unauthorized access granted
                    severity = "CRITICAL"
                    vulnerability_type = "UNAUTHORIZED_ACCESS"
                    remediation = "Restrict access to authorized users only"
                else:
                    # Authorized access denied
                    severity = "MEDIUM"
                    vulnerability_type = "ACCESS_DENIED"
                    remediation = "Review access control rules for authorized users"
            
            return AccessControlResult(
                test_id=test.test_id,
                test_name=test.test_name,
                region=test.region,
                endpoint=test.endpoint,
                status=status,
                severity=severity,
                actual_access=actual_access,
                expected_access=test.expected_access,
                response_code=response.status_code,
                response_time=response_time,
                vulnerability_type=vulnerability_type,
                evidence={
                    'user_roles': user_context.roles,
                    'user_permissions': user_context.permissions,
                    'resource_path': test.resource_path,
                    'http_method': test.http_method,
                    'response_headers': dict(response.headers)
                },
                remediation=remediation,
                timestamp=datetime.now(timezone.utc)
            )
            
        except Exception as e:
            return AccessControlResult(
                test_id=test.test_id,
                test_name=test.test_name,
                region=test.region,
                endpoint=test.endpoint,
                status="ERROR",
                severity="HIGH",
                actual_access=False,
                expected_access=test.expected_access,
                response_code=0,
                response_time=time.time() - start_time,
                vulnerability_type="TEST_ERROR",
                evidence={'error': str(e)},
                remediation="Fix test configuration or endpoint availability",
                timestamp=datetime.now(timezone.utc)
            )


class PrivilegeEscalationTester:
    """Test for privilege escalation vulnerabilities"""
    
    def __init__(self, logger: logging.Logger, token_generator: JWTTokenGenerator):
        self.logger = logger
        self.token_generator = token_generator
        self.session = requests.Session()
    
    async def test_horizontal_privilege_escalation(self, test: AccessControlTest) -> AccessControlResult:
        """Test horizontal privilege escalation"""
        start_time = time.time()
        
        try:
            user_context = UserContext(**test.user_context)
            
            # Test accessing another user's resources
            token = self.token_generator.generate_token(user_context)
            
            # Try to access different user's resources
            target_user_ids = ['user123', 'admin456', 'test789']
            escalation_detected = False
            evidence = []
            
            for target_user_id in target_user_ids:
                if target_user_id == user_context.user_id:
                    continue
                
                # Try to access target user's data
                headers = {'Authorization': f'Bearer {token}'}
                url = f"{test.endpoint}/api/users/{target_user_id}/profile"
                
                response = self.session.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    escalation_detected = True
                    evidence.append({
                        'target_user': target_user_id,
                        'accessible': True,
                        'response_code': response.status_code
                    })
            
            response_time = time.time() - start_time
            
            if escalation_detected:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="FAIL",
                    severity="CRITICAL",
                    actual_access=True,
                    expected_access=False,
                    response_code=200,
                    response_time=response_time,
                    vulnerability_type="HORIZONTAL_PRIVILEGE_ESCALATION",
                    evidence={
                        'user_context': asdict(user_context),
                        'escalation_evidence': evidence
                    },
                    remediation="Implement proper user isolation and access controls",
                    timestamp=datetime.now(timezone.utc)
                )
            else:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="PASS",
                    severity="INFO",
                    actual_access=False,
                    expected_access=False,
                    response_code=403,
                    response_time=response_time,
                    vulnerability_type=None,
                    evidence={'test_attempts': len(target_user_ids)},
                    remediation="User isolation working correctly",
                    timestamp=datetime.now(timezone.utc)
                )
                
        except Exception as e:
            return AccessControlResult(
                test_id=test.test_id,
                test_name=test.test_name,
                region=test.region,
                endpoint=test.endpoint,
                status="ERROR",
                severity="HIGH",
                actual_access=False,
                expected_access=False,
                response_code=0,
                response_time=time.time() - start_time,
                vulnerability_type="TEST_ERROR",
                evidence={'error': str(e)},
                remediation="Fix test configuration",
                timestamp=datetime.now(timezone.utc)
            )
    
    async def test_vertical_privilege_escalation(self, test: AccessControlTest) -> AccessControlResult:
        """Test vertical privilege escalation"""
        start_time = time.time()
        
        try:
            user_context = UserContext(**test.user_context)
            
            # Test accessing admin endpoints with regular user
            admin_endpoints = [
                '/api/admin/users',
                '/api/admin/config',
                '/api/admin/logs',
                '/api/admin/system',
                '/api/admin/reports'
            ]
            
            token = self.token_generator.generate_token(user_context)
            headers = {'Authorization': f'Bearer {token}'}
            
            escalation_detected = False
            evidence = []
            
            for endpoint_path in admin_endpoints:
                url = f"{test.endpoint}{endpoint_path}"
                
                try:
                    response = self.session.get(url, headers=headers, timeout=30)
                    
                    if response.status_code == 200:
                        escalation_detected = True
                        evidence.append({
                            'admin_endpoint': endpoint_path,
                            'accessible': True,
                            'response_code': response.status_code
                        })
                except requests.exceptions.RequestException:
                    # Expected for non-existent endpoints
                    pass
            
            response_time = time.time() - start_time
            
            # Also test malformed token with elevated privileges
            malformed_token = self.token_generator.generate_malformed_token(user_context)
            malformed_headers = {'Authorization': f'Bearer {malformed_token}'}
            
            try:
                response = self.session.get(f"{test.endpoint}/api/admin/users", 
                                         headers=malformed_headers, timeout=30)
                if response.status_code == 200:
                    escalation_detected = True
                    evidence.append({
                        'malformed_token_access': True,
                        'endpoint': '/api/admin/users',
                        'response_code': response.status_code
                    })
            except requests.exceptions.RequestException:
                pass
            
            if escalation_detected:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="FAIL",
                    severity="CRITICAL",
                    actual_access=True,
                    expected_access=False,
                    response_code=200,
                    response_time=response_time,
                    vulnerability_type="VERTICAL_PRIVILEGE_ESCALATION",
                    evidence={
                        'user_roles': user_context.roles,
                        'escalation_evidence': evidence
                    },
                    remediation="Implement proper role-based access controls for admin endpoints",
                    timestamp=datetime.now(timezone.utc)
                )
            else:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="PASS",
                    severity="INFO",
                    actual_access=False,
                    expected_access=False,
                    response_code=403,
                    response_time=response_time,
                    vulnerability_type=None,
                    evidence={'admin_endpoints_tested': len(admin_endpoints)},
                    remediation="Admin access controls working correctly",
                    timestamp=datetime.now(timezone.utc)
                )
                
        except Exception as e:
            return AccessControlResult(
                test_id=test.test_id,
                test_name=test.test_name,
                region=test.region,
                endpoint=test.endpoint,
                status="ERROR",
                severity="HIGH",
                actual_access=False,
                expected_access=False,
                response_code=0,
                response_time=time.time() - start_time,
                vulnerability_type="TEST_ERROR",
                evidence={'error': str(e)},
                remediation="Fix test configuration",
                timestamp=datetime.now(timezone.utc)
            )


class SessionManagementTester:
    """Test session management security"""
    
    def __init__(self, logger: logging.Logger, token_generator: JWTTokenGenerator):
        self.logger = logger
        self.token_generator = token_generator
        self.session = requests.Session()
    
    async def test_session_fixation(self, test: AccessControlTest) -> AccessControlResult:
        """Test session fixation vulnerabilities"""
        start_time = time.time()
        
        try:
            # Get initial session
            initial_response = self.session.get(f"{test.endpoint}/", timeout=30)
            initial_cookies = dict(self.session.cookies)
            
            # Login with user
            user_context = UserContext(**test.user_context)
            login_data = {
                'username': user_context.username,
                'password': 'testpassword'
            }
            
            login_response = self.session.post(
                f"{test.endpoint}/api/auth/login",
                json=login_data,
                timeout=30
            )
            
            post_login_cookies = dict(self.session.cookies)
            
            # Check if session ID changed after login
            session_changed = initial_cookies != post_login_cookies
            
            if not session_changed and initial_cookies:
                # Session fixation vulnerability
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="FAIL",
                    severity="HIGH",
                    actual_access=True,
                    expected_access=False,
                    response_code=login_response.status_code,
                    response_time=time.time() - start_time,
                    vulnerability_type="SESSION_FIXATION",
                    evidence={
                        'initial_cookies': initial_cookies,
                        'post_login_cookies': post_login_cookies,
                        'session_changed': session_changed
                    },
                    remediation="Regenerate session ID after authentication",
                    timestamp=datetime.now(timezone.utc)
                )
            else:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="PASS",
                    severity="INFO",
                    actual_access=False,
                    expected_access=False,
                    response_code=login_response.status_code,
                    response_time=time.time() - start_time,
                    vulnerability_type=None,
                    evidence={'session_regenerated': session_changed},
                    remediation="Session management working correctly",
                    timestamp=datetime.now(timezone.utc)
                )
                
        except Exception as e:
            return AccessControlResult(
                test_id=test.test_id,
                test_name=test.test_name,
                region=test.region,
                endpoint=test.endpoint,
                status="ERROR",
                severity="MEDIUM",
                actual_access=False,
                expected_access=False,
                response_code=0,
                response_time=time.time() - start_time,
                vulnerability_type="TEST_ERROR",
                evidence={'error': str(e)},
                remediation="Fix test configuration or endpoint",
                timestamp=datetime.now(timezone.utc)
            )
    
    async def test_token_validation(self, test: AccessControlTest) -> AccessControlResult:
        """Test JWT token validation"""
        start_time = time.time()
        
        try:
            user_context = UserContext(**test.user_context)
            
            # Test expired token
            expired_token = self.token_generator.generate_expired_token(user_context)
            headers = {'Authorization': f'Bearer {expired_token}'}
            
            response = self.session.get(
                f"{test.endpoint}/api/protected",
                headers=headers,
                timeout=30
            )
            
            expired_token_accepted = response.status_code == 200
            
            # Test malformed token
            malformed_token = self.token_generator.generate_malformed_token(user_context)
            headers = {'Authorization': f'Bearer {malformed_token}'}
            
            response = self.session.get(
                f"{test.endpoint}/api/protected",
                headers=headers,
                timeout=30
            )
            
            malformed_token_accepted = response.status_code == 200
            
            response_time = time.time() - start_time
            
            vulnerabilities = []
            if expired_token_accepted:
                vulnerabilities.append("Expired tokens accepted")
            if malformed_token_accepted:
                vulnerabilities.append("Malformed tokens accepted")
            
            if vulnerabilities:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="FAIL",
                    severity="HIGH",
                    actual_access=True,
                    expected_access=False,
                    response_code=200,
                    response_time=response_time,
                    vulnerability_type="INVALID_TOKEN_ACCEPTANCE",
                    evidence={
                        'expired_token_accepted': expired_token_accepted,
                        'malformed_token_accepted': malformed_token_accepted,
                        'vulnerabilities': vulnerabilities
                    },
                    remediation="Implement proper JWT token validation",
                    timestamp=datetime.now(timezone.utc)
                )
            else:
                return AccessControlResult(
                    test_id=test.test_id,
                    test_name=test.test_name,
                    region=test.region,
                    endpoint=test.endpoint,
                    status="PASS",
                    severity="INFO",
                    actual_access=False,
                    expected_access=False,
                    response_code=401,
                    response_time=response_time,
                    vulnerability_type=None,
                    evidence={'token_validation_working': True},
                    remediation="JWT token validation working correctly",
                    timestamp=datetime.now(timezone.utc)
                )
                
        except Exception as e:
            return AccessControlResult(
                test_id=test.test_id,
                test_name=test.test_name,
                region=test.region,
                endpoint=test.endpoint,
                status="ERROR",
                severity="MEDIUM",
                actual_access=False,
                expected_access=False,
                response_code=0,
                response_time=time.time() - start_time,
                vulnerability_type="TEST_ERROR",
                evidence={'error': str(e)},
                remediation="Fix test configuration",
                timestamp=datetime.now(timezone.utc)
            )


class IAMAccessControlTester:
    """Main IAM and access control testing framework"""
    
    def __init__(self, config_file: str, output_dir: str = "iam_reports"):
        self.logger = self._setup_logger()
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.token_generator = JWTTokenGenerator()
        self.rbac_tester = RBACTester(self.logger, self.token_generator)
        self.privilege_tester = PrivilegeEscalationTester(self.logger, self.token_generator)
        self.session_tester = SessionManagementTester(self.logger, self.token_generator)
        
        self.test_suite = self._generate_test_suite()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("IAMTester")
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger
    
    def _generate_test_suite(self) -> List[AccessControlTest]:
        """Generate comprehensive test suite"""
        tests = []
        
        # Define user contexts for testing
        user_contexts = [
            {
                'user_id': 'user_viewer',
                'username': 'viewer_user',
                'roles': ['viewer'],
                'permissions': ['read:basic'],
                'attributes': {'department': 'testing', 'clearance': 'public'}
            },
            {
                'user_id': 'user_editor',
                'username': 'editor_user',
                'roles': ['editor'],
                'permissions': ['read:basic', 'write:basic'],
                'attributes': {'department': 'operations', 'clearance': 'internal'}
            },
            {
                'user_id': 'user_admin',
                'username': 'admin_user',
                'roles': ['admin'],
                'permissions': ['read:all', 'write:all', 'admin:system'],
                'attributes': {'department': 'security', 'clearance': 'confidential'}
            }
        ]
        
        for region in self.config['regions']:
            region_name = region['name']
            
            for endpoint in region['api_endpoints']:
                
                # RBAC Tests
                test_scenarios = [
                    # Viewer should access public data
                    {
                        'user_context': user_contexts[0],
                        'resource_path': '/api/public/status',
                        'http_method': 'GET',
                        'expected_access': True,
                        'test_type': 'RBAC'
                    },
                    # Viewer should NOT access admin data
                    {
                        'user_context': user_contexts[0],
                        'resource_path': '/api/admin/users',
                        'http_method': 'GET',
                        'expected_access': False,
                        'test_type': 'RBAC'
                    },
                    # Editor should access edit endpoints
                    {
                        'user_context': user_contexts[1],
                        'resource_path': '/api/data/documents',
                        'http_method': 'POST',
                        'expected_access': True,
                        'test_type': 'RBAC',
                        'payload': {'title': 'test document', 'content': 'test content'}
                    },
                    # Editor should NOT access admin endpoints
                    {
                        'user_context': user_contexts[1],
                        'resource_path': '/api/admin/config',
                        'http_method': 'GET',
                        'expected_access': False,
                        'test_type': 'RBAC'
                    },
                    # Admin should access all endpoints
                    {
                        'user_context': user_contexts[2],
                        'resource_path': '/api/admin/system',
                        'http_method': 'GET',
                        'expected_access': True,
                        'test_type': 'RBAC'
                    }
                ]
                
                for scenario in test_scenarios:
                    test_id = f"{region_name}_{scenario['test_type']}_{secrets.token_hex(4)}"
                    
                    tests.append(AccessControlTest(
                        test_id=test_id,
                        test_name=f"{scenario['test_type']} Test - {scenario['user_context']['username']}",
                        test_type=scenario['test_type'],
                        region=region_name,
                        endpoint=endpoint,
                        user_context=scenario['user_context'],
                        expected_access=scenario['expected_access'],
                        resource_path=scenario['resource_path'],
                        http_method=scenario['http_method'],
                        payload=scenario.get('payload')
                    ))
                
                # Privilege escalation tests
                for user_context in user_contexts[:2]:  # Exclude admin for escalation tests
                    tests.append(AccessControlTest(
                        test_id=f"{region_name}_HPRIV_{secrets.token_hex(4)}",
                        test_name="Horizontal Privilege Escalation Test",
                        test_type="PRIVILEGE_ESCALATION",
                        region=region_name,
                        endpoint=endpoint,
                        user_context=user_context,
                        expected_access=False,
                        resource_path="/api/users/other/profile",
                        http_method="GET"
                    ))
                    
                    tests.append(AccessControlTest(
                        test_id=f"{region_name}_VPRIV_{secrets.token_hex(4)}",
                        test_name="Vertical Privilege Escalation Test",
                        test_type="PRIVILEGE_ESCALATION",
                        region=region_name,
                        endpoint=endpoint,
                        user_context=user_context,
                        expected_access=False,
                        resource_path="/api/admin/elevate",
                        http_method="GET"
                    ))
                
                # Session management tests
                tests.append(AccessControlTest(
                    test_id=f"{region_name}_SESSION_{secrets.token_hex(4)}",
                    test_name="Session Management Test",
                    test_type="SESSION_MANAGEMENT",
                    region=region_name,
                    endpoint=endpoint,
                    user_context=user_contexts[1],
                    expected_access=False,
                    resource_path="/api/auth/session",
                    http_method="GET"
                ))
        
        return tests
    
    async def run_all_tests(self) -> str:
        """Run all IAM and access control tests"""
        self.logger.info("Starting IAM and access control testing...")
        start_time = time.time()
        
        all_results = []
        
        # Run tests by type
        for test in self.test_suite:
            try:
                if test.test_type == "RBAC":
                    result = await self.rbac_tester.test_role_based_access(test)
                elif test.test_type == "PRIVILEGE_ESCALATION":
                    if "Horizontal" in test.test_name:
                        result = await self.privilege_tester.test_horizontal_privilege_escalation(test)
                    else:
                        result = await self.privilege_tester.test_vertical_privilege_escalation(test)
                elif test.test_type == "SESSION_MANAGEMENT":
                    if "Session Management" in test.test_name:
                        result = await self.session_tester.test_session_fixation(test)
                    else:
                        result = await self.session_tester.test_token_validation(test)
                else:
                    continue
                
                all_results.append(result)
                self.logger.info(f"Test {test.test_id}: {result.status} ({result.severity})")
                
            except Exception as e:
                self.logger.error(f"Test {test.test_id} failed with exception: {e}")
        
        # Generate report
        report_file = self._generate_report(all_results)
        
        total_time = time.time() - start_time
        self.logger.info(f"IAM testing completed in {total_time:.2f} seconds")
        self.logger.info(f"Report generated: {report_file}")
        
        return report_file
    
    def _generate_report(self, results: List[AccessControlResult]) -> str:
        """Generate comprehensive IAM test report"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_dir, f"iam_report_{timestamp}.json")
        
        # Calculate statistics
        total_tests = len(results)
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        errors = sum(1 for r in results if r.status == "ERROR")
        
        critical_issues = [r for r in results if r.severity == "CRITICAL"]
        high_issues = [r for r in results if r.severity == "HIGH"]
        
        vulnerability_types = {}
        for result in results:
            if result.vulnerability_type:
                vulnerability_types[result.vulnerability_type] = vulnerability_types.get(result.vulnerability_type, 0) + 1
        
        # Generate executive summary
        executive_summary = {
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "pass_rate": f"{(passed/total_tests*100):.1f}%" if total_tests > 0 else "0%",
            "critical_vulnerabilities": len(critical_issues),
            "high_vulnerabilities": len(high_issues),
            "vulnerability_types": vulnerability_types,
            "overall_risk": "CRITICAL" if critical_issues else "HIGH" if high_issues else "MEDIUM" if failed else "LOW"
        }
        
        # Create report
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": "iam_access_control_testing",
                "version": "1.0"
            },
            "executive_summary": executive_summary,
            "test_results": [asdict(result) for result in results],
            "critical_findings": [asdict(issue) for issue in critical_issues[:10]],
            "high_findings": [asdict(issue) for issue in high_issues[:20]],
            "recommendations": self._generate_recommendations(results)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return report_file
    
    def _generate_recommendations(self, results: List[AccessControlResult]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        vulnerability_types = set(r.vulnerability_type for r in results if r.vulnerability_type)
        
        if "UNAUTHORIZED_ACCESS" in vulnerability_types:
            recommendations.append("Review and strengthen role-based access controls")
        
        if "HORIZONTAL_PRIVILEGE_ESCALATION" in vulnerability_types:
            recommendations.append("Implement user-level data isolation controls")
        
        if "VERTICAL_PRIVILEGE_ESCALATION" in vulnerability_types:
            recommendations.append("Restrict admin endpoint access to authorized roles only")
        
        if "SESSION_FIXATION" in vulnerability_types:
            recommendations.append("Implement session regeneration after authentication")
        
        if "INVALID_TOKEN_ACCEPTANCE" in vulnerability_types:
            recommendations.append("Implement comprehensive JWT token validation")
        
        # Add general recommendations
        failed_count = sum(1 for r in results if r.status == "FAIL")
        if failed_count > len(results) * 0.2:
            recommendations.append("Conduct comprehensive access control review and remediation")
        
        return recommendations


async def main():
    parser = argparse.ArgumentParser(description="IAM and Access Control Testing")
    parser.add_argument("--config", required=True, help="Configuration file path")
    parser.add_argument("--output-dir", default="iam_reports", help="Output directory for reports")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config):
        print(f"Configuration file not found: {args.config}")
        sys.exit(1)
    
    tester = IAMAccessControlTester(args.config, args.output_dir)
    report_file = await tester.run_all_tests()
    
    # Display summary
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    summary = report['executive_summary']
    print(f"\n{'='*60}")
    print("IAM ACCESS CONTROL TESTING SUMMARY")
    print(f"{'='*60}")
    print(f"Total Tests: {summary['total_tests']}")
    print(f"Pass Rate: {summary['pass_rate']}")
    print(f"Critical Vulnerabilities: {summary['critical_vulnerabilities']}")
    print(f"High Vulnerabilities: {summary['high_vulnerabilities']}")
    print(f"Overall Risk: {summary['overall_risk']}")
    
    if summary['vulnerability_types']:
        print(f"\nVULNERABILITY BREAKDOWN:")
        for vuln_type, count in summary['vulnerability_types'].items():
            print(f"  {vuln_type}: {count}")
    
    if report['recommendations']:
        print(f"\nRECOMMENDATIONS:")
        for recommendation in report['recommendations']:
            print(f"  • {recommendation}")
    
    # Exit with appropriate code
    if summary['critical_vulnerabilities'] > 0:
        sys.exit(2)
    elif summary['high_vulnerabilities'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())