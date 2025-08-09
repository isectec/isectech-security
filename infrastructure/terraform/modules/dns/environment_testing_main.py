#!/usr/bin/env python3
"""
iSECTECH Multi-Environment Domain Testing
Production-grade environment domain validation and testing

This Cloud Function performs comprehensive testing of multi-environment domain configurations
including DNS resolution, SSL certificate validation, health checks, and security policy verification.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import requests
import dns.resolver
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from google.cloud import dns as cloud_dns
from google.cloud import certificatemanager_v1
from google.cloud import compute_v1
from google.cloud import run_v2
from google.cloud import monitoring_v3
from google.cloud import logging as cloud_logging
from google.cloud import pubsub_v1
from google.cloud import secretmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnvironmentDomainTester:
    """Comprehensive domain testing for multi-environment configurations"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.dns_client = cloud_dns.Client(project=project_id)
        self.cert_client = certificatemanager_v1.CertificateManagerClient()
        self.compute_client = compute_v1.SecurityPoliciesClient()
        self.run_client = run_v2.ServicesClient()
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.logging_client = cloud_logging.Client(project=project_id)
        self.secret_client = secretmanager.SecretManagerServiceClient()
        
        # Load environment configurations
        self.environment_configs = json.loads(os.environ.get('ENVIRONMENT_CONFIGS', '{}'))
        self.domain_name = os.environ.get('DOMAIN_NAME', 'isectech.com')
        self.notification_email = os.environ.get('NOTIFICATION_EMAIL', 'devops@isectech.com')
        
        # Test results storage
        self.test_results = {}
        self.failures = []
        self.warnings = []
    
    def test_environment_domains(self, request):
        """Main entry point for Cloud Function"""
        try:
            logger.info(f"Starting environment domain testing for project {self.project_id}")
            
            # Parse Pub/Sub message
            if request and hasattr(request, 'get_json'):
                data = request.get_json() or {}
            else:
                # Handle Pub/Sub trigger
                import base64
                envelope = json.loads(request.data.decode('utf-8'))
                data = json.loads(base64.b64decode(envelope['message']['data']).decode('utf-8'))
            
            environments_to_test = data.get('environments', list(self.environment_configs.keys()))
            
            logger.info(f"Testing environments: {environments_to_test}")
            
            # Run comprehensive tests for each environment
            for env_name in environments_to_test:
                if env_name in self.environment_configs:
                    logger.info(f"Testing environment: {env_name}")
                    self.test_environment(env_name, self.environment_configs[env_name])
                else:
                    logger.warning(f"Environment {env_name} not found in configurations")
            
            # Generate test summary
            summary = self.generate_test_summary()
            
            # Send notifications if there are failures
            if self.failures:
                self.send_failure_notification(summary)
            
            # Log results to Cloud Logging
            self.log_test_results(summary)
            
            # Send metrics to Cloud Monitoring
            self.send_monitoring_metrics(summary)
            
            return {
                'statusCode': 200,
                'body': json.dumps(summary, indent=2)
            }
            
        except Exception as e:
            logger.error(f"Environment testing failed: {str(e)}")
            self.failures.append({
                'test': 'environment_testing_function',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            # Send critical failure notification
            self.send_critical_failure_notification(str(e))
            
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }
    
    def test_environment(self, env_name: str, env_config: Dict[str, Any]):
        """Test a specific environment configuration"""
        env_results = {
            'environment': env_name,
            'start_time': datetime.now(timezone.utc).isoformat(),
            'tests': {}
        }
        
        try:
            # Test DNS resolution
            env_results['tests']['dns_resolution'] = self.test_dns_resolution(env_name, env_config)
            
            # Test SSL certificates
            env_results['tests']['ssl_certificates'] = self.test_ssl_certificates(env_name, env_config)
            
            # Test security policies
            env_results['tests']['security_policies'] = self.test_security_policies(env_name, env_config)
            
            # Test health checks
            env_results['tests']['health_checks'] = self.test_health_checks(env_name, env_config)
            
            # Test Cloud Run domain mappings
            if 'cloud_run_mappings' in env_config:
                env_results['tests']['cloud_run_mappings'] = self.test_cloud_run_mappings(env_name, env_config)
            
            # Test environment isolation
            env_results['tests']['environment_isolation'] = self.test_environment_isolation(env_name, env_config)
            
        except Exception as e:
            logger.error(f"Error testing environment {env_name}: {str(e)}")
            self.failures.append({
                'test': f'environment_{env_name}',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        
        env_results['end_time'] = datetime.now(timezone.utc).isoformat()
        env_results['duration_seconds'] = (
            datetime.fromisoformat(env_results['end_time'].replace('Z', '+00:00')) -
            datetime.fromisoformat(env_results['start_time'].replace('Z', '+00:00'))
        ).total_seconds()
        
        self.test_results[env_name] = env_results
    
    def test_dns_resolution(self, env_name: str, env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test DNS resolution for environment domains"""
        results = {
            'status': 'passed',
            'tests': [],
            'errors': []
        }
        
        try:
            # Test A records
            for record in env_config.get('a_records', []):
                domain = f"{record['name']}.{env_name}.{self.domain_name}"
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    resolved_ips = [str(answer) for answer in answers]
                    
                    test_result = {
                        'domain': domain,
                        'type': 'A',
                        'expected_ips': record['rrdatas'],
                        'resolved_ips': resolved_ips,
                        'status': 'passed' if set(resolved_ips) == set(record['rrdatas']) else 'failed'
                    }
                    
                    if test_result['status'] == 'failed':
                        results['status'] = 'failed'
                        results['errors'].append(f"DNS A record mismatch for {domain}")
                        self.failures.append({
                            'test': f'dns_a_record_{domain}',
                            'error': f"Expected {record['rrdatas']}, got {resolved_ips}",
                            'environment': env_name
                        })
                    
                    results['tests'].append(test_result)
                    
                except Exception as e:
                    results['status'] = 'failed'
                    results['errors'].append(f"DNS resolution failed for {domain}: {str(e)}")
                    self.failures.append({
                        'test': f'dns_resolution_{domain}',
                        'error': str(e),
                        'environment': env_name
                    })
            
            # Test CNAME records
            for record in env_config.get('cname_records', []):
                domain = f"{record['name']}.{env_name}.{self.domain_name}"
                try:
                    answers = dns.resolver.resolve(domain, 'CNAME')
                    resolved_cnames = [str(answer) for answer in answers]
                    
                    test_result = {
                        'domain': domain,
                        'type': 'CNAME',
                        'expected_cnames': record['rrdatas'],
                        'resolved_cnames': resolved_cnames,
                        'status': 'passed' if set(resolved_cnames) == set(record['rrdatas']) else 'failed'
                    }
                    
                    if test_result['status'] == 'failed':
                        results['status'] = 'failed'
                        results['errors'].append(f"DNS CNAME record mismatch for {domain}")
                        self.failures.append({
                            'test': f'dns_cname_record_{domain}',
                            'error': f"Expected {record['rrdatas']}, got {resolved_cnames}",
                            'environment': env_name
                        })
                    
                    results['tests'].append(test_result)
                    
                except Exception as e:
                    results['status'] = 'failed'
                    results['errors'].append(f"DNS CNAME resolution failed for {domain}: {str(e)}")
                    self.failures.append({
                        'test': f'dns_cname_resolution_{domain}',
                        'error': str(e),
                        'environment': env_name
                    })
                    
        except Exception as e:
            results['status'] = 'failed'
            results['errors'].append(f"DNS testing error: {str(e)}")
            
        return results
    
    def test_ssl_certificates(self, env_name: str, env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test SSL certificate configuration and validity"""
        results = {
            'status': 'passed',
            'certificates': [],
            'errors': []
        }
        
        try:
            for domain_name in env_config.get('certificate_domains', []):
                full_domain = f"{domain_name}.{env_name}.{self.domain_name}"
                
                try:
                    # Test SSL connection
                    context = ssl.create_default_context()
                    with socket.create_connection((full_domain, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=full_domain) as ssock:
                            cert_der = ssock.getpeercert(binary_form=True)
                            cert = x509.load_der_x509_certificate(cert_der, default_backend())
                            
                            # Extract certificate information
                            cert_info = {
                                'domain': full_domain,
                                'subject': cert.subject.rfc4514_string(),
                                'issuer': cert.issuer.rfc4514_string(),
                                'not_before': cert.not_valid_before.isoformat(),
                                'not_after': cert.not_valid_after.isoformat(),
                                'days_until_expiry': (cert.not_valid_after - datetime.now()).days,
                                'status': 'valid'
                            }
                            
                            # Check if certificate is expiring soon
                            if cert_info['days_until_expiry'] < 30:
                                cert_info['status'] = 'warning'
                                self.warnings.append({
                                    'test': f'ssl_cert_expiry_{full_domain}',
                                    'warning': f"Certificate expires in {cert_info['days_until_expiry']} days",
                                    'environment': env_name
                                })
                            
                            # Check if certificate is expired
                            if cert_info['days_until_expiry'] < 0:
                                cert_info['status'] = 'expired'
                                results['status'] = 'failed'
                                self.failures.append({
                                    'test': f'ssl_cert_expired_{full_domain}',
                                    'error': f"Certificate expired {abs(cert_info['days_until_expiry'])} days ago",
                                    'environment': env_name
                                })
                            
                            results['certificates'].append(cert_info)
                            
                except Exception as e:
                    results['status'] = 'failed'
                    results['errors'].append(f"SSL test failed for {full_domain}: {str(e)}")
                    self.failures.append({
                        'test': f'ssl_connection_{full_domain}',
                        'error': str(e),
                        'environment': env_name
                    })
                    
        except Exception as e:
            results['status'] = 'failed'
            results['errors'].append(f"SSL testing error: {str(e)}")
            
        return results
    
    def test_security_policies(self, env_name: str, env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test security policy configuration"""
        results = {
            'status': 'passed',
            'policies': [],
            'errors': []
        }
        
        try:
            policy_name = f"{env_name}-environment-security-policy"
            
            # Get security policy
            request = compute_v1.GetSecurityPolicyRequest(
                project=self.project_id,
                security_policy=policy_name
            )
            
            try:
                policy = self.compute_client.get(request=request)
                
                policy_info = {
                    'name': policy.name,
                    'description': policy.description,
                    'rule_count': len(policy.rules),
                    'adaptive_protection': policy.adaptive_protection_config.layer_7_ddos_defense_config.enable if policy.adaptive_protection_config else False,
                    'status': 'active'
                }
                
                # Validate expected rules exist
                expected_rules = ['rate_based_ban', 'deny', 'allow']
                found_rules = [rule.action for rule in policy.rules if rule.action in expected_rules]
                
                if len(found_rules) < len(expected_rules):
                    policy_info['status'] = 'warning'
                    self.warnings.append({
                        'test': f'security_policy_rules_{env_name}',
                        'warning': f"Missing expected security rules: {set(expected_rules) - set(found_rules)}",
                        'environment': env_name
                    })
                
                results['policies'].append(policy_info)
                
            except Exception as e:
                results['status'] = 'failed'
                results['errors'].append(f"Security policy not found: {policy_name}")
                self.failures.append({
                    'test': f'security_policy_{env_name}',
                    'error': f"Policy {policy_name} not accessible: {str(e)}",
                    'environment': env_name
                })
                
        except Exception as e:
            results['status'] = 'failed'
            results['errors'].append(f"Security policy testing error: {str(e)}")
            
        return results
    
    def test_health_checks(self, env_name: str, env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test health check endpoints"""
        results = {
            'status': 'passed',
            'health_checks': [],
            'errors': []
        }
        
        try:
            health_check_host = env_config.get('health_check_host', 'api')
            health_check_path = env_config.get('health_check_path', '/health')
            health_check_port = env_config.get('health_check_port', 8080)
            expected_response = env_config.get('health_check_response', 'OK')
            
            full_domain = f"{health_check_host}.{env_name}.{self.domain_name}"
            health_url = f"https://{full_domain}{health_check_path}"
            
            try:
                response = requests.get(health_url, timeout=10)
                
                health_result = {
                    'url': health_url,
                    'status_code': response.status_code,
                    'response_time_ms': response.elapsed.total_seconds() * 1000,
                    'content_length': len(response.content),
                    'status': 'passed' if response.status_code == 200 else 'failed'
                }
                
                # Check response content if expected
                if expected_response and expected_response not in response.text:
                    health_result['status'] = 'failed'
                    results['status'] = 'failed'
                    self.failures.append({
                        'test': f'health_check_content_{env_name}',
                        'error': f"Expected response '{expected_response}' not found in response",
                        'environment': env_name
                    })
                
                # Check response time
                if health_result['response_time_ms'] > 5000:  # 5 seconds
                    health_result['status'] = 'warning'
                    self.warnings.append({
                        'test': f'health_check_latency_{env_name}',
                        'warning': f"Health check took {health_result['response_time_ms']:.0f}ms (>5s)",
                        'environment': env_name
                    })
                
                if response.status_code != 200:
                    results['status'] = 'failed'
                    self.failures.append({
                        'test': f'health_check_status_{env_name}',
                        'error': f"Health check returned status {response.status_code}",
                        'environment': env_name
                    })
                
                results['health_checks'].append(health_result)
                
            except Exception as e:
                results['status'] = 'failed'
                results['errors'].append(f"Health check failed for {health_url}: {str(e)}")
                self.failures.append({
                    'test': f'health_check_connection_{env_name}',
                    'error': str(e),
                    'environment': env_name
                })
                
        except Exception as e:
            results['status'] = 'failed'
            results['errors'].append(f"Health check testing error: {str(e)}")
            
        return results
    
    def test_cloud_run_mappings(self, env_name: str, env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Cloud Run domain mappings"""
        results = {
            'status': 'passed',
            'mappings': [],
            'errors': []
        }
        
        try:
            for mapping in env_config.get('cloud_run_mappings', []):
                domain = f"{mapping['domain']}.{env_name}.{self.domain_name}"
                
                try:
                    # Test HTTP request to mapped domain
                    test_url = f"https://{domain}"
                    response = requests.get(test_url, timeout=10, allow_redirects=False)
                    
                    mapping_result = {
                        'domain': domain,
                        'service_name': mapping['service_name'],
                        'region': mapping['region'],
                        'status_code': response.status_code,
                        'response_time_ms': response.elapsed.total_seconds() * 1000,
                        'status': 'passed' if response.status_code in [200, 302, 404] else 'failed'
                    }
                    
                    # Check for Cloud Run service headers
                    if 'x-cloud-trace-context' in response.headers:
                        mapping_result['cloud_run_detected'] = True
                    else:
                        mapping_result['cloud_run_detected'] = False
                        self.warnings.append({
                            'test': f'cloud_run_headers_{domain}',
                            'warning': "Cloud Run headers not detected",
                            'environment': env_name
                        })
                    
                    if response.status_code >= 500:
                        results['status'] = 'failed'
                        self.failures.append({
                            'test': f'cloud_run_mapping_{domain}',
                            'error': f"Service returned status {response.status_code}",
                            'environment': env_name
                        })
                    
                    results['mappings'].append(mapping_result)
                    
                except Exception as e:
                    results['status'] = 'failed'
                    results['errors'].append(f"Cloud Run mapping test failed for {domain}: {str(e)}")
                    self.failures.append({
                        'test': f'cloud_run_mapping_{domain}',
                        'error': str(e),
                        'environment': env_name
                    })
                    
        except Exception as e:
            results['status'] = 'failed'
            results['errors'].append(f"Cloud Run mapping testing error: {str(e)}")
            
        return results
    
    def test_environment_isolation(self, env_name: str, env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test environment isolation and access controls"""
        results = {
            'status': 'passed',
            'isolation_tests': [],
            'errors': []
        }
        
        try:
            # Test IP restrictions for non-production environments
            if env_name != 'production':
                allowed_ranges = env_config.get('allowed_ip_ranges', [])
                
                isolation_test = {
                    'test_type': 'ip_restrictions',
                    'environment': env_name,
                    'allowed_ranges': allowed_ranges,
                    'status': 'passed' if allowed_ranges else 'warning'
                }
                
                if not allowed_ranges:
                    self.warnings.append({
                        'test': f'ip_restrictions_{env_name}',
                        'warning': f"No IP restrictions configured for {env_name} environment",
                        'environment': env_name
                    })
                
                results['isolation_tests'].append(isolation_test)
            
            # Test rate limiting configuration
            rate_limit = env_config.get('rate_limit_requests_per_minute', 0)
            
            rate_limit_test = {
                'test_type': 'rate_limiting',
                'environment': env_name,
                'requests_per_minute': rate_limit,
                'status': 'passed' if rate_limit > 0 else 'failed'
            }
            
            if rate_limit <= 0:
                results['status'] = 'failed'
                self.failures.append({
                    'test': f'rate_limiting_{env_name}',
                    'error': f"No rate limiting configured for {env_name} environment",
                    'environment': env_name
                })
            
            results['isolation_tests'].append(rate_limit_test)
            
        except Exception as e:
            results['status'] = 'failed'
            results['errors'].append(f"Environment isolation testing error: {str(e)}")
            
        return results
    
    def generate_test_summary(self) -> Dict[str, Any]:
        """Generate comprehensive test summary"""
        total_tests = 0
        passed_tests = 0
        failed_tests = len(self.failures)
        warning_tests = len(self.warnings)
        
        for env_results in self.test_results.values():
            for test_category, test_results in env_results.get('tests', {}).items():
                total_tests += 1
                if test_results.get('status') == 'passed':
                    passed_tests += 1
        
        summary = {
            'test_run_id': f"env_test_{int(time.time())}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'project_id': self.project_id,
            'domain_name': self.domain_name,
            'environments_tested': list(self.test_results.keys()),
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'warning_tests': warning_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
            },
            'test_results': self.test_results,
            'failures': self.failures,
            'warnings': self.warnings,
            'status': 'passed' if failed_tests == 0 else 'failed'
        }
        
        return summary
    
    def send_failure_notification(self, summary: Dict[str, Any]):
        """Send notification for test failures"""
        try:
            # Get SendGrid API key from Secret Manager
            sendgrid_secret_name = f"projects/{self.project_id}/secrets/environment-testing-secrets/versions/latest"
            response = self.secret_client.access_secret_version(request={"name": sendgrid_secret_name})
            secrets = json.loads(response.payload.data.decode('utf-8'))
            sendgrid_api_key = secrets.get('sendgrid_api_key')
            
            if not sendgrid_api_key:
                logger.warning("SendGrid API key not found, skipping email notification")
                return
            
            # Prepare email content
            subject = f"Environment Domain Testing Failures - {summary['summary']['failed_tests']} Failed"
            
            html_content = f"""
            <h2>Environment Domain Testing Report</h2>
            <p><strong>Project:</strong> {self.project_id}</p>
            <p><strong>Domain:</strong> {self.domain_name}</p>
            <p><strong>Test Run ID:</strong> {summary['test_run_id']}</p>
            <p><strong>Timestamp:</strong> {summary['timestamp']}</p>
            
            <h3>Summary</h3>
            <ul>
                <li>Total Tests: {summary['summary']['total_tests']}</li>
                <li>Passed: {summary['summary']['passed_tests']}</li>
                <li>Failed: {summary['summary']['failed_tests']}</li>
                <li>Warnings: {summary['summary']['warning_tests']}</li>
                <li>Success Rate: {summary['summary']['success_rate']:.1f}%</li>
            </ul>
            
            <h3>Failures</h3>
            <ul>
            """
            
            for failure in self.failures:
                html_content += f"""
                <li>
                    <strong>{failure.get('test', 'Unknown Test')}</strong>
                    {f" (Environment: {failure.get('environment', 'N/A')})" if failure.get('environment') else ""}
                    <br>
                    Error: {failure.get('error', 'No error message')}
                </li>
                """
            
            html_content += """
            </ul>
            
            <p>Please review the failed tests and take appropriate action.</p>
            <p>Full test results are available in Cloud Logging.</p>
            """
            
            # Send email using SendGrid API
            import sendgrid
            from sendgrid.helpers.mail import Mail
            
            sg = sendgrid.SendGridAPIClient(api_key=sendgrid_api_key)
            mail = Mail(
                from_email='noreply@isectech.com',
                to_emails=self.notification_email,
                subject=subject,
                html_content=html_content
            )
            
            response = sg.send(mail)
            logger.info(f"Failure notification sent successfully: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Failed to send notification: {str(e)}")
    
    def send_critical_failure_notification(self, error_message: str):
        """Send notification for critical failures"""
        try:
            logger.error(f"Critical failure in environment testing: {error_message}")
            # Additional critical failure handling would go here
            
        except Exception as e:
            logger.error(f"Failed to send critical failure notification: {str(e)}")
    
    def log_test_results(self, summary: Dict[str, Any]):
        """Log test results to Cloud Logging"""
        try:
            logger.info(f"Environment domain testing completed: {summary['status']}")
            logger.info(f"Test summary: {json.dumps(summary['summary'], indent=2)}")
            
            # Structured logging for Cloud Logging
            self.logging_client.logger('environment-domain-testing').log_struct({
                'message': 'Environment domain testing completed',
                'test_run_id': summary['test_run_id'],
                'project_id': self.project_id,
                'domain_name': self.domain_name,
                'status': summary['status'],
                'summary': summary['summary'],
                'environments_tested': summary['environments_tested'],
                'failure_count': len(self.failures),
                'warning_count': len(self.warnings)
            }, severity='INFO' if summary['status'] == 'passed' else 'ERROR')
            
        except Exception as e:
            logger.error(f"Failed to log test results: {str(e)}")
    
    def send_monitoring_metrics(self, summary: Dict[str, Any]):
        """Send metrics to Cloud Monitoring"""
        try:
            project_name = f"projects/{self.project_id}"
            
            # Create time series data
            series = []
            
            # Total tests metric
            series.append({
                'metric': {
                    'type': 'custom.googleapis.com/environment_testing/total_tests',
                    'labels': {
                        'domain_name': self.domain_name
                    }
                },
                'resource': {
                    'type': 'global',
                    'labels': {
                        'project_id': self.project_id
                    }
                },
                'points': [{
                    'interval': {
                        'end_time': {'seconds': int(time.time())}
                    },
                    'value': {
                        'int64_value': summary['summary']['total_tests']
                    }
                }]
            })
            
            # Failed tests metric
            series.append({
                'metric': {
                    'type': 'custom.googleapis.com/environment_testing/failed_tests',
                    'labels': {
                        'domain_name': self.domain_name
                    }
                },
                'resource': {
                    'type': 'global',
                    'labels': {
                        'project_id': self.project_id
                    }
                },
                'points': [{
                    'interval': {
                        'end_time': {'seconds': int(time.time())}
                    },
                    'value': {
                        'int64_value': summary['summary']['failed_tests']
                    }
                }]
            })
            
            # Success rate metric
            series.append({
                'metric': {
                    'type': 'custom.googleapis.com/environment_testing/success_rate',
                    'labels': {
                        'domain_name': self.domain_name
                    }
                },
                'resource': {
                    'type': 'global',
                    'labels': {
                        'project_id': self.project_id
                    }
                },
                'points': [{
                    'interval': {
                        'end_time': {'seconds': int(time.time())}
                    },
                    'value': {
                        'double_value': summary['summary']['success_rate']
                    }
                }]
            })
            
            # Send metrics
            request = monitoring_v3.CreateTimeSeriesRequest(
                name=project_name,
                time_series=series
            )
            
            self.monitoring_client.create_time_series(request=request)
            logger.info("Monitoring metrics sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send monitoring metrics: {str(e)}")


def test_environment_domains(request):
    """Cloud Function entry point"""
    project_id = os.environ.get('PROJECT_ID', '${project_id}')
    
    tester = EnvironmentDomainTester(project_id)
    return tester.test_environment_domains(request)


if __name__ == '__main__':
    # For local testing
    import sys
    if len(sys.argv) > 1:
        project_id = sys.argv[1]
    else:
        project_id = os.environ.get('PROJECT_ID', 'isectech-security-platform')
    
    # Mock request for local testing
    class MockRequest:
        def get_json(self):
            return {
                'environments': ['staging', 'development'],
                'trigger_type': 'manual'
            }
    
    tester = EnvironmentDomainTester(project_id)
    result = tester.test_environment_domains(MockRequest())
    print(json.dumps(result, indent=2))