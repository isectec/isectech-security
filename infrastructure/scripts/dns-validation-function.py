#!/usr/bin/env python3
"""
iSECTECH DNS Validation Cloud Function
Production-grade automated DNS propagation testing and validation
Author: Claude Code - iSECTECH Infrastructure Team
"""

import json
import logging
import time
import subprocess
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import socket
import dns.resolver
import dns.exception
from google.cloud import monitoring_v3
from google.cloud import storage
from google.cloud import functions_v1

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DNSValidator:
    """Production-grade DNS validation and testing system."""
    
    def __init__(self):
        self.domains = [
            'app.isectech.org',
            'api.isectech.org', 
            'docs.isectech.org',
            'admin.isectech.org',
            'status.isectech.org'
        ]
        
        self.dns_servers = [
            '8.8.8.8',        # Google DNS
            '8.8.4.4',        # Google DNS Secondary
            '1.1.1.1',        # Cloudflare DNS
            '1.0.0.1',        # Cloudflare DNS Secondary
            '208.67.222.222', # OpenDNS
            '208.67.220.220'  # OpenDNS Secondary
        ]
        
        self.record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA']
        
        # Initialize Google Cloud clients
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.storage_client = storage.Client()
        
        # Configuration
        self.project_id = 'isectech-security-platform'
        self.bucket_name = 'isectech-dns-test-results'
        
    def validate_dns_record(self, domain: str, record_type: str, 
                          dns_server: str, timeout: int = 5) -> Dict:
        """Validate a single DNS record against a specific DNS server."""
        
        start_time = time.time()
        result = {
            'domain': domain,
            'record_type': record_type,
            'dns_server': dns_server,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'UNKNOWN',
            'response_time': 0,
            'records': [],
            'error': None
        }
        
        try:
            # Configure resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            # Perform DNS query
            response = resolver.resolve(domain, record_type)
            end_time = time.time()
            
            result['response_time'] = round((end_time - start_time) * 1000, 2)  # ms
            result['records'] = [str(rdata) for rdata in response]
            result['status'] = 'SUCCESS'
            
            logger.info(f"DNS query successful: {domain} {record_type} @ {dns_server}")
            
        except dns.resolver.NXDOMAIN:
            result['status'] = 'NXDOMAIN'
            result['error'] = f'Domain {domain} does not exist'
            
        except dns.resolver.NoAnswer:
            result['status'] = 'NODATA'
            result['error'] = f'No {record_type} record found for {domain}'
            
        except dns.resolver.Timeout:
            result['status'] = 'TIMEOUT'
            result['error'] = f'DNS query timeout for {domain} {record_type}'
            
        except dns.exception.DNSException as e:
            result['status'] = 'ERROR'
            result['error'] = f'DNS error: {str(e)}'
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['error'] = f'Unexpected error: {str(e)}'
            
        result['response_time'] = round((time.time() - start_time) * 1000, 2)
        return result
    
    def test_dns_propagation(self, domain: str) -> Dict:
        """Test DNS propagation across all configured DNS servers."""
        
        logger.info(f"Testing DNS propagation for {domain}")
        
        propagation_results = {
            'domain': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'propagation_complete': True,
            'consistency_score': 0.0,
            'servers_tested': len(self.dns_servers),
            'servers_consistent': 0,
            'reference_records': [],
            'server_results': {}
        }
        
        # Get reference result from primary DNS server
        reference_result = self.validate_dns_record(domain, 'A', '8.8.8.8')
        if reference_result['status'] == 'SUCCESS':
            propagation_results['reference_records'] = reference_result['records']
        else:
            propagation_results['propagation_complete'] = False
            logger.warning(f"Could not get reference DNS result for {domain}")
            return propagation_results
        
        # Test against all DNS servers
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_server = {
                executor.submit(self.validate_dns_record, domain, 'A', server): server
                for server in self.dns_servers
            }
            
            for future in concurrent.futures.as_completed(future_to_server):
                server = future_to_server[future]
                try:
                    result = future.result()
                    propagation_results['server_results'][server] = result
                    
                    # Check consistency with reference
                    if (result['status'] == 'SUCCESS' and 
                        set(result['records']) == set(propagation_results['reference_records'])):
                        propagation_results['servers_consistent'] += 1
                    else:
                        propagation_results['propagation_complete'] = False
                        
                except Exception as e:
                    logger.error(f"Error testing server {server}: {e}")
                    propagation_results['propagation_complete'] = False
        
        # Calculate consistency score
        if propagation_results['servers_tested'] > 0:
            propagation_results['consistency_score'] = (
                propagation_results['servers_consistent'] / 
                propagation_results['servers_tested']
            )
        
        return propagation_results
    
    def validate_dnssec(self, domain: str) -> Dict:
        """Validate DNSSEC configuration for a domain."""
        
        logger.info(f"Validating DNSSEC for {domain}")
        
        dnssec_result = {
            'domain': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dnssec_enabled': False,
            'validation_successful': False,
            'key_algorithms': [],
            'error': None
        }
        
        try:
            # Use dig command for DNSSEC validation
            cmd = ['dig', '+dnssec', '+short', domain, 'A']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if process.returncode == 0:
                output = process.stdout.strip()
                if 'RRSIG' in output:
                    dnssec_result['dnssec_enabled'] = True
                    dnssec_result['validation_successful'] = True
                    logger.info(f"DNSSEC validation successful for {domain}")
                else:
                    logger.warning(f"DNSSEC not properly configured for {domain}")
            else:
                dnssec_result['error'] = process.stderr.strip()
                
        except subprocess.TimeoutExpired:
            dnssec_result['error'] = 'DNSSEC validation timeout'
            
        except Exception as e:
            dnssec_result['error'] = f'DNSSEC validation error: {str(e)}'
        
        return dnssec_result
    
    def test_security_records(self, domain: str) -> Dict:
        """Test security-related DNS records (CAA, SPF, DMARC)."""
        
        logger.info(f"Testing security records for {domain}")
        
        security_result = {
            'domain': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'caa_records': [],
            'spf_records': [],
            'dmarc_records': [],
            'security_score': 0
        }
        
        # Test CAA records
        caa_result = self.validate_dns_record(domain, 'CAA', '8.8.8.8')
        if caa_result['status'] == 'SUCCESS':
            security_result['caa_records'] = caa_result['records']
            security_result['security_score'] += 1
        
        # Test SPF records
        txt_result = self.validate_dns_record(domain, 'TXT', '8.8.8.8')
        if txt_result['status'] == 'SUCCESS':
            spf_records = [record for record in txt_result['records'] 
                          if record.strip('"').startswith('v=spf1')]
            security_result['spf_records'] = spf_records
            if spf_records:
                security_result['security_score'] += 1
        
        # Test DMARC records
        dmarc_domain = f'_dmarc.{domain}'
        dmarc_result = self.validate_dns_record(dmarc_domain, 'TXT', '8.8.8.8')
        if dmarc_result['status'] == 'SUCCESS':
            dmarc_records = [record for record in dmarc_result['records'] 
                           if record.strip('"').startswith('v=DMARC1')]
            security_result['dmarc_records'] = dmarc_records
            if dmarc_records:
                security_result['security_score'] += 1
        
        # Normalize security score to 0-100
        security_result['security_score'] = (security_result['security_score'] / 3) * 100
        
        return security_result
    
    def run_comprehensive_test(self) -> Dict:
        """Run comprehensive DNS validation tests for all domains."""
        
        logger.info("Starting comprehensive DNS validation tests")
        
        test_results = {
            'test_id': f"dns-test-{int(time.time())}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'domains_tested': len(self.domains),
            'total_tests': 0,
            'successful_tests': 0,
            'domain_results': {}
        }
        
        for domain in self.domains:
            logger.info(f"Testing domain: {domain}")
            
            domain_result = {
                'domain': domain,
                'propagation': self.test_dns_propagation(domain),
                'dnssec': self.validate_dnssec(domain),
                'security': self.test_security_records(domain),
                'overall_health': 'UNKNOWN'
            }
            
            # Calculate overall health score
            health_score = 0
            if domain_result['propagation']['propagation_complete']:
                health_score += 40
            health_score += domain_result['propagation']['consistency_score'] * 30
            
            if domain_result['dnssec']['validation_successful']:
                health_score += 15
            
            health_score += (domain_result['security']['security_score'] / 100) * 15
            
            if health_score >= 90:
                domain_result['overall_health'] = 'EXCELLENT'
            elif health_score >= 75:
                domain_result['overall_health'] = 'GOOD'
            elif health_score >= 50:
                domain_result['overall_health'] = 'FAIR'
            else:
                domain_result['overall_health'] = 'POOR'
            
            domain_result['health_score'] = round(health_score, 2)
            test_results['domain_results'][domain] = domain_result
            
            # Update counters
            test_results['total_tests'] += 3  # propagation, dnssec, security
            if domain_result['propagation']['propagation_complete']:
                test_results['successful_tests'] += 1
            if domain_result['dnssec']['validation_successful']:
                test_results['successful_tests'] += 1
            if domain_result['security']['security_score'] > 0:
                test_results['successful_tests'] += 1
        
        # Calculate overall success rate
        if test_results['total_tests'] > 0:
            test_results['success_rate'] = (
                test_results['successful_tests'] / test_results['total_tests']
            ) * 100
        else:
            test_results['success_rate'] = 0
        
        logger.info(f"DNS validation tests completed. Success rate: {test_results['success_rate']:.2f}%")
        
        return test_results
    
    def save_results_to_storage(self, results: Dict) -> str:
        """Save test results to Google Cloud Storage."""
        
        try:
            bucket = self.storage_client.bucket(self.bucket_name)
            blob_name = f"dns-tests/{results['test_id']}.json"
            blob = bucket.blob(blob_name)
            
            blob.upload_from_string(
                json.dumps(results, indent=2),
                content_type='application/json'
            )
            
            logger.info(f"Test results saved to gs://{self.bucket_name}/{blob_name}")
            return f"gs://{self.bucket_name}/{blob_name}"
            
        except Exception as e:
            logger.error(f"Failed to save results to storage: {e}")
            return ""
    
    def send_metrics_to_monitoring(self, results: Dict):
        """Send DNS test metrics to Google Cloud Monitoring."""
        
        try:
            project_name = f"projects/{self.project_id}"
            
            # Create custom metrics
            series = []
            
            # Overall success rate metric
            series.append(monitoring_v3.TimeSeries({
                'metric': {
                    'type': 'custom.googleapis.com/dns/test_success_rate',
                    'labels': {
                        'test_id': results['test_id']
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
                        'double_value': results['success_rate']
                    }
                }]
            }))
            
            # Per-domain health scores
            for domain, domain_result in results['domain_results'].items():
                series.append(monitoring_v3.TimeSeries({
                    'metric': {
                        'type': 'custom.googleapis.com/dns/domain_health_score',
                        'labels': {
                            'domain': domain,
                            'test_id': results['test_id']
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
                            'double_value': domain_result['health_score']
                        }
                    }]
                }))
            
            # Send metrics
            self.monitoring_client.create_time_series(
                name=project_name,
                time_series=series
            )
            
            logger.info("DNS test metrics sent to Cloud Monitoring")
            
        except Exception as e:
            logger.error(f"Failed to send metrics to monitoring: {e}")


def dns_validation_cloud_function(event, context):
    """Cloud Function entry point for DNS validation."""
    
    logger.info("DNS validation Cloud Function triggered")
    
    try:
        validator = DNSValidator()
        results = validator.run_comprehensive_test()
        
        # Save results to storage
        storage_path = validator.save_results_to_storage(results)
        
        # Send metrics to monitoring
        validator.send_metrics_to_monitoring(results)
        
        # Return summary
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'DNS validation completed successfully',
                'test_id': results['test_id'],
                'success_rate': results['success_rate'],
                'domains_tested': results['domains_tested'],
                'storage_path': storage_path
            })
        }
        
    except Exception as e:
        logger.error(f"DNS validation failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'DNS validation failed'
            })
        }


if __name__ == '__main__':
    # Run validation tests when executed directly
    validator = DNSValidator()
    results = validator.run_comprehensive_test()
    
    print(json.dumps(results, indent=2))