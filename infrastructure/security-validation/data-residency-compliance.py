#!/usr/bin/env python3
"""
Data Residency Compliance Testing Framework
Production-grade validation for multi-region data residency enforcement
Implements GDPR, CCPA, and other data sovereignty requirements
"""

import asyncio
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
from concurrent.futures import ThreadPoolExecutor
import requests
import ipaddress
from geoip2 import database
from geoip2.errors import AddressNotFoundError
import whois
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


@dataclass
class DataFlowRecord:
    """Data flow tracking record"""
    request_id: str
    source_region: str
    target_region: str
    data_type: str
    data_classification: str  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    processing_location: str
    storage_location: str
    encryption_status: str
    compliance_status: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class ComplianceViolation:
    """Compliance violation record"""
    violation_id: str
    violation_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    region: str
    description: str
    regulation: str  # GDPR, CCPA, PDPA, etc.
    evidence: Dict[str, Any]
    remediation: str
    detected_at: datetime


@dataclass
class DataResidencyTest:
    """Data residency test configuration"""
    test_id: str
    test_name: str
    region: str
    endpoint: str
    data_type: str
    expected_location: str
    compliance_rules: List[str]
    test_payload: Dict[str, Any]


class GeoLocationValidator:
    """Geographic location validation using multiple sources"""
    
    def __init__(self, geoip_db_path: Optional[str] = None):
        self.geoip_db_path = geoip_db_path
        self.geoip_reader = None
        
        if geoip_db_path and os.path.exists(geoip_db_path):
            try:
                self.geoip_reader = database.Reader(geoip_db_path)
            except Exception as e:
                logging.warning(f"Failed to load GeoIP database: {e}")
    
    def get_ip_location(self, ip_address: str) -> Optional[Dict[str, str]]:
        """Get geographic location of IP address"""
        try:
            if self.geoip_reader:
                response = self.geoip_reader.city(ip_address)
                return {
                    'country': response.country.iso_code,
                    'region': response.subdivisions.most_specific.iso_code,
                    'city': response.city.name,
                    'latitude': float(response.location.latitude) if response.location.latitude else None,
                    'longitude': float(response.location.longitude) if response.location.longitude else None
                }
            else:
                # Fallback to online service
                response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        return {
                            'country': data['countryCode'],
                            'region': data['regionName'],
                            'city': data['city'],
                            'latitude': data['lat'],
                            'longitude': data['lon']
                        }
        except Exception as e:
            logging.error(f"Failed to get IP location for {ip_address}: {e}")
        
        return None
    
    def validate_region_compliance(self, ip_address: str, expected_regions: List[str]) -> bool:
        """Validate if IP address is within expected geographic regions"""
        location = self.get_ip_location(ip_address)
        if not location:
            return False
        
        country = location.get('country', '').upper()
        region = location.get('region', '').upper()
        
        # Define region mappings
        region_mappings = {
            'US': ['US-EAST-1', 'US-WEST-1', 'US-WEST-2', 'US-CENTRAL'],
            'CA': ['CA-CENTRAL-1'],
            'GB': ['EU-WEST-2', 'EU-LONDON'],
            'IE': ['EU-WEST-1'],
            'DE': ['EU-CENTRAL-1', 'EU-FRANKFURT'],
            'FR': ['EU-WEST-3', 'EU-PARIS'],
            'SG': ['AP-SOUTHEAST-1', 'AP-SINGAPORE'],
            'JP': ['AP-NORTHEAST-1', 'AP-TOKYO'],
            'AU': ['AP-SOUTHEAST-2', 'AP-SYDNEY'],
            'IN': ['AP-SOUTH-1', 'AP-MUMBAI']
        }
        
        allowed_countries = set()
        for expected_region in expected_regions:
            for country_code, regions in region_mappings.items():
                if any(expected_region.upper() in region.upper() for region in regions):
                    allowed_countries.add(country_code)
        
        return country in allowed_countries


class DataClassificationEngine:
    """Data classification and sensitivity analysis"""
    
    def __init__(self):
        self.classification_rules = {
            'RESTRICTED': [
                'ssn', 'social_security', 'passport', 'driver_license',
                'credit_card', 'bank_account', 'medical_record',
                'biometric', 'genetic', 'financial_statement'
            ],
            'CONFIDENTIAL': [
                'email', 'phone', 'address', 'personal_id',
                'employment', 'salary', 'contract', 'legal_document',
                'customer_data', 'financial_transaction'
            ],
            'INTERNAL': [
                'employee_id', 'department', 'project_code',
                'internal_email', 'business_process', 'system_log',
                'performance_metric', 'operational_data'
            ],
            'PUBLIC': [
                'company_name', 'public_announcement', 'marketing_material',
                'press_release', 'product_catalog', 'public_documentation'
            ]
        }
    
    def classify_data(self, data: Dict[str, Any]) -> str:
        """Classify data based on content analysis"""
        data_str = json.dumps(data, default=str).lower()
        
        for classification, keywords in self.classification_rules.items():
            for keyword in keywords:
                if keyword.replace('_', ' ') in data_str or keyword.replace('_', '') in data_str:
                    return classification
        
        return 'INTERNAL'  # Default classification
    
    def analyze_sensitivity(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data sensitivity and compliance requirements"""
        classification = self.classify_data(data)
        
        # Determine compliance requirements based on data type
        compliance_requirements = []
        
        data_str = json.dumps(data, default=str).lower()
        
        # GDPR applies to EU personal data
        if any(keyword in data_str for keyword in ['personal', 'individual', 'citizen', 'resident']):
            compliance_requirements.append('GDPR')
        
        # CCPA applies to California residents
        if 'california' in data_str or 'ca_resident' in data_str:
            compliance_requirements.append('CCPA')
        
        # PDPA applies to Singapore personal data
        if 'singapore' in data_str or 'sg_resident' in data_str:
            compliance_requirements.append('PDPA')
        
        # Financial regulations
        if any(keyword in data_str for keyword in ['financial', 'payment', 'transaction', 'bank']):
            compliance_requirements.extend(['PCI-DSS', 'SOX'])
        
        # Healthcare regulations
        if any(keyword in data_str for keyword in ['health', 'medical', 'patient', 'diagnosis']):
            compliance_requirements.append('HIPAA')
        
        return {
            'classification': classification,
            'compliance_requirements': compliance_requirements,
            'retention_period': self._get_retention_period(classification),
            'encryption_required': classification in ['RESTRICTED', 'CONFIDENTIAL'],
            'cross_border_restrictions': classification in ['RESTRICTED']
        }
    
    def _get_retention_period(self, classification: str) -> str:
        """Get data retention period based on classification"""
        retention_periods = {
            'RESTRICTED': '7_years',
            'CONFIDENTIAL': '5_years',
            'INTERNAL': '3_years',
            'PUBLIC': 'indefinite'
        }
        return retention_periods.get(classification, '3_years')


class DataFlowTracker:
    """Track data flows across regions and services"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.flow_records = []
        self.geo_validator = GeoLocationValidator()
        self.classifier = DataClassificationEngine()
    
    async def track_data_flow(self, test: DataResidencyTest, response_data: Dict[str, Any]) -> DataFlowRecord:
        """Track a single data flow"""
        request_id = f"flow_{secrets.token_hex(8)}"
        
        # Analyze response headers for processing location
        processing_location = response_data.get('headers', {}).get('X-Processing-Region', 'unknown')
        storage_location = response_data.get('headers', {}).get('X-Storage-Region', 'unknown')
        
        # Classify the data
        sensitivity_analysis = self.classifier.analyze_sensitivity(test.test_payload)
        
        # Determine encryption status
        encryption_status = "ENCRYPTED" if response_data.get('https', False) else "UNENCRYPTED"
        
        # Check compliance
        compliance_status = "COMPLIANT"
        if processing_location != test.expected_location:
            compliance_status = "NON_COMPLIANT"
        if storage_location != test.expected_location:
            compliance_status = "NON_COMPLIANT"
        
        flow_record = DataFlowRecord(
            request_id=request_id,
            source_region=test.region,
            target_region=processing_location,
            data_type=test.data_type,
            data_classification=sensitivity_analysis['classification'],
            processing_location=processing_location,
            storage_location=storage_location,
            encryption_status=encryption_status,
            compliance_status=compliance_status,
            timestamp=datetime.now(timezone.utc),
            metadata={
                'test_id': test.test_id,
                'endpoint': test.endpoint,
                'compliance_requirements': sensitivity_analysis['compliance_requirements'],
                'response_time': response_data.get('response_time', 0)
            }
        )
        
        self.flow_records.append(flow_record)
        return flow_record
    
    def analyze_compliance_violations(self) -> List[ComplianceViolation]:
        """Analyze flow records for compliance violations"""
        violations = []
        
        for record in self.flow_records:
            violation_id = f"violation_{secrets.token_hex(6)}"
            
            # Check for cross-border data transfer violations
            if record.compliance_status == "NON_COMPLIANT":
                if record.data_classification in ['RESTRICTED', 'CONFIDENTIAL']:
                    violations.append(ComplianceViolation(
                        violation_id=violation_id,
                        violation_type="UNAUTHORIZED_CROSS_BORDER_TRANSFER",
                        severity="CRITICAL",
                        region=record.source_region,
                        description=f"Restricted data processed outside authorized region",
                        regulation="GDPR_ARTICLE_44",
                        evidence={
                            'expected_region': record.source_region,
                            'actual_processing_region': record.processing_location,
                            'actual_storage_region': record.storage_location,
                            'data_classification': record.data_classification
                        },
                        remediation="Ensure data processing occurs within authorized geographic boundaries",
                        detected_at=record.timestamp
                    ))
            
            # Check for encryption violations
            if record.encryption_status != "ENCRYPTED" and record.data_classification in ['RESTRICTED', 'CONFIDENTIAL']:
                violations.append(ComplianceViolation(
                    violation_id=f"encryption_{secrets.token_hex(6)}",
                    violation_type="INADEQUATE_ENCRYPTION",
                    severity="HIGH",
                    region=record.source_region,
                    description="Sensitive data transmitted without adequate encryption",
                    regulation="GDPR_ARTICLE_32",
                    evidence={
                        'data_classification': record.data_classification,
                        'encryption_status': record.encryption_status,
                        'endpoint': record.metadata.get('endpoint')
                    },
                    remediation="Implement end-to-end encryption for sensitive data",
                    detected_at=record.timestamp
                ))
        
        return violations


class ComplianceReportGenerator:
    """Generate comprehensive compliance reports"""
    
    def __init__(self, output_dir: str = "compliance_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_executive_summary(self, flow_records: List[DataFlowRecord], 
                                 violations: List[ComplianceViolation]) -> Dict[str, Any]:
        """Generate executive summary of compliance status"""
        total_flows = len(flow_records)
        compliant_flows = sum(1 for r in flow_records if r.compliance_status == "COMPLIANT")
        compliance_rate = (compliant_flows / total_flows * 100) if total_flows > 0 else 100
        
        violation_by_severity = {}
        for violation in violations:
            violation_by_severity[violation.severity] = violation_by_severity.get(violation.severity, 0) + 1
        
        data_by_classification = {}
        for record in flow_records:
            classification = record.data_classification
            data_by_classification[classification] = data_by_classification.get(classification, 0) + 1
        
        return {
            "compliance_overview": {
                "total_data_flows": total_flows,
                "compliant_flows": compliant_flows,
                "compliance_rate": f"{compliance_rate:.1f}%",
                "total_violations": len(violations)
            },
            "violation_breakdown": violation_by_severity,
            "data_classification_distribution": data_by_classification,
            "risk_assessment": self._assess_risk_level(violations),
            "recommendations": self._generate_recommendations(violations)
        }
    
    def _assess_risk_level(self, violations: List[ComplianceViolation]) -> str:
        """Assess overall risk level"""
        critical_count = sum(1 for v in violations if v.severity == "CRITICAL")
        high_count = sum(1 for v in violations if v.severity == "HIGH")
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 3:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_recommendations(self, violations: List[ComplianceViolation]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        violation_types = set(v.violation_type for v in violations)
        
        if "UNAUTHORIZED_CROSS_BORDER_TRANSFER" in violation_types:
            recommendations.append("Implement data residency controls to prevent unauthorized cross-border transfers")
        
        if "INADEQUATE_ENCRYPTION" in violation_types:
            recommendations.append("Enforce encryption-in-transit and encryption-at-rest for all sensitive data")
        
        regulations = set(v.regulation for v in violations)
        
        if any("GDPR" in reg for reg in regulations):
            recommendations.append("Review GDPR Article 44-49 requirements for international data transfers")
        
        if any("CCPA" in reg for reg in regulations):
            recommendations.append("Implement CCPA-compliant data processing controls")
        
        return recommendations
    
    def generate_detailed_report(self, flow_records: List[DataFlowRecord], 
                               violations: List[ComplianceViolation]) -> str:
        """Generate detailed compliance report"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_dir, f"compliance_report_{timestamp}.json")
        
        executive_summary = self.generate_executive_summary(flow_records, violations)
        
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_type": "data_residency_compliance",
                "version": "1.0"
            },
            "executive_summary": executive_summary,
            "data_flows": [asdict(record) for record in flow_records],
            "compliance_violations": [asdict(violation) for violation in violations],
            "remediation_plan": self._generate_remediation_plan(violations)
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return report_file


class DataResidencyComplianceTester:
    """Main data residency compliance testing framework"""
    
    def __init__(self, config_file: str, output_dir: str = "compliance_reports"):
        self.logger = self._setup_logger()
        
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.flow_tracker = DataFlowTracker(self.logger)
        self.report_generator = ComplianceReportGenerator(output_dir)
        
        self.test_suite = self._generate_test_suite()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("DataResidencyTester")
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger
    
    def _generate_test_suite(self) -> List[DataResidencyTest]:
        """Generate comprehensive test suite"""
        tests = []
        
        for region in self.config['regions']:
            region_name = region['name']
            expected_location = region['data_residency_zone']
            
            # Test different data types and classifications
            test_scenarios = [
                {
                    'data_type': 'personal_data',
                    'payload': {
                        'user_id': 'test_user_123',
                        'email': 'test@example.com',
                        'name': 'Test User',
                        'address': '123 Test Street, Test City'
                    }
                },
                {
                    'data_type': 'financial_data',
                    'payload': {
                        'account_id': 'acc_123456',
                        'transaction_amount': 1000.00,
                        'currency': 'USD',
                        'payment_method': 'credit_card'
                    }
                },
                {
                    'data_type': 'health_data',
                    'payload': {
                        'patient_id': 'pat_789',
                        'medical_record_number': 'MRN_456',
                        'diagnosis': 'test_diagnosis',
                        'treatment': 'test_treatment'
                    }
                },
                {
                    'data_type': 'business_data',
                    'payload': {
                        'company_id': 'comp_123',
                        'employee_count': 100,
                        'revenue': 5000000,
                        'industry': 'technology'
                    }
                }
            ]
            
            for endpoint in region['api_endpoints']:
                for scenario in test_scenarios:
                    test_id = f"test_{region_name}_{scenario['data_type']}_{secrets.token_hex(4)}"
                    
                    tests.append(DataResidencyTest(
                        test_id=test_id,
                        test_name=f"Data Residency Test - {scenario['data_type'].title()}",
                        region=region_name,
                        endpoint=endpoint,
                        data_type=scenario['data_type'],
                        expected_location=expected_location,
                        compliance_rules=region['compliance_requirements'],
                        test_payload=scenario['payload']
                    ))
        
        return tests
    
    async def execute_test(self, test: DataResidencyTest) -> Dict[str, Any]:
        """Execute a single data residency test"""
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing test: {test.test_name} for region {test.region}")
            
            # Make test request
            headers = {
                'Content-Type': 'application/json',
                'X-Test-ID': test.test_id,
                'X-Expected-Region': test.expected_location
            }
            
            response = requests.post(
                f"{test.endpoint}/api/compliance/data-residency-test",
                json=test.test_payload,
                headers=headers,
                timeout=30
            )
            
            response_time = time.time() - start_time
            
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'response_time': response_time,
                'https': test.endpoint.startswith('https://')
            }
            
            if response.status_code == 200:
                try:
                    response_data['body'] = response.json()
                except json.JSONDecodeError:
                    response_data['body'] = response.text
            
            # Track the data flow
            flow_record = await self.flow_tracker.track_data_flow(test, response_data)
            
            return {
                'test': test,
                'response': response_data,
                'flow_record': flow_record,
                'success': True
            }
            
        except Exception as e:
            self.logger.error(f"Test failed: {test.test_name} - {str(e)}")
            return {
                'test': test,
                'error': str(e),
                'success': False
            }
    
    async def run_all_tests(self) -> str:
        """Run all data residency compliance tests"""
        self.logger.info("Starting data residency compliance testing...")
        start_time = time.time()
        
        # Execute all tests concurrently
        tasks = [self.execute_test(test) for test in self.test_suite]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_results = [r for r in results if isinstance(r, dict) and r.get('success', False)]
        
        self.logger.info(f"Completed {len(successful_results)}/{len(self.test_suite)} tests successfully")
        
        # Analyze compliance violations
        violations = self.flow_tracker.analyze_compliance_violations()
        
        self.logger.info(f"Detected {len(violations)} compliance violations")
        
        # Generate report
        report_file = self.report_generator.generate_detailed_report(
            self.flow_tracker.flow_records, 
            violations
        )
        
        total_time = time.time() - start_time
        self.logger.info(f"Testing completed in {total_time:.2f} seconds")
        self.logger.info(f"Report generated: {report_file}")
        
        return report_file


async def main():
    parser = argparse.ArgumentParser(description="Data Residency Compliance Testing")
    parser.add_argument("--config", required=True, help="Configuration file path")
    parser.add_argument("--output-dir", default="compliance_reports", help="Output directory for reports")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config):
        print(f"Configuration file not found: {args.config}")
        sys.exit(1)
    
    tester = DataResidencyComplianceTester(args.config, args.output_dir)
    report_file = await tester.run_all_tests()
    
    # Load and display summary
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    summary = report['executive_summary']
    print(f"\n{'='*60}")
    print("DATA RESIDENCY COMPLIANCE SUMMARY")
    print(f"{'='*60}")
    print(f"Total Data Flows: {summary['compliance_overview']['total_data_flows']}")
    print(f"Compliance Rate: {summary['compliance_overview']['compliance_rate']}")
    print(f"Total Violations: {summary['compliance_overview']['total_violations']}")
    print(f"Risk Level: {summary['risk_assessment']}")
    
    if summary['compliance_overview']['total_violations'] > 0:
        print(f"\nVIOLATION BREAKDOWN:")
        for severity, count in summary['violation_breakdown'].items():
            print(f"  {severity}: {count}")
    
    if summary['recommendations']:
        print(f"\nRECOMMENDATIONS:")
        for recommendation in summary['recommendations']:
            print(f"  • {recommendation}")
    
    # Exit with appropriate code based on violations
    violation_count = summary['compliance_overview']['total_violations']
    if violation_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())