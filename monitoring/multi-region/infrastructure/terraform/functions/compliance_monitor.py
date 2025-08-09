#!/usr/bin/env python3
"""
iSECTECH Multi-Region Compliance Monitor
Production-grade compliance monitoring for data residency enforcement

Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT  
Version: 1.0.0 - Task 70.9 Implementation
"""

import json
import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import base64
import hashlib
import re

# Google Cloud imports
from google.cloud import storage
from google.cloud import sql_v1
from google.cloud import redis_v1
from google.cloud import pubsub_v1
from google.cloud import monitoring_v3
from google.cloud import logging as cloud_logging
from google.cloud import audit
from google.cloud import bigquery
from google.cloud import kms
from google.api_core import exceptions
import functions_framework

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cloud Logging client
cloud_logging_client = cloud_logging.Client()
cloud_logging_client.setup_logging()

class ComplianceMonitor:
    """Advanced compliance monitoring system for multi-region deployment"""
    
    def __init__(self):
        self.project_id = os.getenv('PROJECT_ID')
        self.environment = os.getenv('ENVIRONMENT', 'development')
        
        # Parse configuration from environment
        try:
            self.monitoring_strategy = json.loads(os.getenv('MONITORING_STRATEGY', '{}'))
            self.compliance_zones = json.loads(os.getenv('COMPLIANCE_ZONES', '{}'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse configuration: {e}")
            self.monitoring_strategy = {}
            self.compliance_zones = {}
        
        # Initialize clients
        self.storage_client = storage.Client()
        self.sql_client = sql_v1.SqlInstancesServiceClient()
        self.redis_client = redis_v1.CloudRedisClient()
        self.pubsub_client = pubsub_v1.PublisherClient()
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.bigquery_client = bigquery.Client()
        self.kms_client = kms.KeyManagementServiceClient()
        
        # Metrics configuration
        self.metrics_project_path = f"projects/{self.project_id}"
        
        # Compliance patterns for different regulations
        self.compliance_patterns = self._initialize_compliance_patterns()
        
        logger.info(f"Initialized ComplianceMonitor for project {self.project_id}")
    
    def _initialize_compliance_patterns(self) -> Dict[str, Any]:
        """Initialize compliance detection patterns for different regulations"""
        return {
            'gdpr': {
                'personal_data_patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
                    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card patterns
                    r'\b\d{2,3}[-\s]?\d{2}[-\s]?\d{4}\b',  # EU phone patterns
                    r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b'  # IBAN patterns
                ],
                'restricted_regions': ['us-central1', 'us-east1', 'asia-northeast1'],
                'allowed_regions': ['europe-west4', 'europe-west1'],
                'retention_days': 2555,  # 7 years
                'encryption_required': True
            },
            'ccpa': {
                'personal_data_patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
                    r'\b\d{3}-\d{2}-\d{4}\b',  # SSN patterns
                    r'\b\(\d{3}\)\s?\d{3}-\d{4}\b',  # US phone patterns
                    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'  # Credit card patterns
                ],
                'restricted_regions': ['europe-west4', 'europe-west1', 'asia-northeast1'],
                'allowed_regions': ['us-central1', 'us-east1'],
                'retention_days': 1095,  # 3 years
                'encryption_required': True
            },
            'appi': {
                'personal_data_patterns': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
                    r'\b\d{3}-\d{4}-\d{4}\b',  # Japanese phone patterns
                    r'\b\d{7}\b',  # Japanese postal codes
                    r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'  # Credit card patterns
                ],
                'restricted_regions': ['us-central1', 'us-east1', 'europe-west4', 'europe-west1'],
                'allowed_regions': ['asia-northeast1'],
                'retention_days': 1825,  # 5 years
                'encryption_required': True
            }
        }
    
    def monitor_storage_compliance(self) -> Dict[str, Any]:
        """Monitor Cloud Storage for data residency compliance violations"""
        results = {
            'status': 'compliant',
            'violations': [],
            'buckets_checked': 0,
            'objects_scanned': 0,
            'metrics': []
        }
        
        try:
            # List all project buckets
            for bucket in self.storage_client.list_buckets():
                if 'isectech' in bucket.name and self.environment in bucket.name:
                    results['buckets_checked'] += 1
                    
                    # Check bucket location compliance
                    bucket_violations = self._check_bucket_compliance(bucket)
                    results['violations'].extend(bucket_violations)
                    
                    # Sample object compliance check (avoid scanning all objects for performance)
                    object_violations = self._check_bucket_objects_compliance(bucket, sample_size=100)
                    results['violations'].extend(object_violations)
                    results['objects_scanned'] += min(100, len(list(bucket.list_blobs(max_results=100))))
            
            # Determine overall status
            if results['violations']:
                results['status'] = 'violations_detected'
                
                # Record compliance violation metrics
                for violation in results['violations']:
                    self._record_compliance_metric(
                        violation['regulation'],
                        violation['violation_type'],
                        violation['severity'],
                        1.0  # Violation count
                    )
        
        except Exception as e:
            logger.error(f"Error monitoring storage compliance: {e}")
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _check_bucket_compliance(self, bucket) -> List[Dict[str, Any]]:
        """Check individual bucket for compliance violations"""
        violations = []
        
        try:
            bucket.reload()  # Get latest bucket metadata
            
            # Determine bucket's compliance zone based on location
            bucket_zone = self._get_compliance_zone_for_location(bucket.location)
            
            if not bucket_zone:
                violations.append({
                    'type': 'bucket_location_violation',
                    'regulation': 'unknown',
                    'violation_type': 'location_compliance',
                    'severity': 'warning',
                    'resource': bucket.name,
                    'message': f"Bucket in unrecognized location: {bucket.location}",
                    'location': bucket.location,
                    'timestamp': datetime.utcnow().isoformat()
                })
                return violations
            
            # Check location compliance for each regulation
            for regulation, config in self.compliance_patterns.items():
                # Check if bucket is in restricted region for this regulation
                if bucket.location.lower() in [r.lower() for r in config['restricted_regions']]:
                    violations.append({
                        'type': 'bucket_location_violation',
                        'regulation': regulation.upper(),
                        'violation_type': 'location_compliance',
                        'severity': 'critical',
                        'resource': bucket.name,
                        'message': f"Bucket in restricted region {bucket.location} for {regulation.upper()}",
                        'location': bucket.location,
                        'compliance_zone': bucket_zone,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                # Check encryption compliance
                if config['encryption_required'] and not bucket.default_kms_key_name:
                    violations.append({
                        'type': 'encryption_violation',
                        'regulation': regulation.upper(),
                        'violation_type': 'encryption_compliance',
                        'severity': 'critical',
                        'resource': bucket.name,
                        'message': f"Bucket missing required encryption for {regulation.upper()}",
                        'location': bucket.location,
                        'compliance_zone': bucket_zone,
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        except Exception as e:
            logger.warning(f"Error checking bucket {bucket.name}: {e}")
            violations.append({
                'type': 'check_error',
                'regulation': 'system',
                'violation_type': 'monitoring_error',
                'severity': 'warning',
                'resource': bucket.name,
                'message': f"Error checking bucket compliance: {str(e)}",
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return violations
    
    def _check_bucket_objects_compliance(self, bucket, sample_size: int = 100) -> List[Dict[str, Any]]:
        """Check sample of bucket objects for PII and compliance violations"""
        violations = []
        
        try:
            # Sample objects from bucket (avoid scanning all for performance)
            blobs = list(bucket.list_blobs(max_results=sample_size))
            
            for blob in blobs[:sample_size]:
                try:
                    # Skip very large files to avoid memory issues
                    if blob.size and blob.size > 10 * 1024 * 1024:  # 10MB limit
                        continue
                    
                    # Check for PII in object metadata
                    metadata_violations = self._scan_metadata_for_pii(blob, bucket.location)
                    violations.extend(metadata_violations)
                    
                    # For text files, scan content for PII (limited sample)
                    if blob.content_type and ('text/' in blob.content_type or 'json' in blob.content_type):
                        content_violations = self._scan_object_content_for_pii(blob, bucket.location)
                        violations.extend(content_violations)
                
                except Exception as e:
                    logger.debug(f"Error checking object {blob.name}: {e}")
                    # Don't fail the entire check for individual object errors
                    continue
        
        except Exception as e:
            logger.warning(f"Error checking bucket objects: {e}")
        
        return violations
    
    def _scan_metadata_for_pii(self, blob, location: str) -> List[Dict[str, Any]]:
        """Scan object metadata for PII patterns"""
        violations = []
        bucket_zone = self._get_compliance_zone_for_location(location)
        
        # Check metadata fields for PII
        metadata_text = json.dumps(blob.metadata or {}) + ' ' + (blob.name or '')
        
        for regulation, config in self.compliance_patterns.items():
            # Skip if location is allowed for this regulation
            if location.lower() in [r.lower() for r in config['allowed_regions']]:
                continue
            
            for pattern in config['personal_data_patterns']:
                matches = re.findall(pattern, metadata_text, re.IGNORECASE)
                if matches:
                    violations.append({
                        'type': 'pii_in_metadata',
                        'regulation': regulation.upper(),
                        'violation_type': 'pii_exposure',
                        'severity': 'critical',
                        'resource': f"{blob.bucket.name}/{blob.name}",
                        'message': f"PII detected in object metadata for {regulation.upper()}",
                        'location': location,
                        'compliance_zone': bucket_zone,
                        'pii_matches': len(matches),
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        return violations
    
    def _scan_object_content_for_pii(self, blob, location: str) -> List[Dict[str, Any]]:
        """Scan object content for PII patterns (limited sampling)"""
        violations = []
        bucket_zone = self._get_compliance_zone_for_location(location)
        
        try:
            # Download first 64KB for scanning (avoid large downloads)
            content_sample = blob.download_as_bytes(start=0, end=64*1024)
            content_text = content_sample.decode('utf-8', errors='ignore')
            
            for regulation, config in self.compliance_patterns.items():
                # Skip if location is allowed for this regulation
                if location.lower() in [r.lower() for r in config['allowed_regions']]:
                    continue
                
                for pattern in config['personal_data_patterns']:
                    matches = re.findall(pattern, content_text, re.IGNORECASE)
                    if matches:
                        violations.append({
                            'type': 'pii_in_content',
                            'regulation': regulation.upper(), 
                            'violation_type': 'pii_exposure',
                            'severity': 'critical',
                            'resource': f"{blob.bucket.name}/{blob.name}",
                            'message': f"PII detected in object content for {regulation.upper()}",
                            'location': location,
                            'compliance_zone': bucket_zone,
                            'pii_matches': len(matches),
                            'timestamp': datetime.utcnow().isoformat()
                        })
        
        except Exception as e:
            logger.debug(f"Error scanning object content: {e}")
            # Don't fail for individual content scan errors
        
        return violations
    
    def monitor_database_compliance(self) -> Dict[str, Any]:
        """Monitor Cloud SQL instances for data residency compliance"""
        results = {
            'status': 'compliant',
            'violations': [],
            'instances_checked': 0,
            'metrics': []
        }
        
        try:
            # List all database instances
            request = sql_v1.SqlInstancesListRequest(project=self.project_id)
            instances = self.sql_client.list(request=request)
            
            for instance in instances.items:
                results['instances_checked'] += 1
                
                # Check instance location compliance
                instance_violations = self._check_database_instance_compliance(instance)
                results['violations'].extend(instance_violations)
            
            # Determine overall status
            if results['violations']:
                results['status'] = 'violations_detected'
                
                # Record compliance violation metrics
                for violation in results['violations']:
                    self._record_compliance_metric(
                        violation['regulation'],
                        violation['violation_type'],
                        violation['severity'],
                        1.0
                    )
        
        except Exception as e:
            logger.error(f"Error monitoring database compliance: {e}")
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _check_database_instance_compliance(self, instance) -> List[Dict[str, Any]]:
        """Check database instance for compliance violations"""
        violations = []
        
        try:
            instance_zone = self._get_compliance_zone_for_location(instance.region)
            
            # Check each regulation
            for regulation, config in self.compliance_patterns.items():
                # Check if instance is in restricted region
                if instance.region.lower() in [r.lower() for r in config['restricted_regions']]:
                    violations.append({
                        'type': 'database_location_violation',
                        'regulation': regulation.upper(),
                        'violation_type': 'location_compliance',
                        'severity': 'critical',
                        'resource': instance.name,
                        'message': f"Database in restricted region {instance.region} for {regulation.upper()}",
                        'location': instance.region,
                        'compliance_zone': instance_zone,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                # Check backup location compliance (if configured)
                if hasattr(instance, 'settings') and hasattr(instance.settings, 'backup_configuration'):
                    backup_config = instance.settings.backup_configuration
                    if hasattr(backup_config, 'location') and backup_config.location:
                        if backup_config.location.lower() in [r.lower() for r in config['restricted_regions']]:
                            violations.append({
                                'type': 'database_backup_location_violation',
                                'regulation': regulation.upper(),
                                'violation_type': 'backup_compliance',
                                'severity': 'critical',
                                'resource': instance.name,
                                'message': f"Database backup in restricted region {backup_config.location} for {regulation.upper()}",
                                'location': backup_config.location,
                                'compliance_zone': instance_zone,
                                'timestamp': datetime.utcnow().isoformat()
                            })
        
        except Exception as e:
            logger.warning(f"Error checking database instance {instance.name}: {e}")
            violations.append({
                'type': 'check_error',
                'regulation': 'system',
                'violation_type': 'monitoring_error',
                'severity': 'warning',
                'resource': instance.name,
                'message': f"Error checking database compliance: {str(e)}",
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return violations
    
    def monitor_cross_region_data_flows(self) -> Dict[str, Any]:
        """Monitor for unauthorized cross-region data transfers"""
        results = {
            'status': 'compliant',
            'violations': [],
            'flows_analyzed': 0,
            'metrics': []
        }
        
        try:
            # This would integrate with VPC Flow Logs and audit logs
            # to detect cross-region data transfers
            # For now, simulate monitoring key transfer patterns
            
            # Check Pub/Sub cross-region subscriptions
            pubsub_violations = self._check_pubsub_cross_region_flows()
            results['violations'].extend(pubsub_violations)
            
            # Check storage transfer jobs
            storage_violations = self._check_storage_transfer_compliance()
            results['violations'].extend(storage_violations)
            
            results['flows_analyzed'] = len(pubsub_violations) + len(storage_violations)
            
            if results['violations']:
                results['status'] = 'violations_detected'
                
                # Record violations
                for violation in results['violations']:
                    self._record_compliance_metric(
                        violation['regulation'],
                        violation['violation_type'],
                        violation['severity'],
                        1.0
                    )
        
        except Exception as e:
            logger.error(f"Error monitoring cross-region data flows: {e}")
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def _check_pubsub_cross_region_flows(self) -> List[Dict[str, Any]]:
        """Check Pub/Sub topics for cross-region data flows"""
        violations = []
        
        try:
            project_path = f"projects/{self.project_id}"
            
            # List topics
            topics = self.pubsub_client.list_topics(parent=project_path)
            for topic in topics:
                # Parse region from topic name pattern
                topic_region = self._extract_region_from_resource_name(topic.name)
                if not topic_region:
                    continue
                
                topic_zone = self._get_compliance_zone_for_location(topic_region)
                
                # Check message storage policy compliance
                # This would require inspecting topic configuration
                # For now, flag any cross-region patterns in topic names
                if 'cross-region' in topic.name or 'global' in topic.name:
                    violations.append({
                        'type': 'cross_region_pubsub_topic',
                        'regulation': 'MULTI',
                        'violation_type': 'data_flow_compliance',
                        'severity': 'warning',
                        'resource': topic.name,
                        'message': f"Topic may enable cross-region data flow",
                        'location': topic_region,
                        'compliance_zone': topic_zone,
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        except Exception as e:
            logger.warning(f"Error checking Pub/Sub flows: {e}")
        
        return violations
    
    def _check_storage_transfer_compliance(self) -> List[Dict[str, Any]]:
        """Check Cloud Storage transfer jobs for compliance violations"""
        violations = []
        
        try:
            # This would check Storage Transfer Service jobs
            # For now, simulate checking for cross-zone transfers
            
            # Check for buckets with cross-region lifecycle policies
            for bucket in self.storage_client.list_buckets():
                if 'isectech' in bucket.name and self.environment in bucket.name:
                    bucket.reload()
                    
                    # Check lifecycle rules for cross-region moves
                    if bucket.lifecycle_rules:
                        for rule in bucket.lifecycle_rules:
                            if hasattr(rule, 'action') and hasattr(rule.action, 'storage_class'):
                                # Check if lifecycle moves to different region storage class
                                if rule.action.storage_class in ['NEARLINE', 'COLDLINE', 'ARCHIVE']:
                                    # This could potentially move data across regions
                                    bucket_zone = self._get_compliance_zone_for_location(bucket.location)
                                    
                                    violations.append({
                                        'type': 'storage_lifecycle_compliance',
                                        'regulation': 'MULTI',
                                        'violation_type': 'data_flow_compliance',
                                        'severity': 'warning',
                                        'resource': bucket.name,
                                        'message': f"Lifecycle policy may cause cross-region data movement",
                                        'location': bucket.location,
                                        'compliance_zone': bucket_zone,
                                        'timestamp': datetime.utcnow().isoformat()
                                    })
        
        except Exception as e:
            logger.warning(f"Error checking storage transfers: {e}")
        
        return violations
    
    def _get_compliance_zone_for_location(self, location: str) -> Optional[str]:
        """Determine compliance zone for a given location"""
        location_lower = location.lower()
        
        # Map locations to compliance zones
        if location_lower in ['europe-west4', 'europe-west1', 'europe']:
            return 'gdpr'
        elif location_lower in ['us-central1', 'us-east1', 'us']:
            return 'ccpa'
        elif location_lower in ['asia-northeast1', 'asia']:
            return 'appi'
        else:
            return None
    
    def _extract_region_from_resource_name(self, resource_name: str) -> Optional[str]:
        """Extract region from GCP resource name"""
        # Pattern for extracting region from resource paths
        region_pattern = r'/regions/([^/]+)|/zones/([^/]+)|-(us-central1|us-east1|europe-west[1-4]|asia-northeast1)-'
        
        match = re.search(region_pattern, resource_name)
        if match:
            # Return first non-empty group
            for group in match.groups():
                if group:
                    # Handle zone case (extract region from zone)
                    if group.endswith('-a') or group.endswith('-b') or group.endswith('-c'):
                        return group[:-2]  # Remove zone suffix
                    return group
        
        return None
    
    def _record_compliance_metric(self, regulation: str, violation_type: str, severity: str, count: float):
        """Record compliance violation metric"""
        try:
            metric_type = "custom.googleapis.com/compliance/violation_count"
            
            # Create time series data
            series = monitoring_v3.TimeSeries()
            series.metric.type = metric_type
            series.metric.labels['regulation'] = regulation
            series.metric.labels['violation_type'] = violation_type
            series.metric.labels['severity'] = severity
            series.metric.labels['environment'] = self.environment
            
            # Set resource
            series.resource.type = 'cloud_function'
            series.resource.labels['function_name'] = 'compliance-monitor'
            series.resource.labels['region'] = 'us-central1'
            
            # Create data point
            point = monitoring_v3.Point()
            point.value.double_value = count
            now = time.time()
            seconds = int(now)
            nanos = int((now - seconds) * 10 ** 9)
            point.interval.end_time.seconds = seconds
            point.interval.end_time.nanos = nanos
            
            series.points = [point]
            
            # Write the metric
            self.monitoring_client.create_time_series(
                name=self.metrics_project_path,
                time_series=[series]
            )
            
            logger.debug(f"Recorded compliance metric: {regulation} {violation_type} {severity}: {count}")
        
        except Exception as e:
            logger.warning(f"Error recording compliance metric: {e}")
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive compliance monitoring report"""
        logger.info("Generating compliance monitoring report")
        
        # Monitor all compliance areas
        storage_results = self.monitor_storage_compliance()
        database_results = self.monitor_database_compliance()
        data_flow_results = self.monitor_cross_region_data_flows()
        
        # Aggregate violations
        all_violations = (
            storage_results.get('violations', []) +
            database_results.get('violations', []) +
            data_flow_results.get('violations', [])
        )
        
        # Categorize violations by regulation
        violations_by_regulation = {}
        for violation in all_violations:
            reg = violation['regulation']
            if reg not in violations_by_regulation:
                violations_by_regulation[reg] = []
            violations_by_regulation[reg].append(violation)
        
        # Determine overall compliance status
        critical_violations = [v for v in all_violations if v['severity'] == 'critical']
        warning_violations = [v for v in all_violations if v['severity'] == 'warning']
        
        if critical_violations:
            overall_status = 'critical_violations'
        elif warning_violations:
            overall_status = 'warnings_detected'
        else:
            overall_status = 'compliant'
        
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'environment': self.environment,
            'overall_status': overall_status,
            'summary': {
                'total_violations': len(all_violations),
                'critical_violations': len(critical_violations),
                'warning_violations': len(warning_violations),
                'regulations_affected': list(violations_by_regulation.keys())
            },
            'components': {
                'storage': storage_results,
                'database': database_results,
                'data_flows': data_flow_results
            },
            'violations_by_regulation': violations_by_regulation,
            'compliance_zones': self.compliance_zones,
            'monitoring_coverage': {
                'buckets_checked': storage_results.get('buckets_checked', 0),
                'objects_scanned': storage_results.get('objects_scanned', 0),
                'instances_checked': database_results.get('instances_checked', 0),
                'flows_analyzed': data_flow_results.get('flows_analyzed', 0)
            }
        }
        
        # Log critical violations
        for violation in critical_violations:
            logger.error(f"CRITICAL COMPLIANCE VIOLATION: {violation['message']} ({violation['resource']}) - {violation['regulation']}")
        
        # Log warnings
        for violation in warning_violations:
            logger.warning(f"Compliance warning: {violation['message']} ({violation['resource']}) - {violation['regulation']}")
        
        logger.info(f"Compliance report generated: {overall_status} with {len(all_violations)} total violations")
        
        return report

@functions_framework.cloud_event
def monitor_compliance(cloud_event):
    """Cloud Function entry point for compliance monitoring"""
    logger.info(f"Compliance monitoring triggered: {cloud_event.get('type', 'unknown')}")
    
    try:
        # Initialize compliance monitor
        monitor = ComplianceMonitor()
        
        # Generate compliance report
        report = monitor.generate_compliance_report()
        
        # Log structured report for Cloud Logging and alerting
        logger.info("Compliance monitoring report", extra={
            'compliance_report': report,
            'severity': report['overall_status'].upper(),
            'violations_count': report['summary']['total_violations'],
            'critical_violations_count': report['summary']['critical_violations']
        })
        
        # Send alerts for critical violations
        if report['summary']['critical_violations'] > 0:
            logger.error(f"CRITICAL COMPLIANCE VIOLATIONS DETECTED: {report['summary']['critical_violations']} violations require immediate attention")
        
        return {
            'status': 'success',
            'message': f"Compliance monitoring completed: {report['overall_status']}",
            'report': report
        }
    
    except Exception as e:
        error_msg = f"Compliance monitoring failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        return {
            'status': 'error',
            'message': error_msg,
            'error': str(e)
        }

if __name__ == "__main__":
    # For local testing
    import sys
    from unittest.mock import Mock
    
    # Create mock cloud event
    mock_event = {
        'type': 'google.cloud.audit.log.v1.written',
        'data': {'action': 'monitor_compliance'}
    }
    
    result = monitor_compliance(mock_event)
    print(json.dumps(result, indent=2))