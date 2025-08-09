"""
iSECTECH Data Residency Monitoring Function
Production-grade monitoring for GDPR, CCPA, and APPI compliance
Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
Version: 1.0.0 - Task 70.5 Implementation
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import base64

from google.cloud import asset_v1
from google.cloud import storage
from google.cloud import sql_v1
from google.cloud import monitoring_v3
from google.cloud import pubsub_v1
from google.cloud import logging as cloud_logging

# Configure logging
cloud_logging_client = cloud_logging.Client()
cloud_logging_client.setup_logging()
logger = logging.getLogger(__name__)

class DataResidencyMonitor:
    """Monitor data residency compliance across all GCP resources."""
    
    def __init__(self):
        self.project_id = os.environ.get('PROJECT_ID')
        self.environment = os.environ.get('ENVIRONMENT', 'development')
        self.compliance_zones = json.loads(os.environ.get('COMPLIANCE_ZONES', '{}'))
        
        # Initialize GCP clients
        self.asset_client = asset_v1.AssetServiceClient()
        self.storage_client = storage.Client()
        self.sql_client = sql_v1.SqlInstancesServiceClient()
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.publisher = pubsub_v1.PublisherClient()
        
        # Compliance zone to region mapping
        self.zone_regions = {
            'gdpr': ['europe-west4', 'europe-west1'],
            'ccpa': ['us-central1', 'us-east1'],
            'appi': ['asia-northeast1']
        }

    def monitor_data_residency(self, cloud_event):
        """Main entry point for Cloud Function."""
        try:
            logger.info(f"Starting data residency compliance check for {self.project_id}")
            
            # Parse the event data
            event_data = self._parse_event_data(cloud_event)
            
            # Check all resource types for compliance
            violations = []
            
            # Monitor Cloud SQL instances
            sql_violations = self._check_sql_instances()
            violations.extend(sql_violations)
            
            # Monitor Cloud Storage buckets
            storage_violations = self._check_storage_buckets()
            violations.extend(storage_violations)
            
            # Monitor compute instances
            compute_violations = self._check_compute_instances()
            violations.extend(compute_violations)
            
            # Monitor BigQuery datasets
            bigquery_violations = self._check_bigquery_datasets()
            violations.extend(bigquery_violations)
            
            # Process violations
            if violations:
                self._process_violations(violations)
                logger.warning(f"Found {len(violations)} data residency violations")
            else:
                logger.info("No data residency violations detected")
                
            # Update compliance metrics
            self._update_compliance_metrics(violations)
            
            return {'status': 'success', 'violations': len(violations)}
            
        except Exception as e:
            logger.error(f"Error monitoring data residency: {str(e)}", exc_info=True)
            raise

    def _parse_event_data(self, cloud_event) -> Dict[str, Any]:
        """Parse Pub/Sub event data."""
        try:
            if hasattr(cloud_event, 'data'):
                # Decode base64 message data
                message_data = base64.b64decode(cloud_event.data).decode('utf-8')
                return json.loads(message_data)
            return {}
        except Exception as e:
            logger.warning(f"Failed to parse event data: {str(e)}")
            return {}

    def _check_sql_instances(self) -> List[Dict[str, Any]]:
        """Check Cloud SQL instances for data residency compliance."""
        violations = []
        
        try:
            # List all SQL instances in the project
            request = sql_v1.SqlInstancesListRequest(project=self.project_id)
            instances = self.sql_client.list(request=request)
            
            for instance in instances.items:
                violation = self._validate_sql_instance(instance)
                if violation:
                    violations.append(violation)
                    
        except Exception as e:
            logger.error(f"Error checking SQL instances: {str(e)}")
            
        return violations

    def _validate_sql_instance(self, instance) -> Optional[Dict[str, Any]]:
        """Validate a single SQL instance for compliance."""
        instance_region = instance.region
        instance_name = instance.name
        
        # Check if instance is in an approved region
        approved_regions = []
        for zone, regions in self.zone_regions.items():
            approved_regions.extend(regions)
            
        if instance_region not in approved_regions:
            return {
                'resource_type': 'sql_instance',
                'resource_name': instance_name,
                'region': instance_region,
                'violation_type': 'unauthorized_region',
                'severity': 'critical',
                'timestamp': datetime.utcnow().isoformat(),
                'details': f'SQL instance {instance_name} is in unauthorized region {instance_region}'
            }
            
        # Check backup configuration for data residency
        if hasattr(instance, 'settings') and hasattr(instance.settings, 'backup_configuration'):
            backup_config = instance.settings.backup_configuration
            if hasattr(backup_config, 'location') and backup_config.location != instance_region:
                return {
                    'resource_type': 'sql_instance',
                    'resource_name': instance_name,
                    'region': instance_region,
                    'violation_type': 'cross_region_backup',
                    'severity': 'high',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': f'SQL instance {instance_name} has backups in different region: {backup_config.location}'
                }
                
        return None

    def _check_storage_buckets(self) -> List[Dict[str, Any]]:
        """Check Cloud Storage buckets for data residency compliance."""
        violations = []
        
        try:
            # List all buckets in the project
            buckets = self.storage_client.list_buckets()
            
            for bucket in buckets:
                violation = self._validate_storage_bucket(bucket)
                if violation:
                    violations.append(violation)
                    
        except Exception as e:
            logger.error(f"Error checking storage buckets: {str(e)}")
            
        return violations

    def _validate_storage_bucket(self, bucket) -> Optional[Dict[str, Any]]:
        """Validate a single storage bucket for compliance."""
        bucket_name = bucket.name
        bucket_location = bucket.location.lower()
        
        # Check if bucket location is compliant
        approved_regions = []
        for zone, regions in self.zone_regions.items():
            approved_regions.extend(regions)
            
        # Handle multi-region buckets (they should not exist for data residency)
        if bucket_location in ['us', 'eu', 'asia']:
            return {
                'resource_type': 'storage_bucket',
                'resource_name': bucket_name,
                'region': bucket_location,
                'violation_type': 'multi_region_bucket',
                'severity': 'critical',
                'timestamp': datetime.utcnow().isoformat(),
                'details': f'Storage bucket {bucket_name} is multi-region ({bucket_location}), violates data residency'
            }
            
        # Check single-region compliance
        if bucket_location not in approved_regions:
            return {
                'resource_type': 'storage_bucket',
                'resource_name': bucket_name,
                'region': bucket_location,
                'violation_type': 'unauthorized_region',
                'severity': 'critical',
                'timestamp': datetime.utcnow().isoformat(),
                'details': f'Storage bucket {bucket_name} is in unauthorized region {bucket_location}'
            }
            
        return None

    def _check_compute_instances(self) -> List[Dict[str, Any]]:
        """Check Compute Engine instances using Asset Inventory."""
        violations = []
        
        try:
            parent = f"projects/{self.project_id}"
            request = asset_v1.ListAssetsRequest(
                parent=parent,
                asset_types=['compute.googleapis.com/Instance'],
                content_type=asset_v1.ContentType.RESOURCE
            )
            
            assets = self.asset_client.list_assets(request=request)
            
            for asset in assets:
                violation = self._validate_compute_instance(asset)
                if violation:
                    violations.append(violation)
                    
        except Exception as e:
            logger.error(f"Error checking compute instances: {str(e)}")
            
        return violations

    def _validate_compute_instance(self, asset) -> Optional[Dict[str, Any]]:
        """Validate a compute instance for compliance."""
        try:
            resource = asset.resource.data
            instance_name = asset.name.split('/')[-1]
            zone = resource.get('zone', '').split('/')[-1]
            region = '-'.join(zone.split('-')[:-1]) if zone else 'unknown'
            
            # Check if instance is in approved region
            approved_regions = []
            for compliance_zone, regions in self.zone_regions.items():
                approved_regions.extend(regions)
                
            if region not in approved_regions:
                return {
                    'resource_type': 'compute_instance',
                    'resource_name': instance_name,
                    'region': region,
                    'violation_type': 'unauthorized_region',
                    'severity': 'high',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': f'Compute instance {instance_name} is in unauthorized region {region}'
                }
                
        except Exception as e:
            logger.error(f"Error validating compute instance: {str(e)}")
            
        return None

    def _check_bigquery_datasets(self) -> List[Dict[str, Any]]:
        """Check BigQuery datasets using Asset Inventory."""
        violations = []
        
        try:
            parent = f"projects/{self.project_id}"
            request = asset_v1.ListAssetsRequest(
                parent=parent,
                asset_types=['bigquery.googleapis.com/Dataset'],
                content_type=asset_v1.ContentType.RESOURCE
            )
            
            assets = self.asset_client.list_assets(request=request)
            
            for asset in assets:
                violation = self._validate_bigquery_dataset(asset)
                if violation:
                    violations.append(violation)
                    
        except Exception as e:
            logger.error(f"Error checking BigQuery datasets: {str(e)}")
            
        return violations

    def _validate_bigquery_dataset(self, asset) -> Optional[Dict[str, Any]]:
        """Validate a BigQuery dataset for compliance."""
        try:
            resource = asset.resource.data
            dataset_name = asset.name.split('/')[-1]
            location = resource.get('location', '').lower()
            
            # Check if dataset location is compliant
            approved_regions = []
            for compliance_zone, regions in self.zone_regions.items():
                approved_regions.extend(regions)
                
            # Handle multi-region locations
            if location in ['us', 'eu', 'asia']:
                return {
                    'resource_type': 'bigquery_dataset',
                    'resource_name': dataset_name,
                    'region': location,
                    'violation_type': 'multi_region_dataset',
                    'severity': 'critical',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': f'BigQuery dataset {dataset_name} is multi-region ({location}), violates data residency'
                }
                
            # Check single-region compliance
            if location not in approved_regions:
                return {
                    'resource_type': 'bigquery_dataset',
                    'resource_name': dataset_name,
                    'region': location,
                    'violation_type': 'unauthorized_region',
                    'severity': 'critical',
                    'timestamp': datetime.utcnow().isoformat(),
                    'details': f'BigQuery dataset {dataset_name} is in unauthorized region {location}'
                }
                
        except Exception as e:
            logger.error(f"Error validating BigQuery dataset: {str(e)}")
            
        return None

    def _process_violations(self, violations: List[Dict[str, Any]]):
        """Process and log violations."""
        for violation in violations:
            # Log violation
            logger.error(
                f"DATA RESIDENCY VIOLATION: {violation['violation_type']} - "
                f"{violation['resource_type']} {violation['resource_name']} "
                f"in region {violation['region']}"
            )
            
            # Send to Pub/Sub for further processing
            self._publish_violation(violation)
            
    def _publish_violation(self, violation: Dict[str, Any]):
        """Publish violation to Pub/Sub topic."""
        try:
            topic_path = self.publisher.topic_path(
                self.project_id, 
                f'isectech-data-residency-violations-{self.environment}'
            )
            
            message_data = json.dumps(violation).encode('utf-8')
            future = self.publisher.publish(topic_path, message_data)
            
            logger.info(f"Published violation {violation['resource_name']} to Pub/Sub: {future.result()}")
            
        except Exception as e:
            logger.error(f"Error publishing violation: {str(e)}")

    def _update_compliance_metrics(self, violations: List[Dict[str, Any]]):
        """Update Cloud Monitoring metrics."""
        try:
            project_name = f"projects/{self.project_id}"
            
            # Group violations by type and region
            violation_counts = {}
            for violation in violations:
                key = (violation['region'], violation.get('compliance_zone', 'unknown'), violation['violation_type'])
                violation_counts[key] = violation_counts.get(key, 0) + 1
                
            # Create time series for each violation group
            series = []
            now = datetime.utcnow()
            
            for (region, compliance_zone, violation_type), count in violation_counts.items():
                series.append(monitoring_v3.TimeSeries(
                    metric=monitoring_v3.Metric(
                        type="custom.googleapis.com/data_residency/violations",
                        labels={
                            "region": region,
                            "compliance_zone": compliance_zone,
                            "violation_type": violation_type
                        }
                    ),
                    resource=monitoring_v3.MonitoredResource(
                        type="global",
                        labels={"project_id": self.project_id}
                    ),
                    points=[monitoring_v3.Point(
                        interval=monitoring_v3.TimeInterval(
                            end_time={"seconds": int(now.timestamp())}
                        ),
                        value=monitoring_v3.TypedValue(int64_value=count)
                    )]
                ))
                
            # Send metrics if we have any
            if series:
                request = monitoring_v3.CreateTimeSeriesRequest(
                    name=project_name,
                    time_series=series
                )
                self.monitoring_client.create_time_series(request=request)
                logger.info(f"Updated {len(series)} compliance metrics")
                
            # Always send a "healthy" metric if no violations
            if not violations:
                series = [monitoring_v3.TimeSeries(
                    metric=monitoring_v3.Metric(
                        type="custom.googleapis.com/data_residency/violations",
                        labels={
                            "region": "global",
                            "compliance_zone": "all",
                            "violation_type": "none"
                        }
                    ),
                    resource=monitoring_v3.MonitoredResource(
                        type="global",
                        labels={"project_id": self.project_id}
                    ),
                    points=[monitoring_v3.Point(
                        interval=monitoring_v3.TimeInterval(
                            end_time={"seconds": int(now.timestamp())}
                        ),
                        value=monitoring_v3.TypedValue(int64_value=0)
                    )]
                )]
                
                request = monitoring_v3.CreateTimeSeriesRequest(
                    name=project_name,
                    time_series=series
                )
                self.monitoring_client.create_time_series(request=request)
                
        except Exception as e:
            logger.error(f"Error updating compliance metrics: {str(e)}")


def monitor_data_residency(cloud_event):
    """Cloud Function entry point."""
    monitor = DataResidencyMonitor()
    return monitor.monitor_data_residency(cloud_event)