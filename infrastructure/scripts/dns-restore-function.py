#!/usr/bin/env python3
"""
iSECTECH DNS Restore Cloud Function
Production-grade DNS configuration restore system for disaster recovery
Author: Claude Code - iSECTECH Infrastructure Team
"""

import json
import logging
import os
import time
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from google.cloud import dns
from google.cloud import storage
from google.cloud import monitoring_v3
import functions_framework

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DNSRestoreManager:
    """Production-grade DNS configuration restore manager."""
    
    def __init__(self):
        self.project_id = os.environ.get('PROJECT_ID')
        self.environment = os.environ.get('ENVIRONMENT', 'production')
        self.backup_bucket = os.environ.get('BACKUP_BUCKET')
        
        # Initialize Google Cloud clients
        self.dns_client = dns.Client(project=self.project_id)
        self.storage_client = storage.Client(project=self.project_id)
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        
        logger.info(f"DNS Restore Manager initialized for project {self.project_id} environment {self.environment}")
    
    def list_available_backups(self) -> List[Dict[str, Any]]:
        """List all available backup files in storage."""
        
        logger.info("Listing available DNS backup files")
        backups = []
        
        try:
            bucket = self.storage_client.bucket(self.backup_bucket)
            
            for blob in bucket.list_blobs(prefix=f"dns-backup-{self.environment}"):
                if blob.name.endswith('.yaml'):
                    backup_info = {
                        'name': blob.name,
                        'created': blob.time_created.isoformat(),
                        'size': blob.size,
                        'metadata': blob.metadata or {},
                        'storage_path': f"gs://{self.backup_bucket}/{blob.name}"
                    }
                    backups.append(backup_info)
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x['created'], reverse=True)
            
            logger.info(f"Found {len(backups)} available backup files")
            
        except Exception as e:
            logger.error(f"Error listing backup files: {e}")
            raise
        
        return backups
    
    def load_backup_data(self, backup_path: Optional[str] = None) -> Dict[str, Any]:
        """Load backup data from storage."""
        
        if not backup_path:
            # Use latest backup
            backup_path = f"latest/{self.environment}-dns-backup-latest.yaml"
            logger.info(f"Using latest backup: {backup_path}")
        else:
            logger.info(f"Loading backup from: {backup_path}")
        
        try:
            bucket = self.storage_client.bucket(self.backup_bucket)
            blob = bucket.blob(backup_path)
            
            if not blob.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
            # Download and parse YAML content
            yaml_content = blob.download_as_text()
            backup_data = yaml.safe_load(yaml_content)
            
            logger.info(f"Loaded backup data: {backup_data['backup_metadata']['backup_id']}")
            return backup_data
            
        except Exception as e:
            logger.error(f"Error loading backup data: {e}")
            raise
    
    def validate_backup_data(self, backup_data: Dict[str, Any]) -> bool:
        """Validate backup data structure and completeness."""
        
        logger.info("Validating backup data")
        
        try:
            # Check required metadata
            metadata = backup_data.get('backup_metadata', {})
            required_fields = ['backup_id', 'timestamp', 'project_id', 'backup_version']
            
            for field in required_fields:
                if field not in metadata:
                    raise ValueError(f"Missing required metadata field: {field}")
            
            # Check if backup failed
            if metadata.get('backup_failed', False):
                raise ValueError(f"Backup data indicates failure: {metadata.get('error', 'Unknown error')}")
            
            # Check zones data
            if 'zones' not in backup_data or not isinstance(backup_data['zones'], list):
                raise ValueError("Invalid or missing zones data")
            
            if 'zone_records' not in backup_data or not isinstance(backup_data['zone_records'], dict):
                raise ValueError("Invalid or missing zone records data")
            
            zones_count = len(backup_data['zones'])
            records_count = sum(
                len(records) for records in backup_data['zone_records'].values()
                if isinstance(records, list)
            )
            
            logger.info(f"Backup validation successful: {zones_count} zones, {records_count} records")
            return True
            
        except Exception as e:
            logger.error(f"Backup validation failed: {e}")
            return False
    
    def create_dns_zone(self, zone_data: Dict[str, Any]) -> bool:
        """Create a DNS zone from backup data."""
        
        zone_name = zone_data['name']
        logger.info(f"Creating DNS zone: {zone_name}")
        
        try:
            # Check if zone already exists
            try:
                existing_zone = self.dns_client.zone(zone_name)
                if existing_zone.exists():
                    logger.warning(f"Zone {zone_name} already exists, skipping creation")
                    return True
            except:
                pass  # Zone doesn't exist, proceed with creation
            
            # Create new zone
            zone = self.dns_client.zone(
                name=zone_name,
                dns_name=zone_data['dns_name'],
                description=zone_data.get('description', f"Restored zone for {zone_name}")
            )
            
            zone.create()
            logger.info(f"Successfully created zone: {zone_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating zone {zone_name}: {e}")
            return False
    
    def restore_zone_records(self, zone_name: str, records_data: List[Dict[str, Any]]) -> int:
        """Restore DNS records for a specific zone."""
        
        logger.info(f"Restoring records for zone: {zone_name}")
        restored_count = 0
        
        try:
            zone = self.dns_client.zone(zone_name)
            
            if not zone.exists():
                logger.error(f"Zone {zone_name} does not exist, cannot restore records")
                return 0
            
            for record_data in records_data:
                try:
                    # Skip default NS and SOA records (they're managed by Google)
                    if record_data['record_type'] in ['NS', 'SOA'] and record_data['name'] == zone.dns_name:
                        continue
                    
                    # Create record set
                    record = zone.resource_record_set(
                        name=record_data['name'],
                        record_type=record_data['record_type'],
                        ttl=record_data['ttl'],
                        rrdatas=record_data['rrdatas']
                    )
                    
                    # Check if record already exists
                    try:
                        if record.exists():
                            logger.warning(f"Record {record_data['name']} ({record_data['record_type']}) already exists, skipping")
                            continue
                    except:
                        pass  # Record doesn't exist, proceed with creation
                    
                    record.create()
                    restored_count += 1
                    logger.debug(f"Restored record: {record_data['name']} ({record_data['record_type']})")
                    
                except Exception as e:
                    logger.error(f"Error restoring record {record_data['name']} ({record_data['record_type']}): {e}")
                    continue
            
            logger.info(f"Successfully restored {restored_count} records for zone {zone_name}")
            
        except Exception as e:
            logger.error(f"Error restoring records for zone {zone_name}: {e}")
        
        return restored_count
    
    def perform_full_restore(self, backup_data: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        """Perform a complete DNS restore from backup data."""
        
        logger.info(f"Starting full DNS restore (dry_run={dry_run})")
        
        restore_results = {
            'restore_id': f"restore-{int(time.time())}",
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dry_run': dry_run,
            'zones_processed': 0,
            'zones_created': 0,
            'zones_failed': 0,
            'records_restored': 0,
            'records_failed': 0,
            'errors': []
        }
        
        try:
            zones_data = backup_data['zones']
            records_data = backup_data['zone_records']
            
            for zone_data in zones_data:
                zone_name = zone_data['name']
                restore_results['zones_processed'] += 1
                
                try:
                    if not dry_run:
                        # Create zone if it doesn't exist
                        if self.create_dns_zone(zone_data):
                            restore_results['zones_created'] += 1
                        
                        # Restore records for this zone
                        if zone_name in records_data and isinstance(records_data[zone_name], list):
                            restored_count = self.restore_zone_records(zone_name, records_data[zone_name])
                            restore_results['records_restored'] += restored_count
                        else:
                            logger.warning(f"No records data found for zone {zone_name}")
                    else:
                        logger.info(f"DRY RUN: Would restore zone {zone_name} with {len(records_data.get(zone_name, []))} records")
                        restore_results['zones_created'] += 1
                        restore_results['records_restored'] += len(records_data.get(zone_name, []))
                        
                except Exception as e:
                    error_msg = f"Failed to restore zone {zone_name}: {str(e)}"
                    logger.error(error_msg)
                    restore_results['zones_failed'] += 1
                    restore_results['errors'].append(error_msg)
            
            # Calculate success rate
            total_zones = restore_results['zones_processed']
            successful_zones = restore_results['zones_created']
            
            if total_zones > 0:
                restore_results['success_rate'] = (successful_zones / total_zones) * 100
            else:
                restore_results['success_rate'] = 0
            
            logger.info(f"DNS restore completed: {successful_zones}/{total_zones} zones, "
                       f"{restore_results['records_restored']} records, "
                       f"{restore_results['success_rate']:.1f}% success rate")
            
        except Exception as e:
            error_msg = f"Critical error during DNS restore: {str(e)}"
            logger.error(error_msg)
            restore_results['errors'].append(error_msg)
            restore_results['restore_failed'] = True
        
        return restore_results
    
    def send_restore_metrics(self, restore_results: Dict[str, Any]):
        """Send restore metrics to Cloud Monitoring."""
        
        try:
            project_name = f"projects/{self.project_id}"
            
            # Restore success metric
            success = not restore_results.get('restore_failed', False) and restore_results.get('success_rate', 0) > 0
            
            series = monitoring_v3.TimeSeries({
                'metric': {
                    'type': 'custom.googleapis.com/dns/restore_success',
                    'labels': {
                        'environment': self.environment,
                        'restore_id': restore_results['restore_id']
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
                        'double_value': 1.0 if success else 0.0
                    }
                }]
            })
            
            # Zones restored metric
            zones_series = monitoring_v3.TimeSeries({
                'metric': {
                    'type': 'custom.googleapis.com/dns/restore_zones_count',
                    'labels': {
                        'environment': self.environment
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
                        'double_value': float(restore_results['zones_created'])
                    }
                }]
            })
            
            self.monitoring_client.create_time_series(
                name=project_name,
                time_series=[series, zones_series]
            )
            
            logger.info("Restore metrics sent to Cloud Monitoring")
            
        except Exception as e:
            logger.error(f"Failed to send restore metrics: {e}")


@functions_framework.http
def dns_restore_cloud_function(request):
    """Cloud Function entry point for DNS restore operations."""
    
    logger.info("DNS restore Cloud Function triggered")
    
    try:
        # Parse request data
        request_json = request.get_json(silent=True) or {}
        backup_path = request_json.get('backup_path')  # Optional specific backup
        dry_run = request_json.get('dry_run', True)  # Default to dry run for safety
        force_restore = request_json.get('force_restore', False)
        
        logger.info(f"Starting DNS restore (dry_run={dry_run}, force_restore={force_restore})")
        
        if not dry_run and not force_restore:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'status': 'error',
                    'message': 'Real restore requires force_restore=true parameter for safety'
                })
            }
        
        # Initialize restore manager
        restore_manager = DNSRestoreManager()
        
        # Load backup data
        backup_data = restore_manager.load_backup_data(backup_path)
        
        # Validate backup data
        if not restore_manager.validate_backup_data(backup_data):
            raise ValueError("Backup data validation failed")
        
        # Perform restore
        restore_results = restore_manager.perform_full_restore(backup_data, dry_run=dry_run)
        
        # Send metrics
        restore_manager.send_restore_metrics(restore_results)
        
        # Return results
        response_data = {
            'status': 'success',
            'message': 'DNS restore completed successfully' if not dry_run else 'DNS restore dry run completed',
            'restore_results': restore_results,
            'backup_used': backup_data['backup_metadata']['backup_id']
        }
        
        logger.info(f"DNS restore completed: {response_data}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(response_data, default=str)
        }
        
    except Exception as e:
        logger.error(f"DNS restore failed: {e}")
        
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'status': 'error',
                'message': 'DNS restore failed',
                'error': str(e)
            })
        }


if __name__ == '__main__':
    # Test the restore function locally
    import sys
    
    # Set environment variables for testing
    os.environ.setdefault('PROJECT_ID', 'isectech-security-platform')
    os.environ.setdefault('ENVIRONMENT', 'development')
    os.environ.setdefault('BACKUP_BUCKET', 'isectech-development-dns-backups')
    
    try:
        restore_manager = DNSRestoreManager()
        
        # List available backups
        backups = restore_manager.list_available_backups()
        print(f"Available backups: {len(backups)}")
        
        if backups:
            # Test restore with latest backup (dry run)
            backup_data = restore_manager.load_backup_data()
            
            if restore_manager.validate_backup_data(backup_data):
                restore_results = restore_manager.perform_full_restore(backup_data, dry_run=True)
                print(json.dumps(restore_results, indent=2))
                print(f"\nDry run restore completed successfully!")
            else:
                print("Backup data validation failed")
        else:
            print("No backup files found")
        
    except Exception as e:
        print(f"Restore test failed: {e}")
        sys.exit(1)