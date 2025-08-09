#!/usr/bin/env python3
"""
iSECTECH DNS Backup Cloud Function
Production-grade DNS configuration backup and versioning system
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

class DNSBackupManager:
    """Production-grade DNS configuration backup manager."""
    
    def __init__(self):
        self.project_id = os.environ.get('PROJECT_ID')
        self.environment = os.environ.get('ENVIRONMENT', 'production')
        self.backup_bucket = os.environ.get('BACKUP_BUCKET')
        self.retention_days = int(os.environ.get('RETENTION_DAYS', '90'))
        
        # Initialize Google Cloud clients
        self.dns_client = dns.Client(project=self.project_id)
        self.storage_client = storage.Client(project=self.project_id)
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        
        # Backup configuration
        self.backup_prefix = f"dns-backup-{self.environment}"
        self.backup_format = "yaml"  # YAML for human readability
        
        logger.info(f"DNS Backup Manager initialized for project {self.project_id} environment {self.environment}")
    
    def list_dns_zones(self) -> List[Dict[str, Any]]:
        """List all DNS managed zones in the project."""
        
        logger.info("Listing DNS managed zones")
        zones = []
        
        try:
            for zone in self.dns_client.list_zones():
                zone_info = {
                    'name': zone.name,
                    'dns_name': zone.dns_name,
                    'description': zone.description,
                    'creation_time': zone.created.isoformat() if zone.created else None,
                    'visibility': getattr(zone, 'visibility', 'public'),
                    'dnssec_config': self._get_dnssec_config(zone),
                    'name_servers': list(zone.name_servers) if zone.name_servers else []
                }
                zones.append(zone_info)
                logger.info(f"Found zone: {zone.name} ({zone.dns_name})")
                
        except Exception as e:
            logger.error(f"Error listing DNS zones: {e}")
            raise
        
        logger.info(f"Found {len(zones)} DNS zones")
        return zones
    
    def _get_dnssec_config(self, zone) -> Dict[str, Any]:
        """Extract DNSSEC configuration from zone."""
        
        try:
            if hasattr(zone, 'dnssec_config') and zone.dnssec_config:
                return {
                    'state': zone.dnssec_config.get('state', 'off'),
                    'non_existence': zone.dnssec_config.get('non_existence', 'nsec3'),
                    'key_specs': zone.dnssec_config.get('default_key_specs', [])
                }
        except Exception as e:
            logger.warning(f"Could not get DNSSEC config for zone {zone.name}: {e}")
        
        return {'state': 'off'}
    
    def backup_zone_records(self, zone_name: str) -> List[Dict[str, Any]]:
        """Backup all records for a specific DNS zone."""
        
        logger.info(f"Backing up records for zone: {zone_name}")
        records = []
        
        try:
            zone = self.dns_client.zone(zone_name)
            
            for record in zone.list_resource_record_sets():
                record_info = {
                    'name': record.name,
                    'record_type': record.record_type,
                    'ttl': record.ttl,
                    'rrdatas': list(record.rrdatas) if record.rrdatas else [],
                    'created': datetime.now(timezone.utc).isoformat()
                }
                
                # Add routing policy if exists
                if hasattr(record, 'routing_policy') and record.routing_policy:
                    record_info['routing_policy'] = record.routing_policy
                
                records.append(record_info)
                
        except Exception as e:
            logger.error(f"Error backing up records for zone {zone_name}: {e}")
            raise
        
        logger.info(f"Backed up {len(records)} records for zone {zone_name}")
        return records
    
    def create_full_backup(self) -> Dict[str, Any]:
        """Create a complete backup of all DNS zones and records."""
        
        logger.info("Creating full DNS backup")
        backup_timestamp = datetime.now(timezone.utc)
        
        backup_data = {
            'backup_metadata': {
                'backup_id': f"{self.backup_prefix}-{int(backup_timestamp.timestamp())}",
                'timestamp': backup_timestamp.isoformat(),
                'project_id': self.project_id,
                'environment': self.environment,
                'backup_type': 'full',
                'backup_version': '2.0',
                'backup_format': self.backup_format
            },
            'zones': [],
            'zone_records': {}
        }
        
        try:
            # Backup all zones
            zones = self.list_dns_zones()
            backup_data['zones'] = zones
            
            # Backup records for each zone
            for zone in zones:
                zone_name = zone['name']
                logger.info(f"Backing up records for zone: {zone_name}")
                
                try:
                    records = self.backup_zone_records(zone_name)
                    backup_data['zone_records'][zone_name] = records
                    
                except Exception as e:
                    logger.error(f"Failed to backup records for zone {zone_name}: {e}")
                    # Continue with other zones even if one fails
                    backup_data['zone_records'][zone_name] = {
                        'error': str(e),
                        'backup_failed': True
                    }
            
            backup_data['backup_metadata']['zones_count'] = len(zones)
            backup_data['backup_metadata']['total_records'] = sum(
                len(records) for records in backup_data['zone_records'].values() 
                if isinstance(records, list)
            )
            
            logger.info(f"Full backup completed: {backup_data['backup_metadata']['zones_count']} zones, "
                       f"{backup_data['backup_metadata']['total_records']} records")
            
        except Exception as e:
            logger.error(f"Error creating full backup: {e}")
            backup_data['backup_metadata']['backup_failed'] = True
            backup_data['backup_metadata']['error'] = str(e)
            raise
        
        return backup_data
    
    def save_backup_to_storage(self, backup_data: Dict[str, Any]) -> str:
        """Save backup data to Google Cloud Storage."""
        
        backup_id = backup_data['backup_metadata']['backup_id']
        timestamp = datetime.now(timezone.utc).strftime('%Y/%m/%d')
        
        try:
            bucket = self.storage_client.bucket(self.backup_bucket)
            
            # Create timestamped folder structure
            blob_name = f"{timestamp}/{backup_id}.yaml"
            blob = bucket.blob(blob_name)
            
            # Convert to YAML for better human readability
            yaml_content = yaml.dump(backup_data, default_flow_style=False, sort_keys=False)
            
            blob.upload_from_string(
                yaml_content,
                content_type='application/x-yaml'
            )
            
            # Set metadata
            blob.metadata = {
                'backup_id': backup_id,
                'environment': self.environment,
                'backup_type': backup_data['backup_metadata']['backup_type'],
                'zones_count': str(backup_data['backup_metadata'].get('zones_count', 0)),
                'total_records': str(backup_data['backup_metadata'].get('total_records', 0))
            }
            blob.patch()
            
            storage_path = f"gs://{self.backup_bucket}/{blob_name}"
            logger.info(f"Backup saved to: {storage_path}")
            
            # Also save a latest symlink for easy access
            latest_blob_name = f"latest/{self.environment}-dns-backup-latest.yaml"
            latest_blob = bucket.blob(latest_blob_name)
            latest_blob.upload_from_string(yaml_content, content_type='application/x-yaml')
            
            return storage_path
            
        except Exception as e:
            logger.error(f"Failed to save backup to storage: {e}")
            raise
    
    def cleanup_old_backups(self):
        """Clean up old backup files based on retention policy."""
        
        logger.info(f"Cleaning up backups older than {self.retention_days} days")
        
        try:
            bucket = self.storage_client.bucket(self.backup_bucket)
            cutoff_time = time.time() - (self.retention_days * 24 * 60 * 60)
            
            deleted_count = 0
            for blob in bucket.list_blobs(prefix=f"{self.backup_prefix}"):
                if blob.time_created.timestamp() < cutoff_time:
                    logger.info(f"Deleting old backup: {blob.name}")
                    blob.delete()
                    deleted_count += 1
            
            logger.info(f"Cleaned up {deleted_count} old backup files")
            
        except Exception as e:
            logger.error(f"Error cleaning up old backups: {e}")
    
    def send_backup_metrics(self, backup_data: Dict[str, Any], success: bool):
        """Send backup metrics to Cloud Monitoring."""
        
        try:
            project_name = f"projects/{self.project_id}"
            
            # Backup success metric
            series = monitoring_v3.TimeSeries({
                'metric': {
                    'type': 'custom.googleapis.com/dns/backup_success',
                    'labels': {
                        'environment': self.environment,
                        'backup_id': backup_data['backup_metadata']['backup_id']
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
            
            # Zones backed up metric
            if success and 'zones_count' in backup_data['backup_metadata']:
                zones_series = monitoring_v3.TimeSeries({
                    'metric': {
                        'type': 'custom.googleapis.com/dns/backup_zones_count',
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
                            'double_value': float(backup_data['backup_metadata']['zones_count'])
                        }
                    }]
                })
                
                self.monitoring_client.create_time_series(
                    name=project_name,
                    time_series=[series, zones_series]
                )
            else:
                self.monitoring_client.create_time_series(
                    name=project_name,
                    time_series=[series]
                )
            
            logger.info("Backup metrics sent to Cloud Monitoring")
            
        except Exception as e:
            logger.error(f"Failed to send backup metrics: {e}")


@functions_framework.http
def dns_backup_cloud_function(request):
    """Cloud Function entry point for DNS backup operations."""
    
    logger.info("DNS backup Cloud Function triggered")
    
    try:
        # Parse request data
        request_json = request.get_json(silent=True) or {}
        backup_type = request_json.get('backup_type', 'manual')
        full_backup = request_json.get('full_backup', True)
        
        logger.info(f"Starting {backup_type} DNS backup (full_backup={full_backup})")
        
        # Initialize backup manager
        backup_manager = DNSBackupManager()
        
        # Create backup
        backup_data = backup_manager.create_full_backup()
        
        # Save to storage
        storage_path = backup_manager.save_backup_to_storage(backup_data)
        
        # Clean up old backups
        backup_manager.cleanup_old_backups()
        
        # Send success metrics
        backup_manager.send_backup_metrics(backup_data, success=True)
        
        # Return success response
        response_data = {
            'status': 'success',
            'message': 'DNS backup completed successfully',
            'backup_id': backup_data['backup_metadata']['backup_id'],
            'storage_path': storage_path,
            'zones_backed_up': backup_data['backup_metadata'].get('zones_count', 0),
            'records_backed_up': backup_data['backup_metadata'].get('total_records', 0),
            'timestamp': backup_data['backup_metadata']['timestamp']
        }
        
        logger.info(f"DNS backup completed successfully: {response_data}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(response_data)
        }
        
    except Exception as e:
        logger.error(f"DNS backup failed: {e}")
        
        # Send failure metrics
        try:
            backup_manager = DNSBackupManager()
            failure_backup_data = {
                'backup_metadata': {
                    'backup_id': f"failed-{int(time.time())}",
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'backup_failed': True,
                    'error': str(e)
                }
            }
            backup_manager.send_backup_metrics(failure_backup_data, success=False)
        except:
            pass  # Don't fail on metrics failure
        
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'status': 'error',
                'message': 'DNS backup failed',
                'error': str(e)
            })
        }


if __name__ == '__main__':
    # Test the backup function locally
    import sys
    
    # Set environment variables for testing
    os.environ.setdefault('PROJECT_ID', 'isectech-security-platform')
    os.environ.setdefault('ENVIRONMENT', 'development')
    os.environ.setdefault('BACKUP_BUCKET', 'isectech-development-dns-backups')
    os.environ.setdefault('RETENTION_DAYS', '30')
    
    try:
        backup_manager = DNSBackupManager()
        backup_data = backup_manager.create_full_backup()
        
        print(json.dumps(backup_data, indent=2))
        print(f"\nBackup completed successfully!")
        
    except Exception as e:
        print(f"Backup failed: {e}")
        sys.exit(1)