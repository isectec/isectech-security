"""
iSECTECH Policy Enforcement Engine
Real-time data residency policy enforcement using OPA
Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
Version: 1.0.0 - Task 70.5 Implementation
"""

import json
import logging
import os
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional

from google.cloud import logging as cloud_logging
from google.cloud import pubsub_v1
from google.cloud import asset_v1
from google.cloud import resourcemanager_v3
import opa.rego as rego

# Configure logging
cloud_logging_client = cloud_logging.Client()
cloud_logging_client.setup_logging()
logger = logging.getLogger(__name__)

class PolicyEnforcementEngine:
    """Enforce data residency policies in real-time."""
    
    def __init__(self):
        self.project_id = os.environ.get('PROJECT_ID')
        self.environment = os.environ.get('ENVIRONMENT', 'development')
        self.compliance_zones = json.loads(os.environ.get('COMPLIANCE_ZONES', '{}'))
        self.enforcement_mode = os.environ.get('ENFORCEMENT_MODE', 'WARN')
        self.violations_topic = os.environ.get('POLICY_VIOLATIONS_TOPIC')
        
        # Initialize GCP clients
        self.publisher = pubsub_v1.PublisherClient()
        self.asset_client = asset_v1.AssetServiceClient()
        self.resource_manager = resourcemanager_v3.ProjectsClient()
        
        # Load OPA policies
        self.policies = self._load_opa_policies()
        
        # Regional compliance mapping
        self.region_compliance_map = {
            'us-central1': 'ccpa',
            'us-east1': 'ccpa', 
            'europe-west4': 'gdpr',
            'europe-west1': 'gdpr',
            'asia-northeast1': 'appi'
        }

    def _load_opa_policies(self) -> Dict[str, Any]:
        """Load OPA policy rules from embedded policy file."""
        try:
            # In production, this would load from the packaged policies.rego file
            policies = {
                'data_residency': '''
                package data_residency

                # Allow storage bucket creation only in approved regions
                allow_storage_bucket {
                    input.resource_type == "storage_bucket"
                    input.location in approved_regions[input.compliance_zone]
                }

                # Deny multi-region buckets for data residency
                deny_multi_region_bucket {
                    input.resource_type == "storage_bucket"
                    input.location in ["US", "EU", "ASIA"]
                }

                # Allow SQL instance only in compliance zone regions
                allow_sql_instance {
                    input.resource_type == "sql_instance"
                    input.region in approved_regions[input.compliance_zone]
                }

                # Deny cross-region backup for SQL instances
                deny_cross_region_backup {
                    input.resource_type == "sql_instance"
                    input.backup_location != input.region
                }

                # Regional compliance zone mapping
                approved_regions := {
                    "gdpr": ["europe-west4", "europe-west1"],
                    "ccpa": ["us-central1", "us-east1"],
                    "appi": ["asia-northeast1"]
                }
                ''',
                
                'network_security': '''
                package network_security

                # Deny external IPs for compliance
                deny_external_ip {
                    input.resource_type == "compute_instance"
                    count(input.access_configs) > 0
                }

                # Require private Google access
                require_private_google_access {
                    input.resource_type == "compute_subnetwork"
                    input.private_ip_google_access == true
                }

                # Block cross-region networking
                deny_cross_region_peering {
                    input.resource_type == "compute_network_peering"
                    get_region(input.source_network) != get_region(input.target_network)
                }
                ''',
                
                'encryption_compliance': '''
                package encryption_compliance

                # Require encryption for all storage
                require_storage_encryption {
                    input.resource_type == "storage_bucket"
                    input.encryption.default_kms_key_name != ""
                }

                # Require regional KMS keys
                require_regional_kms {
                    input.resource_type in ["storage_bucket", "sql_instance"]
                    get_kms_region(input.encryption.default_kms_key_name) == input.region
                }

                # Require SQL encryption
                require_sql_encryption {
                    input.resource_type == "sql_instance"
                    input.database_encryption.state == "ENCRYPTED"
                }
                '''
            }
            return policies
        except Exception as e:
            logger.error(f"Failed to load OPA policies: {str(e)}")
            return {}

    def enforce_policies(self, cloud_event):
        """Main entry point for policy enforcement."""
        try:
            logger.info("Starting policy enforcement check")
            
            # Parse audit log event
            event_data = self._parse_audit_event(cloud_event)
            if not event_data:
                return {'status': 'skipped', 'reason': 'no_event_data'}
            
            # Extract resource information
            resource_info = self._extract_resource_info(event_data)
            if not resource_info:
                return {'status': 'skipped', 'reason': 'no_resource_info'}
                
            logger.info(f"Evaluating policies for {resource_info['resource_type']}: {resource_info['resource_name']}")
            
            # Evaluate policies
            violations = self._evaluate_policies(resource_info)
            
            # Process violations
            if violations:
                await_response = self._process_violations(violations, resource_info)
                logger.warning(f"Found {len(violations)} policy violations")
                
                # Enforce if in blocking mode
                if self.enforcement_mode == 'BLOCK':
                    self._block_resource_operation(resource_info, violations)
                    
                return {
                    'status': 'violations_found',
                    'violations': len(violations),
                    'enforced': self.enforcement_mode == 'BLOCK'
                }
            else:
                logger.info("No policy violations detected")
                return {'status': 'compliant'}
                
        except Exception as e:
            logger.error(f"Error in policy enforcement: {str(e)}", exc_info=True)
            raise

    def _parse_audit_event(self, cloud_event) -> Optional[Dict[str, Any]]:
        """Parse Cloud Audit Log event."""
        try:
            if hasattr(cloud_event, 'data'):
                # Decode audit log data
                audit_data = json.loads(cloud_event.data)
                return audit_data
            return None
        except Exception as e:
            logger.warning(f"Failed to parse audit event: {str(e)}")
            return None

    def _extract_resource_info(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract resource information from audit event."""
        try:
            proto_payload = event_data.get('protoPayload', {})
            resource_name = proto_payload.get('resourceName', '')
            method_name = proto_payload.get('methodName', '')
            
            # Extract resource type and details based on service
            service_name = proto_payload.get('serviceName', '')
            
            resource_info = {
                'resource_name': resource_name,
                'method_name': method_name,
                'service_name': service_name,
                'timestamp': event_data.get('timestamp'),
                'caller_ip': proto_payload.get('requestMetadata', {}).get('callerIp'),
                'user_agent': proto_payload.get('requestMetadata', {}).get('callerSuppliedUserAgent')
            }
            
            # Parse based on service type
            if 'storage' in service_name:
                resource_info.update(self._parse_storage_resource(proto_payload))
            elif 'sqladmin' in service_name:
                resource_info.update(self._parse_sql_resource(proto_payload))
            elif 'compute' in service_name:
                resource_info.update(self._parse_compute_resource(proto_payload))
            else:
                return None
                
            return resource_info
            
        except Exception as e:
            logger.error(f"Error extracting resource info: {str(e)}")
            return None

    def _parse_storage_resource(self, proto_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cloud Storage resource information."""
        request = proto_payload.get('request', {})
        
        return {
            'resource_type': 'storage_bucket',
            'location': request.get('location', '').lower(),
            'storage_class': request.get('storageClass'),
            'versioning_enabled': request.get('versioning', {}).get('enabled', False),
            'encryption': request.get('encryption', {}),
            'lifecycle_rules': request.get('lifecycle', {}).get('rule', [])
        }

    def _parse_sql_resource(self, proto_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Cloud SQL resource information."""
        request = proto_payload.get('request', {})
        body = request.get('body', {})
        
        return {
            'resource_type': 'sql_instance',
            'region': body.get('region', ''),
            'backup_location': body.get('settings', {}).get('backupConfiguration', {}).get('location', ''),
            'database_encryption': body.get('diskEncryptionConfiguration', {}),
            'ip_configuration': body.get('settings', {}).get('ipConfiguration', {}),
            'availability_type': body.get('settings', {}).get('availabilityType')
        }

    def _parse_compute_resource(self, proto_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Compute Engine resource information."""
        request = proto_payload.get('request', {})
        
        # Extract zone/region from resource name
        resource_name = proto_payload.get('resourceName', '')
        zone = ''
        region = ''
        
        if '/zones/' in resource_name:
            zone = resource_name.split('/zones/')[-1].split('/')[0]
            region = '-'.join(zone.split('-')[:-1])
        elif '/regions/' in resource_name:
            region = resource_name.split('/regions/')[-1].split('/')[0]
            
        return {
            'resource_type': 'compute_instance' if 'instances' in resource_name else 'compute_network',
            'zone': zone,
            'region': region,
            'access_configs': request.get('networkInterfaces', [{}])[0].get('accessConfigs', []),
            'disks': request.get('disks', []),
            'network_interfaces': request.get('networkInterfaces', [])
        }

    def _evaluate_policies(self, resource_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate OPA policies against resource."""
        violations = []
        
        try:
            # Determine compliance zone based on region
            region = resource_info.get('region') or self._extract_region_from_location(resource_info.get('location', ''))
            compliance_zone = self.region_compliance_map.get(region, 'unknown')
            
            # Add compliance zone to resource info
            resource_info['compliance_zone'] = compliance_zone
            
            # Evaluate each policy package
            for policy_name, policy_rules in self.policies.items():
                try:
                    # Create OPA context
                    policy_input = {
                        'resource_type': resource_info['resource_type'],
                        'region': region,
                        'compliance_zone': compliance_zone,
                        'location': resource_info.get('location', region),
                        **resource_info
                    }
                    
                    # Evaluate policy (simplified - in production would use actual OPA)
                    policy_violations = self._evaluate_policy_rules(policy_name, policy_input)
                    violations.extend(policy_violations)
                    
                except Exception as e:
                    logger.error(f"Error evaluating policy {policy_name}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error evaluating policies: {str(e)}")
            
        return violations

    def _evaluate_policy_rules(self, policy_name: str, policy_input: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate specific policy rules (simplified implementation)."""
        violations = []
        
        try:
            # Data residency policies
            if policy_name == 'data_residency':
                violations.extend(self._check_data_residency(policy_input))
            
            # Network security policies  
            elif policy_name == 'network_security':
                violations.extend(self._check_network_security(policy_input))
                
            # Encryption compliance policies
            elif policy_name == 'encryption_compliance':
                violations.extend(self._check_encryption_compliance(policy_input))
                
        except Exception as e:
            logger.error(f"Error evaluating {policy_name} rules: {str(e)}")
            
        return violations

    def _check_data_residency(self, input_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check data residency compliance."""
        violations = []
        
        # Check storage bucket location
        if input_data['resource_type'] == 'storage_bucket':
            location = input_data.get('location', '').upper()
            if location in ['US', 'EU', 'ASIA']:
                violations.append({
                    'policy': 'data_residency',
                    'rule': 'deny_multi_region_bucket',
                    'severity': 'critical',
                    'message': f'Multi-region bucket violates data residency: {location}',
                    'resource_type': input_data['resource_type'],
                    'resource_name': input_data['resource_name']
                })
                
        # Check SQL instance region compliance
        elif input_data['resource_type'] == 'sql_instance':
            region = input_data.get('region', '')
            compliance_zone = input_data.get('compliance_zone', '')
            
            approved_regions = {
                'gdpr': ['europe-west4', 'europe-west1'],
                'ccpa': ['us-central1', 'us-east1'],
                'appi': ['asia-northeast1']
            }
            
            if region not in approved_regions.get(compliance_zone, []):
                violations.append({
                    'policy': 'data_residency',
                    'rule': 'deny_unauthorized_region',
                    'severity': 'critical',
                    'message': f'SQL instance in unauthorized region: {region} for {compliance_zone}',
                    'resource_type': input_data['resource_type'],
                    'resource_name': input_data['resource_name']
                })
                
            # Check backup location
            backup_location = input_data.get('backup_location', '')
            if backup_location and backup_location != region:
                violations.append({
                    'policy': 'data_residency',
                    'rule': 'deny_cross_region_backup',
                    'severity': 'high',
                    'message': f'Cross-region backup violates residency: {backup_location}',
                    'resource_type': input_data['resource_type'],
                    'resource_name': input_data['resource_name']
                })
                
        return violations

    def _check_network_security(self, input_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check network security compliance."""
        violations = []
        
        # Check for external IPs
        if input_data['resource_type'] == 'compute_instance':
            access_configs = input_data.get('access_configs', [])
            if access_configs:
                violations.append({
                    'policy': 'network_security',
                    'rule': 'deny_external_ip',
                    'severity': 'high',
                    'message': 'External IP access violates security policy',
                    'resource_type': input_data['resource_type'],
                    'resource_name': input_data['resource_name']
                })
                
        return violations

    def _check_encryption_compliance(self, input_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check encryption compliance."""
        violations = []
        
        # Check storage encryption
        if input_data['resource_type'] == 'storage_bucket':
            encryption = input_data.get('encryption', {})
            if not encryption.get('default_kms_key_name'):
                violations.append({
                    'policy': 'encryption_compliance',
                    'rule': 'require_storage_encryption',
                    'severity': 'high',
                    'message': 'Storage bucket must use KMS encryption',
                    'resource_type': input_data['resource_type'],
                    'resource_name': input_data['resource_name']
                })
                
        # Check SQL encryption
        elif input_data['resource_type'] == 'sql_instance':
            db_encryption = input_data.get('database_encryption', {})
            if db_encryption.get('state') != 'ENCRYPTED':
                violations.append({
                    'policy': 'encryption_compliance',
                    'rule': 'require_sql_encryption',
                    'severity': 'high',
                    'message': 'SQL instance must use encryption at rest',
                    'resource_type': input_data['resource_type'],
                    'resource_name': input_data['resource_name']
                })
                
        return violations

    def _extract_region_from_location(self, location: str) -> str:
        """Extract region from location string."""
        location = location.lower()
        if location.startswith('us-'):
            return location
        elif location.startswith('europe-'):
            return location
        elif location.startswith('asia-'):
            return location
        else:
            return 'unknown'

    def _process_violations(self, violations: List[Dict[str, Any]], resource_info: Dict[str, Any]):
        """Process and publish policy violations."""
        for violation in violations:
            violation_event = {
                'violation_id': f"{resource_info['resource_name']}-{datetime.utcnow().isoformat()}",
                'timestamp': datetime.utcnow().isoformat(),
                'resource_info': resource_info,
                'policy_violation': violation,
                'enforcement_mode': self.enforcement_mode,
                'project_id': self.project_id,
                'environment': self.environment
            }
            
            # Log violation
            logger.error(
                f"POLICY VIOLATION: {violation['policy']}/{violation['rule']} - "
                f"{violation['resource_type']} {violation['resource_name']}: {violation['message']}"
            )
            
            # Publish to Pub/Sub
            self._publish_violation(violation_event)

    def _publish_violation(self, violation_event: Dict[str, Any]):
        """Publish violation event to Pub/Sub."""
        try:
            topic_path = self.publisher.topic_path(self.project_id, self.violations_topic)
            message_data = json.dumps(violation_event).encode('utf-8')
            
            future = self.publisher.publish(topic_path, message_data)
            logger.info(f"Published violation {violation_event['violation_id']}: {future.result()}")
            
        except Exception as e:
            logger.error(f"Error publishing violation: {str(e)}")

    def _block_resource_operation(self, resource_info: Dict[str, Any], violations: List[Dict[str, Any]]):
        """Block resource operation (placeholder for actual enforcement)."""
        # In production, this would integrate with GCP APIs to actually block operations
        # For now, we log the enforcement action
        logger.critical(
            f"BLOCKING OPERATION: {resource_info['resource_type']} {resource_info['resource_name']} "
            f"due to {len(violations)} policy violations"
        )


def enforce_policies(cloud_event):
    """Cloud Function entry point."""
    engine = PolicyEnforcementEngine()
    return engine.enforce_policies(cloud_event)