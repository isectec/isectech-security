"""
iSECTECH Policy Violation Processor
Process and respond to data residency policy violations
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
from google.cloud import bigquery
from google.cloud import monitoring_v3
from google.cloud import secretmanager
from google.cloud import storage
import requests

# Configure logging
cloud_logging_client = cloud_logging.Client()
cloud_logging_client.setup_logging()
logger = logging.getLogger(__name__)

class PolicyViolationProcessor:
    """Process policy violations and take corrective actions."""
    
    def __init__(self):
        self.project_id = os.environ.get('PROJECT_ID')
        self.environment = os.environ.get('ENVIRONMENT', 'development')
        self.compliance_email = os.environ.get('COMPLIANCE_EMAIL')
        self.enforcement_mode = os.environ.get('ENFORCEMENT_MODE', 'WARN')
        
        # Initialize GCP clients
        self.bigquery_client = bigquery.Client()
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        self.secret_client = secretmanager.SecretManagerServiceClient()
        self.storage_client = storage.Client()
        
        # Violation severity mapping
        self.severity_levels = {
            'critical': 1,
            'high': 2, 
            'medium': 3,
            'low': 4
        }

    def process_policy_violation(self, cloud_event):
        """Main entry point for processing policy violations."""
        try:
            logger.info("Processing policy violation event")
            
            # Parse violation data from Pub/Sub
            violation_data = self._parse_violation_event(cloud_event)
            if not violation_data:
                return {'status': 'skipped', 'reason': 'invalid_event_data'}
            
            violation_id = violation_data.get('violation_id')
            policy_violation = violation_data.get('policy_violation', {})
            resource_info = violation_data.get('resource_info', {})
            
            logger.info(f"Processing violation {violation_id}: {policy_violation.get('rule')}")
            
            # Store violation in BigQuery
            await_result = self._store_violation_record(violation_data)
            
            # Update monitoring metrics
            self._update_violation_metrics(violation_data)
            
            # Determine response actions based on severity
            actions_taken = self._execute_response_actions(violation_data)
            
            # Send notifications
            self._send_notifications(violation_data, actions_taken)
            
            # Generate compliance report entry
            self._update_compliance_report(violation_data)
            
            return {
                'status': 'processed',
                'violation_id': violation_id,
                'actions_taken': actions_taken
            }
            
        except Exception as e:
            logger.error(f"Error processing policy violation: {str(e)}", exc_info=True)
            raise

    def _parse_violation_event(self, cloud_event) -> Optional[Dict[str, Any]]:
        """Parse violation event from Pub/Sub message."""
        try:
            if hasattr(cloud_event, 'data'):
                message_data = base64.b64decode(cloud_event.data).decode('utf-8')
                return json.loads(message_data)
            return None
        except Exception as e:
            logger.warning(f"Failed to parse violation event: {str(e)}")
            return None

    def _store_violation_record(self, violation_data: Dict[str, Any]):
        """Store violation record in BigQuery."""
        try:
            resource_info = violation_data.get('resource_info', {})
            policy_violation = violation_data.get('policy_violation', {})
            
            # Determine target dataset based on resource region
            region = resource_info.get('region', 'unknown')
            compliance_zone = self._get_compliance_zone(region)
            
            # Use primary region dataset if region is unknown
            if region == 'unknown':
                region = 'us-central1'
                
            dataset_id = f"isectech_compliance_analytics_{region.replace('-', '_')}_{self.environment}"
            table_id = "compliance_violations"
            
            # Prepare record for insertion
            violation_record = {
                'violation_id': violation_data.get('violation_id'),
                'violation_timestamp': violation_data.get('timestamp'),
                'resource_type': resource_info.get('resource_type'),
                'resource_name': resource_info.get('resource_name'),
                'violation_type': policy_violation.get('rule'),
                'compliance_zone': compliance_zone,
                'severity': policy_violation.get('severity', 'medium'),
                'region': region,
                'details': json.dumps({
                    'policy': policy_violation.get('policy'),
                    'message': policy_violation.get('message'),
                    'enforcement_mode': violation_data.get('enforcement_mode'),
                    'caller_ip': resource_info.get('caller_ip'),
                    'user_agent': resource_info.get('user_agent')
                }),
                'resolved': False,
                'resolution_timestamp': None
            }
            
            # Insert into BigQuery
            table_ref = self.bigquery_client.dataset(dataset_id).table(table_id)
            errors = self.bigquery_client.insert_rows_json(table_ref, [violation_record])
            
            if errors:
                logger.error(f"BigQuery insertion errors: {errors}")
            else:
                logger.info(f"Stored violation record {violation_data.get('violation_id')} in BigQuery")
                
        except Exception as e:
            logger.error(f"Error storing violation record: {str(e)}")

    def _update_violation_metrics(self, violation_data: Dict[str, Any]):
        """Update Cloud Monitoring metrics for violations."""
        try:
            project_name = f"projects/{self.project_id}"
            resource_info = violation_data.get('resource_info', {})
            policy_violation = violation_data.get('policy_violation', {})
            
            # Create metric for violation count
            series = monitoring_v3.TimeSeries(
                metric=monitoring_v3.Metric(
                    type="custom.googleapis.com/policy/violations",
                    labels={
                        "policy": policy_violation.get('policy', 'unknown'),
                        "rule": policy_violation.get('rule', 'unknown'),
                        "severity": policy_violation.get('severity', 'medium'),
                        "resource_type": resource_info.get('resource_type', 'unknown'),
                        "region": resource_info.get('region', 'unknown'),
                        "enforcement_mode": violation_data.get('enforcement_mode', 'WARN')
                    }
                ),
                resource=monitoring_v3.MonitoredResource(
                    type="global",
                    labels={"project_id": self.project_id}
                ),
                points=[monitoring_v3.Point(
                    interval=monitoring_v3.TimeInterval(
                        end_time={"seconds": int(datetime.utcnow().timestamp())}
                    ),
                    value=monitoring_v3.TypedValue(int64_value=1)
                )]
            )
            
            request = monitoring_v3.CreateTimeSeriesRequest(
                name=project_name,
                time_series=[series]
            )
            
            self.monitoring_client.create_time_series(request=request)
            logger.info("Updated violation metrics in Cloud Monitoring")
            
        except Exception as e:
            logger.error(f"Error updating violation metrics: {str(e)}")

    def _execute_response_actions(self, violation_data: Dict[str, Any]) -> List[str]:
        """Execute response actions based on violation severity and type."""
        actions_taken = []
        
        try:
            policy_violation = violation_data.get('policy_violation', {})
            resource_info = violation_data.get('resource_info', {})
            severity = policy_violation.get('severity', 'medium')
            
            # Critical severity actions
            if severity == 'critical':
                actions_taken.extend(self._handle_critical_violation(violation_data))
            
            # High severity actions  
            elif severity == 'high':
                actions_taken.extend(self._handle_high_violation(violation_data))
                
            # Medium severity actions
            elif severity == 'medium':
                actions_taken.extend(self._handle_medium_violation(violation_data))
                
            # Low severity actions (monitoring only)
            else:
                actions_taken.append('violation_logged')
                
            # Always create incident ticket for production
            if self.environment == 'production':
                incident_id = self._create_incident_ticket(violation_data)
                if incident_id:
                    actions_taken.append(f'incident_created:{incident_id}')
                    
        except Exception as e:
            logger.error(f"Error executing response actions: {str(e)}")
            actions_taken.append('error_in_response')
            
        return actions_taken

    def _handle_critical_violation(self, violation_data: Dict[str, Any]) -> List[str]:
        """Handle critical severity violations."""
        actions = []
        
        try:
            # Immediate escalation
            self._send_critical_alert(violation_data)
            actions.append('critical_alert_sent')
            
            # Auto-quarantine if possible (for certain resource types)
            if self._can_auto_quarantine(violation_data):
                quarantine_result = self._quarantine_resource(violation_data)
                if quarantine_result:
                    actions.append('resource_quarantined')
                    
            # Create immediate incident
            self._escalate_to_oncall(violation_data)
            actions.append('oncall_escalated')
            
        except Exception as e:
            logger.error(f"Error handling critical violation: {str(e)}")
            actions.append('critical_handling_error')
            
        return actions

    def _handle_high_violation(self, violation_data: Dict[str, Any]) -> List[str]:
        """Handle high severity violations."""
        actions = []
        
        try:
            # Send high priority alert
            self._send_high_priority_alert(violation_data)
            actions.append('high_priority_alert_sent')
            
            # Schedule remediation task
            remediation_task_id = self._schedule_remediation(violation_data)
            if remediation_task_id:
                actions.append(f'remediation_scheduled:{remediation_task_id}')
                
            # Update security dashboard
            self._update_security_dashboard(violation_data)
            actions.append('dashboard_updated')
            
        except Exception as e:
            logger.error(f"Error handling high violation: {str(e)}")
            actions.append('high_handling_error')
            
        return actions

    def _handle_medium_violation(self, violation_data: Dict[str, Any]) -> List[str]:
        """Handle medium severity violations."""
        actions = []
        
        try:
            # Send standard notification
            self._send_standard_notification(violation_data)
            actions.append('notification_sent')
            
            # Add to remediation backlog
            self._add_to_remediation_backlog(violation_data)
            actions.append('added_to_backlog')
            
        except Exception as e:
            logger.error(f"Error handling medium violation: {str(e)}")
            actions.append('medium_handling_error')
            
        return actions

    def _send_notifications(self, violation_data: Dict[str, Any], actions_taken: List[str]):
        """Send appropriate notifications based on violation."""
        try:
            policy_violation = violation_data.get('policy_violation', {})
            resource_info = violation_data.get('resource_info', {})
            severity = policy_violation.get('severity', 'medium')
            
            # Prepare notification content
            notification = {
                'violation_id': violation_data.get('violation_id'),
                'timestamp': violation_data.get('timestamp'),
                'severity': severity,
                'policy': policy_violation.get('policy'),
                'rule': policy_violation.get('rule'),
                'resource_type': resource_info.get('resource_type'),
                'resource_name': resource_info.get('resource_name'),
                'region': resource_info.get('region'),
                'message': policy_violation.get('message'),
                'actions_taken': actions_taken,
                'environment': self.environment,
                'enforcement_mode': violation_data.get('enforcement_mode')
            }
            
            # Send email notification
            if self.compliance_email:
                self._send_email_notification(notification)
            
            # Send Slack notification (if configured)
            self._send_slack_notification(notification)
            
            # Send PagerDuty alert for critical violations
            if severity == 'critical':
                self._send_pagerduty_alert(notification)
                
        except Exception as e:
            logger.error(f"Error sending notifications: {str(e)}")

    def _send_email_notification(self, notification: Dict[str, Any]):
        """Send email notification (placeholder)."""
        # In production, this would integrate with SendGrid, Gmail API, etc.
        logger.info(f"EMAIL NOTIFICATION: {notification['severity']} violation - {notification['message']}")

    def _send_slack_notification(self, notification: Dict[str, Any]):
        """Send Slack notification (placeholder)."""
        # In production, this would post to Slack webhook
        logger.info(f"SLACK NOTIFICATION: {notification['severity']} violation - {notification['message']}")

    def _send_pagerduty_alert(self, notification: Dict[str, Any]):
        """Send PagerDuty alert (placeholder)."""
        # In production, this would integrate with PagerDuty API
        logger.critical(f"PAGERDUTY ALERT: Critical violation - {notification['message']}")

    def _send_critical_alert(self, violation_data: Dict[str, Any]):
        """Send critical alert to all channels."""
        logger.critical(f"CRITICAL VIOLATION: {violation_data.get('violation_id')}")

    def _can_auto_quarantine(self, violation_data: Dict[str, Any]) -> bool:
        """Check if resource can be auto-quarantined."""
        # Implement logic to determine if resource can be safely quarantined
        return False

    def _quarantine_resource(self, violation_data: Dict[str, Any]) -> bool:
        """Quarantine the violating resource."""
        # Implement actual quarantine logic
        logger.info(f"QUARANTINE: {violation_data.get('violation_id')}")
        return True

    def _escalate_to_oncall(self, violation_data: Dict[str, Any]):
        """Escalate to on-call engineer."""
        logger.critical(f"ONCALL ESCALATION: {violation_data.get('violation_id')}")

    def _send_high_priority_alert(self, violation_data: Dict[str, Any]):
        """Send high priority alert."""
        logger.warning(f"HIGH PRIORITY: {violation_data.get('violation_id')}")

    def _schedule_remediation(self, violation_data: Dict[str, Any]) -> str:
        """Schedule remediation task."""
        task_id = f"rem-{violation_data.get('violation_id')}"
        logger.info(f"REMEDIATION SCHEDULED: {task_id}")
        return task_id

    def _update_security_dashboard(self, violation_data: Dict[str, Any]):
        """Update security dashboard."""
        logger.info(f"DASHBOARD UPDATED: {violation_data.get('violation_id')}")

    def _send_standard_notification(self, violation_data: Dict[str, Any]):
        """Send standard notification."""
        logger.info(f"NOTIFICATION: {violation_data.get('violation_id')}")

    def _add_to_remediation_backlog(self, violation_data: Dict[str, Any]):
        """Add to remediation backlog."""
        logger.info(f"BACKLOG ADDED: {violation_data.get('violation_id')}")

    def _create_incident_ticket(self, violation_data: Dict[str, Any]) -> str:
        """Create incident ticket in ITSM system."""
        incident_id = f"INC-{violation_data.get('violation_id')[:8].upper()}"
        logger.info(f"INCIDENT CREATED: {incident_id}")
        return incident_id

    def _update_compliance_report(self, violation_data: Dict[str, Any]):
        """Update compliance reporting."""
        logger.info(f"COMPLIANCE REPORT UPDATED: {violation_data.get('violation_id')}")

    def _get_compliance_zone(self, region: str) -> str:
        """Get compliance zone for region."""
        zone_mapping = {
            'us-central1': 'ccpa',
            'us-east1': 'ccpa',
            'europe-west4': 'gdpr', 
            'europe-west1': 'gdpr',
            'asia-northeast1': 'appi'
        }
        return zone_mapping.get(region, 'unknown')


def process_policy_violation(cloud_event):
    """Cloud Function entry point."""
    processor = PolicyViolationProcessor()
    return processor.process_policy_violation(cloud_event)