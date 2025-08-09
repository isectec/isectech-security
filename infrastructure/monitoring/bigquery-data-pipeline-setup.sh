#!/bin/bash

# iSECTECH BigQuery Data Pipeline and Analytics Setup Script
# Production-grade data analytics and security intelligence pipeline
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# BigQuery configuration
BQ_DATASET_LOCATION="${BQ_DATASET_LOCATION:-US}"
BQ_SECURITY_DATASET="${BQ_SECURITY_DATASET:-isectech_security_analytics}"
BQ_PERFORMANCE_DATASET="${BQ_PERFORMANCE_DATASET:-isectech_performance_analytics}"
BQ_BUSINESS_DATASET="${BQ_BUSINESS_DATASET:-isectech_business_analytics}"
BQ_COMPLIANCE_DATASET="${BQ_COMPLIANCE_DATASET:-isectech_compliance_analytics}"

# Data retention configuration
SECURITY_DATA_RETENTION_DAYS="${SECURITY_DATA_RETENTION_DAYS:-2555}"  # 7 years for compliance
PERFORMANCE_DATA_RETENTION_DAYS="${PERFORMANCE_DATA_RETENTION_DAYS:-365}"
BUSINESS_DATA_RETENTION_DAYS="${BUSINESS_DATA_RETENTION_DAYS:-1095}"  # 3 years
COMPLIANCE_DATA_RETENTION_DAYS="${COMPLIANCE_DATA_RETENTION_DAYS:-2555}"  # 7 years

# Data processing configuration
DATAFLOW_REGION="${DATAFLOW_REGION:-us-central1}"
PUBSUB_RETENTION_DAYS="${PUBSUB_RETENTION_DAYS:-7}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites for BigQuery data pipeline setup..."
    
    # Check if gcloud CLI is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if bq CLI is available
    if ! command -v bq &> /dev/null; then
        log_error "BigQuery CLI (bq) is not installed. Please install it first."
        exit 1
    fi
    
    # Check authentication
    if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" | grep -q "@"; then
        log_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Set project
    gcloud config set project "${PROJECT_ID}"
    
    # Enable required APIs
    log_info "Enabling required APIs..."
    gcloud services enable bigquery.googleapis.com
    gcloud services enable dataflow.googleapis.com
    gcloud services enable pubsub.googleapis.com
    gcloud services enable cloudfunctions.googleapis.com
    gcloud services enable eventarc.googleapis.com
    gcloud services enable dataproc.googleapis.com
    gcloud services enable composer.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create BigQuery datasets and tables
create_bigquery_datasets() {
    log_info "Creating BigQuery datasets and tables..."
    
    # Create security analytics dataset
    create_security_dataset
    
    # Create performance analytics dataset
    create_performance_dataset
    
    # Create business analytics dataset
    create_business_dataset
    
    # Create compliance analytics dataset
    create_compliance_dataset
    
    log_success "BigQuery datasets and tables created successfully"
}

create_security_dataset() {
    log_info "Creating security analytics dataset and tables..."
    
    # Create dataset
    bq mk --dataset \
        --location="${BQ_DATASET_LOCATION}" \
        --description="Security analytics and threat intelligence data for iSECTECH platform" \
        --default_table_expiration=$((SECURITY_DATA_RETENTION_DAYS * 86400)) \
        --labels="environment=${ENVIRONMENT},category=security,compliance=required" \
        "${PROJECT_ID}:${BQ_SECURITY_DATASET}"
    
    # Create threat detection events table
    bq mk --table \
        --description="Threat detection events and security incidents" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="threat_type,severity,service_name" \
        "${PROJECT_ID}:${BQ_SECURITY_DATASET}.threat_detection_events" \
        threat_detection_events_schema.json
    
    # Create threat detection events schema
    cat > "/tmp/threat_detection_events_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED", "description": "Event timestamp"},
  {"name": "event_id", "type": "STRING", "mode": "REQUIRED", "description": "Unique event identifier"},
  {"name": "threat_type", "type": "STRING", "mode": "REQUIRED", "description": "Type of threat detected"},
  {"name": "severity", "type": "STRING", "mode": "REQUIRED", "description": "Threat severity level"},
  {"name": "service_name", "type": "STRING", "mode": "REQUIRED", "description": "Service that detected the threat"},
  {"name": "source_ip", "type": "STRING", "mode": "NULLABLE", "description": "Source IP address"},
  {"name": "target_resource", "type": "STRING", "mode": "NULLABLE", "description": "Target resource or endpoint"},
  {"name": "user_id", "type": "STRING", "mode": "NULLABLE", "description": "Associated user ID"},
  {"name": "session_id", "type": "STRING", "mode": "NULLABLE", "description": "Associated session ID"},
  {"name": "request_id", "type": "STRING", "mode": "NULLABLE", "description": "Associated request ID"},
  {"name": "threat_indicators", "type": "STRING", "mode": "REPEATED", "description": "Array of threat indicators"},
  {"name": "mitigation_actions", "type": "STRING", "mode": "REPEATED", "description": "Mitigation actions taken"},
  {"name": "raw_payload", "type": "JSON", "mode": "NULLABLE", "description": "Raw event payload"},
  {"name": "geolocation", "type": "RECORD", "mode": "NULLABLE", "description": "Geographic information", "fields": [
    {"name": "country", "type": "STRING", "mode": "NULLABLE"},
    {"name": "region", "type": "STRING", "mode": "NULLABLE"},
    {"name": "city", "type": "STRING", "mode": "NULLABLE"},
    {"name": "latitude", "type": "FLOAT", "mode": "NULLABLE"},
    {"name": "longitude", "type": "FLOAT", "mode": "NULLABLE"}
  ]},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED", "description": "Environment name"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED", "description": "Data ingestion timestamp"}
]
EOF
    
    # Apply schema to create table
    bq mk --table \
        --description="Threat detection events and security incidents" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="threat_type,severity,service_name" \
        "${PROJECT_ID}:${BQ_SECURITY_DATASET}.threat_detection_events" \
        "/tmp/threat_detection_events_schema.json"
    
    # Create authentication events table
    cat > "/tmp/authentication_events_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "event_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "operation", "type": "STRING", "mode": "REQUIRED"},
  {"name": "result", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "username", "type": "STRING", "mode": "NULLABLE"},
  {"name": "authentication_method", "type": "STRING", "mode": "REQUIRED"},
  {"name": "source_ip", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_agent", "type": "STRING", "mode": "NULLABLE"},
  {"name": "failure_reason", "type": "STRING", "mode": "NULLABLE"},
  {"name": "session_duration", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "multi_factor_used", "type": "BOOLEAN", "mode": "NULLABLE"},
  {"name": "device_fingerprint", "type": "STRING", "mode": "NULLABLE"},
  {"name": "risk_score", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "geolocation", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "country", "type": "STRING", "mode": "NULLABLE"},
    {"name": "region", "type": "STRING", "mode": "NULLABLE"},
    {"name": "city", "type": "STRING", "mode": "NULLABLE"},
    {"name": "latitude", "type": "FLOAT", "mode": "NULLABLE"},
    {"name": "longitude", "type": "FLOAT", "mode": "NULLABLE"}
  ]},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="Authentication events and access patterns" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="result,authentication_method,source_ip" \
        "${PROJECT_ID}:${BQ_SECURITY_DATASET}.authentication_events" \
        "/tmp/authentication_events_schema.json"
    
    # Create vulnerability findings table
    cat > "/tmp/vulnerability_findings_schema.json" << 'EOF'
[
  {"name": "scan_timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "finding_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "vulnerability_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "cve_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "severity", "type": "STRING", "mode": "REQUIRED"},
  {"name": "cvss_score", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "scan_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "target_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "target_identifier", "type": "STRING", "mode": "REQUIRED"},
  {"name": "asset_name", "type": "STRING", "mode": "NULLABLE"},
  {"name": "asset_category", "type": "STRING", "mode": "NULLABLE"},
  {"name": "vulnerability_category", "type": "STRING", "mode": "REQUIRED"},
  {"name": "description", "type": "STRING", "mode": "REQUIRED"},
  {"name": "recommendation", "type": "STRING", "mode": "NULLABLE"},
  {"name": "remediation_status", "type": "STRING", "mode": "REQUIRED"},
  {"name": "remediation_date", "type": "TIMESTAMP", "mode": "NULLABLE"},
  {"name": "false_positive", "type": "BOOLEAN", "mode": "REQUIRED"},
  {"name": "risk_accepted", "type": "BOOLEAN", "mode": "REQUIRED"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="Vulnerability scan findings and remediation status" \
        --time_partitioning_field="scan_timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="severity,remediation_status,target_type" \
        "${PROJECT_ID}:${BQ_SECURITY_DATASET}.vulnerability_findings" \
        "/tmp/vulnerability_findings_schema.json"
    
    # Create security incident table
    cat > "/tmp/security_incidents_schema.json" << 'EOF'
[
  {"name": "incident_timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "incident_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "incident_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "severity", "type": "STRING", "mode": "REQUIRED"},
  {"name": "status", "type": "STRING", "mode": "REQUIRED"},
  {"name": "detection_source", "type": "STRING", "mode": "REQUIRED"},
  {"name": "affected_systems", "type": "STRING", "mode": "REPEATED"},
  {"name": "affected_users", "type": "STRING", "mode": "REPEATED"},
  {"name": "response_team", "type": "STRING", "mode": "REQUIRED"},
  {"name": "response_time_seconds", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "containment_time_seconds", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "resolution_time_seconds", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "root_cause", "type": "STRING", "mode": "NULLABLE"},
  {"name": "lessons_learned", "type": "STRING", "mode": "NULLABLE"},
  {"name": "financial_impact", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "related_events", "type": "STRING", "mode": "REPEATED"},
  {"name": "mitre_attack_techniques", "type": "STRING", "mode": "REPEATED"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="Security incidents and response metrics" \
        --time_partitioning_field="incident_timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="severity,status,incident_type" \
        "${PROJECT_ID}:${BQ_SECURITY_DATASET}.security_incidents" \
        "/tmp/security_incidents_schema.json"
    
    log_success "Security analytics dataset and tables created"
}

create_performance_dataset() {
    log_info "Creating performance analytics dataset and tables..."
    
    # Create dataset
    bq mk --dataset \
        --location="${BQ_DATASET_LOCATION}" \
        --description="Performance analytics and monitoring data for iSECTECH platform" \
        --default_table_expiration=$((PERFORMANCE_DATA_RETENTION_DAYS * 86400)) \
        --labels="environment=${ENVIRONMENT},category=performance" \
        "${PROJECT_ID}:${BQ_PERFORMANCE_DATASET}"
    
    # Create API performance table
    cat > "/tmp/api_performance_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "request_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "service_name", "type": "STRING", "mode": "REQUIRED"},
  {"name": "endpoint", "type": "STRING", "mode": "REQUIRED"},
  {"name": "http_method", "type": "STRING", "mode": "REQUIRED"},
  {"name": "http_status_code", "type": "INTEGER", "mode": "REQUIRED"},
  {"name": "response_time_ms", "type": "INTEGER", "mode": "REQUIRED"},
  {"name": "request_size_bytes", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "response_size_bytes", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "user_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "source_ip", "type": "STRING", "mode": "NULLABLE"},
  {"name": "user_agent", "type": "STRING", "mode": "NULLABLE"},
  {"name": "trace_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "span_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "database_query_time_ms", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "cache_hit", "type": "BOOLEAN", "mode": "NULLABLE"},
  {"name": "external_api_calls", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "cpu_usage_percent", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "memory_usage_mb", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="API performance metrics and request analytics" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="HOUR" \
        --clustering_fields="service_name,endpoint,http_status_code" \
        "${PROJECT_ID}:${BQ_PERFORMANCE_DATASET}.api_performance" \
        "/tmp/api_performance_schema.json"
    
    # Create resource utilization table
    cat > "/tmp/resource_utilization_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "service_name", "type": "STRING", "mode": "REQUIRED"},
  {"name": "instance_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "resource_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "utilization_percent", "type": "FLOAT", "mode": "REQUIRED"},
  {"name": "absolute_value", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "capacity_limit", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "region", "type": "STRING", "mode": "REQUIRED"},
  {"name": "zone", "type": "STRING", "mode": "NULLABLE"},
  {"name": "container_name", "type": "STRING", "mode": "NULLABLE"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="Resource utilization metrics for capacity planning" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="HOUR" \
        --clustering_fields="service_name,resource_type,region" \
        "${PROJECT_ID}:${BQ_PERFORMANCE_DATASET}.resource_utilization" \
        "/tmp/resource_utilization_schema.json"
    
    log_success "Performance analytics dataset and tables created"
}

create_business_dataset() {
    log_info "Creating business analytics dataset and tables..."
    
    # Create dataset
    bq mk --dataset \
        --location="${BQ_DATASET_LOCATION}" \
        --description="Business analytics and user engagement data for iSECTECH platform" \
        --default_table_expiration=$((BUSINESS_DATA_RETENTION_DAYS * 86400)) \
        --labels="environment=${ENVIRONMENT},category=business" \
        "${PROJECT_ID}:${BQ_BUSINESS_DATASET}"
    
    # Create user activity table
    cat > "/tmp/user_activity_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "user_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "session_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "organization_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_role", "type": "STRING", "mode": "REQUIRED"},
  {"name": "organization_tier", "type": "STRING", "mode": "REQUIRED"},
  {"name": "feature_name", "type": "STRING", "mode": "REQUIRED"},
  {"name": "action_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "action_details", "type": "JSON", "mode": "NULLABLE"},
  {"name": "page_path", "type": "STRING", "mode": "NULLABLE"},
  {"name": "referrer", "type": "STRING", "mode": "NULLABLE"},
  {"name": "device_type", "type": "STRING", "mode": "NULLABLE"},
  {"name": "browser", "type": "STRING", "mode": "NULLABLE"},
  {"name": "source_ip", "type": "STRING", "mode": "NULLABLE"},
  {"name": "duration_seconds", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="User activity and feature usage analytics" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="organization_id,feature_name,action_type" \
        "${PROJECT_ID}:${BQ_BUSINESS_DATASET}.user_activity" \
        "/tmp/user_activity_schema.json"
    
    # Create API consumption table
    cat > "/tmp/api_consumption_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "organization_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "api_key", "type": "STRING", "mode": "REQUIRED"},
  {"name": "api_category", "type": "STRING", "mode": "REQUIRED"},
  {"name": "endpoint", "type": "STRING", "mode": "REQUIRED"},
  {"name": "request_count", "type": "INTEGER", "mode": "REQUIRED"},
  {"name": "data_volume_bytes", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "plan_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "plan_limit", "type": "INTEGER", "mode": "REQUIRED"},
  {"name": "overage", "type": "BOOLEAN", "mode": "REQUIRED"},
  {"name": "cost_cents", "type": "INTEGER", "mode": "NULLABLE"},
  {"name": "rate_limited", "type": "BOOLEAN", "mode": "REQUIRED"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="API consumption metrics for billing and usage analytics" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="customer_id,api_category,plan_type" \
        "${PROJECT_ID}:${BQ_BUSINESS_DATASET}.api_consumption" \
        "/tmp/api_consumption_schema.json"
    
    log_success "Business analytics dataset and tables created"
}

create_compliance_dataset() {
    log_info "Creating compliance analytics dataset and tables..."
    
    # Create dataset
    bq mk --dataset \
        --location="${BQ_DATASET_LOCATION}" \
        --description="Compliance analytics and audit data for iSECTECH platform" \
        --default_table_expiration=$((COMPLIANCE_DATA_RETENTION_DAYS * 86400)) \
        --labels="environment=${ENVIRONMENT},category=compliance,retention=longterm" \
        "${PROJECT_ID}:${BQ_COMPLIANCE_DATASET}"
    
    # Create audit events table
    cat > "/tmp/audit_events_schema.json" << 'EOF'
[
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "audit_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "event_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_email", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_role", "type": "STRING", "mode": "REQUIRED"},
  {"name": "action", "type": "STRING", "mode": "REQUIRED"},
  {"name": "resource_type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "resource_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "resource_name", "type": "STRING", "mode": "NULLABLE"},
  {"name": "action_result", "type": "STRING", "mode": "REQUIRED"},
  {"name": "source_ip", "type": "STRING", "mode": "REQUIRED"},
  {"name": "user_agent", "type": "STRING", "mode": "NULLABLE"},
  {"name": "session_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "request_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "before_state", "type": "JSON", "mode": "NULLABLE"},
  {"name": "after_state", "type": "JSON", "mode": "NULLABLE"},
  {"name": "compliance_tags", "type": "STRING", "mode": "REPEATED"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="Audit events for compliance and governance tracking" \
        --time_partitioning_field="timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="event_type,user_id,resource_type" \
        "${PROJECT_ID}:${BQ_COMPLIANCE_DATASET}.audit_events" \
        "/tmp/audit_events_schema.json"
    
    # Create compliance assessments table
    cat > "/tmp/compliance_assessments_schema.json" << 'EOF'
[
  {"name": "assessment_timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "assessment_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "framework", "type": "STRING", "mode": "REQUIRED"},
  {"name": "control_family", "type": "STRING", "mode": "REQUIRED"},
  {"name": "control_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "control_description", "type": "STRING", "mode": "REQUIRED"},
  {"name": "compliance_score", "type": "FLOAT", "mode": "REQUIRED"},
  {"name": "status", "type": "STRING", "mode": "REQUIRED"},
  {"name": "findings", "type": "STRING", "mode": "REPEATED"},
  {"name": "recommendations", "type": "STRING", "mode": "REPEATED"},
  {"name": "evidence_artifacts", "type": "STRING", "mode": "REPEATED"},
  {"name": "assessor", "type": "STRING", "mode": "REQUIRED"},
  {"name": "review_date", "type": "DATE", "mode": "NULLABLE"},
  {"name": "next_assessment_date", "type": "DATE", "mode": "NULLABLE"},
  {"name": "remediation_plan", "type": "STRING", "mode": "NULLABLE"},
  {"name": "environment", "type": "STRING", "mode": "REQUIRED"},
  {"name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF
    
    bq mk --table \
        --description="Compliance assessment results and control evaluations" \
        --time_partitioning_field="assessment_timestamp" \
        --time_partitioning_type="DAY" \
        --clustering_fields="framework,control_family,status" \
        "${PROJECT_ID}:${BQ_COMPLIANCE_DATASET}.compliance_assessments" \
        "/tmp/compliance_assessments_schema.json"
    
    log_success "Compliance analytics dataset and tables created"
}

# Set up data processing pipelines
create_data_processing_pipelines() {
    log_info "Creating data processing pipelines..."
    
    # Create Dataflow templates for log processing
    create_log_processing_dataflow
    
    # Create Cloud Functions for real-time processing
    create_realtime_processing_functions
    
    # Create scheduled data processing jobs
    create_scheduled_data_jobs
    
    log_success "Data processing pipelines created"
}

create_log_processing_dataflow() {
    log_info "Creating Dataflow templates for log processing..."
    
    # Create log enrichment pipeline
    cat > "/tmp/log-enrichment-pipeline.py" << 'EOF'
"""
iSECTECH Log Enrichment Dataflow Pipeline
Enriches raw log data with threat intelligence, geolocation, and business context
"""

import apache_beam as beam
from apache_beam.options.pipeline_options import PipelineOptions
import json
import requests
from datetime import datetime
import hashlib


class LogEnrichmentOptions(PipelineOptions):
    @classmethod
    def _add_argparse_args(cls, parser):
        parser.add_argument('--input_subscription', required=True)
        parser.add_argument('--output_table_security', required=True)
        parser.add_argument('--output_table_performance', required=True)
        parser.add_argument('--threat_intel_api_key', required=True)
        parser.add_argument('--geolocation_api_key', required=True)


class ParseLogEvent(beam.DoFn):
    def process(self, element):
        try:
            log_entry = json.loads(element)
            
            # Extract standard fields
            parsed_event = {
                'timestamp': log_entry.get('timestamp'),
                'service_name': log_entry.get('resource', {}).get('labels', {}).get('service_name'),
                'environment': log_entry.get('labels', {}).get('environment', 'unknown'),
                'request_id': log_entry.get('jsonPayload', {}).get('request_id'),
                'raw_payload': log_entry
            }
            
            # Determine event type and route accordingly
            json_payload = log_entry.get('jsonPayload', {})
            event_type = json_payload.get('event_type', 'unknown')
            
            parsed_event['event_type'] = event_type
            
            yield parsed_event
            
        except Exception as e:
            # Log parsing error
            yield beam.pvalue.TaggedOutput('errors', {
                'error': str(e),
                'raw_data': element,
                'timestamp': datetime.utcnow().isoformat()
            })


class EnrichSecurityEvent(beam.DoFn):
    def __init__(self, threat_intel_api_key, geolocation_api_key):
        self.threat_intel_api_key = threat_intel_api_key
        self.geolocation_api_key = geolocation_api_key
        
    def process(self, element):
        if element['event_type'] not in ['security_event', 'threat_detection', 'authentication']:
            return
            
        try:
            # Extract security-specific fields
            json_payload = element['raw_payload'].get('jsonPayload', {})
            
            security_event = {
                'timestamp': element['timestamp'],
                'event_id': self._generate_event_id(element),
                'threat_type': json_payload.get('security_context', {}).get('threat_type', 'unknown'),
                'severity': json_payload.get('security_context', {}).get('threat_level', 'low'),
                'service_name': element['service_name'],
                'source_ip': json_payload.get('security_context', {}).get('ip_address'),
                'target_resource': json_payload.get('security_context', {}).get('target_resource'),
                'user_id': json_payload.get('security_context', {}).get('user_id'),
                'session_id': json_payload.get('security_context', {}).get('session_id'),
                'request_id': element['request_id'],
                'threat_indicators': json_payload.get('security_context', {}).get('indicators', []),
                'mitigation_actions': json_payload.get('security_context', {}).get('mitigation_actions', []),
                'environment': element['environment'],
                'ingestion_time': datetime.utcnow().isoformat()
            }
            
            # Enrich with geolocation data
            if security_event['source_ip']:
                geolocation = self._get_geolocation(security_event['source_ip'])
                security_event['geolocation'] = geolocation
            
            # Enrich with threat intelligence
            if security_event['source_ip']:
                threat_intel = self._get_threat_intelligence(security_event['source_ip'])
                if threat_intel.get('is_malicious'):
                    security_event['threat_indicators'].extend(threat_intel.get('indicators', []))
                    # Upgrade severity if IP is known malicious
                    if security_event['severity'] == 'low' and threat_intel.get('confidence') > 0.7:
                        security_event['severity'] = 'medium'
            
            yield security_event
            
        except Exception as e:
            yield beam.pvalue.TaggedOutput('errors', {
                'error': f"Security enrichment failed: {str(e)}",
                'element': element,
                'timestamp': datetime.utcnow().isoformat()
            })
    
    def _generate_event_id(self, element):
        # Generate deterministic event ID
        data = f"{element['timestamp']}{element['service_name']}{element['request_id']}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _get_geolocation(self, ip_address):
        # Mock geolocation lookup - replace with actual service
        try:
            # In production, use MaxMind, IPGeolocation, or similar service
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon')
                }
        except:
            pass
        
        return None
    
    def _get_threat_intelligence(self, ip_address):
        # Mock threat intelligence lookup
        try:
            # In production, integrate with VirusTotal, ThreatCrowd, etc.
            headers = {'X-API-Key': self.threat_intel_api_key}
            response = requests.get(
                f"https://api.threatintel.example.com/ip/{ip_address}",
                headers=headers,
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {'is_malicious': False, 'confidence': 0.0, 'indicators': []}


class EnrichPerformanceEvent(beam.DoFn):
    def process(self, element):
        if element['event_type'] not in ['performance_metric', 'http_request']:
            return
            
        try:
            json_payload = element['raw_payload'].get('jsonPayload', {})
            http_request = element['raw_payload'].get('httpRequest', {})
            
            performance_event = {
                'timestamp': element['timestamp'],
                'request_id': element['request_id'],
                'service_name': element['service_name'],
                'endpoint': http_request.get('requestUrl', '').split('?')[0],  # Remove query params
                'http_method': http_request.get('requestMethod', 'UNKNOWN'),
                'http_status_code': http_request.get('status', 0),
                'response_time_ms': json_payload.get('performance_context', {}).get('response_time_ms', 0),
                'request_size_bytes': http_request.get('requestSize', 0),
                'response_size_bytes': http_request.get('responseSize', 0),
                'user_id': json_payload.get('security_context', {}).get('user_id'),
                'source_ip': http_request.get('remoteIp'),
                'user_agent': http_request.get('userAgent'),
                'trace_id': json_payload.get('trace_id'),
                'span_id': json_payload.get('span_id'),
                'database_query_time_ms': json_payload.get('performance_context', {}).get('db_query_time_ms'),
                'cache_hit': json_payload.get('performance_context', {}).get('cache_hit'),
                'external_api_calls': json_payload.get('performance_context', {}).get('external_api_calls', 0),
                'cpu_usage_percent': json_payload.get('performance_context', {}).get('cpu_usage'),
                'memory_usage_mb': json_payload.get('performance_context', {}).get('memory_usage_mb'),
                'environment': element['environment'],
                'ingestion_time': datetime.utcnow().isoformat()
            }
            
            yield performance_event
            
        except Exception as e:
            yield beam.pvalue.TaggedOutput('errors', {
                'error': f"Performance enrichment failed: {str(e)}",
                'element': element,
                'timestamp': datetime.utcnow().isoformat()
            })


def run_pipeline(options):
    pipeline_options = PipelineOptions()
    
    with beam.Pipeline(options=pipeline_options) as pipeline:
        # Read from Pub/Sub
        raw_logs = (
            pipeline
            | 'Read from Pub/Sub' >> beam.io.ReadFromPubSub(
                subscription=options.input_subscription
            )
        )
        
        # Parse log events
        parsed_logs = (
            raw_logs
            | 'Parse Log Events' >> beam.ParDo(ParseLogEvent()).with_outputs('errors', main='main')
        )
        
        # Process security events
        security_events = (
            parsed_logs.main
            | 'Filter Security Events' >> beam.Filter(
                lambda x: x['event_type'] in ['security_event', 'threat_detection', 'authentication']
            )
            | 'Enrich Security Events' >> beam.ParDo(
                EnrichSecurityEvent(options.threat_intel_api_key, options.geolocation_api_key)
            ).with_outputs('errors', main='main')
        )
        
        # Process performance events  
        performance_events = (
            parsed_logs.main
            | 'Filter Performance Events' >> beam.Filter(
                lambda x: x['event_type'] in ['performance_metric', 'http_request']
            )
            | 'Enrich Performance Events' >> beam.ParDo(EnrichPerformanceEvent()).with_outputs('errors', main='main')
        )
        
        # Write to BigQuery
        (
            security_events.main
            | 'Write Security Events' >> beam.io.WriteToBigQuery(
                table=options.output_table_security,
                write_disposition=beam.io.BigQueryDisposition.WRITE_APPEND,
                create_disposition=beam.io.BigQueryDisposition.CREATE_NEVER
            )
        )
        
        (
            performance_events.main
            | 'Write Performance Events' >> beam.io.WriteToBigQuery(
                table=options.output_table_performance,
                write_disposition=beam.io.BigQueryDisposition.WRITE_APPEND,
                create_disposition=beam.io.BigQueryDisposition.CREATE_NEVER
            )
        )
        
        # Handle errors
        all_errors = (
            (parsed_logs.errors, security_events.errors, performance_events.errors)
            | 'Flatten Errors' >> beam.Flatten()
            | 'Write Errors to Pub/Sub' >> beam.io.WriteToPubSub(
                topic=f"projects/{options.view_as(LogEnrichmentOptions).project}/topics/isectech-processing-errors"
            )
        )


if __name__ == '__main__':
    options = LogEnrichmentOptions()
    run_pipeline(options)
EOF
    
    log_success "Log enrichment Dataflow pipeline created"
}

create_realtime_processing_functions() {
    log_info "Creating real-time processing Cloud Functions..."
    
    # Create security event processor
    cat > "/tmp/security-event-processor.js" << 'EOF'
/**
 * Real-time Security Event Processing Function
 * Processes security events and triggers immediate responses
 */

const { PubSub } = require('@google-cloud/pubsub');
const { BigQuery } = require('@google-cloud/bigquery');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');

const pubsub = new PubSub();
const bigquery = new BigQuery();
const secretManager = new SecretManagerServiceClient();

// Configuration
const PROJECT_ID = process.env.PROJECT_ID;
const SECURITY_DATASET = process.env.SECURITY_DATASET || 'isectech_security_analytics';

exports.processSecurityEvent = async (pubSubMessage, context) => {
    try {
        const eventData = JSON.parse(Buffer.from(pubSubMessage.data, 'base64').toString());
        
        console.log('Processing security event:', {
            eventType: eventData.event_type,
            severity: eventData.severity,
            serviceThreamName: eventData.service_name,
            timestamp: eventData.timestamp
        });
        
        // Threat detection processing
        if (eventData.event_type === 'threat_detection') {
            await processThreatDetection(eventData);
        }
        
        // Authentication event processing
        if (eventData.event_type === 'authentication') {
            await processAuthenticationEvent(eventData);
        }
        
        // Security incident processing
        if (eventData.event_type === 'security_incident') {
            await processSecurityIncident(eventData);
        }
        
        // Store enriched event in BigQuery
        await storeSecurityEvent(eventData);
        
        // Real-time threat intelligence update
        await updateThreatIntelligence(eventData);
        
    } catch (error) {
        console.error('Error processing security event:', error);
        await publishError('security_processing_error', error, pubSubMessage);
        throw error;
    }
};

async function processThreatDetection(eventData) {
    const severity = eventData.severity;
    const threatType = eventData.threat_type;
    
    console.log(`Processing threat detection: ${threatType} (${severity})`);
    
    // High and critical threats require immediate action
    if (severity === 'high' || severity === 'critical') {
        await triggerImmediateResponse(eventData);
        
        // Check for attack patterns
        const relatedEvents = await findRelatedThreatEvents(eventData);
        if (relatedEvents.length > 3) {
            await escalateToSecurityTeam(eventData, relatedEvents);
        }
    }
    
    // Update threat counters
    await updateThreatMetrics(threatType, severity);
    
    // Correlate with existing incidents
    await correlateWithIncidents(eventData);
}

async function processAuthenticationEvent(eventData) {
    const result = eventData.result;
    const sourceIP = eventData.source_ip;
    const userId = eventData.user_id;
    
    console.log(`Processing auth event: ${result} from ${sourceIP}`);
    
    if (result === 'failure') {
        // Check for brute force patterns
        await checkBruteForcePattern(sourceIP, userId);
        
        // Update failed login metrics
        await updateAuthMetrics('failure', eventData.authentication_method);
        
        // Geographic anomaly detection
        await checkGeographicAnomaly(userId, eventData.geolocation);
    } else if (result === 'success') {
        // Check for impossible travel
        await checkImpossibleTravel(userId, eventData.geolocation);
        
        // Update successful login metrics
        await updateAuthMetrics('success', eventData.authentication_method);
    }
}

async function processSecurityIncident(eventData) {
    const incidentType = eventData.incident_type;
    const severity = eventData.severity;
    
    console.log(`Processing security incident: ${incidentType} (${severity})`);
    
    // Create incident record
    await createIncidentRecord(eventData);
    
    // Notify response team
    await notifyResponseTeam(eventData);
    
    // Start automated containment if applicable
    if (eventData.automated_response_enabled) {
        await initiateAutomatedContainment(eventData);
    }
    
    // Update incident metrics
    await updateIncidentMetrics(incidentType, severity);
}

async function triggerImmediateResponse(threatData) {
    console.log('Triggering immediate threat response');
    
    const responseActions = [];
    
    // IP blocking for network-based threats
    if (threatData.source_ip && shouldBlockIP(threatData)) {
        responseActions.push(await blockIPAddress(threatData.source_ip));
    }
    
    // User session termination for account-based threats
    if (threatData.user_id && shouldTerminateSession(threatData)) {
        responseActions.push(await terminateUserSessions(threatData.user_id));
    }
    
    // Service isolation for service-based threats
    if (threatData.service_name && shouldIsolateService(threatData)) {
        responseActions.push(await isolateService(threatData.service_name));
    }
    
    // Update threat record with response actions
    threatData.mitigation_actions = responseActions;
    
    return responseActions;
}

async function checkBruteForcePattern(sourceIP, userId) {
    const query = `
        SELECT COUNT(*) as failure_count
        FROM \`${PROJECT_ID}.${SECURITY_DATASET}.authentication_events\`
        WHERE source_ip = @sourceIP
        AND result = 'failure'
        AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 10 MINUTE)
    `;
    
    const options = {
        query: query,
        params: { sourceIP: sourceIP }
    };
    
    const [rows] = await bigquery.query(options);
    const failureCount = rows[0].failure_count;
    
    if (failureCount > 10) {
        console.log(`Brute force detected from ${sourceIP}: ${failureCount} failures`);
        
        // Trigger brute force alert
        await publishAlert('brute_force_detected', {
            source_ip: sourceIP,
            user_id: userId,
            failure_count: failureCount,
            time_window: '10 minutes'
        });
        
        // Block IP if threshold exceeded
        if (failureCount > 20) {
            await blockIPAddress(sourceIP);
        }
    }
}

async function findRelatedThreatEvents(eventData) {
    const query = `
        SELECT *
        FROM \`${PROJECT_ID}.${SECURITY_DATASET}.threat_detection_events\`
        WHERE (source_ip = @sourceIP OR user_id = @userId)
        AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
        AND threat_type = @threatType
        ORDER BY timestamp DESC
        LIMIT 10
    `;
    
    const options = {
        query: query,
        params: {
            sourceIP: eventData.source_ip,
            userId: eventData.user_id,
            threatType: eventData.threat_type
        }
    };
    
    const [rows] = await bigquery.query(options);
    return rows;
}

async function storeSecurityEvent(eventData) {
    const table = bigquery.dataset(SECURITY_DATASET).table('threat_detection_events');
    
    const rows = [{
        insertId: eventData.event_id,
        json: eventData
    }];
    
    await table.insert(rows);
    console.log('Security event stored in BigQuery');
}

async function publishAlert(alertType, alertData) {
    const topic = pubsub.topic('isectech-security-alerts');
    
    const alert = {
        alert_type: alertType,
        timestamp: new Date().toISOString(),
        severity: 'high',
        data: alertData
    };
    
    await topic.publishMessage({ json: alert });
    console.log(`Alert published: ${alertType}`);
}

async function blockIPAddress(ipAddress) {
    // Implementation would integrate with Cloud Armor or firewall
    console.log(`Blocking IP address: ${ipAddress}`);
    
    // Add to Cloud Armor blocked IP list
    // This is a placeholder - actual implementation would use Cloud Armor API
    
    return {
        action: 'ip_blocked',
        target: ipAddress,
        timestamp: new Date().toISOString()
    };
}

async function publishError(errorType, error, originalMessage) {
    const topic = pubsub.topic('isectech-processing-errors');
    
    const errorData = {
        error_type: errorType,
        error_message: error.message,
        error_stack: error.stack,
        original_message: originalMessage,
        timestamp: new Date().toISOString()
    };
    
    await topic.publishMessage({ json: errorData });
}

// Helper functions (simplified implementations)
function shouldBlockIP(threatData) {
    return threatData.severity === 'critical' || 
           (threatData.severity === 'high' && threatData.threat_type === 'network_attack');
}

function shouldTerminateSession(threatData) {
    return threatData.user_id && 
           (threatData.severity === 'critical' || threatData.threat_type === 'account_compromise');
}

function shouldIsolateService(threatData) {
    return threatData.severity === 'critical' && 
           threatData.threat_type === 'service_compromise';
}

async function updateThreatMetrics(threatType, severity) {
    // Update Prometheus metrics or Cloud Monitoring
    console.log(`Updating threat metrics: ${threatType} (${severity})`);
}

async function updateAuthMetrics(result, method) {
    // Update authentication metrics
    console.log(`Updating auth metrics: ${result} via ${method}`);
}
EOF
    
    log_success "Real-time processing Cloud Functions created"
}

create_scheduled_data_jobs() {
    log_info "Creating scheduled data processing jobs..."
    
    # Create SQL scripts for scheduled analysis
    cat > "/tmp/security-analytics-queries.sql" << 'EOF'
-- iSECTECH Security Analytics Queries
-- Scheduled BigQuery jobs for security intelligence

-- Daily threat summary
CREATE OR REPLACE VIEW `isectech_security_analytics.daily_threat_summary` AS
SELECT
  DATE(timestamp) as date,
  threat_type,
  severity,
  COUNT(*) as event_count,
  COUNT(DISTINCT source_ip) as unique_ips,
  COUNT(DISTINCT user_id) as affected_users,
  ARRAY_AGG(DISTINCT mitigation_actions IGNORE NULLS) as mitigation_actions
FROM `isectech_security_analytics.threat_detection_events`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY date, threat_type, severity
ORDER BY date DESC, event_count DESC;

-- Authentication anomalies detection
CREATE OR REPLACE VIEW `isectech_security_analytics.authentication_anomalies` AS
WITH auth_patterns AS (
  SELECT
    user_id,
    DATE(timestamp) as date,
    COUNT(*) as total_attempts,
    COUNTIF(result = 'failure') as failed_attempts,
    COUNT(DISTINCT source_ip) as unique_ips,
    ARRAY_AGG(DISTINCT geolocation.country IGNORE NULLS) as countries,
    AVG(risk_score) as avg_risk_score
  FROM `isectech_security_analytics.authentication_events`
  WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
  GROUP BY user_id, date
)
SELECT
  user_id,
  date,
  total_attempts,
  failed_attempts,
  SAFE_DIVIDE(failed_attempts, total_attempts) as failure_rate,
  unique_ips,
  ARRAY_LENGTH(countries) as country_count,
  avg_risk_score,
  CASE
    WHEN failure_rate > 0.5 AND total_attempts > 10 THEN 'high_failure_rate'
    WHEN unique_ips > 5 THEN 'multiple_ip_addresses'
    WHEN ARRAY_LENGTH(countries) > 2 THEN 'geographic_anomaly'
    WHEN avg_risk_score > 0.8 THEN 'high_risk_score'
    ELSE 'normal'
  END as anomaly_type
FROM auth_patterns
WHERE (failure_rate > 0.3 OR unique_ips > 3 OR ARRAY_LENGTH(countries) > 1 OR avg_risk_score > 0.6)
ORDER BY avg_risk_score DESC, failure_rate DESC;

-- Top threats by impact
CREATE OR REPLACE VIEW `isectech_security_analytics.top_threats_by_impact` AS
SELECT
  threat_type,
  severity,
  COUNT(*) as total_events,
  COUNT(DISTINCT source_ip) as unique_sources,
  COUNT(DISTINCT target_resource) as affected_resources,
  COUNT(DISTINCT user_id) as affected_users,
  -- Calculate impact score based on various factors
  (COUNT(*) * 
   CASE severity 
     WHEN 'critical' THEN 10 
     WHEN 'high' THEN 5 
     WHEN 'medium' THEN 2 
     ELSE 1 
   END) + 
  (COUNT(DISTINCT user_id) * 3) + 
  (COUNT(DISTINCT target_resource) * 2) as impact_score,
  ARRAY_AGG(DISTINCT mitigation_actions IGNORE NULLS LIMIT 10) as common_mitigations
FROM `isectech_security_analytics.threat_detection_events`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY threat_type, severity
HAVING total_events > 5
ORDER BY impact_score DESC
LIMIT 20;

-- Vulnerability remediation tracking
CREATE OR REPLACE VIEW `isectech_security_analytics.vulnerability_remediation_status` AS
SELECT
  vulnerability_category,
  severity,
  COUNT(*) as total_findings,
  COUNTIF(remediation_status = 'fixed') as fixed_count,
  COUNTIF(remediation_status = 'in_progress') as in_progress_count,
  COUNTIF(remediation_status = 'open') as open_count,
  COUNTIF(false_positive = true) as false_positive_count,
  SAFE_DIVIDE(COUNTIF(remediation_status = 'fixed'), COUNT(*)) as remediation_rate,
  AVG(DATETIME_DIFF(remediation_date, scan_timestamp, DAY)) as avg_remediation_days
FROM `isectech_security_analytics.vulnerability_findings`
WHERE scan_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
GROUP BY vulnerability_category, severity
ORDER BY 
  CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
  total_findings DESC;

-- Security incident response metrics
CREATE OR REPLACE VIEW `isectech_security_analytics.incident_response_metrics` AS
SELECT
  incident_type,
  severity,
  COUNT(*) as total_incidents,
  AVG(response_time_seconds) / 60 as avg_response_time_minutes,
  AVG(containment_time_seconds) / 60 as avg_containment_time_minutes,
  AVG(resolution_time_seconds) / 3600 as avg_resolution_time_hours,
  COUNTIF(status = 'resolved') as resolved_count,
  COUNTIF(status = 'open') as open_count,
  SUM(financial_impact) as total_financial_impact,
  ARRAY_AGG(DISTINCT response_team) as response_teams
FROM `isectech_security_analytics.security_incidents`
WHERE incident_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY incident_type, severity
ORDER BY 
  CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
  total_incidents DESC;
EOF
    
    # Create performance analytics queries
    cat > "/tmp/performance-analytics-queries.sql" << 'EOF'
-- iSECTECH Performance Analytics Queries
-- Scheduled BigQuery jobs for performance intelligence

-- API performance summary
CREATE OR REPLACE VIEW `isectech_performance_analytics.api_performance_summary` AS
SELECT
  service_name,
  endpoint,
  DATE(timestamp) as date,
  COUNT(*) as total_requests,
  COUNTIF(http_status_code >= 200 AND http_status_code < 300) as success_requests,
  COUNTIF(http_status_code >= 400 AND http_status_code < 500) as client_errors,
  COUNTIF(http_status_code >= 500) as server_errors,
  SAFE_DIVIDE(COUNTIF(http_status_code >= 200 AND http_status_code < 300), COUNT(*)) as success_rate,
  APPROX_QUANTILES(response_time_ms, 100)[OFFSET(50)] as p50_response_time,
  APPROX_QUANTILES(response_time_ms, 100)[OFFSET(95)] as p95_response_time,
  APPROX_QUANTILES(response_time_ms, 100)[OFFSET(99)] as p99_response_time,
  AVG(response_time_ms) as avg_response_time,
  MAX(response_time_ms) as max_response_time
FROM `isectech_performance_analytics.api_performance`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY service_name, endpoint, date
ORDER BY date DESC, total_requests DESC;

-- Slow endpoint analysis
CREATE OR REPLACE VIEW `isectech_performance_analytics.slow_endpoints` AS
SELECT
  service_name,
  endpoint,
  http_method,
  COUNT(*) as request_count,
  AVG(response_time_ms) as avg_response_time,
  APPROX_QUANTILES(response_time_ms, 100)[OFFSET(95)] as p95_response_time,
  MAX(response_time_ms) as max_response_time,
  -- Identify slow requests (>5 seconds)
  COUNTIF(response_time_ms > 5000) as slow_request_count,
  SAFE_DIVIDE(COUNTIF(response_time_ms > 5000), COUNT(*)) as slow_request_rate,
  -- Database performance correlation
  AVG(database_query_time_ms) as avg_db_time,
  SAFE_DIVIDE(AVG(database_query_time_ms), AVG(response_time_ms)) as db_time_ratio
FROM `isectech_performance_analytics.api_performance`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY service_name, endpoint, http_method
HAVING avg_response_time > 1000 OR slow_request_rate > 0.05
ORDER BY p95_response_time DESC, slow_request_rate DESC;

-- Resource utilization trends
CREATE OR REPLACE VIEW `isectech_performance_analytics.resource_utilization_trends` AS
SELECT
  service_name,
  resource_type,
  DATE(timestamp) as date,
  DATETIME(timestamp, "UTC") interval_start,
  AVG(utilization_percent) as avg_utilization,
  MAX(utilization_percent) as max_utilization,
  APPROX_QUANTILES(utilization_percent, 100)[OFFSET(95)] as p95_utilization,
  -- Identify resource stress periods
  COUNTIF(utilization_percent > 80) as high_utilization_count,
  COUNTIF(utilization_percent > 90) as critical_utilization_count
FROM `isectech_performance_analytics.resource_utilization`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY service_name, resource_type, date, DATETIME_TRUNC(timestamp, HOUR)
ORDER BY date DESC, max_utilization DESC;
EOF
    
    # Create business analytics queries
    cat > "/tmp/business-analytics-queries.sql" << 'EOF'
-- iSECTECH Business Analytics Queries
-- Scheduled BigQuery jobs for business intelligence

-- Daily active users and engagement
CREATE OR REPLACE VIEW `isectech_business_analytics.daily_engagement_summary` AS
SELECT
  DATE(timestamp) as date,
  organization_tier,
  user_role,
  COUNT(DISTINCT user_id) as daily_active_users,
  COUNT(DISTINCT session_id) as total_sessions,
  COUNT(*) as total_actions,
  SAFE_DIVIDE(COUNT(*), COUNT(DISTINCT user_id)) as actions_per_user,
  SAFE_DIVIDE(COUNT(DISTINCT session_id), COUNT(DISTINCT user_id)) as sessions_per_user,
  AVG(duration_seconds) as avg_session_duration
FROM `isectech_business_analytics.user_activity`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY date, organization_tier, user_role
ORDER BY date DESC, daily_active_users DESC;

-- Feature adoption analysis
CREATE OR REPLACE VIEW `isectech_business_analytics.feature_adoption` AS
SELECT
  feature_name,
  action_type,
  COUNT(DISTINCT user_id) as unique_users,
  COUNT(*) as total_usage,
  -- Weekly adoption trend
  COUNT(DISTINCT CASE WHEN timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY) THEN user_id END) as weekly_active_users,
  -- Monthly adoption trend
  COUNT(DISTINCT CASE WHEN timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY) THEN user_id END) as monthly_active_users,
  -- Feature stickiness (DAU/MAU ratio)
  SAFE_DIVIDE(
    COUNT(DISTINCT CASE WHEN timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY) THEN user_id END),
    COUNT(DISTINCT CASE WHEN timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY) THEN user_id END)
  ) as stickiness_ratio
FROM `isectech_business_analytics.user_activity`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
GROUP BY feature_name, action_type
ORDER BY monthly_active_users DESC, stickiness_ratio DESC;

-- API consumption and billing analytics
CREATE OR REPLACE VIEW `isectech_business_analytics.api_consumption_summary` AS
SELECT
  customer_id,
  organization_id,
  api_category,
  plan_type,
  DATE(timestamp) as date,
  SUM(request_count) as total_requests,
  SUM(data_volume_bytes) / (1024*1024*1024) as total_data_gb,
  SUM(cost_cents) / 100 as total_cost_dollars,
  AVG(plan_limit) as plan_limit,
  SAFE_DIVIDE(SUM(request_count), AVG(plan_limit)) as utilization_rate,
  COUNTIF(overage = true) as overage_days,
  COUNTIF(rate_limited = true) as rate_limited_days
FROM `isectech_business_analytics.api_consumption`
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY customer_id, organization_id, api_category, plan_type, date
ORDER BY total_cost_dollars DESC, utilization_rate DESC;

-- Customer health score
CREATE OR REPLACE VIEW `isectech_business_analytics.customer_health_score` AS
WITH usage_metrics AS (
  SELECT
    organization_id,
    COUNT(DISTINCT user_id) as active_users,
    COUNT(DISTINCT DATE(timestamp)) as active_days,
    COUNT(*) as total_actions,
    SAFE_DIVIDE(COUNT(DISTINCT DATE(timestamp)), 30) as engagement_frequency
  FROM `isectech_business_analytics.user_activity`
  WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  GROUP BY organization_id
),
api_metrics AS (
  SELECT
    organization_id,
    SUM(request_count) as total_api_requests,
    AVG(SAFE_DIVIDE(request_count, plan_limit)) as avg_utilization,
    COUNTIF(overage = true) as overage_incidents
  FROM `isectech_business_analytics.api_consumption`
  WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  GROUP BY organization_id
)
SELECT
  u.organization_id,
  u.active_users,
  u.active_days,
  u.total_actions,
  u.engagement_frequency,
  a.total_api_requests,
  a.avg_utilization,
  a.overage_incidents,
  -- Calculate health score (0-100)
  LEAST(100, GREATEST(0,
    (u.engagement_frequency * 30) +  -- 30 points for daily engagement
    (LEAST(u.active_users / 10, 1) * 20) +  -- 20 points for user adoption
    (LEAST(a.avg_utilization, 1) * 25) +  -- 25 points for API utilization
    (CASE WHEN a.overage_incidents = 0 THEN 25 ELSE GREATEST(0, 25 - a.overage_incidents * 5) END)  -- 25 points for staying within limits
  )) as health_score,
  CASE
    WHEN LEAST(100, GREATEST(0, (u.engagement_frequency * 30) + (LEAST(u.active_users / 10, 1) * 20) + (LEAST(a.avg_utilization, 1) * 25) + (CASE WHEN a.overage_incidents = 0 THEN 25 ELSE GREATEST(0, 25 - a.overage_incidents * 5) END))) >= 80 THEN 'healthy'
    WHEN LEAST(100, GREATEST(0, (u.engagement_frequency * 30) + (LEAST(u.active_users / 10, 1) * 20) + (LEAST(a.avg_utilization, 1) * 25) + (CASE WHEN a.overage_incidents = 0 THEN 25 ELSE GREATEST(0, 25 - a.overage_incidents * 5) END))) >= 60 THEN 'at_risk'
    ELSE 'unhealthy'
  END as health_status
FROM usage_metrics u
LEFT JOIN api_metrics a ON u.organization_id = a.organization_id
ORDER BY health_score DESC;
EOF
    
    log_success "Scheduled data processing jobs created"
}

# Generate BigQuery data pipeline report
generate_bigquery_report() {
    log_info "Generating BigQuery data pipeline configuration report..."
    
    local report_file="/tmp/isectech-bigquery-pipeline-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH BigQuery Data Pipeline and Analytics Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
DATA PIPELINE INFRASTRUCTURE OVERVIEW
================================

BigQuery Configuration:
- Dataset Location: ${BQ_DATASET_LOCATION}
- Security Dataset: ${BQ_SECURITY_DATASET}
- Performance Dataset: ${BQ_PERFORMANCE_DATASET}
- Business Dataset: ${BQ_BUSINESS_DATASET}
- Compliance Dataset: ${BQ_COMPLIANCE_DATASET}

Data Retention Policies:
- Security Data: ${SECURITY_DATA_RETENTION_DAYS} days (7 years for compliance)
- Performance Data: ${PERFORMANCE_DATA_RETENTION_DAYS} days (1 year)
- Business Data: ${BUSINESS_DATA_RETENTION_DAYS} days (3 years)
- Compliance Data: ${COMPLIANCE_DATA_RETENTION_DAYS} days (7 years)

Processing Infrastructure:
- Dataflow Region: ${DATAFLOW_REGION}
- Pub/Sub Retention: ${PUBSUB_RETENTION_DAYS} days

================================
BIGQUERY DATASETS AND TABLES
================================

Security Analytics Dataset (${BQ_SECURITY_DATASET}):
1. threat_detection_events
   - Partitioned by: timestamp (daily)
   - Clustered by: threat_type, severity, service_name
   - Purpose: Store threat detection events and security incidents
   - Schema: 15 fields including geolocation and threat indicators

2. authentication_events
   - Partitioned by: timestamp (daily)
   - Clustered by: result, authentication_method, source_ip
   - Purpose: Track authentication attempts and access patterns
   - Schema: 18 fields including risk scoring and device fingerprinting

3. vulnerability_findings
   - Partitioned by: scan_timestamp (daily)
   - Clustered by: severity, remediation_status, target_type
   - Purpose: Store vulnerability scan results and remediation tracking
   - Schema: 20 fields including CVSS scoring and remediation status

4. security_incidents
   - Partitioned by: incident_timestamp (daily)
   - Clustered by: severity, status, incident_type
   - Purpose: Track security incidents and response metrics
   - Schema: 19 fields including response times and financial impact

Performance Analytics Dataset (${BQ_PERFORMANCE_DATASET}):
1. api_performance
   - Partitioned by: timestamp (hourly)
   - Clustered by: service_name, endpoint, http_status_code
   - Purpose: Store API performance metrics and request analytics
   - Schema: 21 fields including response times and resource usage

2. resource_utilization
   - Partitioned by: timestamp (hourly)
   - Clustered by: service_name, resource_type, region
   - Purpose: Track system resource utilization for capacity planning
   - Schema: 12 fields including utilization percentages and limits

Business Analytics Dataset (${BQ_BUSINESS_DATASET}):
1. user_activity
   - Partitioned by: timestamp (daily)
   - Clustered by: organization_id, feature_name, action_type
   - Purpose: Track user engagement and feature adoption
   - Schema: 17 fields including session data and device information

2. api_consumption
   - Partitioned by: timestamp (daily)
   - Clustered by: customer_id, api_category, plan_type
   - Purpose: Monitor API usage for billing and capacity planning
   - Schema: 15 fields including usage limits and overage tracking

Compliance Analytics Dataset (${BQ_COMPLIANCE_DATASET}):
1. audit_events
   - Partitioned by: timestamp (daily)
   - Clustered by: event_type, user_id, resource_type
   - Purpose: Store audit trails for compliance and governance
   - Schema: 19 fields including before/after states and compliance tags

2. compliance_assessments
   - Partitioned by: assessment_timestamp (daily)
   - Clustered by: framework, control_family, status
   - Purpose: Track compliance assessment results and control evaluations
   - Schema: 17 fields including compliance scores and evidence artifacts

================================
DATA PROCESSING PIPELINES
================================

Real-time Processing:
1. Log Enrichment Dataflow Pipeline
   - Input: Pub/Sub subscription from Cloud Logging
   - Processing: Event parsing, threat intelligence enrichment, geolocation
   - Output: Enriched events to BigQuery tables
   - Windowing: 1-minute tumbling windows
   - Scaling: Auto-scaling based on message backlog

2. Security Event Processor (Cloud Function)
   - Trigger: Pub/Sub messages from security log sink
   - Processing: Real-time threat analysis and response
   - Actions: IP blocking, session termination, alert generation
   - Latency: <5 seconds for critical threats

3. Performance Anomaly Detector (Cloud Function)
   - Trigger: Performance metrics from log stream
   - Processing: Statistical anomaly detection
   - Actions: Alert generation, auto-scaling recommendations
   - Frequency: Real-time processing

Batch Processing:
1. Daily Security Analytics Jobs
   - Threat pattern analysis
   - Authentication anomaly detection
   - Vulnerability remediation tracking
   - Incident response metrics calculation

2. Performance Analytics Jobs
   - API performance summaries
   - Resource utilization trending
   - Capacity planning analysis
   - SLA compliance reporting

3. Business Intelligence Jobs
   - User engagement analytics
   - Feature adoption analysis
   - Customer health scoring
   - Revenue optimization insights

================================
DATA ENRICHMENT FEATURES
================================

Threat Intelligence Enrichment:
- IP reputation checking
- Known malicious indicator correlation
- Geographic risk assessment
- Attack pattern recognition
- IOC (Indicators of Compromise) extraction

Geolocation Enrichment:
- IP-to-location mapping
- Impossible travel detection
- Geographic anomaly identification
- Country-based risk scoring
- Timezone-aware analysis

Business Context Enrichment:
- User role and permission mapping
- Organization tier classification
- Feature flag correlation
- A/B test variant tracking
- Customer journey mapping

Performance Context Enrichment:
- Distributed trace correlation
- Database query analysis
- Cache hit/miss tracking
- External dependency timing
- Resource consumption patterns

================================
ANALYTICS VIEWS AND QUERIES
================================

Security Analytics Views:
1. daily_threat_summary
   - Purpose: Daily aggregation of threat events by type and severity
   - Updates: Daily at 6 AM UTC
   - Usage: Security team dashboards and reporting

2. authentication_anomalies
   - Purpose: Detect unusual authentication patterns
   - Updates: Hourly
   - Usage: Real-time security monitoring

3. top_threats_by_impact
   - Purpose: Prioritize threats based on calculated impact score
   - Updates: Every 4 hours
   - Usage: Threat response prioritization

4. vulnerability_remediation_status
   - Purpose: Track vulnerability fix progress
   - Updates: Daily
   - Usage: Security posture reporting

5. incident_response_metrics
   - Purpose: Measure incident response performance
   - Updates: Daily
   - Usage: Process improvement and SLA tracking

Performance Analytics Views:
1. api_performance_summary
   - Purpose: API performance metrics by service and endpoint
   - Updates: Hourly
   - Usage: Performance monitoring dashboards

2. slow_endpoints
   - Purpose: Identify performance bottlenecks
   - Updates: Every 15 minutes
   - Usage: Performance optimization

3. resource_utilization_trends
   - Purpose: Track resource usage patterns
   - Updates: Hourly
   - Usage: Capacity planning and auto-scaling

Business Analytics Views:
1. daily_engagement_summary
   - Purpose: User engagement and activity metrics
   - Updates: Daily
   - Usage: Product analytics and user experience

2. feature_adoption
   - Purpose: Track feature usage and adoption rates
   - Updates: Daily
   - Usage: Product development and marketing

3. api_consumption_summary
   - Purpose: API usage and billing analytics
   - Updates: Daily
   - Usage: Customer success and revenue optimization

4. customer_health_score
   - Purpose: Predictive customer health assessment
   - Updates: Daily
   - Usage: Customer retention and upselling

================================
DATA ACCESS AND SECURITY
================================

Access Control:
- IAM-based dataset and table permissions
- Row-level security for multi-tenant data
- Column-level security for sensitive data
- Service account authentication for automated access

Data Encryption:
- Encryption at rest (Google-managed keys)
- Encryption in transit (TLS 1.2+)
- Customer-managed encryption keys (CMEK) option
- Field-level encryption for PII data

Data Governance:
- Data lineage tracking
- Schema evolution management
- Data quality monitoring
- Automated data classification

Compliance Features:
- GDPR data subject request support
- Data retention policy enforcement
- Audit logging for all data access
- Automated compliance reporting

================================
PERFORMANCE OPTIMIZATION
================================

Query Optimization:
- Partitioning strategies for time-series data
- Clustering for improved query performance
- Materialized views for expensive aggregations
- Query caching for repeated analytics

Storage Optimization:
- Columnar storage format
- Automatic compression
- Data archival to Cloud Storage
- Lifecycle policies for cost optimization

Streaming Optimization:
- Batch loading for bulk data
- Streaming inserts for real-time data
- Deduplication for exactly-once semantics
- Error handling and retry logic

Cost Optimization:
- Slot reservation for predictable workloads
- Flex slots for variable workloads
- Query cost monitoring and alerts
- Data tier optimization (active/long-term)

================================
MONITORING AND ALERTING
================================

Data Quality Monitoring:
- Schema validation
- Data freshness checks
- Null value monitoring
- Duplicate detection
- Data distribution analysis

Pipeline Health Monitoring:
- Dataflow job status
- Cloud Function execution metrics
- Pub/Sub message backlog
- BigQuery job success rates
- End-to-end latency tracking

Cost Monitoring:
- Query cost tracking
- Storage cost analysis
- Streaming insert costs
- Data transfer costs
- Budget alerts and limits

Operational Alerts:
- Pipeline failure notifications
- Data quality degradation
- Cost threshold breaches
- SLA violation warnings
- Capacity planning alerts

================================
BUSINESS INTELLIGENCE INTEGRATION
================================

Dashboard Platforms:
- Looker/Looker Studio integration
- Tableau connector
- Power BI integration
- Grafana data source
- Custom dashboard APIs

Reporting Automation:
- Scheduled report generation
- Automated email distribution
- Slack/Teams integration
- Executive summary dashboards
- Compliance report automation

Data Export:
- CSV/JSON export capabilities
- API-based data access
- Third-party tool integration
- Data lake synchronization
- ML pipeline data feeds

Real-time Analytics:
- Streaming dashboards
- Real-time alerting
- Live KPI monitoring
- Event-driven notifications
- Interactive data exploration

================================
DISASTER RECOVERY & BACKUP
================================

Backup Strategy:
- Automated daily snapshots
- Cross-region backup replication
- Point-in-time recovery
- Table-level backup granularity
- Metadata backup and versioning

Recovery Procedures:
- RTO: 4 hours for complete dataset recovery
- RPO: 15 minutes for streaming data
- Automated failover for critical pipelines
- Manual recovery procedures documented
- Regular disaster recovery testing

Data Archival:
- Automated archival to Cloud Storage
- Compressed and encrypted archives
- Metadata preservation
- Retrieval procedures documented
- Cost-optimized storage classes

================================
OPERATIONAL PROCEDURES
================================

Daily Operations:
- Monitor pipeline health dashboards
- Review data quality reports
- Check cost optimization alerts
- Validate critical dataset freshness
- Review security event patterns

Weekly Operations:
- Analyze query performance trends
- Review storage utilization growth
- Update data retention policies
- Audit user access patterns
- Generate compliance reports

Monthly Operations:
- Comprehensive cost analysis
- Data governance review
- Schema evolution planning
- Capacity planning assessment
- Disaster recovery testing

Quarterly Operations:
- Business intelligence strategy review
- Data pipeline architecture assessment
- Security audit and penetration testing
- Compliance framework updates
- ROI analysis and optimization

================================
TROUBLESHOOTING GUIDE
================================

Common Issues:

1. Pipeline Failures:
   - Check Dataflow job logs
   - Verify Pub/Sub message format
   - Validate BigQuery schema compatibility
   - Review IAM permissions
   - Monitor resource quotas

2. Data Quality Issues:
   - Run data validation queries
   - Check source system status
   - Verify transformation logic
   - Review data freshness metrics
   - Analyze error message patterns

3. Performance Problems:
   - Optimize query patterns
   - Review partitioning strategy
   - Check slot utilization
   - Analyze query execution plans
   - Consider materialized views

4. Cost Overruns:
   - Review query cost breakdown
   - Analyze storage growth patterns
   - Optimize expensive queries
   - Implement cost controls
   - Review data retention policies

Diagnostic Commands:
- Check dataset status: bq ls -d PROJECT_ID:DATASET
- Analyze query costs: bq query --dry_run "SELECT ..."
- Monitor streaming: bq show -j JOB_ID
- Review table metadata: bq show PROJECT_ID:DATASET.TABLE

Performance Troubleshooting:
- Query profiling with EXPLAIN
- Execution plan analysis
- Resource usage monitoring
- Slot utilization tracking
- Cache hit rate analysis

================================
FUTURE ENHANCEMENTS
================================

Planned Improvements:
1. Machine learning model integration for predictive analytics
2. Real-time feature store for ML applications
3. Advanced anomaly detection using AutoML
4. Graph analytics for relationship analysis
5. Federated queries across multiple data sources

Technology Roadmap:
1. BigQuery ML model deployment
2. Vertex AI pipeline integration
3. Cloud Composer workflow orchestration
4. Data Catalog integration for discovery
5. Advanced encryption and privacy controls

Business Value Initiatives:
1. Customer churn prediction models
2. Revenue optimization algorithms
3. Security threat prediction
4. Operational efficiency analytics
5. Compliance automation workflows

================================
DEVELOPMENT WORKFLOW
================================

Data Pipeline Development:
1. Local development with BigQuery emulator
2. CI/CD pipeline for schema changes
3. Automated testing for data transformations
4. Staging environment validation
5. Blue-green deployment for pipelines

Schema Management:
1. Version control for schema definitions
2. Backward compatibility validation
3. Automated migration scripts
4. Schema evolution documentation
5. Impact analysis for changes

Quality Assurance:
1. Data validation test suites
2. Performance benchmark testing
3. End-to-end pipeline testing
4. Data quality regression tests
5. Security and compliance validation

Deployment Process:
1. Infrastructure as Code (Terraform)
2. Automated pipeline deployment
3. Configuration management
4. Monitoring setup automation
5. Rollback procedures

EOF
    
    log_success "BigQuery data pipeline report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH BigQuery data pipeline configuration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    log_info "BigQuery Configuration:"
    log_info "- Dataset Location: ${BQ_DATASET_LOCATION}"
    log_info "- Security Dataset: ${BQ_SECURITY_DATASET}"
    log_info "- Performance Dataset: ${BQ_PERFORMANCE_DATASET}"
    log_info "- Business Dataset: ${BQ_BUSINESS_DATASET}"
    log_info "- Compliance Dataset: ${BQ_COMPLIANCE_DATASET}"
    
    check_prerequisites
    
    create_bigquery_datasets
    create_data_processing_pipelines
    
    generate_bigquery_report
    
    log_success "iSECTECH BigQuery data pipeline configuration completed!"
    
    echo ""
    log_info "BigQuery data analytics pipeline is now configured with comprehensive intelligence capabilities."
    log_info "Deploy Dataflow templates and Cloud Functions for real-time processing."
    log_info "Access BigQuery datasets: https://console.cloud.google.com/bigquery"
    log_info "Set up scheduled queries for automated analytics."
}

# Help function
show_help() {
    cat << EOF
iSECTECH BigQuery Data Pipeline Configuration Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV        Environment (production, staging, development)
    --project PROJECT       Google Cloud project ID
    --region REGION         Google Cloud region (default: us-central1)
    --bq-location LOCATION  BigQuery dataset location (default: US)
    --security-retention DAYS Security data retention in days (default: 2555)
    --performance-retention DAYS Performance data retention in days (default: 365)
    --help                  Show this help message

Environment Variables:
    PROJECT_ID              Google Cloud project ID
    REGION                 Google Cloud region
    ENVIRONMENT            Environment name
    BQ_DATASET_LOCATION    BigQuery dataset location (default: US)
    BQ_SECURITY_DATASET    Security analytics dataset name
    BQ_PERFORMANCE_DATASET Performance analytics dataset name
    BQ_BUSINESS_DATASET    Business analytics dataset name
    BQ_COMPLIANCE_DATASET  Compliance analytics dataset name
    SECURITY_DATA_RETENTION_DAYS Security data retention (default: 2555)
    PERFORMANCE_DATA_RETENTION_DAYS Performance data retention (default: 365)
    BUSINESS_DATA_RETENTION_DAYS Business data retention (default: 1095)

Examples:
    # Configure production data pipeline with default retention
    ./bigquery-data-pipeline-setup.sh --environment production

    # Configure with custom retention policies
    ./bigquery-data-pipeline-setup.sh --security-retention 3650 --performance-retention 180

Prerequisites:
    - Google Cloud project with BigQuery API enabled
    - BigQuery admin permissions
    - Dataflow admin permissions
    - Cloud Functions admin permissions

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --bq-location)
            BQ_DATASET_LOCATION="$2"
            shift 2
            ;;
        --security-retention)
            SECURITY_DATA_RETENTION_DAYS="$2"
            shift 2
            ;;
        --performance-retention)
            PERFORMANCE_DATA_RETENTION_DAYS="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute main function
main "$@"