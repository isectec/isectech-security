# Infrastructure Rollback Guide - iSECTECH Security Platform

**Document Version:** 1.0  
**Last Updated:** 2025-08-05  
**Owner:** DevOps Team  
**Classification:** CONFIDENTIAL - Internal Use Only

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Infrastructure Components](#infrastructure-components)
4. [Rollback Scenarios](#rollback-scenarios)
5. [Terraform State Management](#terraform-state-management)
6. [Service Rollback Procedures](#service-rollback-procedures)
7. [Database Rollback Procedures](#database-rollback-procedures)
8. [Network and Security Rollback](#network-and-security-rollback)
9. [Validation and Testing](#validation-and-testing)
10. [Emergency Contacts](#emergency-contacts)
11. [Post-Rollback Actions](#post-rollback-actions)

## Overview

This guide provides comprehensive procedures for rolling back infrastructure changes for the iSECTECH Security Platform. It covers Terraform state rollbacks, service deployment rollbacks, database schema rollbacks, and network configuration rollbacks.

### Infrastructure Architecture Overview

```
iSECTECH Security Platform Infrastructure
├── Compute Resources
│   ├── Cloud Run Services (Frontend, API, Admin, Monitoring)
│   ├── Cloud Functions (Event Processing, Webhooks)
│   └── Cloud Build (CI/CD Pipeline)
├── Data Layer
│   ├── Cloud SQL (PostgreSQL - Primary Database)
│   ├── Cloud Firestore (Real-time Security Events)
│   ├── Cloud Storage (File Storage, Backups)
│   └── Cloud Memorystore (Redis Cache)
├── Network & Security
│   ├── VPC Networks (Production, Staging, Development)
│   ├── Cloud Load Balancer (Global HTTPS Load Balancer)
│   ├── Cloud Armor (WAF and DDoS Protection)
│   ├── Cloud DNS (Domain Management)
│   └── Certificate Manager (SSL/TLS Certificates)
├── Monitoring & Logging
│   ├── Cloud Monitoring (Metrics and Alerting)
│   ├── Cloud Logging (Centralized Logs)
│   ├── Cloud Trace (Distributed Tracing)
│   └── Error Reporting (Application Errors)
└── Security & IAM
    ├── Identity and Access Management (IAM)
    ├── Secret Manager (Credentials and Keys)
    ├── Cloud KMS (Encryption Keys)
    └── Security Command Center (Security Insights)
```

### Rollback Objectives

- **RTO (Recovery Time Objective):** 20 minutes for complete infrastructure rollback
- **RPO (Recovery Point Objective):** 15 minutes for infrastructure state
- **Maximum Allowable Downtime:** 30 minutes for critical services

## Prerequisites

### Required Access and Permissions

```bash
# Required Google Cloud IAM roles
- roles/editor (Project Editor - for emergency rollbacks)
- roles/compute.admin (Compute Admin)
- roles/cloudsql.admin (Cloud SQL Admin) 
- roles/run.admin (Cloud Run Admin)
- roles/storage.admin (Storage Admin)
- roles/dns.admin (DNS Administrator)
- roles/secretmanager.admin (Secret Manager Admin)
- roles/iam.serviceAccountAdmin (Service Account Admin)
```

### Required Tools and Environment

```bash
# Install required tools
gcloud components install --quiet
terraform --version
kubectl version --client
docker --version
git --version

# Configure environment
export PROJECT_ID="isectech-security-platform"
export REGION="us-central1"
export TERRAFORM_STATE_BUCKET="gs://isectech-terraform-state"
export BACKUP_BUCKET="gs://isectech-infrastructure-backups"
export GIT_REPO="https://github.com/isectech/security-platform-infrastructure"
```

### Terraform Backend Configuration

```hcl
# terraform/environments/production/backend.tf
terraform {
  backend "gcs" {
    bucket = "isectech-terraform-state"
    prefix = "production"
  }
  
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}
```

## Infrastructure Components

### Terraform State Structure

```
terraform/
├── environments/
│   ├── production/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── terraform.tfvars
│   ├── staging/
│   └── development/
├── modules/
│   ├── cloud-run/
│   ├── cloud-sql/
│   ├── load-balancer/
│   ├── vpc-network/
│   ├── dns-ssl/
│   └── monitoring/
└── shared/
    ├── iam.tf
    ├── kms.tf
    └── secrets.tf
```

### Critical Infrastructure Components

1. **Cloud Run Services**
   - `isectech-api` (Main API Gateway)
   - `isectech-frontend` (React Frontend)
   - `isectech-admin` (Admin Portal)
   - `isectech-monitoring` (Monitoring Dashboard)

2. **Database Resources**
   - `isectech-db-primary` (Cloud SQL PostgreSQL)
   - `isectech-cache` (Cloud Memorystore Redis)
   - `isectech-firestore` (Document Database)

3. **Network Infrastructure**
   - `isectech-vpc-prod` (Production VPC)
   - `isectech-lb-global` (Global Load Balancer)
   - `isectech-dns-zone` (DNS Zone)

## Rollback Scenarios

### Scenario 1: Failed Terraform Deployment

**Symptoms:**
- Terraform apply failed with resource conflicts
- Infrastructure in inconsistent state
- Services unreachable or degraded

**Impact:** CRITICAL - Infrastructure partially deployed

### Scenario 2: Cloud Run Service Deployment Failure

**Symptoms:**
- New service revision failing health checks
- Application returning 5xx errors
- Performance degradation

**Impact:** HIGH - Service degradation

### Scenario 3: Database Schema Migration Failure

**Symptoms:**
- Database connectivity issues
- Application data integrity errors
- Migration script failures

**Impact:** CRITICAL - Data layer compromise

### Scenario 4: Network Configuration Issues

**Symptoms:**
- Load balancer routing failures
- SSL/TLS certificate issues
- VPC connectivity problems

**Impact:** HIGH - Network connectivity issues

### Scenario 5: Monitoring and Security Policy Changes

**Symptoms:**
- Monitoring alerts not firing
- Security policies blocking legitimate traffic
- Compliance violations

**Impact:** MEDIUM - Operational visibility issues

## Terraform State Management

### Terraform State Backup and Recovery

```bash
#!/bin/bash
# Terraform State Backup and Recovery Script
# Usage: ./terraform-state-rollback.sh [environment] [rollback-timestamp]

set -euo pipefail

ENVIRONMENT=${1:-"production"}
ROLLBACK_TIMESTAMP=${2:-}
ROLLBACK_LOG="/tmp/terraform-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Terraform State Rollback for $ENVIRONMENT - $(date)" | tee -a $ROLLBACK_LOG

# Step 1: Backup current state
echo "Step 1: Backing up current Terraform state..." | tee -a $ROLLBACK_LOG
cd terraform/environments/$ENVIRONMENT

# Download current state
terraform init 2>&1 | tee -a $ROLLBACK_LOG
gsutil cp $TERRAFORM_STATE_BUCKET/$ENVIRONMENT/default.tfstate \
    /tmp/current-state-backup-$(date +%Y%m%d%H%M%S).tfstate 2>&1 | tee -a $ROLLBACK_LOG

# Step 2: List available state backups
echo "Step 2: Available state backups..." | tee -a $ROLLBACK_LOG
gsutil ls -la $BACKUP_BUCKET/terraform-state/$ENVIRONMENT/ | tail -20 | tee -a $ROLLBACK_LOG

# Step 3: Select rollback target
if [[ -z "$ROLLBACK_TIMESTAMP" ]]; then
    echo "No rollback timestamp specified. Showing recent backups:" | tee -a $ROLLBACK_LOG
    gsutil ls $BACKUP_BUCKET/terraform-state/$ENVIRONMENT/ | \
        grep -E "[0-9]{8}T[0-9]{6}" | tail -10 | tee -a $ROLLBACK_LOG
    
    echo "Please run script with timestamp: ./terraform-state-rollback.sh $ENVIRONMENT YYYYMMDDTHHMMSS" | tee -a $ROLLBACK_LOG
    exit 1
fi

# Step 4: Restore state from backup
echo "Step 4: Restoring Terraform state from backup timestamp: $ROLLBACK_TIMESTAMP" | tee -a $ROLLBACK_LOG

if ! gsutil ls $BACKUP_BUCKET/terraform-state/$ENVIRONMENT/terraform-state-$ROLLBACK_TIMESTAMP.tfstate >/dev/null 2>&1; then
    echo "ERROR: Backup not found for timestamp $ROLLBACK_TIMESTAMP" | tee -a $ROLLBACK_LOG
    exit 1
fi

# Download backup state
gsutil cp $BACKUP_BUCKET/terraform-state/$ENVIRONMENT/terraform-state-$ROLLBACK_TIMESTAMP.tfstate \
    /tmp/rollback-state.tfstate 2>&1 | tee -a $ROLLBACK_LOG

# Upload to state bucket
gsutil cp /tmp/rollback-state.tfstate \
    $TERRAFORM_STATE_BUCKET/$ENVIRONMENT/default.tfstate 2>&1 | tee -a $ROLLBACK_LOG

# Step 5: Reinitialize Terraform
echo "Step 5: Reinitializing Terraform..." | tee -a $ROLLBACK_LOG
terraform init -reconfigure 2>&1 | tee -a $ROLLBACK_LOG

# Step 6: Plan rollback changes
echo "Step 6: Planning Terraform rollback changes..." | tee -a $ROLLBACK_LOG
terraform plan -out=rollback.tfplan 2>&1 | tee -a $ROLLBACK_LOG

# Step 7: Apply rollback (with confirmation)
echo "Step 7: Ready to apply rollback changes..." | tee -a $ROLLBACK_LOG
echo "MANUAL CONFIRMATION REQUIRED: Review the plan above and apply with:" | tee -a $ROLLBACK_LOG
echo "  terraform apply rollback.tfplan" | tee -a $ROLLBACK_LOG

echo "Terraform State Rollback preparation completed - $(date)" | tee -a $ROLLBACK_LOG
echo "Rollback log saved to: $ROLLBACK_LOG"
```

### Terraform Import Recovery

```bash
#!/bin/bash
# Terraform Import Recovery Script
# Usage: ./terraform-import-recovery.sh [environment] [resource-type] [resource-name] [resource-id]

set -euo pipefail

ENVIRONMENT=${1:-"production"}
RESOURCE_TYPE=${2}
RESOURCE_NAME=${3}
RESOURCE_ID=${4}
IMPORT_LOG="/tmp/terraform-import-$(date +%Y%m%d%H%M%S).log"

echo "Starting Terraform Import Recovery - $(date)" | tee -a $IMPORT_LOG
echo "Environment: $ENVIRONMENT" | tee -a $IMPORT_LOG
echo "Resource: $RESOURCE_TYPE.$RESOURCE_NAME" | tee -a $IMPORT_LOG
echo "Google Cloud Resource ID: $RESOURCE_ID" | tee -a $IMPORT_LOG

cd terraform/environments/$ENVIRONMENT

# Step 1: Initialize Terraform
echo "Step 1: Initializing Terraform..." | tee -a $IMPORT_LOG
terraform init 2>&1 | tee -a $IMPORT_LOG

# Step 2: Import existing resource
echo "Step 2: Importing existing resource..." | tee -a $IMPORT_LOG
terraform import $RESOURCE_TYPE.$RESOURCE_NAME $RESOURCE_ID 2>&1 | tee -a $IMPORT_LOG

# Step 3: Generate configuration for review
echo "Step 3: Generating configuration template..." | tee -a $IMPORT_LOG
case $RESOURCE_TYPE in
    "google_cloud_run_service")
        cat << EOF > imported-$RESOURCE_NAME.tf
resource "google_cloud_run_service" "$RESOURCE_NAME" {
  name     = "$(echo $RESOURCE_ID | cut -d'/' -f6)"
  location = "$(echo $RESOURCE_ID | cut -d'/' -f4)"
  project  = "$(echo $RESOURCE_ID | cut -d'/' -f2)"
  
  # Configuration will be generated after import
  # Review and update as needed
}
EOF
        ;;
    "google_sql_database_instance")
        cat << EOF > imported-$RESOURCE_NAME.tf
resource "google_sql_database_instance" "$RESOURCE_NAME" {
  name             = "$(echo $RESOURCE_ID | cut -d'/' -f4)"
  project          = "$(echo $RESOURCE_ID | cut -d'/' -f2)"
  database_version = "POSTGRES_15"
  region          = "$REGION"
  
  # Configuration will be generated after import
  # Review and update as needed
}
EOF
        ;;
    *)
        echo "# Resource type $RESOURCE_TYPE imported" > imported-$RESOURCE_NAME.tf
        echo "# Please add appropriate configuration manually" >> imported-$RESOURCE_NAME.tf
        ;;
esac

# Step 4: Plan to verify import
echo "Step 4: Planning to verify import..." | tee -a $IMPORT_LOG
terraform plan 2>&1 | tee -a $IMPORT_LOG

echo "Terraform Import Recovery completed - $(date)" | tee -a $IMPORT_LOG
echo "Import log saved to: $IMPORT_LOG"
echo "Review imported-$RESOURCE_NAME.tf and update configuration as needed"
```

## Service Rollback Procedures

### Cloud Run Service Rollback

```bash
#!/bin/bash
# Cloud Run Service Rollback Script
# Usage: ./cloud-run-rollback.sh [service-name] [revision-number]

set -euo pipefail

SERVICE_NAME=${1:-"isectech-api"}
TARGET_REVISION=${2:-}
SERVICE_LOG="/tmp/service-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Cloud Run Service Rollback for $SERVICE_NAME - $(date)" | tee -a $SERVICE_LOG

# Step 1: List current and previous revisions
echo "Step 1: Listing current and previous revisions..." | tee -a $SERVICE_LOG
gcloud run revisions list \
    --service=$SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="table(metadata.name,status.conditions[0].status,metadata.creationTimestamp)" \
    2>&1 | tee -a $SERVICE_LOG

# Step 2: Get current traffic allocation
echo "Step 2: Current traffic allocation..." | tee -a $SERVICE_LOG
CURRENT_TRAFFIC=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="json" | jq -r '.spec.traffic')

echo "Current traffic allocation: $CURRENT_TRAFFIC" | tee -a $SERVICE_LOG

# Step 3: Determine rollback target
if [[ -z "$TARGET_REVISION" ]]; then
    echo "No target revision specified. Getting last stable revision..." | tee -a $SERVICE_LOG
    
    # Get the second most recent revision (assuming current is failing)
    TARGET_REVISION=$(gcloud run revisions list \
        --service=$SERVICE_NAME \
        --region=$REGION \
        --project=$PROJECT_ID \
        --format="value(metadata.name)" \
        --sort-by="~metadata.creationTimestamp" \
        --limit=2 | tail -1)
    
    echo "Auto-selected rollback target: $TARGET_REVISION" | tee -a $SERVICE_LOG
fi

if [[ -z "$TARGET_REVISION" ]]; then
    echo "ERROR: Could not determine rollback target revision" | tee -a $SERVICE_LOG
    exit 1
fi

# Step 4: Validate target revision exists and is healthy
echo "Step 4: Validating target revision..." | tee -a $SERVICE_LOG
REVISION_STATUS=$(gcloud run revisions describe $TARGET_REVISION \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="value(status.conditions[0].status)" 2>/dev/null || echo "NOT_FOUND")

if [[ "$REVISION_STATUS" != "True" ]]; then
    echo "ERROR: Target revision $TARGET_REVISION is not healthy (status: $REVISION_STATUS)" | tee -a $SERVICE_LOG
    exit 1
fi

echo "Target revision is healthy: $TARGET_REVISION" | tee -a $SERVICE_LOG

# Step 5: Perform gradual rollback (blue-green deployment)
echo "Step 5: Performing gradual rollback..." | tee -a $SERVICE_LOG

# Phase 1: Route 10% of traffic to old revision
echo "  Phase 1: Routing 10% traffic to target revision..." | tee -a $SERVICE_LOG
gcloud run services update-traffic $SERVICE_NAME \
    --to-revisions=$TARGET_REVISION=10 \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $SERVICE_LOG

# Wait and monitor
echo "  Waiting 2 minutes for monitoring..." | tee -a $SERVICE_LOG
sleep 120

# Check error rates
ERROR_RATE=$(gcloud logging read \
    "resource.type=\"cloud_run_revision\" resource.labels.service_name=\"$SERVICE_NAME\" severity>=ERROR" \
    --limit=10 --format="value(timestamp)" --freshness=2m | wc -l)

echo "  Error rate in last 2 minutes: $ERROR_RATE events" | tee -a $SERVICE_LOG

if [[ $ERROR_RATE -gt 5 ]]; then
    echo "  WARNING: High error rate detected. Consider aborting rollback." | tee -a $SERVICE_LOG
    echo "  Continue? (y/N): "
    read -r CONTINUE
    if [[ "$CONTINUE" != "y" ]]; then
        echo "  Rollback aborted by user" | tee -a $SERVICE_LOG
        exit 1
    fi
fi

# Phase 2: Route 50% of traffic
echo "  Phase 2: Routing 50% traffic to target revision..." | tee -a $SERVICE_LOG
gcloud run services update-traffic $SERVICE_NAME \
    --to-revisions=$TARGET_REVISION=50 \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $SERVICE_LOG

sleep 120

# Phase 3: Route 100% of traffic (complete rollback)
echo "  Phase 3: Routing 100% traffic to target revision..." | tee -a $SERVICE_LOG
gcloud run services update-traffic $SERVICE_NAME \
    --to-revisions=$TARGET_REVISION=100 \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $SERVICE_LOG

# Step 6: Verify rollback success
echo "Step 6: Verifying rollback success..." | tee -a $SERVICE_LOG
FINAL_TRAFFIC=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="json" | jq -r '.spec.traffic[0].revisionName')

echo "Final active revision: $FINAL_TRAFFIC" | tee -a $SERVICE_LOG

if [[ "$FINAL_TRAFFIC" == "$TARGET_REVISION" ]]; then
    echo "SUCCESS: Rollback completed successfully" | tee -a $SERVICE_LOG
else
    echo "ERROR: Rollback may have failed. Current revision: $FINAL_TRAFFIC" | tee -a $SERVICE_LOG
fi

# Step 7: Test service health
echo "Step 7: Testing service health..." | tee -a $SERVICE_LOG
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="value(status.url)")

HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $SERVICE_URL/health || echo "000")
echo "Service health check: HTTP $HEALTH_STATUS" | tee -a $SERVICE_LOG

if [[ "$HEALTH_STATUS" == "200" ]]; then
    echo "SUCCESS: Service is responding normally" | tee -a $SERVICE_LOG
else
    echo "WARNING: Service health check failed" | tee -a $SERVICE_LOG
fi

echo "Cloud Run Service Rollback completed - $(date)" | tee -a $SERVICE_LOG
echo "Service rollback log saved to: $SERVICE_LOG"
```

### Container Image Rollback

```bash
#!/bin/bash
# Container Image Rollback Script
# Usage: ./container-image-rollback.sh [service-name] [image-tag]

set -euo pipefail

SERVICE_NAME=${1:-"isectech-api"}
IMAGE_TAG=${2:-}
IMAGE_LOG="/tmp/image-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Container Image Rollback for $SERVICE_NAME - $(date)" | tee -a $IMAGE_LOG

# Step 1: List available image tags
echo "Step 1: Listing available container images..." | tee -a $IMAGE_LOG
gcloud container images list-tags gcr.io/$PROJECT_ID/$SERVICE_NAME \
    --limit=10 \
    --sort-by=~TIMESTAMP \
    --format="table(tags,timestamp,digest.slice(7:19))" 2>&1 | tee -a $IMAGE_LOG

# Step 2: Determine rollback image
if [[ -z "$IMAGE_TAG" ]]; then
    echo "No image tag specified. Getting previous stable image..." | tee -a $IMAGE_LOG
    
    # Get the second most recent image tag
    IMAGE_TAG=$(gcloud container images list-tags gcr.io/$PROJECT_ID/$SERVICE_NAME \
        --limit=2 \
        --sort-by=~TIMESTAMP \
        --format="value(tags)" | tail -1 | cut -d';' -f1)
    
    echo "Auto-selected rollback image tag: $IMAGE_TAG" | tee -a $IMAGE_LOG
fi

if [[ -z "$IMAGE_TAG" ]]; then
    echo "ERROR: Could not determine rollback image tag" | tee -a $IMAGE_LOG
    exit 1
fi

# Step 3: Validate image exists
echo "Step 3: Validating rollback image..." | tee -a $IMAGE_LOG
ROLLBACK_IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME:$IMAGE_TAG"

if ! gcloud container images describe $ROLLBACK_IMAGE >/dev/null 2>&1; then
    echo "ERROR: Rollback image not found: $ROLLBACK_IMAGE" | tee -a $IMAGE_LOG
    exit 1
fi

echo "Rollback image validated: $ROLLBACK_IMAGE" | tee -a $IMAGE_LOG

# Step 4: Deploy new revision with rollback image
echo "Step 4: Deploying new revision with rollback image..." | tee -a $IMAGE_LOG

gcloud run deploy $SERVICE_NAME \
    --image=$ROLLBACK_IMAGE \
    --region=$REGION \
    --project=$PROJECT_ID \
    --no-traffic 2>&1 | tee -a $IMAGE_LOG

# Step 5: Get new revision name
NEW_REVISION=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="value(spec.template.metadata.name)")

echo "New revision created: $NEW_REVISION" | tee -a $IMAGE_LOG

# Step 6: Gradually shift traffic to new revision
echo "Step 6: Gradually shifting traffic to rollback revision..." | tee -a $IMAGE_LOG

# 10% traffic
gcloud run services update-traffic $SERVICE_NAME \
    --to-revisions=$NEW_REVISION=10 \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $IMAGE_LOG

sleep 60

# 50% traffic  
gcloud run services update-traffic $SERVICE_NAME \
    --to-revisions=$NEW_REVISION=50 \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $IMAGE_LOG

sleep 60

# 100% traffic
gcloud run services update-traffic $SERVICE_NAME \
    --to-revisions=$NEW_REVISION=100 \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $IMAGE_LOG

# Step 7: Verify deployment
echo "Step 7: Verifying image rollback..." | tee -a $IMAGE_LOG

CURRENT_IMAGE=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --format="value(spec.template.spec.containers[0].image)")

echo "Current deployed image: $CURRENT_IMAGE" | tee -a $IMAGE_LOG

if [[ "$CURRENT_IMAGE" == "$ROLLBACK_IMAGE" ]]; then
    echo "SUCCESS: Image rollback completed successfully" | tee -a $IMAGE_LOG
else
    echo "ERROR: Image rollback may have failed" | tee -a $IMAGE_LOG
fi

echo "Container Image Rollback completed - $(date)" | tee -a $IMAGE_LOG
echo "Image rollback log saved to: $IMAGE_LOG"
```

## Database Rollback Procedures

### Cloud SQL Database Rollback

```bash
#!/bin/bash
# Cloud SQL Database Rollback Script
# Usage: ./database-rollback.sh [instance-name] [backup-timestamp]

set -euo pipefail

INSTANCE_NAME=${1:-"isectech-db-primary"}
BACKUP_TIMESTAMP=${2:-}
DB_LOG="/tmp/database-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Cloud SQL Database Rollback for $INSTANCE_NAME - $(date)" | tee -a $DB_LOG

# Step 1: List available backups
echo "Step 1: Listing available database backups..." | tee -a $DB_LOG
gcloud sql backups list \
    --instance=$INSTANCE_NAME \
    --project=$PROJECT_ID \
    --format="table(id,windowStartTime,type,status)" \
    --limit=10 2>&1 | tee -a $DB_LOG

# Step 2: Determine rollback target
if [[ -z "$BACKUP_TIMESTAMP" ]]; then
    echo "No backup timestamp specified. Getting most recent backup..." | tee -a $DB_LOG
    
    BACKUP_TIMESTAMP=$(gcloud sql backups list \
        --instance=$INSTANCE_NAME \
        --project=$PROJECT_ID \
        --format="value(id)" \
        --limit=1)
    
    echo "Auto-selected backup: $BACKUP_TIMESTAMP" | tee -a $DB_LOG
fi

if [[ -z "$BACKUP_TIMESTAMP" ]]; then
    echo "ERROR: Could not determine backup timestamp" | tee -a $DB_LOG
    exit 1
fi

# Step 3: Create current database backup before rollback
echo "Step 3: Creating pre-rollback backup..." | tee -a $DB_LOG
PRE_ROLLBACK_BACKUP="pre-rollback-$(date +%Y%m%d%H%M%S)"

gcloud sql backups create \
    --instance=$INSTANCE_NAME \
    --project=$PROJECT_ID \
    --description="Pre-rollback backup created $(date)" 2>&1 | tee -a $DB_LOG

# Step 4: Stop application services to prevent data corruption
echo "Step 4: Stopping application services..." | tee -a $DB_LOG
SERVICES=("isectech-api" "isectech-admin" "isectech-monitoring")

for service in "${SERVICES[@]}"; do
    echo "  Scaling down $service..." | tee -a $DB_LOG
    gcloud run services update $service \
        --region=$REGION \
        --project=$PROJECT_ID \
        --min-instances=0 \
        --max-instances=0 2>&1 | tee -a $DB_LOG
done

# Wait for services to scale down
echo "  Waiting 30 seconds for services to scale down..." | tee -a $DB_LOG
sleep 30

# Step 5: Create temporary instance for restoration
echo "Step 5: Creating temporary database instance for restoration..." | tee -a $DB_LOG
TEMP_INSTANCE="$INSTANCE_NAME-rollback-temp"

gcloud sql instances create $TEMP_INSTANCE \
    --database-version=POSTGRES_15 \
    --tier=db-g1-small \
    --region=$REGION \
    --project=$PROJECT_ID \
    --backup=$BACKUP_TIMESTAMP \
    --source-instance=$INSTANCE_NAME 2>&1 | tee -a $DB_LOG

# Step 6: Wait for restore to complete
echo "Step 6: Waiting for database restore to complete..." | tee -a $DB_LOG
MAX_WAIT_MINUTES=30
WAIT_COUNT=0

while [[ $WAIT_COUNT -lt $MAX_WAIT_MINUTES ]]; do
    INSTANCE_STATUS=$(gcloud sql instances describe $TEMP_INSTANCE \
        --project=$PROJECT_ID \
        --format="value(state)" 2>/dev/null || echo "UNKNOWN")
    
    echo "  Restore status: $INSTANCE_STATUS (waited ${WAIT_COUNT} minutes)" | tee -a $DB_LOG
    
    if [[ "$INSTANCE_STATUS" == "RUNNABLE" ]]; then
        echo "  Database restore completed!" | tee -a $DB_LOG
        break
    elif [[ "$INSTANCE_STATUS" == "FAILED" ]]; then
        echo "  ERROR: Database restore failed!" | tee -a $DB_LOG
        exit 1
    fi
    
    sleep 60
    ((WAIT_COUNT++))
done

if [[ $WAIT_COUNT -ge $MAX_WAIT_MINUTES ]]; then
    echo "ERROR: Database restore timeout after $MAX_WAIT_MINUTES minutes" | tee -a $DB_LOG
    exit 1
fi

# Step 7: Validate restored data
echo "Step 7: Validating restored database..." | tee -a $DB_LOG

# Get temporary instance connection info
TEMP_DB_IP=$(gcloud sql instances describe $TEMP_INSTANCE \
    --project=$PROJECT_ID \
    --format="value(ipAddresses[0].ipAddress)")

echo "  Temporary database IP: $TEMP_DB_IP" | tee -a $DB_LOG

# Basic connectivity test (requires Cloud SQL Proxy)
gcloud sql connect $TEMP_INSTANCE --user=postgres --quiet <<EOF 2>&1 | tee -a $DB_LOG
\l
\q
EOF

# Step 8: Promote temporary instance to replace original
echo "Step 8: Promoting temporary instance..." | tee -a $DB_LOG

# Delete original instance
echo "  WARNING: About to delete original database instance!" | tee -a $DB_LOG
echo "  This action cannot be undone. Continue? (y/N): "
read -r CONFIRM_DELETE

if [[ "$CONFIRM_DELETE" != "y" ]]; then
    echo "  Database rollback aborted by user" | tee -a $DB_LOG
    echo "  Temporary instance $TEMP_INSTANCE is available for manual promotion" | tee -a $DB_LOG
    exit 1
fi

gcloud sql instances delete $INSTANCE_NAME \
    --project=$PROJECT_ID \
    --quiet 2>&1 | tee -a $DB_LOG

# Rename temporary instance to original name
# Note: This requires the original instance to be fully deleted first
echo "  Waiting for original instance deletion to complete..." | tee -a $DB_LOG
sleep 120

# Clone temp instance to original name
gcloud sql instances clone $TEMP_INSTANCE $INSTANCE_NAME \
    --project=$PROJECT_ID 2>&1 | tee -a $DB_LOG

# Step 9: Restart application services
echo "Step 9: Restarting application services..." | tee -a $DB_LOG

for service in "${SERVICES[@]}"; do
    echo "  Scaling up $service..." | tee -a $DB_LOG
    gcloud run services update $service \
        --region=$REGION \
        --project=$PROJECT_ID \
        --min-instances=1 \
        --max-instances=10 2>&1 | tee -a $DB_LOG
done

# Step 10: Cleanup temporary instance
echo "Step 10: Cleaning up temporary instance..." | tee -a $DB_LOG
gcloud sql instances delete $TEMP_INSTANCE \
    --project=$PROJECT_ID \
    --quiet 2>&1 | tee -a $DB_LOG

echo "Cloud SQL Database Rollback completed - $(date)" | tee -a $DB_LOG
echo "Database rollback log saved to: $DB_LOG"
echo "IMPORTANT: Verify application functionality before considering rollback complete"
```

### Database Schema Migration Rollback

```bash
#!/bin/bash
# Database Schema Migration Rollback Script
# Usage: ./schema-migration-rollback.sh [migration-version]

set -euo pipefail

MIGRATION_VERSION=${1:-}
SCHEMA_LOG="/tmp/schema-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Database Schema Migration Rollback - $(date)" | tee -a $SCHEMA_LOG

# Step 1: Check current migration version
echo "Step 1: Checking current migration version..." | tee -a $SCHEMA_LOG

# Connect to database and check schema_migrations table
CURRENT_VERSION=$(gcloud sql connect isectech-db-primary --user=postgres --quiet <<EOF
SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;
\q
EOF
)

echo "Current migration version: $CURRENT_VERSION" | tee -a $SCHEMA_LOG

# Step 2: Determine rollback target
if [[ -z "$MIGRATION_VERSION" ]]; then
    echo "No target migration specified. Listing recent migrations..." | tee -a $SCHEMA_LOG
    
    gcloud sql connect isectech-db-primary --user=postgres --quiet <<EOF 2>&1 | tee -a $SCHEMA_LOG
SELECT version, applied_at FROM schema_migrations ORDER BY version DESC LIMIT 10;
\q
EOF
    
    echo "Please specify target migration version: ./schema-migration-rollback.sh YYYYMMDDHHMMSS" | tee -a $SCHEMA_LOG
    exit 1
fi

# Step 3: Create database backup before schema rollback
echo "Step 3: Creating pre-schema-rollback backup..." | tee -a $SCHEMA_LOG
gcloud sql backups create \
    --instance=isectech-db-primary \
    --project=$PROJECT_ID \
    --description="Pre-schema-rollback backup for version $MIGRATION_VERSION" 2>&1 | tee -a $SCHEMA_LOG

# Step 4: Generate rollback SQL
echo "Step 4: Generating rollback SQL..." | tee -a $SCHEMA_LOG

# List migrations to rollback (from current version down to target)
ROLLBACK_MIGRATIONS=$(gcloud sql connect isectech-db-primary --user=postgres --quiet <<EOF
SELECT version FROM schema_migrations 
WHERE version > '$MIGRATION_VERSION' 
ORDER BY version DESC;
\q
EOF
)

echo "Migrations to rollback: $ROLLBACK_MIGRATIONS" | tee -a $SCHEMA_LOG

# Step 5: Execute rollback migrations
echo "Step 5: Executing rollback migrations..." | tee -a $SCHEMA_LOG

# Create rollback script
cat > /tmp/rollback_migrations.sql << EOF
-- Database Schema Rollback Script
-- Target version: $MIGRATION_VERSION
-- Generated: $(date)

BEGIN;

-- Remove migration records for rolled back versions
DELETE FROM schema_migrations WHERE version > '$MIGRATION_VERSION';

-- Add your rollback SQL statements here
-- This should be manually created based on your migration files

-- Example rollback statements:
-- DROP TABLE IF EXISTS new_security_events;
-- ALTER TABLE users DROP COLUMN IF EXISTS new_security_field;
-- DROP INDEX IF EXISTS idx_security_events_timestamp;

-- Verify final state
SELECT COUNT(*) as remaining_migrations FROM schema_migrations;

COMMIT;
EOF

echo "Manual rollback SQL created at /tmp/rollback_migrations.sql" | tee -a $SCHEMA_LOG
echo "MANUAL ACTION REQUIRED: Review and execute rollback SQL" | tee -a $SCHEMA_LOG

# Step 6: Execute rollback (with manual confirmation)
echo "Step 6: Ready to execute schema rollback..." | tee -a $SCHEMA_LOG
echo "Review /tmp/rollback_migrations.sql and execute manually:" | tee -a $SCHEMA_LOG
echo "  gcloud sql connect isectech-db-primary --user=postgres" | tee -a $SCHEMA_LOG
echo "  \\i /tmp/rollback_migrations.sql" | tee -a $SCHEMA_LOG

echo "Database Schema Migration Rollback preparation completed - $(date)" | tee -a $SCHEMA_LOG
echo "Schema rollback log saved to: $SCHEMA_LOG"
```

## Network and Security Rollback

### Load Balancer Configuration Rollback

```bash
#!/bin/bash
# Load Balancer Configuration Rollback Script
# Usage: ./load-balancer-rollback.sh [config-backup-timestamp]

set -euo pipefail

CONFIG_TIMESTAMP=${1:-}
LB_LOG="/tmp/lb-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Load Balancer Configuration Rollback - $(date)" | tee -a $LB_LOG

# Step 1: List available configuration backups
echo "Step 1: Listing available load balancer configuration backups..." | tee -a $LB_LOG
gsutil ls -la $BACKUP_BUCKET/load-balancer-configs/ | tail -10 | tee -a $LB_LOG

# Step 2: Determine rollback target
if [[ -z "$CONFIG_TIMESTAMP" ]]; then
    echo "No config timestamp specified. Getting most recent backup..." | tee -a $LB_LOG
    
    CONFIG_TIMESTAMP=$(gsutil ls $BACKUP_BUCKET/load-balancer-configs/ | \
        grep -E "lb-config-[0-9]{8}T[0-9]{6}" | \
        sort | tail -2 | head -1 | \
        sed 's/.*lb-config-\([0-9T]*\)\.json/\1/')
    
    echo "Auto-selected config backup: $CONFIG_TIMESTAMP" | tee -a $LB_LOG
fi

# Step 3: Download and validate backup configuration
echo "Step 3: Downloading backup configuration..." | tee -a $LB_LOG
BACKUP_FILE="$BACKUP_BUCKET/load-balancer-configs/lb-config-$CONFIG_TIMESTAMP.json"

if ! gsutil ls $BACKUP_FILE >/dev/null 2>&1; then
    echo "ERROR: Configuration backup not found: $BACKUP_FILE" | tee -a $LB_LOG
    exit 1
fi

gsutil cp $BACKUP_FILE /tmp/lb-rollback-config.json 2>&1 | tee -a $LB_LOG

# Step 4: Backup current configuration
echo "Step 4: Backing up current load balancer configuration..." | tee -a $LB_LOG

# Export current URL map
gcloud compute url-maps export isectech-main-urlmap \
    --destination=/tmp/current-urlmap-backup.yaml \
    --global \
    --project=$PROJECT_ID 2>&1 | tee -a $LB_LOG

# Export current backend services
gcloud compute backend-services list --global --project=$PROJECT_ID \
    --filter="name ~ isectech" \
    --format="value(name)" | \
while read -r backend_service; do
    if [[ -n "$backend_service" ]]; then
        gcloud compute backend-services export $backend_service \
            --destination=/tmp/current-$backend_service-backup.yaml \
            --global \
            --project=$PROJECT_ID 2>&1 | tee -a $LB_LOG
    fi
done

# Step 5: Apply rollback configuration
echo "Step 5: Applying rollback configuration..." | tee -a $LB_LOG

# Parse backup configuration and apply changes
ROLLBACK_CONFIG=$(cat /tmp/lb-rollback-config.json)

# Update URL map
URL_MAP_CONFIG=$(echo "$ROLLBACK_CONFIG" | jq -r '.urlMap')
if [[ "$URL_MAP_CONFIG" != "null" ]]; then
    echo "$URL_MAP_CONFIG" > /tmp/rollback-urlmap.yaml
    gcloud compute url-maps import isectech-main-urlmap \
        --source=/tmp/rollback-urlmap.yaml \
        --global \
        --project=$PROJECT_ID 2>&1 | tee -a $LB_LOG
fi

# Update backend services
BACKEND_SERVICES=$(echo "$ROLLBACK_CONFIG" | jq -r '.backendServices | keys[]')
for backend_service in $BACKEND_SERVICES; do
    BACKEND_CONFIG=$(echo "$ROLLBACK_CONFIG" | jq -r ".backendServices.$backend_service")
    echo "$BACKEND_CONFIG" > /tmp/rollback-$backend_service.yaml
    
    gcloud compute backend-services import $backend_service \
        --source=/tmp/rollback-$backend_service.yaml \
        --global \
        --project=$PROJECT_ID 2>&1 | tee -a $LB_LOG
done

# Step 6: Verify load balancer health
echo "Step 6: Verifying load balancer health..." | tee -a $LB_LOG

# Check URL map status
gcloud compute url-maps describe isectech-main-urlmap \
    --global \
    --project=$PROJECT_ID \
    --format="value(name,selfLink)" 2>&1 | tee -a $LB_LOG

# Check backend service health
gcloud compute backend-services list --global --project=$PROJECT_ID \
    --filter="name ~ isectech" \
    --format="table(name,protocol,loadBalancingScheme)" 2>&1 | tee -a $LB_LOG

# Test load balancer endpoints
DOMAINS=("api.isectech.com" "app.isectech.com" "admin.isectech.com")
for domain in "${DOMAINS[@]}"; do
    echo "Testing $domain..." | tee -a $LB_LOG
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://$domain/health || echo "000")
    echo "  HTTP Status: $HTTP_STATUS" | tee -a $LB_LOG
done

echo "Load Balancer Configuration Rollback completed - $(date)" | tee -a $LB_LOG
echo "Load balancer rollback log saved to: $LB_LOG"
```

### Cloud Armor Security Policy Rollback

```bash
#!/bin/bash
# Cloud Armor Security Policy Rollback Script
# Usage: ./cloud-armor-rollback.sh [policy-backup-timestamp]

set -euo pipefail

POLICY_TIMESTAMP=${1:-}
ARMOR_LOG="/tmp/armor-rollback-$(date +%Y%m%d%H%M%S).log"

echo "Starting Cloud Armor Security Policy Rollback - $(date)" | tee -a $ARMOR_LOG

# Step 1: List current security policies
echo "Step 1: Listing current Cloud Armor security policies..." | tee -a $ARMOR_LOG
gcloud compute security-policies list --project=$PROJECT_ID \
    --format="table(name,description,ruleCounts.total)" 2>&1 | tee -a $ARMOR_LOG

# Step 2: Backup current policies before rollback
echo "Step 2: Backing up current security policies..." | tee -a $ARMOR_LOG
POLICIES=$(gcloud compute security-policies list --project=$PROJECT_ID --format="value(name)")

for policy in $POLICIES; do
    if [[ -n "$policy" ]]; then
        echo "  Backing up policy: $policy" | tee -a $ARMOR_LOG
        gcloud compute security-policies export $policy \
            --destination=/tmp/current-$policy-$(date +%Y%m%d%H%M%S).yaml \
            --project=$PROJECT_ID 2>&1 | tee -a $ARMOR_LOG
    fi
done

# Step 3: Determine rollback target
if [[ -z "$POLICY_TIMESTAMP" ]]; then
    echo "No policy timestamp specified. Listing available backups..." | tee -a $ARMOR_LOG
    gsutil ls $BACKUP_BUCKET/cloud-armor-policies/ | tail -10 | tee -a $ARMOR_LOG
    
    POLICY_TIMESTAMP=$(gsutil ls $BACKUP_BUCKET/cloud-armor-policies/ | \
        grep -E "armor-policies-[0-9]{8}T[0-9]{6}" | \
        sort | tail -1 | \
        sed 's/.*armor-policies-\([0-9T]*\)\.tar\.gz/\1/')
    
    echo "Auto-selected policy backup: $POLICY_TIMESTAMP" | tee -a $ARMOR_LOG
fi

# Step 4: Download and extract policy backups
echo "Step 4: Downloading policy backups..." | tee -a $ARMOR_LOG
BACKUP_FILE="$BACKUP_BUCKET/cloud-armor-policies/armor-policies-$POLICY_TIMESTAMP.tar.gz"

gsutil cp $BACKUP_FILE /tmp/armor-policies-backup.tar.gz 2>&1 | tee -a $ARMOR_LOG
cd /tmp
tar -xzf armor-policies-backup.tar.gz 2>&1 | tee -a $ARMOR_LOG

# Step 5: Apply rollback policies
echo "Step 5: Applying rollback security policies..." | tee -a $ARMOR_LOG

for policy_file in /tmp/armor-policies-$POLICY_TIMESTAMP/*.yaml; do
    if [[ -f "$policy_file" ]]; then
        POLICY_NAME=$(basename "$policy_file" .yaml)
        echo "  Restoring policy: $POLICY_NAME" | tee -a $ARMOR_LOG
        
        gcloud compute security-policies import $POLICY_NAME \
            --source="$policy_file" \
            --project=$PROJECT_ID 2>&1 | tee -a $ARMOR_LOG
    fi
done

# Step 6: Verify policy restoration
echo "Step 6: Verifying security policy restoration..." | tee -a $ARMOR_LOG

for policy in $POLICIES; do
    if [[ -n "$policy" ]]; then
        echo "  Verifying policy: $policy" | tee -a $ARMOR_LOG
        gcloud compute security-policies describe $policy \
            --project=$PROJECT_ID \
            --format="table(name,rules.priority,rules.action)" 2>&1 | tee -a $ARMOR_LOG
    fi
done

echo "Cloud Armor Security Policy Rollback completed - $(date)" | tee -a $ARMOR_LOG
echo "Cloud Armor rollback log saved to: $ARMOR_LOG"
```

## Validation and Testing

### Infrastructure Health Check Script

```bash
#!/bin/bash
# Infrastructure Health Check Script
# Usage: ./infrastructure-health-check.sh

set -euo pipefail

HEALTH_LOG="/tmp/infrastructure-health-$(date +%Y%m%d%H%M%S).log"

echo "Starting Infrastructure Health Check - $(date)" | tee -a $HEALTH_LOG

FAILED_CHECKS=0

# Check 1: Cloud Run Services
echo "Check 1: Cloud Run Services Health..." | tee -a $HEALTH_LOG
SERVICES=("isectech-api" "isectech-frontend" "isectech-admin" "isectech-monitoring")

for service in "${SERVICES[@]}"; do
    SERVICE_STATUS=$(gcloud run services describe $service \
        --region=$REGION \
        --project=$PROJECT_ID \
        --format="value(status.conditions[0].status)" 2>/dev/null || echo "UNKNOWN")
    
    if [[ "$SERVICE_STATUS" == "True" ]]; then
        echo "  OK: $service is healthy" | tee -a $HEALTH_LOG
    else
        echo "  FAILED: $service is unhealthy (status: $SERVICE_STATUS)" | tee -a $HEALTH_LOG
        ((FAILED_CHECKS++))
    fi
done

# Check 2: Database Connectivity
echo "Check 2: Database Connectivity..." | tee -a $HEALTH_LOG
DB_STATUS=$(gcloud sql instances describe isectech-db-primary \
    --project=$PROJECT_ID \
    --format="value(state)" 2>/dev/null || echo "UNKNOWN")

if [[ "$DB_STATUS" == "RUNNABLE" ]]; then
    echo "  OK: Database is running" | tee -a $HEALTH_LOG
else
    echo "  FAILED: Database is not running (status: $DB_STATUS)" | tee -a $HEALTH_LOG
    ((FAILED_CHECKS++))
fi

# Check 3: Load Balancer Health
echo "Check 3: Load Balancer Health..." | tee -a $HEALTH_LOG
DOMAINS=("api.isectech.com" "app.isectech.com" "admin.isectech.com")

for domain in "${DOMAINS[@]}"; do
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://$domain/health || echo "000")
    if [[ "$HTTP_STATUS" == "200" ]]; then
        echo "  OK: $domain is responding" | tee -a $HEALTH_LOG
    else
        echo "  FAILED: $domain is not responding (HTTP $HTTP_STATUS)" | tee -a $HEALTH_LOG
        ((FAILED_CHECKS++))
    fi
done

# Check 4: DNS Resolution
echo "Check 4: DNS Resolution..." | tee -a $HEALTH_LOG
for domain in "${DOMAINS[@]}"; do
    DNS_RESULT=$(dig +short $domain @8.8.8.8 2>/dev/null || echo "FAILED")
    if [[ "$DNS_RESULT" != "FAILED" ]] && [[ -n "$DNS_RESULT" ]]; then
        echo "  OK: $domain resolves to $DNS_RESULT" | tee -a $HEALTH_LOG
    else
        echo "  FAILED: $domain DNS resolution failed" | tee -a $HEALTH_LOG
        ((FAILED_CHECKS++))
    fi
done

# Check 5: SSL Certificates
echo "Check 5: SSL Certificate Validity..." | tee -a $HEALTH_LOG
for domain in "${DOMAINS[@]}"; do
    CERT_STATUS=$(echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | \
        openssl x509 -noout -checkend 86400 2>/dev/null && echo "VALID" || echo "INVALID")
    
    if [[ "$CERT_STATUS" == "VALID" ]]; then
        echo "  OK: $domain SSL certificate is valid" | tee -a $HEALTH_LOG
    else
        echo "  FAILED: $domain SSL certificate is invalid or expiring" | tee -a $HEALTH_LOG
        ((FAILED_CHECKS++))
    fi
done

# Summary
echo "Infrastructure Health Check Summary - $(date)" | tee -a $HEALTH_LOG
if [[ $FAILED_CHECKS -eq 0 ]]; then
    echo "  OVERALL STATUS: HEALTHY (0 failed checks)" | tee -a $HEALTH_LOG
elif [[ $FAILED_CHECKS -le 2 ]]; then
    echo "  OVERALL STATUS: DEGRADED ($FAILED_CHECKS failed checks)" | tee -a $HEALTH_LOG
else
    echo "  OVERALL STATUS: CRITICAL ($FAILED_CHECKS failed checks)" | tee -a $HEALTH_LOG
fi

echo "Infrastructure Health Check completed - $(date)" | tee -a $HEALTH_LOG
echo "Health check log saved to: $HEALTH_LOG"

exit $FAILED_CHECKS
```

## Emergency Contacts

### Primary Contacts
- **DevOps On-Call:** +1-555-0123 (oncall@isectech.com)
- **Infrastructure Team:** +1-555-0126 (infrastructure@isectech.com)
- **Engineering Manager:** +1-555-0125 (engineering-mgr@isectech.com)

### Vendor Support
- **Google Cloud Support:** Via Console + Premium Support
- **Terraform Support:** Community + Enterprise Support
- **GitHub Support:** Via Support Portal

### Communication Channels
- **Slack:** #infrastructure-alerts, #incident-response
- **Email:** infrastructure@isectech.com
- **Status Page:** status.isectech.com

## Post-Rollback Actions

### Immediate Actions (0-30 minutes)
1. **Verify complete system functionality**
   ```bash
   ./infrastructure-health-check.sh
   ```

2. **Clear monitoring alerts**
   - Reset any infrastructure-related alerts
   - Verify monitoring dashboards are green

3. **Update incident communication**
   - Notify stakeholders of rollback completion
   - Update status page with recovery notice

### Short-term Actions (30 minutes - 4 hours)
1. **Root cause analysis**
   - Document what caused the need for rollback
   - Identify infrastructure change that failed

2. **Update change management process**
   - Review deployment procedures
   - Enhance rollback automation

3. **Backup validation**
   - Verify all backup systems are working
   - Test backup restoration procedures

### Long-term Actions (4+ hours)
1. **Infrastructure improvements**
   - Implement additional monitoring
   - Enhance automated testing

2. **Documentation updates**
   - Update rollback procedures based on experience
   - Create new runbooks for discovered scenarios

3. **Team training**
   - Conduct rollback drill exercises
   - Share lessons learned with team

---

**Document Control:**
- **Classification:** CONFIDENTIAL - Internal Use Only
- **Review Frequency:** Quarterly
- **Next Review Date:** 2025-11-05
- **Owner:** DevOps Team
- **Approver:** Infrastructure Team Lead

**Change Log:**
- v1.0 (2025-08-05): Initial version - Comprehensive infrastructure rollback procedures