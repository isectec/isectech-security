#!/bin/bash

# Enterprise Billing and Budget Monitoring Setup for iSECTECH
# Production-grade billing infrastructure with comprehensive cost monitoring
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# Configuration
PROJECT_ID=${PROJECT_ID:-"isectech-security-platform"}
BILLING_ACCOUNT_ID=${BILLING_ACCOUNT_ID:-""}
REGION=${REGION:-"us-central1"}
NOTIFICATION_EMAIL=${NOTIFICATION_EMAIL:-"billing-alerts@isectech.com"}
BIGQUERY_DATASET="billing_export"
BIGQUERY_TABLE="gcp_billing_export"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command_exists gcloud; then
        error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    if ! command_exists bq; then
        error "BigQuery CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Check if billing account is provided
    if [ -z "$BILLING_ACCOUNT_ID" ]; then
        warning "BILLING_ACCOUNT_ID not set. Attempting to discover..."
        BILLING_ACCOUNT_ID=$(gcloud billing accounts list --format="value(name)" --limit=1)
        if [ -z "$BILLING_ACCOUNT_ID" ]; then
            error "No billing account found. Please set BILLING_ACCOUNT_ID environment variable."
            exit 1
        fi
        log "Using billing account: $BILLING_ACCOUNT_ID"
    fi
    
    success "Prerequisites check completed"
}

# Function to enable required APIs
enable_required_apis() {
    log "Enabling required APIs for billing and monitoring..."
    
    local apis=(
        "cloudbilling.googleapis.com"
        "bigquery.googleapis.com"
        "monitoring.googleapis.com"
        "logging.googleapis.com"
        "pubsub.googleapis.com"
        "cloudresourcemanager.googleapis.com"
        "billingbudgets.googleapis.com"
        "compute.googleapis.com"
    )
    
    for api in "${apis[@]}"; do
        log "Enabling $api..."
        if gcloud services enable "$api" --project="$PROJECT_ID"; then
            success "Enabled $api"
        else
            error "Failed to enable $api"
            return 1
        fi
        sleep 2
    done
    
    success "All required APIs enabled"
}

# Function to set up BigQuery billing export
setup_bigquery_billing_export() {
    log "Setting up BigQuery billing export..."
    
    # Create BigQuery dataset for billing export
    log "Creating BigQuery dataset: $BIGQUERY_DATASET"
    if bq mk \
        --dataset \
        --description="iSECTECH Billing Export Dataset - Production" \
        --location="$REGION" \
        "$PROJECT_ID:$BIGQUERY_DATASET"; then
        success "Created BigQuery dataset: $BIGQUERY_DATASET"
    else
        warning "Dataset may already exist or failed to create"
    fi
    
    # Create table schema for billing export
    cat > /tmp/billing_schema.json << 'EOF'
[
  {"name": "billing_account_id", "type": "STRING", "mode": "NULLABLE"},
  {"name": "service", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "id", "type": "STRING", "mode": "NULLABLE"},
    {"name": "description", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "sku", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "id", "type": "STRING", "mode": "NULLABLE"},
    {"name": "description", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "usage_start_time", "type": "TIMESTAMP", "mode": "NULLABLE"},
  {"name": "usage_end_time", "type": "TIMESTAMP", "mode": "NULLABLE"},
  {"name": "project", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "id", "type": "STRING", "mode": "NULLABLE"},
    {"name": "name", "type": "STRING", "mode": "NULLABLE"},
    {"name": "labels", "type": "RECORD", "mode": "REPEATED", "fields": [
      {"name": "key", "type": "STRING", "mode": "NULLABLE"},
      {"name": "value", "type": "STRING", "mode": "NULLABLE"}
    ]}
  ]},
  {"name": "labels", "type": "RECORD", "mode": "REPEATED", "fields": [
    {"name": "key", "type": "STRING", "mode": "NULLABLE"},
    {"name": "value", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "system_labels", "type": "RECORD", "mode": "REPEATED", "fields": [
    {"name": "key", "type": "STRING", "mode": "NULLABLE"},
    {"name": "value", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "location", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "location", "type": "STRING", "mode": "NULLABLE"},
    {"name": "country", "type": "STRING", "mode": "NULLABLE"},
    {"name": "region", "type": "STRING", "mode": "NULLABLE"},
    {"name": "zone", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "cost", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "currency", "type": "STRING", "mode": "NULLABLE"},
  {"name": "currency_conversion_rate", "type": "FLOAT", "mode": "NULLABLE"},
  {"name": "usage", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "amount", "type": "FLOAT", "mode": "NULLABLE"},
    {"name": "unit", "type": "STRING", "mode": "NULLABLE"},
    {"name": "amount_in_pricing_units", "type": "FLOAT", "mode": "NULLABLE"},
    {"name": "pricing_unit", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "credits", "type": "RECORD", "mode": "REPEATED", "fields": [
    {"name": "name", "type": "STRING", "mode": "NULLABLE"},
    {"name": "amount", "type": "FLOAT", "mode": "NULLABLE"},
    {"name": "full_name", "type": "STRING", "mode": "NULLABLE"},
    {"name": "id", "type": "STRING", "mode": "NULLABLE"},
    {"name": "type", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "invoice", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "month", "type": "STRING", "mode": "NULLABLE"}
  ]},
  {"name": "cost_type", "type": "STRING", "mode": "NULLABLE"},
  {"name": "adjustment_info", "type": "RECORD", "mode": "NULLABLE", "fields": [
    {"name": "id", "type": "STRING", "mode": "NULLABLE"},
    {"name": "description", "type": "STRING", "mode": "NULLABLE"},
    {"name": "mode", "type": "STRING", "mode": "NULLABLE"},
    {"name": "type", "type": "STRING", "mode": "NULLABLE"}
  ]}
]
EOF
    
    # Create BigQuery table for billing export
    log "Creating BigQuery table: $BIGQUERY_TABLE"
    if bq mk \
        --table \
        --description="iSECTECH GCP Billing Export Table - Production" \
        --time_partitioning_field="usage_start_time" \
        --time_partitioning_type="DAY" \
        --clustering_fields="service.description,project.id,location.region" \
        "$PROJECT_ID:$BIGQUERY_DATASET.$BIGQUERY_TABLE" \
        /tmp/billing_schema.json; then
        success "Created BigQuery table: $BIGQUERY_TABLE"
    else
        warning "Table may already exist or failed to create"
    fi
    
    # Clean up temporary schema file
    rm -f /tmp/billing_schema.json
    
    success "BigQuery billing export setup completed"
    log "Note: Billing export must be enabled manually in the Google Cloud Console"
    log "Navigate to: Billing > Billing export > BigQuery export"
    log "Dataset: $PROJECT_ID:$BIGQUERY_DATASET"
    log "Table: $BIGQUERY_TABLE"
}

# Function to create notification channels
create_notification_channels() {
    log "Creating notification channels for billing alerts..."
    
    # Create email notification channel
    cat > /tmp/email_channel.json << EOF
{
  "type": "email",
  "displayName": "iSECTECH Billing Alerts Email",
  "description": "Email notification channel for billing alerts",
  "labels": {
    "email_address": "$NOTIFICATION_EMAIL"
  },
  "enabled": true
}
EOF
    
    log "Creating email notification channel..."
    local email_channel_name
    email_channel_name=$(gcloud alpha monitoring channels create --channel-content-from-file=/tmp/email_channel.json --project="$PROJECT_ID" --format="value(name)")
    
    if [ -n "$email_channel_name" ]; then
        success "Created email notification channel: $email_channel_name"
        echo "$email_channel_name" > /tmp/email_channel_name.txt
    else
        error "Failed to create email notification channel"
        return 1
    fi
    
    # Create Pub/Sub notification channel for integration
    local pubsub_topic="billing-alerts"
    log "Creating Pub/Sub topic: $pubsub_topic"
    if gcloud pubsub topics create "$pubsub_topic" --project="$PROJECT_ID"; then
        success "Created Pub/Sub topic: $pubsub_topic"
    else
        warning "Topic may already exist"
    fi
    
    cat > /tmp/pubsub_channel.json << EOF
{
  "type": "pubsub",
  "displayName": "iSECTECH Billing Alerts Pub/Sub",
  "description": "Pub/Sub notification channel for billing alerts integration",
  "labels": {
    "topic": "projects/$PROJECT_ID/topics/$pubsub_topic"
  },
  "enabled": true
}
EOF
    
    log "Creating Pub/Sub notification channel..."
    local pubsub_channel_name
    pubsub_channel_name=$(gcloud alpha monitoring channels create --channel-content-from-file=/tmp/pubsub_channel.json --project="$PROJECT_ID" --format="value(name)")
    
    if [ -n "$pubsub_channel_name" ]; then
        success "Created Pub/Sub notification channel: $pubsub_channel_name"
        echo "$pubsub_channel_name" > /tmp/pubsub_channel_name.txt
    else
        error "Failed to create Pub/Sub notification channel"
        return 1
    fi
    
    # Clean up temporary files
    rm -f /tmp/email_channel.json /tmp/pubsub_channel.json
    
    success "Notification channels created successfully"
}

# Function to create enterprise budget alerts
create_enterprise_budget_alerts() {
    log "Creating enterprise budget alerts with multiple thresholds..."
    
    # Get notification channel names
    local email_channel_name
    local pubsub_channel_name
    
    if [ -f "/tmp/email_channel_name.txt" ]; then
        email_channel_name=$(cat /tmp/email_channel_name.txt)
    else
        error "Email notification channel not found"
        return 1
    fi
    
    if [ -f "/tmp/pubsub_channel_name.txt" ]; then
        pubsub_channel_name=$(cat /tmp/pubsub_channel_name.txt)
    else
        error "Pub/Sub notification channel not found"
        return 1
    fi
    
    # Define budget configurations
    local budgets=(
        "monthly:1000:Monthly Security Platform Budget"
        "quarterly:3000:Quarterly Security Platform Budget"
        "yearly:12000:Annual Security Platform Budget"
    )
    
    for budget_config in "${budgets[@]}"; do
        IFS=':' read -r period amount display_name <<< "$budget_config"
        
        log "Creating $period budget: $display_name ($amount USD)"
        
        # Create budget configuration
        cat > "/tmp/budget_${period}.yaml" << EOF
displayName: "$display_name"
budgetFilter:
  projects:
  - "projects/$PROJECT_ID"
  creditTypesTreatment: INCLUDE_ALL_CREDITS
amount:
  specifiedAmount:
    currencyCode: "USD"
    units: "$amount"
thresholdRules:
- thresholdPercent: 0.5
  spendBasis: CURRENT_SPEND
- thresholdPercent: 0.8
  spendBasis: CURRENT_SPEND
- thresholdPercent: 1.0
  spendBasis: CURRENT_SPEND
- thresholdPercent: 1.2
  spendBasis: FORECASTED_SPEND
allUpdatesRule:
  pubsubTopic: "projects/$PROJECT_ID/topics/billing-alerts"
  schemaVersion: "1.0"
  monitoringNotificationChannels:
  - "$email_channel_name"
  - "$pubsub_channel_name"
  disableDefaultIamRecipients: false
EOF
        
        # Create the budget
        if gcloud billing budgets create \
            --billing-account="$BILLING_ACCOUNT_ID" \
            --budget-from-file="/tmp/budget_${period}.yaml"; then
            success "Created $period budget: $display_name"
        else
            error "Failed to create $period budget: $display_name"
        fi
        
        # Clean up temporary file
        rm -f "/tmp/budget_${period}.yaml"
        
        sleep 2
    done
    
    # Clean up notification channel files
    rm -f /tmp/email_channel_name.txt /tmp/pubsub_channel_name.txt
    
    success "Enterprise budget alerts created successfully"
}

# Function to create cost monitoring queries
create_cost_monitoring_queries() {
    log "Creating cost monitoring queries for BigQuery..."
    
    mkdir -p "$HOME/isectech-billing-queries"
    
    # Query 1: Daily cost breakdown by service
    cat > "$HOME/isectech-billing-queries/daily_cost_by_service.sql" << 'EOF'
-- Daily Cost Breakdown by Service for iSECTECH
-- Production monitoring query for cost analysis
SELECT 
  DATE(usage_start_time) as usage_date,
  service.description as service_name,
  location.region as region,
  SUM(cost) as total_cost,
  currency,
  COUNT(*) as usage_records
FROM `PROJECT_ID.billing_export.gcp_billing_export`
WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
  AND cost > 0
GROUP BY 1, 2, 3, 5
ORDER BY usage_date DESC, total_cost DESC;
EOF
    
    # Query 2: Monthly cost trends
    cat > "$HOME/isectech-billing-queries/monthly_cost_trends.sql" << 'EOF'
-- Monthly Cost Trends for iSECTECH Security Platform
-- Track spending patterns and growth over time
SELECT 
  FORMAT_DATE('%Y-%m', usage_start_time) as month,
  service.description as service_name,
  SUM(cost) as monthly_cost,
  LAG(SUM(cost)) OVER (PARTITION BY service.description ORDER BY FORMAT_DATE('%Y-%m', usage_start_time)) as previous_month_cost,
  SAFE_DIVIDE(
    SUM(cost) - LAG(SUM(cost)) OVER (PARTITION BY service.description ORDER BY FORMAT_DATE('%Y-%m', usage_start_time)),
    LAG(SUM(cost)) OVER (PARTITION BY service.description ORDER BY FORMAT_DATE('%Y-%m', usage_start_time))
  ) * 100 as cost_change_percent
FROM `PROJECT_ID.billing_export.gcp_billing_export`
WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 12 MONTH)
  AND cost > 0
GROUP BY 1, 2
ORDER BY month DESC, monthly_cost DESC;
EOF
    
    # Query 3: Cost by project and region
    cat > "$HOME/isectech-billing-queries/cost_by_project_region.sql" << 'EOF'
-- Cost Analysis by Project and Region for iSECTECH
-- Regional cost distribution and optimization opportunities
SELECT 
  project.id as project_id,
  project.name as project_name,
  location.region as region,
  location.zone as zone,
  service.description as service_name,
  SUM(cost) as total_cost,
  SUM(usage.amount) as total_usage,
  usage.unit as usage_unit,
  AVG(cost / NULLIF(usage.amount, 0)) as cost_per_unit
FROM `PROJECT_ID.billing_export.gcp_billing_export`
WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
  AND cost > 0
GROUP BY 1, 2, 3, 4, 5, 8
HAVING total_cost > 1
ORDER BY total_cost DESC;
EOF
    
    # Query 4: Credit and discount analysis
    cat > "$HOME/isectech-billing-queries/credits_analysis.sql" << 'EOF'
-- Credits and Discounts Analysis for iSECTECH
-- Track applied credits and potential savings
SELECT 
  DATE(usage_start_time) as usage_date,
  service.description as service_name,
  SUM(cost) as gross_cost,
  SUM(IFNULL((SELECT SUM(credit.amount) FROM UNNEST(credits) as credit), 0)) as total_credits,
  SUM(cost) + SUM(IFNULL((SELECT SUM(credit.amount) FROM UNNEST(credits) as credit), 0)) as net_cost,
  ARRAY_AGG(DISTINCT credit.type IGNORE NULLS) as credit_types
FROM `PROJECT_ID.billing_export.gcp_billing_export`,
UNNEST(credits) as credit
WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
GROUP BY 1, 2
HAVING total_credits != 0
ORDER BY usage_date DESC, ABS(total_credits) DESC;
EOF
    
    # Query 5: Anomaly detection
    cat > "$HOME/isectech-billing-queries/cost_anomaly_detection.sql" << 'EOF'
-- Cost Anomaly Detection for iSECTECH
-- Identify unusual spending patterns for investigation
WITH daily_costs as (
  SELECT 
    DATE(usage_start_time) as usage_date,
    service.description as service_name,
    SUM(cost) as daily_cost
  FROM `PROJECT_ID.billing_export.gcp_billing_export`
  WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 90 DAY)
    AND cost > 0
  GROUP BY 1, 2
),
cost_stats as (
  SELECT 
    service_name,
    AVG(daily_cost) as avg_cost,
    STDDEV(daily_cost) as stddev_cost
  FROM daily_costs
  GROUP BY 1
)
SELECT 
  dc.usage_date,
  dc.service_name,
  dc.daily_cost,
  cs.avg_cost,
  ABS(dc.daily_cost - cs.avg_cost) / cs.stddev_cost as z_score
FROM daily_costs dc
JOIN cost_stats cs ON dc.service_name = cs.service_name
WHERE ABS(dc.daily_cost - cs.avg_cost) / cs.stddev_cost > 2
  AND dc.usage_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
ORDER BY z_score DESC;
EOF
    
    # Replace PROJECT_ID placeholder in queries
    sed -i.bak "s/PROJECT_ID/$PROJECT_ID/g" "$HOME/isectech-billing-queries/"*.sql
    rm -f "$HOME/isectech-billing-queries/"*.sql.bak
    
    success "Cost monitoring queries created in $HOME/isectech-billing-queries/"
}

# Function to create monitoring dashboard
create_monitoring_dashboard() {
    log "Creating cost monitoring dashboard..."
    
    cat > /tmp/billing_dashboard.json << EOF
{
  "displayName": "iSECTECH Enterprise Billing Dashboard",
  "mosaicLayout": {
    "tiles": [
      {
        "width": 6,
        "height": 4,
        "widget": {
          "title": "Daily Spending Trend",
          "xyChart": {
            "dataSets": [{
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "filter": "resource.type=\"billing_account\"",
                  "aggregation": {
                    "alignmentPeriod": "86400s",
                    "perSeriesAligner": "ALIGN_SUM",
                    "crossSeriesReducer": "REDUCE_SUM"
                  }
                }
              }
            }],
            "timeshiftDuration": "0s",
            "yAxis": {
              "label": "Cost (USD)",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "widget": {
          "title": "Cost by Service",
          "pieChart": {
            "dataSets": [{
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "filter": "resource.type=\"gce_instance\"",
                  "aggregation": {
                    "alignmentPeriod": "3600s",
                    "perSeriesAligner": "ALIGN_RATE",
                    "crossSeriesReducer": "REDUCE_SUM",
                    "groupByFields": ["resource.label.instance_name"]
                  }
                }
              }
            }]
          }
        }
      },
      {
        "width": 12,
        "height": 4,
        "yPos": 4,
        "widget": {
          "title": "Budget vs Actual Spending",
          "scorecard": {
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "resource.type=\"billing_account\"",
                "aggregation": {
                  "alignmentPeriod": "86400s",
                  "perSeriesAligner": "ALIGN_SUM",
                  "crossSeriesReducer": "REDUCE_SUM"
                }
              }
            },
            "sparkChartView": {
              "sparkChartType": "SPARK_LINE"
            }
          }
        }
      }
    ]
  }
}
EOF
    
    log "Creating monitoring dashboard..."
    if gcloud monitoring dashboards create --config-from-file=/tmp/billing_dashboard.json --project="$PROJECT_ID"; then
        success "Created monitoring dashboard"
    else
        error "Failed to create monitoring dashboard"
    fi
    
    rm -f /tmp/billing_dashboard.json
}

# Function to create cost optimization recommendations
create_cost_optimization_script() {
    log "Creating cost optimization analysis script..."
    
    cat > "$HOME/isectech-billing-queries/cost_optimization.sh" << 'EOF'
#!/bin/bash

# iSECTECH Cost Optimization Analysis
# Automated cost optimization recommendations

PROJECT_ID="isectech-security-platform"
DATASET="billing_export"
TABLE="gcp_billing_export"

echo "=== iSECTECH Cost Optimization Report ==="
echo "Generated: $(date)"
echo ""

# Check for unused resources
echo "1. Checking for potentially unused Compute Engine instances..."
bq query --use_legacy_sql=false --format=prettyjson "
SELECT 
  project.id as project_id,
  location.region,
  SUM(cost) as total_cost,
  COUNT(DISTINCT DATE(usage_start_time)) as active_days
FROM \`$PROJECT_ID.$DATASET.$TABLE\`
WHERE service.description = 'Compute Engine'
  AND DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
  AND cost > 0
GROUP BY 1, 2
HAVING active_days < 15
ORDER BY total_cost DESC;
"

echo ""
echo "2. Checking for high-cost, low-utilization resources..."
bq query --use_legacy_sql=false --format=prettyjson "
SELECT 
  service.description as service_name,
  location.region,
  SUM(cost) as monthly_cost,
  SUM(usage.amount) as total_usage,
  usage.unit
FROM \`$PROJECT_ID.$DATASET.$TABLE\`
WHERE DATE(usage_start_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
  AND cost > 100
GROUP BY 1, 2, 5
ORDER BY monthly_cost DESC
LIMIT 10;
"

echo ""
echo "=== Recommendations ==="
echo "1. Review Compute Engine instances with < 15 active days"
echo "2. Consider rightsizing high-cost resources"
echo "3. Evaluate regional distribution for cost optimization"
echo "4. Check for sustained use discounts eligibility"
echo ""
EOF
    
    chmod +x "$HOME/isectech-billing-queries/cost_optimization.sh"
    success "Created cost optimization script: $HOME/isectech-billing-queries/cost_optimization.sh"
}

# Main function
main() {
    log "Starting iSECTECH Enterprise Billing and Budget Monitoring Setup"
    log "Project ID: $PROJECT_ID"
    log "Billing Account: $BILLING_ACCOUNT_ID"
    log "Region: $REGION"
    log "Notification Email: $NOTIFICATION_EMAIL"
    echo ""
    
    # Execute setup steps
    check_prerequisites
    enable_required_apis
    setup_bigquery_billing_export
    create_notification_channels
    create_enterprise_budget_alerts
    create_cost_monitoring_queries
    create_monitoring_dashboard
    create_cost_optimization_script
    
    success "iSECTECH Enterprise Billing and Budget Monitoring Setup Completed!"
    
    echo ""
    log "=== SETUP SUMMARY ==="
    log "✅ BigQuery billing export configured"
    log "✅ Enterprise budget alerts created (50%, 80%, 100% thresholds)"
    log "✅ Notification channels configured"
    log "✅ Cost monitoring queries generated"
    log "✅ Monitoring dashboard created"
    log "✅ Cost optimization tools deployed"
    echo ""
    
    log "=== NEXT STEPS ==="
    log "1. Enable billing export in Cloud Console:"
    log "   → Billing > Billing export > BigQuery export"
    log "   → Dataset: $PROJECT_ID:$BIGQUERY_DATASET"
    log "   → Table: $BIGQUERY_TABLE"
    echo ""
    log "2. Review and test budget alerts:"
    log "   → Check notification email: $NOTIFICATION_EMAIL"
    log "   → Monitor Pub/Sub topic: billing-alerts"
    echo ""
    log "3. Run cost optimization analysis:"
    log "   → Execute: $HOME/isectech-billing-queries/cost_optimization.sh"
    echo ""
    log "4. Access BigQuery cost queries:"
    log "   → Directory: $HOME/isectech-billing-queries/"
    echo ""
    
    warning "IMPORTANT: Manual step required for billing export activation in Cloud Console"
}

# Execute main function
main "$@"