# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH ML-POWERED ANOMALY DETECTION SYSTEM  
# Automated anomaly detection for multi-region deployment using BigQuery ML
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.9 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.10"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Anomaly detection configuration
  anomaly_config = {
    # Model training parameters
    training_config = {
      # Training data lookback period
      training_days = 30
      # Model retaining frequency  
      retrain_frequency_hours = 24
      # Minimum training samples required
      min_training_samples = 1000
      # Anomaly sensitivity levels
      sensitivity_levels = {
        high = 0.01      # 99% confidence interval
        medium = 0.05    # 95% confidence interval  
        low = 0.1        # 90% confidence interval
      }
    }
    
    # Metrics to monitor for anomalies
    monitored_metrics = {
      # Request rate anomalies
      request_rate = {
        metric_name = "request_rate_per_minute"
        source_table = "monitoring_metrics.request_rates"
        sensitivity = "medium"
        seasonality = "daily"
        threshold_multiplier = 2.0
        business_impact = "high"
      }
      
      # Response time anomalies
      response_time = {
        metric_name = "response_time_p95" 
        source_table = "monitoring_metrics.response_times"
        sensitivity = "high"
        seasonality = "hourly"
        threshold_multiplier = 1.5
        business_impact = "high"
      }
      
      # Error rate anomalies
      error_rate = {
        metric_name = "error_rate_percentage"
        source_table = "monitoring_metrics.error_rates"
        sensitivity = "high"
        seasonality = "none"
        threshold_multiplier = 1.2
        business_impact = "critical"
      }
      
      # Resource utilization anomalies
      cpu_utilization = {
        metric_name = "cpu_utilization_percentage"
        source_table = "monitoring_metrics.resource_usage"
        sensitivity = "medium"
        seasonality = "daily"
        threshold_multiplier = 1.8
        business_impact = "medium"
      }
      
      # Database connection anomalies
      db_connections = {
        metric_name = "database_connection_count"
        source_table = "monitoring_metrics.database_metrics"
        sensitivity = "medium"
        seasonality = "hourly"
        threshold_multiplier = 2.5
        business_impact = "high"
      }
      
      # Cross-region latency anomalies
      cross_region_latency = {
        metric_name = "cross_region_latency_ms"
        source_table = "monitoring_metrics.cross_region_latency"
        sensitivity = "medium"
        seasonality = "daily"
        threshold_multiplier = 2.0
        business_impact = "medium"
      }
      
      # Replication lag anomalies
      replication_lag = {
        metric_name = "replication_lag_seconds"
        source_table = "monitoring_metrics.replication_metrics" 
        sensitivity = "high"
        seasonality = "none"
        threshold_multiplier = 1.5
        business_impact = "high"
      }
    }
    
    # Regional anomaly detection settings
    regional_settings = {
      "us-central1" = {
        timezone = "America/Chicago"
        business_hours_start = 6  # 6 AM CST
        business_hours_end = 18   # 6 PM CST
        peak_traffic_multiplier = 1.5
      }
      "europe-west4" = {
        timezone = "Europe/Amsterdam"
        business_hours_start = 8  # 8 AM CET
        business_hours_end = 17   # 5 PM CET
        peak_traffic_multiplier = 1.3
      }
      "asia-northeast1" = {
        timezone = "Asia/Tokyo"
        business_hours_start = 9  # 9 AM JST
        business_hours_end = 18   # 6 PM JST
        peak_traffic_multiplier = 1.4
      }
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BIGQUERY DATASETS AND TABLES FOR ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

# BigQuery dataset for anomaly detection
resource "google_bigquery_dataset" "anomaly_detection" {
  dataset_id  = "anomaly_detection_${var.environment}"
  project     = var.project_id
  description = "Anomaly detection ML models and training data"
  location    = "US"
  
  # Data retention for ML training
  default_table_expiration_ms = 2592000000  # 30 days
  
  access {
    role          = "OWNER"
    user_by_email = google_service_account.anomaly_detection.email
  }
  
  access {
    role          = "READER"
    user_by_email = google_service_account.monitoring_data_export.email
  }
  
  labels = merge(local.common_labels, {
    data-type = "ml-training"
    purpose   = "anomaly-detection"
  })
}

# Monitoring metrics aggregation table
resource "google_bigquery_table" "monitoring_metrics" {
  dataset_id = google_bigquery_dataset.anomaly_detection.dataset_id
  table_id   = "monitoring_metrics"
  project    = var.project_id
  
  # Partitioned table for efficient querying
  time_partitioning {
    type                     = "DAY"
    field                    = "timestamp"
    require_partition_filter = true
    expiration_ms           = 2592000000  # 30 days
  }
  
  # Clustering for efficient queries
  clustering = ["region", "metric_type", "service"]
  
  schema = jsonencode([
    {
      name = "timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
      description = "Metric collection timestamp"
    },
    {
      name = "region"
      type = "STRING"
      mode = "REQUIRED"  
      description = "Source region for the metric"
    },
    {
      name = "metric_type"
      type = "STRING"
      mode = "REQUIRED"
      description = "Type of metric (request_rate, response_time, etc.)"
    },
    {
      name = "service"
      type = "STRING"
      mode = "REQUIRED"
      description = "Service name"
    },
    {
      name = "metric_value"
      type = "FLOAT"
      mode = "REQUIRED"
      description = "Metric value"
    },
    {
      name = "labels"
      type = "JSON"
      mode = "NULLABLE"
      description = "Additional metric labels"
    },
    {
      name = "business_impact"
      type = "STRING"
      mode = "NULLABLE"
      description = "Business impact classification"
    }
  ])
  
  description = "Aggregated monitoring metrics for anomaly detection training"
}

# Anomaly detection results table
resource "google_bigquery_table" "anomaly_results" {
  dataset_id = google_bigquery_dataset.anomaly_detection.dataset_id
  table_id   = "anomaly_results"
  project    = var.project_id
  
  time_partitioning {
    type  = "DAY"
    field = "detection_timestamp"
    require_partition_filter = true
    expiration_ms = 7776000000  # 90 days
  }
  
  clustering = ["region", "metric_type", "anomaly_score"]
  
  schema = jsonencode([
    {
      name = "detection_timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
      description = "When anomaly was detected"
    },
    {
      name = "region"
      type = "STRING"
      mode = "REQUIRED"
      description = "Region where anomaly was detected"
    },
    {
      name = "metric_type"
      type = "STRING"
      mode = "REQUIRED"
      description = "Type of metric showing anomaly"
    },
    {
      name = "service"
      type = "STRING"
      mode = "REQUIRED"
      description = "Affected service"
    },
    {
      name = "anomaly_score"
      type = "FLOAT"
      mode = "REQUIRED"
      description = "Anomaly score (0-1, higher = more anomalous)"
    },
    {
      name = "expected_value"
      type = "FLOAT"
      mode = "REQUIRED"
      description = "Expected metric value based on model"
    },
    {
      name = "actual_value" 
      type = "FLOAT"
      mode = "REQUIRED"
      description = "Actual observed metric value"
    },
    {
      name = "deviation_percentage"
      type = "FLOAT"
      mode = "REQUIRED"
      description = "Percentage deviation from expected"
    },
    {
      name = "confidence_interval_lower"
      type = "FLOAT"
      mode = "NULLABLE"
      description = "Lower bound of confidence interval"
    },
    {
      name = "confidence_interval_upper"
      type = "FLOAT"
      mode = "NULLABLE"
      description = "Upper bound of confidence interval"
    },
    {
      name = "business_impact"
      type = "STRING"
      mode = "NULLABLE"
      description = "Assessed business impact level"
    },
    {
      name = "alert_triggered"
      type = "BOOLEAN"
      mode = "NULLABLE"
      description = "Whether an alert was triggered"
    },
    {
      name = "model_version"
      type = "STRING"
      mode = "NULLABLE"
      description = "Version of ML model used"
    }
  ])
  
  description = "Anomaly detection results and alerts"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BIGQUERY ML MODELS FOR ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

# Time series forecasting model for request rates
resource "google_bigquery_routine" "request_rate_anomaly_model" {
  dataset_id      = google_bigquery_dataset.anomaly_detection.dataset_id
  routine_id      = "request_rate_anomaly_model"
  routine_type    = "SCALAR_FUNCTION"
  project         = var.project_id
  language        = "SQL"
  
  definition_body = templatefile("${path.module}/sql/create_anomaly_model.sql", {
    dataset_id = google_bigquery_dataset.anomaly_detection.dataset_id
    metric_type = "request_rate"
    model_type = "ARIMA_PLUS"
    training_days = local.anomaly_config.training_config.training_days
  })
  
  description = "ARIMA+ model for detecting request rate anomalies"
  
  depends_on = [google_bigquery_table.monitoring_metrics]
}

# Anomaly detection scoring function
resource "google_bigquery_routine" "calculate_anomaly_score" {
  dataset_id      = google_bigquery_dataset.anomaly_detection.dataset_id
  routine_id      = "calculate_anomaly_score"
  routine_type    = "SCALAR_FUNCTION"
  project         = var.project_id
  language        = "SQL"
  
  arguments {
    name      = "actual_value"
    data_type = jsonencode({ "typeKind": "FLOAT64" })
  }
  
  arguments {
    name      = "forecast_value"
    data_type = jsonencode({ "typeKind": "FLOAT64" })
  }
  
  arguments {
    name      = "confidence_interval_lower"
    data_type = jsonencode({ "typeKind": "FLOAT64" })
  }
  
  arguments {
    name      = "confidence_interval_upper"
    data_type = jsonencode({ "typeKind": "FLOAT64" })
  }
  
  return_type = jsonencode({ "typeKind": "FLOAT64" })
  
  definition_body = file("${path.module}/sql/calculate_anomaly_score.sql")
  
  description = "Calculate anomaly score based on forecast vs actual values"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD FUNCTIONS FOR ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

# Function bucket for anomaly detection code
resource "google_storage_bucket" "anomaly_detection_functions" {
  name     = "isectech-anomaly-functions-${var.environment}-${random_id.anomaly_suffix.hex}"
  location = "US"
  project  = var.project_id
  
  uniform_bucket_level_access = true
  force_destroy = true
  
  labels = merge(local.common_labels, {
    function-type = "anomaly-detection"
  })
}

# Anomaly detection function source
resource "google_storage_bucket_object" "anomaly_detector_source" {
  name   = "anomaly-detector-${random_id.anomaly_suffix.hex}.zip"
  bucket = google_storage_bucket.anomaly_detection_functions.name
  source = data.archive_file.anomaly_detector_source.output_path
  
  depends_on = [data.archive_file.anomaly_detector_source]
}

# Create function source archive
data "archive_file" "anomaly_detector_source" {
  type        = "zip"
  output_path = "/tmp/anomaly-detector.zip"
  
  source {
    content = templatefile("${path.module}/functions/anomaly_detector.py", {
      project_id = var.project_id
      dataset_id = google_bigquery_dataset.anomaly_detection.dataset_id
      anomaly_config = jsonencode(local.anomaly_config)
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/requirements-anomaly.txt")
    filename = "requirements.txt"
  }
}

# Anomaly detection Cloud Function
resource "google_cloudfunctions2_function" "anomaly_detector" {
  name        = "isectech-anomaly-detector-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "ML-powered anomaly detection for multi-region monitoring"
  
  build_config {
    runtime     = "python311"
    entry_point = "detect_anomalies"
    
    source {
      storage_source {
        bucket = google_storage_bucket.anomaly_detection_functions.name
        object = google_storage_bucket_object.anomaly_detector_source.name
      }
    }
  }
  
  service_config {
    max_instance_count = 10
    available_memory   = "2Gi"
    timeout_seconds    = 540
    
    environment_variables = {
      PROJECT_ID     = var.project_id
      DATASET_ID     = google_bigquery_dataset.anomaly_detection.dataset_id
      ANOMALY_CONFIG = jsonencode(local.anomaly_config)
      ENVIRONMENT    = var.environment
    }
    
    service_account_email = google_service_account.anomaly_detection.email
  }
  
  # Scheduled trigger for anomaly detection
  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.scheduler.job.v1.executed"
    pubsub_topic   = google_pubsub_topic.anomaly_detection_schedule.id
  }
  
  depends_on = [
    google_project_service.required_services,
    google_storage_bucket_object.anomaly_detector_source
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULING AND AUTOMATION
# ═══════════════════════════════════════════════════════════════════════════════

# Pub/Sub topic for anomaly detection scheduling
resource "google_pubsub_topic" "anomaly_detection_schedule" {
  name    = "isectech-anomaly-detection-schedule-${var.environment}"
  project = var.project_id
  
  labels = merge(local.common_labels, {
    topic-type = "scheduling"
  })
}

# Cloud Scheduler for regular anomaly detection
resource "google_cloud_scheduler_job" "anomaly_detection_schedule" {
  name             = "isectech-anomaly-detection-${var.environment}"
  region           = "us-central1"
  project          = var.project_id
  description      = "Trigger anomaly detection every 5 minutes"
  schedule         = "*/5 * * * *"  # Every 5 minutes
  time_zone        = "UTC"
  attempt_deadline = "300s"
  
  pubsub_target {
    topic_name = google_pubsub_topic.anomaly_detection_schedule.id
    data       = base64encode(jsonencode({
      action = "detect_anomalies"
      timestamp = timestamp()
    }))
  }
  
  depends_on = [google_pubsub_topic.anomaly_detection_schedule]
}

# Model retraining scheduler (daily)
resource "google_cloud_scheduler_job" "model_retrain_schedule" {
  name             = "isectech-model-retrain-${var.environment}"
  region           = "us-central1"
  project          = var.project_id
  description      = "Retrain anomaly detection models daily"
  schedule         = "0 2 * * *"  # 2 AM UTC daily
  time_zone        = "UTC"
  attempt_deadline = "1800s"  # 30 minutes
  
  pubsub_target {
    topic_name = google_pubsub_topic.model_retrain_schedule.id
    data       = base64encode(jsonencode({
      action = "retrain_models"
      timestamp = timestamp()
    }))
  }
  
  depends_on = [google_pubsub_topic.model_retrain_schedule]
}

resource "google_pubsub_topic" "model_retrain_schedule" {
  name    = "isectech-model-retrain-schedule-${var.environment}"
  project = var.project_id
  
  labels = merge(local.common_labels, {
    topic-type = "model-training"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE ACCOUNTS AND IAM
# ═══════════════════════════════════════════════════════════════════════════════

# Service account for anomaly detection
resource "google_service_account" "anomaly_detection" {
  account_id   = "anomaly-detection-${var.environment}"
  display_name = "Anomaly Detection Service Account"
  description  = "Service account for ML anomaly detection system"
  project      = var.project_id
}

# IAM roles for anomaly detection
resource "google_project_iam_member" "anomaly_detection_roles" {
  for_each = toset([
    "roles/bigquery.dataEditor",
    "roles/bigquery.jobUser",
    "roles/ml.developer",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/pubsub.publisher",
    "roles/cloudfunctions.invoker"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.anomaly_detection.email}"
}

# Service account for monitoring data export
resource "google_service_account" "monitoring_data_export" {
  account_id   = "monitoring-data-export-${var.environment}"
  display_name = "Monitoring Data Export Service Account" 
  description  = "Service account for exporting monitoring data to BigQuery"
  project      = var.project_id
}

# IAM roles for monitoring data export
resource "google_project_iam_member" "monitoring_data_export_roles" {
  for_each = toset([
    "roles/bigquery.dataEditor",
    "roles/bigquery.jobUser",
    "roles/monitoring.viewer",
    "roles/logging.viewer"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.monitoring_data_export.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# ALERT POLICIES FOR ANOMALIES
# ═══════════════════════════════════════════════════════════════════════════════

# High anomaly score alert
resource "google_monitoring_alert_policy" "high_anomaly_detected" {
  display_name = "High Anomaly Score Detected"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Anomaly score exceeds threshold"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND metric.type=\"custom.googleapis.com/anomaly/score\""
      duration        = "300s"  # 5 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8     # High anomaly threshold
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_MAX"
        
        group_by_fields = [
          "metric.label.region",
          "metric.label.metric_type",
          "metric.label.service"
        ]
      }
    }
  }
  
  severity = "WARNING"
  
  notification_channels = [
    google_monitoring_notification_channel.anomaly_alerts.id
  ]
  
  documentation {
    content = "High anomaly score detected indicating potential service issue or unusual traffic pattern. Investigate the affected service and region."
    mime_type = "text/markdown"
  }
}

# Critical business impact anomaly alert
resource "google_monitoring_alert_policy" "critical_anomaly_detected" {
  display_name = "Critical Business Impact Anomaly"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Critical anomaly affecting business metrics"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND metric.type=\"custom.googleapis.com/anomaly/score\" AND metric.label.business_impact=\"critical\""
      duration        = "180s"  # 3 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 0.7     # Lower threshold for critical impact
      
      aggregations {
        alignment_period     = "180s"
        per_series_aligner   = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_MAX"
        
        group_by_fields = [
          "metric.label.region",
          "metric.label.metric_type"
        ]
      }
    }
  }
  
  severity = "CRITICAL"
  
  notification_channels = [
    google_monitoring_notification_channel.critical_anomaly_alerts.id,
    google_monitoring_notification_channel.pagerduty_anomaly.id
  ]
  
  documentation {
    content = "**CRITICAL ANOMALY DETECTED**\n\nCritical business impact anomaly detected. This may indicate:\n- Service outage\n- Security incident\n- Infrastructure failure\n- Data quality issues\n\nImmediate investigation required."
    mime_type = "text/markdown"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CHANNELS FOR ANOMALY ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_monitoring_notification_channel" "anomaly_alerts" {
  display_name = "Anomaly Detection Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "anomaly-alerts@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "critical_anomaly_alerts" {
  display_name = "Critical Anomaly Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "critical-anomalies@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "pagerduty_anomaly" {
  display_name = "PagerDuty Anomaly Escalation"
  type         = "pagerduty"
  project      = var.project_id
  
  labels = {
    service_key = var.pagerduty_anomaly_service_key
  }
  
  enabled = var.enable_pagerduty
}

# ═══════════════════════════════════════════════════════════════════════════════
# REQUIRED RESOURCES
# ═══════════════════════════════════════════════════════════════════════════════

resource "random_id" "anomaly_suffix" {
  byte_length = 4
}

resource "google_project_service" "required_services" {
  for_each = toset([
    "bigquery.googleapis.com",
    "cloudfunctions.googleapis.com", 
    "cloudscheduler.googleapis.com",
    "pubsub.googleapis.com",
    "ml.googleapis.com"
  ])
  
  project = var.project_id
  service = each.value
  
  disable_dependent_services = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "anomaly_detection_config" {
  description = "Anomaly detection system configuration"
  value = {
    dataset_id = google_bigquery_dataset.anomaly_detection.dataset_id
    
    functions = {
      anomaly_detector = google_cloudfunctions2_function.anomaly_detector.name
    }
    
    tables = {
      monitoring_metrics = google_bigquery_table.monitoring_metrics.table_id
      anomaly_results = google_bigquery_table.anomaly_results.table_id
    }
    
    service_accounts = {
      anomaly_detection = google_service_account.anomaly_detection.email
      data_export = google_service_account.monitoring_data_export.email
    }
    
    schedules = {
      anomaly_detection = google_cloud_scheduler_job.anomaly_detection_schedule.name
      model_retrain = google_cloud_scheduler_job.model_retrain_schedule.name
    }
    
    alert_policies = {
      high_anomaly = google_monitoring_alert_policy.high_anomaly_detected.name
      critical_anomaly = google_monitoring_alert_policy.critical_anomaly_detected.name
    }
    
    configuration = local.anomaly_config
  }
  sensitive = true
}