-- ═══════════════════════════════════════════════════════════════════════════════
-- CREATE ANOMALY DETECTION MODEL
-- BigQuery ML ARIMA+ model for time series anomaly detection
-- Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
-- Version: 1.0.0 - Task 70.9 Implementation
-- ═══════════════════════════════════════════════════════════════════════════════

-- Create or replace the anomaly detection model
CREATE OR REPLACE MODEL `${project_id}.${dataset_id}.${metric_type}_anomaly_model`
OPTIONS(
  model_type='${model_type}',
  time_series_timestamp_col='timestamp',
  time_series_data_col='metric_value',
  time_series_id_col=['region', 'service'],
  auto_arima=TRUE,
  data_frequency='HOURLY',
  include_drift=TRUE,
  clean_spikes_and_dips=TRUE,
  adjust_step_changes=TRUE,
  holiday_region='US',
  decompose_time_series=TRUE
) AS
-- Training query for the model
WITH training_data AS (
  SELECT 
    timestamp,
    region,
    service,
    metric_value,
    -- Add time-based features for better seasonality detection
    EXTRACT(HOUR FROM timestamp) as hour_of_day,
    EXTRACT(DAYOFWEEK FROM timestamp) as day_of_week,
    EXTRACT(DAY FROM timestamp) as day_of_month,
    -- Business hours indicator
    CASE 
      WHEN EXTRACT(HOUR FROM timestamp) BETWEEN 8 AND 18 
       AND EXTRACT(DAYOFWEEK FROM timestamp) BETWEEN 2 AND 6 
      THEN 1 
      ELSE 0 
    END as is_business_hours,
    -- Weekend indicator  
    CASE 
      WHEN EXTRACT(DAYOFWEEK FROM timestamp) IN (1, 7) 
      THEN 1 
      ELSE 0 
    END as is_weekend
  FROM `${project_id}.${dataset_id}.monitoring_metrics`
  WHERE 
    metric_type = '${metric_type}'
    AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL ${training_days} DAY)
    AND timestamp < CURRENT_TIMESTAMP()
    AND metric_value IS NOT NULL
    AND metric_value >= 0  -- Filter out negative values which may be erroneous
)

SELECT 
  timestamp,
  region, 
  service,
  metric_value,
  hour_of_day,
  day_of_week,
  day_of_month,
  is_business_hours,
  is_weekend
FROM training_data
WHERE 
  -- Ensure we have sufficient data points per time series
  (region, service) IN (
    SELECT region, service
    FROM training_data
    GROUP BY region, service
    HAVING COUNT(*) >= 168  -- At least 1 week of hourly data
  )
ORDER BY region, service, timestamp;