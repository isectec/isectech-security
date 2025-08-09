-- ═══════════════════════════════════════════════════════════════════════════════
-- CALCULATE ANOMALY SCORE FUNCTION
-- Calculate normalized anomaly score based on forecast vs actual values
-- Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT  
-- Version: 1.0.0 - Task 70.9 Implementation
-- ═══════════════════════════════════════════════════════════════════════════════

-- Calculate anomaly score function
-- Returns a score between 0 (normal) and 1 (highly anomalous)

-- Calculate the deviation from the confidence interval
CASE
  -- If actual value is within confidence interval, low anomaly score
  WHEN actual_value BETWEEN confidence_interval_lower AND confidence_interval_upper 
  THEN 0.0
  
  -- If actual value is outside confidence interval, calculate severity
  WHEN actual_value > confidence_interval_upper
  THEN LEAST(
    1.0,  -- Cap at 1.0
    (actual_value - confidence_interval_upper) / 
    GREATEST(
      confidence_interval_upper - forecast_value,
      forecast_value * 0.1  -- Minimum denominator to avoid division by very small numbers
    )
  )
  
  WHEN actual_value < confidence_interval_lower
  THEN LEAST(
    1.0,  -- Cap at 1.0
    (confidence_interval_lower - actual_value) /
    GREATEST(
      forecast_value - confidence_interval_lower,
      forecast_value * 0.1  -- Minimum denominator to avoid division by very small numbers
    )
  )
  
  -- Default case (shouldn't happen but safety net)
  ELSE 0.0
END