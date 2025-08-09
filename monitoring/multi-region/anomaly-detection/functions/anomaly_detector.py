#!/usr/bin/env python3
"""
iSECTECH Multi-Region Anomaly Detection System
ML-powered anomaly detection using BigQuery ML ARIMA+ models

Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
Version: 1.0.0 - Task 70.9 Implementation
"""

import json
import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import base64

# Google Cloud imports
from google.cloud import bigquery
from google.cloud import monitoring_v3
from google.cloud import logging as cloud_logging
from google.api_core import exceptions
import functions_framework

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cloud Logging client
cloud_logging_client = cloud_logging.Client()
cloud_logging_client.setup_logging()

class AnomalyDetector:
    """Advanced ML-powered anomaly detection system"""
    
    def __init__(self):
        self.project_id = os.getenv('PROJECT_ID')
        self.dataset_id = os.getenv('DATASET_ID')
        self.environment = os.getenv('ENVIRONMENT', 'production')
        
        # Parse anomaly configuration
        try:
            self.anomaly_config = json.loads(os.getenv('ANOMALY_CONFIG', '{}'))
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse anomaly configuration: {e}")
            self.anomaly_config = {}
        
        # Initialize clients
        self.bigquery_client = bigquery.Client(project=self.project_id)
        self.monitoring_client = monitoring_v3.MetricServiceClient()
        
        # Metrics configuration
        self.metrics_project_path = f"projects/{self.project_id}"
        
        logger.info(f"Initialized AnomalyDetector for project {self.project_id}")
    
    def detect_anomalies_for_metric(self, metric_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies for a specific metric using BigQuery ML"""
        metric_name = metric_config['metric_name']
        logger.info(f"Detecting anomalies for metric: {metric_name}")
        
        anomalies = []
        
        try:
            # Query for recent data and forecasts
            forecast_query = self._build_forecast_query(metric_config)
            
            # Execute forecast query
            forecast_results = self.bigquery_client.query(forecast_query)
            
            # Process forecast results to identify anomalies
            for row in forecast_results:
                anomaly = self._evaluate_forecast_row(row, metric_config)
                if anomaly:
                    anomalies.append(anomaly)
            
            logger.info(f"Detected {len(anomalies)} anomalies for {metric_name}")
            
        except Exception as e:
            logger.error(f"Error detecting anomalies for {metric_name}: {e}")
        
        return anomalies
    
    def _build_forecast_query(self, metric_config: Dict[str, Any]) -> str:
        """Build BigQuery ML forecast query for anomaly detection"""
        metric_name = metric_config['metric_name']
        model_name = f"{metric_name}_anomaly_model"
        sensitivity = self.anomaly_config['training_config']['sensitivity_levels'][metric_config['sensitivity']]
        
        query = f"""
        WITH recent_data AS (
          -- Get recent actual data points
          SELECT 
            timestamp,
            region,
            service,
            metric_value as actual_value,
            EXTRACT(HOUR FROM timestamp) as hour_of_day,
            EXTRACT(DAYOFWEEK FROM timestamp) as day_of_week,
            EXTRACT(DAY FROM timestamp) as day_of_month,
            CASE 
              WHEN EXTRACT(HOUR FROM timestamp) BETWEEN 8 AND 18 
               AND EXTRACT(DAYOFWEEK FROM timestamp) BETWEEN 2 AND 6 
              THEN 1 ELSE 0 
            END as is_business_hours,
            CASE 
              WHEN EXTRACT(DAYOFWEEK FROM timestamp) IN (1, 7) 
              THEN 1 ELSE 0 
            END as is_weekend
          FROM `{self.project_id}.{self.dataset_id}.monitoring_metrics`
          WHERE 
            metric_type = '{metric_name}'
            AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 HOUR)
            AND timestamp < CURRENT_TIMESTAMP()
            AND metric_value IS NOT NULL
        ),
        
        forecasts AS (
          -- Generate forecasts using the ML model
          SELECT
            *
          FROM ML.FORECAST(
            MODEL `{self.project_id}.{self.dataset_id}.{model_name}`,
            STRUCT(
              2 as horizon,  -- 2 hours forecast
              {sensitivity} as confidence_level
            )
          )
        )
        
        SELECT 
          r.timestamp,
          r.region,
          r.service,
          r.actual_value,
          f.forecast_value,
          f.standard_error,
          f.confidence_interval_lower_bound,
          f.confidence_interval_upper_bound,
          -- Calculate anomaly score using custom function
          `{self.project_id}.{self.dataset_id}`.calculate_anomaly_score(
            r.actual_value,
            f.forecast_value,
            f.confidence_interval_lower_bound,
            f.confidence_interval_upper_bound
          ) as anomaly_score,
          -- Calculate deviation percentage
          ABS(r.actual_value - f.forecast_value) / NULLIF(f.forecast_value, 0) * 100 as deviation_percentage
        FROM recent_data r
        LEFT JOIN forecasts f 
          ON r.timestamp = f.forecast_timestamp
          AND r.region = f.region
          AND r.service = f.service
        WHERE f.forecast_value IS NOT NULL
        ORDER BY anomaly_score DESC, deviation_percentage DESC
        """
        
        return query
    
    def _evaluate_forecast_row(self, row, metric_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate forecast row for anomalies"""
        anomaly_score = row.anomaly_score if row.anomaly_score else 0.0
        deviation_percentage = row.deviation_percentage if row.deviation_percentage else 0.0
        
        # Determine if this is an anomaly based on thresholds
        threshold_multiplier = metric_config.get('threshold_multiplier', 2.0)
        business_impact = metric_config.get('business_impact', 'medium')
        
        # Adjust thresholds based on business impact
        if business_impact == 'critical':
            anomaly_threshold = 0.5  # Lower threshold for critical metrics
            deviation_threshold = 20  # 20% deviation
        elif business_impact == 'high':
            anomaly_threshold = 0.6
            deviation_threshold = 30  # 30% deviation
        else:
            anomaly_threshold = 0.7
            deviation_threshold = 50  # 50% deviation
        
        # Check if anomaly thresholds are exceeded
        is_anomaly = (
            anomaly_score >= anomaly_threshold or 
            deviation_percentage >= deviation_threshold
        )
        
        if not is_anomaly:
            return None
        
        # Create anomaly record
        anomaly = {
            'detection_timestamp': datetime.utcnow().isoformat(),
            'region': row.region,
            'metric_type': metric_config['metric_name'],
            'service': row.service,
            'anomaly_score': float(anomaly_score),
            'expected_value': float(row.forecast_value),
            'actual_value': float(row.actual_value),
            'deviation_percentage': float(deviation_percentage),
            'confidence_interval_lower': float(row.confidence_interval_lower_bound) if row.confidence_interval_lower_bound else None,
            'confidence_interval_upper': float(row.confidence_interval_upper_bound) if row.confidence_interval_upper_bound else None,
            'business_impact': business_impact,
            'alert_triggered': anomaly_score >= 0.8 or deviation_percentage >= 100,  # High severity threshold
            'model_version': '1.0',
            'timestamp': row.timestamp.isoformat()
        }
        
        return anomaly
    
    def store_anomaly_results(self, anomalies: List[Dict[str, Any]]) -> int:
        """Store anomaly detection results in BigQuery"""
        if not anomalies:
            return 0
        
        try:
            # Prepare table reference
            table_ref = self.bigquery_client.dataset(self.dataset_id).table('anomaly_results')
            table = self.bigquery_client.get_table(table_ref)
            
            # Convert anomalies to BigQuery rows
            rows_to_insert = []
            for anomaly in anomalies:
                row = {
                    'detection_timestamp': anomaly['detection_timestamp'],
                    'region': anomaly['region'],
                    'metric_type': anomaly['metric_type'],
                    'service': anomaly['service'],
                    'anomaly_score': anomaly['anomaly_score'],
                    'expected_value': anomaly['expected_value'],
                    'actual_value': anomaly['actual_value'],
                    'deviation_percentage': anomaly['deviation_percentage'],
                    'confidence_interval_lower': anomaly['confidence_interval_lower'],
                    'confidence_interval_upper': anomaly['confidence_interval_upper'],
                    'business_impact': anomaly['business_impact'],
                    'alert_triggered': anomaly['alert_triggered'],
                    'model_version': anomaly['model_version']
                }
                rows_to_insert.append(row)
            
            # Insert rows
            errors = self.bigquery_client.insert_rows_json(table, rows_to_insert)
            
            if errors:
                logger.error(f"Errors inserting anomaly results: {errors}")
                return 0
            
            logger.info(f"Successfully stored {len(rows_to_insert)} anomaly results")
            return len(rows_to_insert)
            
        except Exception as e:
            logger.error(f"Error storing anomaly results: {e}")
            return 0
    
    def send_anomaly_alerts(self, anomalies: List[Dict[str, Any]]) -> int:
        """Send alerts for detected anomalies"""
        alerts_sent = 0
        
        for anomaly in anomalies:
            if not anomaly.get('alert_triggered', False):
                continue
            
            try:
                # Record anomaly metric for alerting
                self._record_anomaly_metric(anomaly)
                alerts_sent += 1
                
                # Log structured alert for Cloud Logging
                logger.warning("Anomaly detected", extra={
                    'anomaly_details': anomaly,
                    'severity': 'WARNING' if anomaly['anomaly_score'] < 0.9 else 'CRITICAL',
                    'business_impact': anomaly['business_impact']
                })
                
            except Exception as e:
                logger.error(f"Error sending alert for anomaly: {e}")
        
        return alerts_sent
    
    def _record_anomaly_metric(self, anomaly: Dict[str, Any]):
        """Record anomaly as a custom metric for alerting"""
        try:
            metric_type = "custom.googleapis.com/anomaly/score"
            
            # Create time series data
            series = monitoring_v3.TimeSeries()
            series.metric.type = metric_type
            series.metric.labels['region'] = anomaly['region']
            series.metric.labels['metric_type'] = anomaly['metric_type']
            series.metric.labels['service'] = anomaly['service']
            series.metric.labels['business_impact'] = anomaly['business_impact']
            
            # Set resource
            series.resource.type = 'cloud_function'
            series.resource.labels['function_name'] = 'anomaly-detector'
            series.resource.labels['region'] = 'us-central1'
            
            # Create data point
            point = monitoring_v3.Point()
            point.value.double_value = anomaly['anomaly_score']
            now = time.time()
            seconds = int(now)
            nanos = int((now - seconds) * 10 ** 9)
            point.interval.end_time.seconds = seconds
            point.interval.end_time.nanos = nanos
            
            series.points = [point]
            
            # Write the metric
            self.monitoring_client.create_time_series(
                name=self.metrics_project_path,
                time_series=[series]
            )
            
            logger.debug(f"Recorded anomaly metric: {anomaly['metric_type']} in {anomaly['region']} = {anomaly['anomaly_score']}")
            
        except Exception as e:
            logger.warning(f"Error recording anomaly metric: {e}")
    
    def retrain_models(self) -> Dict[str, Any]:
        """Retrain anomaly detection models with fresh data"""
        logger.info("Starting model retraining process")
        
        retrain_results = {
            'models_retrained': 0,
            'errors': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        monitored_metrics = self.anomaly_config.get('monitored_metrics', {})
        
        for metric_name, metric_config in monitored_metrics.items():
            try:
                logger.info(f"Retraining model for {metric_name}")
                
                # Build model creation query
                model_query = self._build_model_creation_query(metric_name, metric_config)
                
                # Execute model creation/retraining
                query_job = self.bigquery_client.query(model_query)
                query_job.result()  # Wait for completion
                
                retrain_results['models_retrained'] += 1
                logger.info(f"Successfully retrained model for {metric_name}")
                
            except Exception as e:
                error_msg = f"Error retraining model for {metric_name}: {str(e)}"
                logger.error(error_msg)
                retrain_results['errors'].append(error_msg)
        
        logger.info(f"Model retraining completed: {retrain_results['models_retrained']} models retrained")
        return retrain_results
    
    def _build_model_creation_query(self, metric_name: str, metric_config: Dict[str, Any]) -> str:
        """Build BigQuery ML model creation query"""
        training_days = self.anomaly_config['training_config']['training_days']
        
        query = f"""
        CREATE OR REPLACE MODEL `{self.project_id}.{self.dataset_id}.{metric_name}_anomaly_model`
        OPTIONS(
          model_type='ARIMA_PLUS',
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
        SELECT 
          timestamp,
          region,
          service,
          metric_value,
          EXTRACT(HOUR FROM timestamp) as hour_of_day,
          EXTRACT(DAYOFWEEK FROM timestamp) as day_of_week,
          EXTRACT(DAY FROM timestamp) as day_of_month,
          CASE 
            WHEN EXTRACT(HOUR FROM timestamp) BETWEEN 8 AND 18 
             AND EXTRACT(DAYOFWEEK FROM timestamp) BETWEEN 2 AND 6 
            THEN 1 ELSE 0 
          END as is_business_hours,
          CASE 
            WHEN EXTRACT(DAYOFWEEK FROM timestamp) IN (1, 7) 
            THEN 1 ELSE 0 
          END as is_weekend
        FROM `{self.project_id}.{self.dataset_id}.monitoring_metrics`
        WHERE 
          metric_type = '{metric_name}'
          AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {training_days} DAY)
          AND timestamp < CURRENT_TIMESTAMP()
          AND metric_value IS NOT NULL
          AND metric_value >= 0
          AND (region, service) IN (
            SELECT region, service
            FROM `{self.project_id}.{self.dataset_id}.monitoring_metrics`
            WHERE metric_type = '{metric_name}'
              AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {training_days} DAY)
            GROUP BY region, service
            HAVING COUNT(*) >= 168  -- At least 1 week of data
          )
        ORDER BY region, service, timestamp
        """
        
        return query
    
    def run_anomaly_detection(self) -> Dict[str, Any]:
        """Run complete anomaly detection process"""
        logger.info("Starting anomaly detection process")
        
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'environment': self.environment,
            'total_anomalies': 0,
            'alerts_sent': 0,
            'metrics_processed': 0,
            'errors': []
        }
        
        monitored_metrics = self.anomaly_config.get('monitored_metrics', {})
        
        all_anomalies = []
        
        # Process each monitored metric
        for metric_name, metric_config in monitored_metrics.items():
            try:
                logger.info(f"Processing anomaly detection for {metric_name}")
                
                # Detect anomalies for this metric
                metric_anomalies = self.detect_anomalies_for_metric(metric_config)
                all_anomalies.extend(metric_anomalies)
                
                results['metrics_processed'] += 1
                
            except Exception as e:
                error_msg = f"Error processing {metric_name}: {str(e)}"
                logger.error(error_msg)
                results['errors'].append(error_msg)
        
        # Store all anomalies
        if all_anomalies:
            stored_count = self.store_anomaly_results(all_anomalies)
            results['total_anomalies'] = len(all_anomalies)
            
            # Send alerts for critical anomalies
            alerts_sent = self.send_anomaly_alerts(all_anomalies)
            results['alerts_sent'] = alerts_sent
            
            logger.info(f"Anomaly detection completed: {len(all_anomalies)} anomalies detected, {alerts_sent} alerts sent")
        else:
            logger.info("No anomalies detected")
        
        return results

@functions_framework.cloud_event
def detect_anomalies(cloud_event):
    """Cloud Function entry point for anomaly detection"""
    logger.info(f"Anomaly detection triggered: {cloud_event.get('type', 'unknown')}")
    
    try:
        # Parse event data
        event_data = {}
        if cloud_event.get('data'):
            try:
                event_data = json.loads(base64.b64decode(cloud_event['data']).decode())
            except Exception as e:
                logger.warning(f"Could not parse event data: {e}")
        
        # Initialize anomaly detector
        detector = AnomalyDetector()
        
        # Determine action from event data
        action = event_data.get('action', 'detect_anomalies')
        
        if action == 'retrain_models':
            # Model retraining request
            results = detector.retrain_models()
            logger.info("Model retraining completed", extra={'retrain_results': results})
        else:
            # Normal anomaly detection
            results = detector.run_anomaly_detection()
            
            # Log structured results
            logger.info("Anomaly detection completed", extra={
                'anomaly_results': results,
                'severity': 'WARNING' if results['alerts_sent'] > 0 else 'INFO'
            })
        
        return {
            'status': 'success',
            'message': f"Anomaly detection completed: {action}",
            'results': results
        }
        
    except Exception as e:
        error_msg = f"Anomaly detection failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        return {
            'status': 'error',
            'message': error_msg,
            'error': str(e)
        }

if __name__ == "__main__":
    # For local testing
    import sys
    from unittest.mock import Mock
    
    # Create mock cloud event
    mock_event = {
        'type': 'google.cloud.scheduler.job.v1.executed',
        'data': base64.b64encode(json.dumps({'action': 'detect_anomalies'}).encode()).decode()
    }
    
    result = detect_anomalies(mock_event)
    print(json.dumps(result, indent=2))