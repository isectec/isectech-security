"""
Bias Monitoring System for AI/ML Models
Production-grade continuous bias monitoring and alerting system
"""

import logging
import json
import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score
import aioredis
from sqlalchemy import create_engine, Column, String, DateTime, Float, Integer, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import warnings

logger = logging.getLogger(__name__)

class BiasAlertSeverity(Enum):
    """Severity levels for bias alerts"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MonitoringFrequency(Enum):
    """Monitoring frequency options"""
    REAL_TIME = "real_time"
    HOURLY = "hourly" 
    DAILY = "daily"
    WEEKLY = "weekly"

@dataclass
class BiasAlert:
    """Bias alert notification"""
    alert_id: str
    model_id: str
    timestamp: datetime
    severity: BiasAlertSeverity
    bias_type: str
    protected_attribute: str
    affected_group: str
    metric_name: str
    current_value: float
    threshold_value: float
    confidence_level: float
    sample_size: int
    description: str
    recommended_actions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['severity'] = self.severity.value
        return data

@dataclass
class BiasMetricSnapshot:
    """Snapshot of bias metrics at a point in time"""
    snapshot_id: str
    model_id: str
    timestamp: datetime
    protected_attributes: Dict[str, Dict[str, float]]  # attr -> group -> metrics
    overall_bias_score: float
    drift_detected: bool
    data_quality_score: float
    sample_sizes: Dict[str, int]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

class BiasMonitoringDB:
    """Database models for bias monitoring"""
    Base = declarative_base()
    
    class BiasMetricRecord(Base):
        __tablename__ = 'bias_metrics'
        
        id = Column(String, primary_key=True)
        model_id = Column(String, nullable=False, index=True)
        timestamp = Column(DateTime, nullable=False, index=True)
        protected_attribute = Column(String, nullable=False)
        group_name = Column(String, nullable=False)
        metric_name = Column(String, nullable=False)
        metric_value = Column(Float, nullable=False)
        sample_size = Column(Integer, nullable=False)
        confidence_interval_lower = Column(Float, nullable=True)
        confidence_interval_upper = Column(Float, nullable=True)
        baseline_value = Column(Float, nullable=True)
        drift_magnitude = Column(Float, nullable=True)
        
    class BiasAlertRecord(Base):
        __tablename__ = 'bias_alerts'
        
        alert_id = Column(String, primary_key=True)
        model_id = Column(String, nullable=False, index=True)
        timestamp = Column(DateTime, nullable=False, index=True)
        severity = Column(String, nullable=False)
        bias_type = Column(String, nullable=False)
        protected_attribute = Column(String, nullable=False)
        affected_group = Column(String, nullable=False)
        metric_name = Column(String, nullable=False)
        current_value = Column(Float, nullable=False)
        threshold_value = Column(Float, nullable=False)
        confidence_level = Column(Float, nullable=False)
        sample_size = Column(Integer, nullable=False)
        description = Column(String, nullable=False)
        recommended_actions = Column(JSON, nullable=False)
        acknowledged = Column(Boolean, default=False)
        resolved = Column(Boolean, default=False)
        resolved_at = Column(DateTime, nullable=True)
    
    class MonitoringConfiguration(Base):
        __tablename__ = 'monitoring_config'
        
        config_id = Column(String, primary_key=True)
        model_id = Column(String, nullable=False, index=True)
        protected_attributes = Column(JSON, nullable=False)
        bias_thresholds = Column(JSON, nullable=False)
        monitoring_frequency = Column(String, nullable=False)
        alert_thresholds = Column(JSON, nullable=False)
        enabled = Column(Boolean, default=True)
        created_at = Column(DateTime, default=datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.utcnow)

class BiasMonitoringSystem:
    """
    Comprehensive bias monitoring system for AI/ML threat detection models
    Provides continuous monitoring, alerting, and reporting of bias metrics
    """
    
    def __init__(
        self,
        database_url: str = "postgresql://localhost/isectech_bias_monitoring",
        redis_url: str = "redis://localhost:6379/3",
        default_bias_threshold: float = 0.1,
        default_confidence_level: float = 0.95
    ):
        """Initialize bias monitoring system"""
        self.database_url = database_url
        self.redis_url = redis_url
        self.default_bias_threshold = default_bias_threshold
        self.default_confidence_level = default_confidence_level
        
        # Database setup
        self.engine = create_engine(database_url)
        BiasMonitoringDB.Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Redis for real-time monitoring
        self.redis_pool = None
        
        # Standard protected attributes
        self.standard_protected_attributes = [
            'gender', 'race', 'ethnicity', 'age_group', 'location',
            'socioeconomic_status', 'disability_status', 'religion'
        ]
        
        # Bias metrics to monitor
        self.monitored_metrics = [
            'selection_rate', 'accuracy', 'precision', 'recall', 'f1_score',
            'false_positive_rate', 'false_negative_rate', 'positive_predictive_value'
        ]
        
        logger.info("Bias Monitoring System initialized")

    async def initialize_redis(self) -> None:
        """Initialize Redis connection"""
        if not self.redis_pool:
            self.redis_pool = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=10
            )

    async def configure_model_monitoring(
        self,
        model_id: str,
        protected_attributes: List[str],
        bias_thresholds: Optional[Dict[str, float]] = None,
        monitoring_frequency: MonitoringFrequency = MonitoringFrequency.DAILY,
        alert_thresholds: Optional[Dict[str, Dict[str, float]]] = None
    ) -> str:
        """
        Configure bias monitoring for a specific model
        
        Args:
            model_id: Unique model identifier
            protected_attributes: List of protected attributes to monitor
            bias_thresholds: Custom thresholds for bias detection
            monitoring_frequency: How often to check for bias
            alert_thresholds: Thresholds for different alert severities
            
        Returns:
            Configuration ID
        """
        config_id = str(uuid.uuid4())
        
        # Default bias thresholds
        if bias_thresholds is None:
            bias_thresholds = {metric: self.default_bias_threshold 
                             for metric in self.monitored_metrics}
        
        # Default alert thresholds
        if alert_thresholds is None:
            alert_thresholds = {
                'low': {'threshold': 0.05, 'confidence': 0.90},
                'medium': {'threshold': 0.10, 'confidence': 0.95},
                'high': {'threshold': 0.15, 'confidence': 0.99},
                'critical': {'threshold': 0.20, 'confidence': 0.99}
            }
        
        db = self.SessionLocal()
        try:
            # Check if configuration already exists
            existing = db.query(BiasMonitoringDB.MonitoringConfiguration).filter(
                BiasMonitoringDB.MonitoringConfiguration.model_id == model_id
            ).first()
            
            if existing:
                # Update existing configuration
                existing.protected_attributes = protected_attributes
                existing.bias_thresholds = bias_thresholds
                existing.monitoring_frequency = monitoring_frequency.value
                existing.alert_thresholds = alert_thresholds
                existing.updated_at = datetime.utcnow()
                config_id = existing.config_id
            else:
                # Create new configuration
                config = BiasMonitoringDB.MonitoringConfiguration(
                    config_id=config_id,
                    model_id=model_id,
                    protected_attributes=protected_attributes,
                    bias_thresholds=bias_thresholds,
                    monitoring_frequency=monitoring_frequency.value,
                    alert_thresholds=alert_thresholds
                )
                db.add(config)
            
            db.commit()
            
            logger.info(f"Monitoring configured for model {model_id}: {config_id}")
            return config_id
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error configuring monitoring: {str(e)}")
            raise
        finally:
            db.close()

    async def monitor_model_predictions(
        self,
        model_id: str,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        feature_data: pd.DataFrame,
        prediction_timestamp: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Monitor model predictions for bias
        
        Args:
            model_id: Model to monitor
            predictions: Model predictions
            ground_truth: True labels
            feature_data: Feature data including protected attributes
            prediction_timestamp: When predictions were made
            
        Returns:
            Monitoring results including any alerts generated
        """
        if prediction_timestamp is None:
            prediction_timestamp = datetime.utcnow()
        
        logger.info(f"Monitoring bias for model {model_id} with {len(predictions)} predictions")
        
        # Get monitoring configuration
        config = await self._get_monitoring_config(model_id)
        if not config:
            logger.warning(f"No monitoring configuration found for model {model_id}")
            return {'status': 'no_config', 'alerts': []}
        
        # Calculate bias metrics
        bias_metrics = await self._calculate_bias_metrics(
            model_id, predictions, ground_truth, feature_data, 
            config['protected_attributes'], prediction_timestamp
        )
        
        # Store metrics
        await self._store_bias_metrics(bias_metrics)
        
        # Check for bias alerts
        alerts = await self._check_bias_alerts(
            model_id, bias_metrics, config
        )
        
        # Store alerts
        for alert in alerts:
            await self._store_bias_alert(alert)
        
        # Update real-time monitoring cache
        await self._update_real_time_cache(model_id, bias_metrics, alerts)
        
        result = {
            'status': 'success',
            'timestamp': prediction_timestamp.isoformat(),
            'metrics_calculated': len(bias_metrics),
            'alerts_generated': len(alerts),
            'alerts': [alert.to_dict() for alert in alerts]
        }
        
        logger.info(f"Bias monitoring completed for {model_id}: {len(alerts)} alerts generated")
        
        return result

    async def _get_monitoring_config(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get monitoring configuration for a model"""
        db = self.SessionLocal()
        try:
            config = db.query(BiasMonitoringDB.MonitoringConfiguration).filter(
                BiasMonitoringDB.MonitoringConfiguration.model_id == model_id,
                BiasMonitoringDB.MonitoringConfiguration.enabled == True
            ).first()
            
            if config:
                return {
                    'config_id': config.config_id,
                    'protected_attributes': config.protected_attributes,
                    'bias_thresholds': config.bias_thresholds,
                    'monitoring_frequency': config.monitoring_frequency,
                    'alert_thresholds': config.alert_thresholds
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting monitoring config: {str(e)}")
            return None
        finally:
            db.close()

    async def _calculate_bias_metrics(
        self,
        model_id: str,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        feature_data: pd.DataFrame,
        protected_attributes: List[str],
        timestamp: datetime
    ) -> List[Dict[str, Any]]:
        """Calculate bias metrics for all protected groups"""
        bias_metrics = []
        
        for attr in protected_attributes:
            if attr not in feature_data.columns:
                logger.warning(f"Protected attribute {attr} not found in feature data")
                continue
            
            # Get unique groups for this attribute
            groups = feature_data[attr].unique()
            
            for group in groups:
                group_mask = feature_data[attr] == group
                group_predictions = predictions[group_mask]
                group_truth = ground_truth[group_mask]
                
                if len(group_predictions) == 0:
                    continue
                
                # Calculate metrics for this group
                group_metrics = self._calculate_group_metrics(
                    group_predictions, group_truth
                )
                
                # Store each metric separately
                for metric_name, metric_value in group_metrics.items():
                    bias_metrics.append({
                        'id': str(uuid.uuid4()),
                        'model_id': model_id,
                        'timestamp': timestamp,
                        'protected_attribute': attr,
                        'group_name': str(group),
                        'metric_name': metric_name,
                        'metric_value': metric_value,
                        'sample_size': len(group_predictions)
                    })
        
        # Calculate cross-group comparisons
        cross_group_metrics = await self._calculate_cross_group_metrics(
            model_id, predictions, ground_truth, feature_data, 
            protected_attributes, timestamp
        )
        
        bias_metrics.extend(cross_group_metrics)
        
        return bias_metrics

    def _calculate_group_metrics(
        self, 
        predictions: np.ndarray, 
        ground_truth: np.ndarray
    ) -> Dict[str, float]:
        """Calculate standard fairness metrics for a group"""
        if len(predictions) == 0:
            return {}
        
        metrics = {}
        
        try:
            # Basic metrics
            metrics['selection_rate'] = np.mean(predictions)
            metrics['accuracy'] = accuracy_score(ground_truth, predictions)
            
            # Precision, recall, F1 (handle edge cases)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                metrics['precision'] = precision_score(ground_truth, predictions, zero_division=0)
                metrics['recall'] = recall_score(ground_truth, predictions, zero_division=0)
                
                # F1 score
                if metrics['precision'] + metrics['recall'] > 0:
                    metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall'])
                else:
                    metrics['f1_score'] = 0.0
            
            # Confusion matrix based metrics
            if len(np.unique(predictions)) > 1 and len(np.unique(ground_truth)) > 1:
                cm = confusion_matrix(ground_truth, predictions)
                if cm.shape == (2, 2):
                    tn, fp, fn, tp = cm.ravel()
                    
                    # False positive rate
                    metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0
                    
                    # False negative rate
                    metrics['false_negative_rate'] = fn / (fn + tp) if (fn + tp) > 0 else 0
                    
                    # Positive predictive value
                    metrics['positive_predictive_value'] = tp / (tp + fp) if (tp + fp) > 0 else 0
                    
                    # True negative rate (specificity)
                    metrics['true_negative_rate'] = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        except Exception as e:
            logger.error(f"Error calculating group metrics: {str(e)}")
        
        return metrics

    async def _calculate_cross_group_metrics(
        self,
        model_id: str,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        feature_data: pd.DataFrame,
        protected_attributes: List[str],
        timestamp: datetime
    ) -> List[Dict[str, Any]]:
        """Calculate bias metrics comparing across groups"""
        cross_metrics = []
        
        for attr in protected_attributes:
            if attr not in feature_data.columns:
                continue
            
            groups = feature_data[attr].unique()
            
            if len(groups) < 2:
                continue
            
            # Calculate metrics for each group
            group_metrics = {}
            for group in groups:
                group_mask = feature_data[attr] == group
                group_predictions = predictions[group_mask]
                group_truth = ground_truth[group_mask]
                
                if len(group_predictions) == 0:
                    continue
                
                group_metrics[group] = self._calculate_group_metrics(
                    group_predictions, group_truth
                )
            
            # Compare groups pairwise
            group_list = list(group_metrics.keys())
            for i, group1 in enumerate(group_list):
                for group2 in group_list[i+1:]:
                    if group1 == group2:
                        continue
                    
                    # Calculate differences for each metric
                    for metric_name in self.monitored_metrics:
                        if (metric_name in group_metrics[group1] and 
                            metric_name in group_metrics[group2]):
                            
                            value1 = group_metrics[group1][metric_name]
                            value2 = group_metrics[group2][metric_name]
                            difference = abs(value1 - value2)
                            
                            cross_metrics.append({
                                'id': str(uuid.uuid4()),
                                'model_id': model_id,
                                'timestamp': timestamp,
                                'protected_attribute': attr,
                                'group_name': f'{group1}_vs_{group2}',
                                'metric_name': f'{metric_name}_difference',
                                'metric_value': difference,
                                'sample_size': min(
                                    len(feature_data[feature_data[attr] == group1]),
                                    len(feature_data[feature_data[attr] == group2])
                                )
                            })
        
        return cross_metrics

    async def _store_bias_metrics(self, bias_metrics: List[Dict[str, Any]]) -> None:
        """Store bias metrics in database"""
        if not bias_metrics:
            return
        
        db = self.SessionLocal()
        try:
            for metric in bias_metrics:
                # Calculate confidence intervals if enough data
                confidence_intervals = self._calculate_confidence_intervals(
                    metric['metric_value'], metric['sample_size']
                )
                
                # Get baseline value for drift detection
                baseline_value = await self._get_baseline_value(
                    metric['model_id'], 
                    metric['protected_attribute'],
                    metric['group_name'],
                    metric['metric_name']
                )
                
                # Calculate drift magnitude
                drift_magnitude = None
                if baseline_value is not None:
                    drift_magnitude = abs(metric['metric_value'] - baseline_value)
                
                db_record = BiasMonitoringDB.BiasMetricRecord(
                    id=metric['id'],
                    model_id=metric['model_id'],
                    timestamp=metric['timestamp'],
                    protected_attribute=metric['protected_attribute'],
                    group_name=metric['group_name'],
                    metric_name=metric['metric_name'],
                    metric_value=metric['metric_value'],
                    sample_size=metric['sample_size'],
                    confidence_interval_lower=confidence_intervals.get('lower'),
                    confidence_interval_upper=confidence_intervals.get('upper'),
                    baseline_value=baseline_value,
                    drift_magnitude=drift_magnitude
                )
                
                db.add(db_record)
            
            db.commit()
            logger.info(f"Stored {len(bias_metrics)} bias metrics")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error storing bias metrics: {str(e)}")
            raise
        finally:
            db.close()

    def _calculate_confidence_intervals(
        self, 
        metric_value: float, 
        sample_size: int,
        confidence_level: float = 0.95
    ) -> Dict[str, Optional[float]]:
        """Calculate confidence intervals for a metric"""
        if sample_size < 30:  # Too small for reliable CI
            return {'lower': None, 'upper': None}
        
        try:
            # For proportions (0-1 range metrics)
            if 0 <= metric_value <= 1:
                # Wilson score interval
                z = stats.norm.ppf((1 + confidence_level) / 2)
                denominator = 1 + z**2 / sample_size
                centre_adjusted = metric_value + z**2 / (2 * sample_size)
                adjustment = z * np.sqrt((metric_value * (1 - metric_value) + z**2 / (4 * sample_size)) / sample_size)
                
                lower = (centre_adjusted - adjustment) / denominator
                upper = (centre_adjusted + adjustment) / denominator
                
                return {'lower': max(0, lower), 'upper': min(1, upper)}
            
            # For other metrics, use normal approximation
            std_error = np.sqrt(metric_value * (1 - metric_value) / sample_size)
            margin_error = stats.norm.ppf((1 + confidence_level) / 2) * std_error
            
            return {
                'lower': metric_value - margin_error,
                'upper': metric_value + margin_error
            }
            
        except Exception as e:
            logger.error(f"Error calculating confidence intervals: {str(e)}")
            return {'lower': None, 'upper': None}

    async def _get_baseline_value(
        self, 
        model_id: str, 
        protected_attribute: str,
        group_name: str,
        metric_name: str
    ) -> Optional[float]:
        """Get baseline value for drift detection"""
        db = self.SessionLocal()
        try:
            # Get average of last 30 days excluding today
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            today = datetime.utcnow().date()
            
            baseline_query = db.query(BiasMonitoringDB.BiasMetricRecord).filter(
                BiasMonitoringDB.BiasMetricRecord.model_id == model_id,
                BiasMonitoringDB.BiasMetricRecord.protected_attribute == protected_attribute,
                BiasMonitoringDB.BiasMetricRecord.group_name == group_name,
                BiasMonitoringDB.BiasMetricRecord.metric_name == metric_name,
                BiasMonitoringDB.BiasMetricRecord.timestamp >= cutoff_date,
                BiasMonitoringDB.BiasMetricRecord.timestamp < datetime.combine(today, datetime.min.time())
            )
            
            records = baseline_query.all()
            
            if len(records) >= 5:  # Need at least 5 data points
                values = [r.metric_value for r in records]
                return np.mean(values)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting baseline value: {str(e)}")
            return None
        finally:
            db.close()

    async def _check_bias_alerts(
        self,
        model_id: str,
        bias_metrics: List[Dict[str, Any]],
        config: Dict[str, Any]
    ) -> List[BiasAlert]:
        """Check for bias alerts based on current metrics"""
        alerts = []
        alert_thresholds = config['alert_thresholds']
        
        for metric in bias_metrics:
            metric_name = metric['metric_name']
            metric_value = metric['metric_value']
            
            # Check if this is a difference metric (cross-group comparison)
            if '_difference' in metric_name:
                base_metric = metric_name.replace('_difference', '')
                
                # Check against alert thresholds
                for severity_name, threshold_config in alert_thresholds.items():
                    threshold = threshold_config['threshold']
                    
                    if metric_value > threshold:
                        # Generate alert
                        alert = self._create_bias_alert(
                            model_id=model_id,
                            metric=metric,
                            severity=BiasAlertSeverity(severity_name),
                            threshold=threshold,
                            confidence=threshold_config['confidence']
                        )
                        
                        alerts.append(alert)
                        break  # Only create one alert per metric (highest severity)
        
        return alerts

    def _create_bias_alert(
        self,
        model_id: str,
        metric: Dict[str, Any],
        severity: BiasAlertSeverity,
        threshold: float,
        confidence: float
    ) -> BiasAlert:
        """Create a bias alert"""
        alert_id = str(uuid.uuid4())
        
        # Generate description based on metric
        description = self._generate_alert_description(metric, threshold)
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(metric, severity)
        
        return BiasAlert(
            alert_id=alert_id,
            model_id=model_id,
            timestamp=metric['timestamp'],
            severity=severity,
            bias_type="fairness_disparity",
            protected_attribute=metric['protected_attribute'],
            affected_group=metric['group_name'],
            metric_name=metric['metric_name'],
            current_value=metric['metric_value'],
            threshold_value=threshold,
            confidence_level=confidence,
            sample_size=metric['sample_size'],
            description=description,
            recommended_actions=recommended_actions
        )

    def _generate_alert_description(
        self, 
        metric: Dict[str, Any], 
        threshold: float
    ) -> str:
        """Generate human-readable alert description"""
        attr = metric['protected_attribute']
        group = metric['group_name']
        metric_name = metric['metric_name']
        value = metric['metric_value']
        
        if '_difference' in metric_name:
            base_metric = metric_name.replace('_difference', '')
            return (f"Significant bias detected in {base_metric} for {attr} "
                   f"(groups: {group}). Difference of {value:.3f} exceeds "
                   f"threshold of {threshold:.3f}.")
        else:
            return (f"Bias metric {metric_name} for {attr}={group} is {value:.3f}, "
                   f"which exceeds the threshold of {threshold:.3f}.")

    def _generate_recommended_actions(
        self, 
        metric: Dict[str, Any], 
        severity: BiasAlertSeverity
    ) -> List[str]:
        """Generate recommended actions based on bias alert"""
        actions = []
        
        if severity in [BiasAlertSeverity.HIGH, BiasAlertSeverity.CRITICAL]:
            actions.append("Immediate review required - consider halting model deployment")
            actions.append("Conduct thorough bias analysis and root cause investigation")
            actions.append("Implement bias mitigation techniques")
            actions.append("Retrain model with bias-aware methods")
        elif severity == BiasAlertSeverity.MEDIUM:
            actions.append("Schedule bias review within 24 hours")
            actions.append("Increase monitoring frequency")
            actions.append("Consider collecting more representative training data")
        else:  # LOW
            actions.append("Monitor closely for trend development")
            actions.append("Document findings in bias assessment report")
        
        # Metric-specific recommendations
        metric_name = metric['metric_name']
        if 'accuracy' in metric_name:
            actions.append("Examine training data balance across groups")
            actions.append("Consider group-specific model calibration")
        elif 'selection_rate' in metric_name:
            actions.append("Review decision thresholds for different groups")
            actions.append("Implement threshold optimization for fairness")
        elif 'false_positive_rate' in metric_name:
            actions.append("Analyze false positive patterns by group")
            actions.append("Consider adjusting classification thresholds")
        
        return actions

    async def _store_bias_alert(self, alert: BiasAlert) -> None:
        """Store bias alert in database"""
        db = self.SessionLocal()
        try:
            db_record = BiasMonitoringDB.BiasAlertRecord(
                alert_id=alert.alert_id,
                model_id=alert.model_id,
                timestamp=alert.timestamp,
                severity=alert.severity.value,
                bias_type=alert.bias_type,
                protected_attribute=alert.protected_attribute,
                affected_group=alert.affected_group,
                metric_name=alert.metric_name,
                current_value=alert.current_value,
                threshold_value=alert.threshold_value,
                confidence_level=alert.confidence_level,
                sample_size=alert.sample_size,
                description=alert.description,
                recommended_actions=alert.recommended_actions
            )
            
            db.add(db_record)
            db.commit()
            
            logger.info(f"Stored bias alert: {alert.alert_id} ({alert.severity.value})")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error storing bias alert: {str(e)}")
            raise
        finally:
            db.close()

    async def _update_real_time_cache(
        self,
        model_id: str,
        bias_metrics: List[Dict[str, Any]],
        alerts: List[BiasAlert]
    ) -> None:
        """Update Redis cache for real-time monitoring"""
        await self.initialize_redis()
        
        try:
            # Store latest metrics
            metrics_key = f"bias_metrics:{model_id}:latest"
            metrics_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'metrics_count': len(bias_metrics),
                'alerts_count': len(alerts),
                'metrics': bias_metrics[:10],  # Store top 10 for quick access
            }
            
            await self.redis_pool.setex(
                metrics_key,
                3600,  # 1 hour
                json.dumps(metrics_data, default=str)
            )
            
            # Store active alerts
            if alerts:
                alerts_key = f"bias_alerts:{model_id}:active"
                alerts_data = [alert.to_dict() for alert in alerts]
                
                await self.redis_pool.setex(
                    alerts_key,
                    86400,  # 24 hours
                    json.dumps(alerts_data, default=str)
                )
            
        except Exception as e:
            logger.error(f"Error updating real-time cache: {str(e)}")

    async def get_real_time_bias_status(self, model_id: str) -> Dict[str, Any]:
        """Get real-time bias monitoring status for a model"""
        await self.initialize_redis()
        
        try:
            # Get latest metrics
            metrics_key = f"bias_metrics:{model_id}:latest"
            metrics_data = await self.redis_pool.get(metrics_key)
            
            # Get active alerts
            alerts_key = f"bias_alerts:{model_id}:active"
            alerts_data = await self.redis_pool.get(alerts_key)
            
            status = {
                'model_id': model_id,
                'last_updated': None,
                'metrics_available': False,
                'active_alerts': 0,
                'bias_status': 'unknown',
                'alerts': []
            }
            
            if metrics_data:
                metrics = json.loads(metrics_data)
                status.update({
                    'last_updated': metrics['timestamp'],
                    'metrics_available': True,
                    'metrics_count': metrics['metrics_count']
                })
            
            if alerts_data:
                alerts = json.loads(alerts_data)
                status.update({
                    'active_alerts': len(alerts),
                    'alerts': alerts
                })
                
                # Determine overall bias status
                severities = [alert['severity'] for alert in alerts]
                if 'critical' in severities:
                    status['bias_status'] = 'critical'
                elif 'high' in severities:
                    status['bias_status'] = 'high'
                elif 'medium' in severities:
                    status['bias_status'] = 'medium'
                else:
                    status['bias_status'] = 'low'
            else:
                status['bias_status'] = 'good' if status['metrics_available'] else 'unknown'
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting real-time bias status: {str(e)}")
            return {'model_id': model_id, 'error': str(e)}

    async def generate_bias_report(
        self,
        model_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        include_historical_trends: bool = True
    ) -> Dict[str, Any]:
        """Generate comprehensive bias monitoring report"""
        if end_date is None:
            end_date = datetime.utcnow()
        if start_date is None:
            start_date = end_date - timedelta(days=30)
        
        db = self.SessionLocal()
        try:
            # Get metrics for the period
            metrics_query = db.query(BiasMonitoringDB.BiasMetricRecord).filter(
                BiasMonitoringDB.BiasMetricRecord.model_id == model_id,
                BiasMonitoringDB.BiasMetricRecord.timestamp.between(start_date, end_date)
            )
            
            metrics = metrics_query.all()
            
            # Get alerts for the period
            alerts_query = db.query(BiasMonitoringDB.BiasAlertRecord).filter(
                BiasMonitoringDB.BiasAlertRecord.model_id == model_id,
                BiasMonitoringDB.BiasAlertRecord.timestamp.between(start_date, end_date)
            )
            
            alerts = alerts_query.all()
            
            # Analyze metrics
            metrics_analysis = self._analyze_metrics(metrics)
            
            # Analyze alerts
            alerts_analysis = self._analyze_alerts(alerts)
            
            # Generate report
            report = {
                'model_id': model_id,
                'report_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'summary': {
                    'total_measurements': len(metrics),
                    'total_alerts': len(alerts),
                    'critical_alerts': len([a for a in alerts if a.severity == 'critical']),
                    'high_alerts': len([a for a in alerts if a.severity == 'high']),
                    'bias_status': alerts_analysis.get('overall_status', 'good')
                },
                'metrics_analysis': metrics_analysis,
                'alerts_analysis': alerts_analysis,
                'recommendations': self._generate_report_recommendations(
                    metrics_analysis, alerts_analysis
                ),
                'generated_at': datetime.utcnow().isoformat()
            }
            
            if include_historical_trends:
                report['historical_trends'] = await self._analyze_historical_trends(
                    model_id, start_date
                )
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating bias report: {str(e)}")
            raise
        finally:
            db.close()

    def _analyze_metrics(self, metrics: List[BiasMonitoringDB.BiasMetricRecord]) -> Dict[str, Any]:
        """Analyze bias metrics for reporting"""
        if not metrics:
            return {'status': 'no_data'}
        
        # Group metrics by protected attribute and metric type
        grouped_metrics = {}
        for metric in metrics:
            attr = metric.protected_attribute
            metric_name = metric.metric_name
            
            if attr not in grouped_metrics:
                grouped_metrics[attr] = {}
            if metric_name not in grouped_metrics[attr]:
                grouped_metrics[attr][metric_name] = []
            
            grouped_metrics[attr][metric_name].append(metric.metric_value)
        
        # Calculate statistics for each group
        analysis = {}
        for attr, attr_metrics in grouped_metrics.items():
            analysis[attr] = {}
            for metric_name, values in attr_metrics.items():
                analysis[attr][metric_name] = {
                    'mean': np.mean(values),
                    'std': np.std(values),
                    'min': np.min(values),
                    'max': np.max(values),
                    'trend': 'stable'  # Could implement trend analysis
                }
        
        return analysis

    def _analyze_alerts(self, alerts: List[BiasMonitoringDB.BiasAlertRecord]) -> Dict[str, Any]:
        """Analyze bias alerts for reporting"""
        if not alerts:
            return {'overall_status': 'good', 'alert_breakdown': {}}
        
        # Count alerts by severity
        severity_counts = {}
        for alert in alerts:
            severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
        
        # Determine overall status
        if severity_counts.get('critical', 0) > 0:
            overall_status = 'critical'
        elif severity_counts.get('high', 0) > 0:
            overall_status = 'high_risk'
        elif severity_counts.get('medium', 0) > 0:
            overall_status = 'medium_risk'
        else:
            overall_status = 'low_risk'
        
        # Analyze alert patterns
        protected_attr_alerts = {}
        for alert in alerts:
            attr = alert.protected_attribute
            protected_attr_alerts[attr] = protected_attr_alerts.get(attr, 0) + 1
        
        return {
            'overall_status': overall_status,
            'alert_breakdown': severity_counts,
            'most_affected_attributes': protected_attr_alerts,
            'resolution_rate': len([a for a in alerts if a.resolved]) / len(alerts)
        }

    def _generate_report_recommendations(
        self,
        metrics_analysis: Dict[str, Any],
        alerts_analysis: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on report analysis"""
        recommendations = []
        
        overall_status = alerts_analysis.get('overall_status', 'good')
        
        if overall_status == 'critical':
            recommendations.append("URGENT: Model deployment should be halted until bias issues are resolved")
            recommendations.append("Conduct immediate bias audit and implement corrective measures")
        elif overall_status in ['high_risk', 'medium_risk']:
            recommendations.append("Implement bias mitigation strategies within 48 hours")
            recommendations.append("Increase monitoring frequency to hourly")
            recommendations.append("Consider retraining with fairness constraints")
        
        # Attribute-specific recommendations
        most_affected = alerts_analysis.get('most_affected_attributes', {})
        for attr, count in most_affected.items():
            if count > 2:
                recommendations.append(f"Focus bias mitigation efforts on '{attr}' attribute")
        
        # Resolution recommendations
        resolution_rate = alerts_analysis.get('resolution_rate', 1.0)
        if resolution_rate < 0.8:
            recommendations.append("Improve alert resolution processes - current rate is below target")
        
        if not recommendations:
            recommendations.append("Continue current monitoring practices - no immediate action required")
        
        return recommendations

    async def _analyze_historical_trends(
        self, 
        model_id: str, 
        cutoff_date: datetime
    ) -> Dict[str, Any]:
        """Analyze historical bias trends"""
        db = self.SessionLocal()
        try:
            # Get historical data (before the report period)
            historical_metrics = db.query(BiasMonitoringDB.BiasMetricRecord).filter(
                BiasMonitoringDB.BiasMetricRecord.model_id == model_id,
                BiasMonitoringDB.BiasMetricRecord.timestamp < cutoff_date
            ).order_by(BiasMonitoringDB.BiasMetricRecord.timestamp).all()
            
            if len(historical_metrics) < 10:
                return {'status': 'insufficient_historical_data'}
            
            # Simple trend analysis
            timestamps = [m.timestamp for m in historical_metrics]
            values = [m.metric_value for m in historical_metrics]
            
            # Calculate trend (simple linear regression slope)
            x = np.array([(t - timestamps[0]).total_seconds() for t in timestamps])
            y = np.array(values)
            
            if len(x) > 1:
                slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
                
                trend_direction = 'improving' if slope < 0 else 'degrading' if slope > 0 else 'stable'
                
                return {
                    'trend_direction': trend_direction,
                    'trend_strength': abs(r_value),
                    'statistical_significance': p_value,
                    'data_points': len(historical_metrics)
                }
            
            return {'status': 'insufficient_data_for_trend'}
            
        except Exception as e:
            logger.error(f"Error analyzing historical trends: {str(e)}")
            return {'error': str(e)}
        finally:
            db.close()

# Utility functions for easy integration
async def setup_threat_detection_bias_monitoring(
    monitoring_system: BiasMonitoringSystem,
    model_id: str
) -> str:
    """Setup bias monitoring for threat detection model"""
    
    # Standard protected attributes for cybersecurity context
    protected_attributes = [
        'user_location', 'user_role', 'device_type', 'network_segment',
        'time_of_day', 'department', 'seniority_level'
    ]
    
    # Threat detection specific thresholds
    bias_thresholds = {
        'selection_rate': 0.05,  # 5% difference max
        'accuracy': 0.03,        # 3% accuracy difference max
        'false_positive_rate': 0.02,  # 2% FPR difference max
        'false_negative_rate': 0.02   # 2% FNR difference max
    }
    
    return await monitoring_system.configure_model_monitoring(
        model_id=model_id,
        protected_attributes=protected_attributes,
        bias_thresholds=bias_thresholds,
        monitoring_frequency=MonitoringFrequency.HOURLY
    )

if __name__ == "__main__":
    # Example usage and testing
    async def test_bias_monitoring():
        monitoring = BiasMonitoringSystem()
        
        # Configure monitoring
        config_id = await setup_threat_detection_bias_monitoring(
            monitoring, "threat_detection_v1"
        )
        print(f"Monitoring configured: {config_id}")
        
        # Generate sample data
        np.random.seed(42)
        n_samples = 1000
        
        feature_data = pd.DataFrame({
            'feature1': np.random.randn(n_samples),
            'feature2': np.random.randn(n_samples),
            'user_location': np.random.choice(['US', 'EU', 'APAC'], n_samples),
            'user_role': np.random.choice(['admin', 'user', 'guest'], n_samples),
            'device_type': np.random.choice(['desktop', 'mobile', 'server'], n_samples)
        })
        
        # Introduce some bias (higher threat detection for certain groups)
        predictions = np.random.randint(0, 2, n_samples)
        # Bias: higher positive rate for mobile devices
        mobile_mask = feature_data['device_type'] == 'mobile'
        predictions[mobile_mask] = np.random.choice([0, 1], sum(mobile_mask), p=[0.3, 0.7])
        
        ground_truth = np.random.randint(0, 2, n_samples)
        
        # Monitor predictions
        result = await monitoring.monitor_model_predictions(
            model_id="threat_detection_v1",
            predictions=predictions,
            ground_truth=ground_truth,
            feature_data=feature_data
        )
        
        print(f"Monitoring result: {result}")
        
        # Get real-time status
        status = await monitoring.get_real_time_bias_status("threat_detection_v1")
        print(f"Real-time status: {status}")
        
        # Generate report
        report = await monitoring.generate_bias_report("threat_detection_v1")
        print(f"Report generated with {len(report.get('summary', {}))} sections")
    
    # Run test
    asyncio.run(test_bias_monitoring())