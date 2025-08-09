"""
Model Drift Detection System

Advanced drift detection using statistical tests, distribution analysis,
and machine learning techniques to identify model degradation.
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum
from collections import defaultdict, deque
from scipy import stats
from scipy.spatial.distance import jensenshannon
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class DriftType(Enum):
    """Types of model drift."""
    DATA_DRIFT = "data_drift"
    CONCEPT_DRIFT = "concept_drift"
    PREDICTION_DRIFT = "prediction_drift"
    PERFORMANCE_DRIFT = "performance_drift"
    COVARIATE_SHIFT = "covariate_shift"
    PRIOR_PROBABILITY_SHIFT = "prior_probability_shift"


class DriftSeverity(Enum):
    """Severity levels for drift detection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DriftAlert:
    """Drift detection alert."""
    alert_id: str
    model_id: str
    drift_type: DriftType
    severity: DriftSeverity
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Drift metrics
    drift_score: float = 0.0
    statistical_significance: float = 0.0
    affected_features: List[str] = field(default_factory=list)
    
    # Evidence
    test_statistics: Dict[str, float] = field(default_factory=dict)
    distribution_metrics: Dict[str, float] = field(default_factory=dict)
    
    # Context
    baseline_period: Tuple[datetime, datetime] = field(default_factory=lambda: (datetime.utcnow(), datetime.utcnow()))
    detection_period: Tuple[datetime, datetime] = field(default_factory=lambda: (datetime.utcnow(), datetime.utcnow()))
    sample_size: int = 0
    
    # Recommendations
    recommended_actions: List[str] = field(default_factory=list)
    retraining_recommended: bool = False


class ModelDriftDetector:
    """
    Advanced model drift detection system with multiple statistical tests
    and machine learning-based change point detection.
    """
    
    def __init__(
        self,
        statistical_threshold: float = 0.05,
        distribution_threshold: float = 0.1,
        min_samples: int = 1000,
        detection_window_hours: int = 24
    ):
        self.statistical_threshold = statistical_threshold
        self.distribution_threshold = distribution_threshold
        self.min_samples = min_samples
        self.detection_window_hours = detection_window_hours
        
        # Data storage
        self._baseline_data: Dict[str, pd.DataFrame] = {}
        self._recent_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._drift_history: Dict[str, List[DriftAlert]] = defaultdict(list)
        
        # Drift detection models
        self._drift_detectors: Dict[str, Any] = {}
        
        logger.info("Model Drift Detector initialized")
    
    def set_baseline(self, model_id: str, baseline_data: pd.DataFrame):
        """Set baseline data for drift detection."""
        self._baseline_data[model_id] = baseline_data.copy()
        
        # Train drift detection model on baseline
        if len(baseline_data) >= self.min_samples:
            self._train_drift_detector(model_id, baseline_data)
        
        logger.info(f"Baseline set for model {model_id}: {len(baseline_data)} samples")
    
    def _train_drift_detector(self, model_id: str, data: pd.DataFrame):
        """Train unsupervised drift detection model."""
        try:
            # Use Isolation Forest for anomaly detection
            numeric_columns = data.select_dtypes(include=[np.number]).columns
            if len(numeric_columns) == 0:
                logger.warning(f"No numeric columns found for drift detection: {model_id}")
                return
            
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(data[numeric_columns].fillna(0))
            
            detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            detector.fit(X_scaled)
            
            self._drift_detectors[model_id] = {
                'detector': detector,
                'scaler': scaler,
                'feature_columns': numeric_columns.tolist()
            }
            
            logger.info(f"Drift detector trained for model {model_id}")
        except Exception as e:
            logger.error(f"Failed to train drift detector for {model_id}: {e}")
    
    async def add_observation(self, model_id: str, data: Dict[str, Any]):
        """Add new observation for drift monitoring."""
        timestamp = datetime.utcnow()
        observation = {**data, 'timestamp': timestamp}
        
        self._recent_data[model_id].append(observation)
        
        # Check if we have enough data for drift detection
        if len(self._recent_data[model_id]) >= self.min_samples:
            # Trigger drift detection asynchronously
            asyncio.create_task(self._check_drift_async(model_id))
    
    async def _check_drift_async(self, model_id: str):
        """Asynchronously check for drift."""
        try:
            drift_alerts = await self.detect_drift(model_id)
            if drift_alerts:
                for alert in drift_alerts:
                    self._drift_history[model_id].append(alert)
                    logger.warning(f"Drift detected for {model_id}: {alert.drift_type.value}")
        except Exception as e:
            logger.error(f"Drift detection failed for {model_id}: {e}")
    
    async def detect_drift(self, model_id: str) -> List[DriftAlert]:
        """Comprehensive drift detection across multiple dimensions."""
        if model_id not in self._baseline_data:
            logger.warning(f"No baseline data for model {model_id}")
            return []
        
        if len(self._recent_data[model_id]) < self.min_samples:
            return []
        
        # Convert recent data to DataFrame
        recent_df = pd.DataFrame(list(self._recent_data[model_id]))
        baseline_df = self._baseline_data[model_id]
        
        alerts = []
        
        # Data Drift Detection
        data_drift_alerts = await self._detect_data_drift(
            model_id, baseline_df, recent_df
        )
        alerts.extend(data_drift_alerts)
        
        # Prediction Drift Detection
        if 'prediction' in recent_df.columns:
            pred_drift_alerts = await self._detect_prediction_drift(
                model_id, baseline_df, recent_df
            )
            alerts.extend(pred_drift_alerts)
        
        # Performance Drift Detection
        if 'actual' in recent_df.columns and 'prediction' in recent_df.columns:
            perf_drift_alerts = await self._detect_performance_drift(
                model_id, baseline_df, recent_df
            )
            alerts.extend(perf_drift_alerts)
        
        # ML-based Drift Detection
        ml_drift_alerts = await self._detect_ml_drift(
            model_id, baseline_df, recent_df
        )
        alerts.extend(ml_drift_alerts)
        
        return alerts
    
    async def _detect_data_drift(
        self,
        model_id: str,
        baseline_df: pd.DataFrame,
        recent_df: pd.DataFrame
    ) -> List[DriftAlert]:
        """Detect data drift using statistical tests."""
        alerts = []
        
        # Get numeric columns
        numeric_cols = baseline_df.select_dtypes(include=[np.number]).columns
        
        for col in numeric_cols:
            if col not in recent_df.columns:
                continue
            
            baseline_values = baseline_df[col].dropna()
            recent_values = recent_df[col].dropna()
            
            if len(baseline_values) == 0 or len(recent_values) == 0:
                continue
            
            # Kolmogorov-Smirnov test
            ks_statistic, ks_pvalue = stats.ks_2samp(baseline_values, recent_values)
            
            # Jensen-Shannon divergence
            js_div = self._calculate_js_divergence(baseline_values, recent_values)
            
            # Population Stability Index
            psi = self._calculate_psi(baseline_values, recent_values)
            
            # Check for significant drift
            if (ks_pvalue < self.statistical_threshold or 
                js_div > self.distribution_threshold or 
                psi > 0.2):
                
                severity = self._determine_severity(ks_pvalue, js_div, psi)
                
                alert = DriftAlert(
                    alert_id=f"drift_{model_id}_{col}_{int(datetime.utcnow().timestamp())}",
                    model_id=model_id,
                    drift_type=DriftType.DATA_DRIFT,
                    severity=severity,
                    drift_score=max(1 - ks_pvalue, js_div, psi / 0.2),
                    statistical_significance=ks_pvalue,
                    affected_features=[col],
                    test_statistics={
                        'ks_statistic': ks_statistic,
                        'ks_pvalue': ks_pvalue,
                        'jensen_shannon_divergence': js_div,
                        'population_stability_index': psi
                    },
                    sample_size=len(recent_values),
                    retraining_recommended=(severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL])
                )
                
                alert.recommended_actions = self._get_data_drift_recommendations(severity, col)
                alerts.append(alert)
        
        return alerts
    
    async def _detect_prediction_drift(
        self,
        model_id: str,
        baseline_df: pd.DataFrame,
        recent_df: pd.DataFrame
    ) -> List[DriftAlert]:
        """Detect prediction drift."""
        alerts = []
        
        if 'prediction' not in baseline_df.columns or 'prediction' not in recent_df.columns:
            return alerts
        
        baseline_preds = baseline_df['prediction'].dropna()
        recent_preds = recent_df['prediction'].dropna()
        
        # Statistical tests on predictions
        ks_stat, ks_pvalue = stats.ks_2samp(baseline_preds, recent_preds)
        js_div = self._calculate_js_divergence(baseline_preds, recent_preds)
        
        # Check prediction confidence drift if available
        confidence_drift = 0.0
        if 'prediction_confidence' in baseline_df.columns and 'prediction_confidence' in recent_df.columns:
            baseline_conf = baseline_df['prediction_confidence'].dropna()
            recent_conf = recent_df['prediction_confidence'].dropna()
            
            if len(baseline_conf) > 0 and len(recent_conf) > 0:
                conf_ks_stat, conf_ks_pvalue = stats.ks_2samp(baseline_conf, recent_conf)
                confidence_drift = 1 - conf_ks_pvalue
        
        if ks_pvalue < self.statistical_threshold or js_div > self.distribution_threshold:
            severity = self._determine_severity(ks_pvalue, js_div, confidence_drift)
            
            alert = DriftAlert(
                alert_id=f"pred_drift_{model_id}_{int(datetime.utcnow().timestamp())}",
                model_id=model_id,
                drift_type=DriftType.PREDICTION_DRIFT,
                severity=severity,
                drift_score=max(1 - ks_pvalue, js_div, confidence_drift),
                statistical_significance=ks_pvalue,
                test_statistics={
                    'prediction_ks_pvalue': ks_pvalue,
                    'prediction_js_divergence': js_div,
                    'confidence_drift': confidence_drift
                },
                sample_size=len(recent_preds),
                retraining_recommended=(severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL])
            )
            
            alert.recommended_actions = self._get_prediction_drift_recommendations(severity)
            alerts.append(alert)
        
        return alerts
    
    async def _detect_performance_drift(
        self,
        model_id: str,
        baseline_df: pd.DataFrame,
        recent_df: pd.DataFrame
    ) -> List[DriftAlert]:
        """Detect performance drift using accuracy metrics."""
        alerts = []
        
        if 'actual' not in recent_df.columns or 'prediction' not in recent_df.columns:
            return alerts
        
        # Calculate recent accuracy
        recent_accuracy = (recent_df['actual'] == recent_df['prediction']).mean()
        
        # Calculate baseline accuracy if available
        baseline_accuracy = 0.0
        if 'actual' in baseline_df.columns and 'prediction' in baseline_df.columns:
            baseline_accuracy = (baseline_df['actual'] == baseline_df['prediction']).mean()
        
        # Check for significant accuracy drop
        accuracy_drop = baseline_accuracy - recent_accuracy
        
        if accuracy_drop > 0.05:  # 5% accuracy drop threshold
            severity = DriftSeverity.CRITICAL if accuracy_drop > 0.15 else (
                DriftSeverity.HIGH if accuracy_drop > 0.10 else DriftSeverity.MEDIUM
            )
            
            alert = DriftAlert(
                alert_id=f"perf_drift_{model_id}_{int(datetime.utcnow().timestamp())}",
                model_id=model_id,
                drift_type=DriftType.PERFORMANCE_DRIFT,
                severity=severity,
                drift_score=accuracy_drop,
                test_statistics={
                    'baseline_accuracy': baseline_accuracy,
                    'recent_accuracy': recent_accuracy,
                    'accuracy_drop': accuracy_drop
                },
                sample_size=len(recent_df),
                retraining_recommended=True
            )
            
            alert.recommended_actions = self._get_performance_drift_recommendations(severity)
            alerts.append(alert)
        
        return alerts
    
    async def _detect_ml_drift(
        self,
        model_id: str,
        baseline_df: pd.DataFrame,
        recent_df: pd.DataFrame
    ) -> List[DriftAlert]:
        """ML-based drift detection using trained anomaly detectors."""
        alerts = []
        
        if model_id not in self._drift_detectors:
            return alerts
        
        detector_info = self._drift_detectors[model_id]
        detector = detector_info['detector']
        scaler = detector_info['scaler']
        feature_cols = detector_info['feature_columns']
        
        # Check if all required columns are present
        available_cols = [col for col in feature_cols if col in recent_df.columns]
        if len(available_cols) < len(feature_cols) * 0.8:  # Need at least 80% of features
            return alerts
        
        try:
            # Prepare recent data
            recent_features = recent_df[available_cols].fillna(0)
            recent_scaled = scaler.transform(recent_features)
            
            # Get anomaly scores
            anomaly_scores = detector.decision_function(recent_scaled)
            anomalies = detector.predict(recent_scaled)
            
            # Calculate drift metrics
            anomaly_rate = (anomalies == -1).mean()
            avg_anomaly_score = np.mean(anomaly_scores)
            
            # Check for significant drift
            if anomaly_rate > 0.15:  # More than 15% anomalies
                severity = DriftSeverity.CRITICAL if anomaly_rate > 0.3 else (
                    DriftSeverity.HIGH if anomaly_rate > 0.25 else DriftSeverity.MEDIUM
                )
                
                alert = DriftAlert(
                    alert_id=f"ml_drift_{model_id}_{int(datetime.utcnow().timestamp())}",
                    model_id=model_id,
                    drift_type=DriftType.CONCEPT_DRIFT,
                    severity=severity,
                    drift_score=anomaly_rate,
                    affected_features=available_cols,
                    test_statistics={
                        'anomaly_rate': anomaly_rate,
                        'avg_anomaly_score': avg_anomaly_score,
                        'total_anomalies': int((anomalies == -1).sum())
                    },
                    sample_size=len(recent_df),
                    retraining_recommended=(severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL])
                )
                
                alert.recommended_actions = self._get_ml_drift_recommendations(severity)
                alerts.append(alert)
        
        except Exception as e:
            logger.error(f"ML drift detection failed for {model_id}: {e}")
        
        return alerts
    
    def _calculate_js_divergence(self, baseline: pd.Series, recent: pd.Series) -> float:
        """Calculate Jensen-Shannon divergence between two distributions."""
        try:
            # Create histograms
            min_val = min(baseline.min(), recent.min())
            max_val = max(baseline.max(), recent.max())
            bins = np.linspace(min_val, max_val, 50)
            
            baseline_hist, _ = np.histogram(baseline, bins=bins, density=True)
            recent_hist, _ = np.histogram(recent, bins=bins, density=True)
            
            # Add small epsilon to avoid log(0)
            baseline_hist += 1e-10
            recent_hist += 1e-10
            
            # Normalize to probabilities
            baseline_hist /= baseline_hist.sum()
            recent_hist /= recent_hist.sum()
            
            return jensenshannon(baseline_hist, recent_hist)
        except Exception:
            return 0.0
    
    def _calculate_psi(self, baseline: pd.Series, recent: pd.Series) -> float:
        """Calculate Population Stability Index."""
        try:
            # Create bins based on baseline quantiles
            percentiles = np.linspace(0, 100, 11)
            bins = np.percentile(baseline, percentiles)
            bins = np.unique(bins)  # Remove duplicates
            
            if len(bins) < 2:
                return 0.0
            
            # Calculate distributions
            baseline_counts, _ = np.histogram(baseline, bins=bins)
            recent_counts, _ = np.histogram(recent, bins=bins)
            
            # Convert to percentages
            baseline_pct = baseline_counts / baseline_counts.sum()
            recent_pct = recent_counts / recent_counts.sum()
            
            # Add small epsilon to avoid log(0) and division by 0
            baseline_pct = np.maximum(baseline_pct, 1e-6)
            recent_pct = np.maximum(recent_pct, 1e-6)
            
            # Calculate PSI
            psi = np.sum((recent_pct - baseline_pct) * np.log(recent_pct / baseline_pct))
            
            return abs(psi)
        except Exception:
            return 0.0
    
    def _determine_severity(self, ks_pvalue: float, js_div: float, additional_metric: float = 0.0) -> DriftSeverity:
        """Determine drift severity based on multiple metrics."""
        # Calculate composite score
        ks_score = 1 - ks_pvalue if ks_pvalue < 1.0 else 0.0
        js_score = js_div
        additional_score = additional_metric
        
        composite_score = max(ks_score, js_score, additional_score)
        
        if composite_score >= 0.8:
            return DriftSeverity.CRITICAL
        elif composite_score >= 0.6:
            return DriftSeverity.HIGH
        elif composite_score >= 0.3:
            return DriftSeverity.MEDIUM
        else:
            return DriftSeverity.LOW
    
    def _get_data_drift_recommendations(self, severity: DriftSeverity, feature: str) -> List[str]:
        """Get recommendations for data drift."""
        recommendations = [
            f"Investigate feature '{feature}' for data quality issues",
            "Check data pipeline for changes",
            "Validate data source consistency"
        ]
        
        if severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]:
            recommendations.extend([
                "Consider immediate model retraining",
                "Implement feature engineering adjustments",
                "Set up enhanced monitoring for this feature"
            ])
        
        return recommendations
    
    def _get_prediction_drift_recommendations(self, severity: DriftSeverity) -> List[str]:
        """Get recommendations for prediction drift."""
        recommendations = [
            "Analyze prediction distribution changes",
            "Check model confidence patterns",
            "Validate prediction pipeline"
        ]
        
        if severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]:
            recommendations.extend([
                "Retrain model with recent data",
                "Consider ensemble approaches",
                "Implement prediction confidence thresholds"
            ])
        
        return recommendations
    
    def _get_performance_drift_recommendations(self, severity: DriftSeverity) -> List[str]:
        """Get recommendations for performance drift."""
        recommendations = [
            "Immediate model retraining required",
            "Analyze error patterns in recent data",
            "Consider model architecture changes"
        ]
        
        if severity == DriftSeverity.CRITICAL:
            recommendations.extend([
                "Implement fallback model",
                "Increase human oversight",
                "Emergency model rollback consideration"
            ])
        
        return recommendations
    
    def _get_ml_drift_recommendations(self, severity: DriftSeverity) -> List[str]:
        """Get recommendations for ML-detected drift."""
        recommendations = [
            "Investigate concept drift patterns",
            "Analyze feature importance changes",
            "Consider incremental learning approaches"
        ]
        
        if severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]:
            recommendations.extend([
                "Implement adaptive model updates",
                "Consider online learning techniques",
                "Enhance feature monitoring"
            ])
        
        return recommendations
    
    def get_drift_summary(self, model_id: str) -> Dict[str, Any]:
        """Get drift detection summary for a model."""
        if model_id not in self._drift_history:
            return {'model_id': model_id, 'total_alerts': 0, 'recent_alerts': 0}
        
        alerts = self._drift_history[model_id]
        recent_alerts = [
            alert for alert in alerts 
            if alert.timestamp > datetime.utcnow() - timedelta(hours=24)
        ]
        
        # Count by type and severity
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for alert in recent_alerts:
            type_counts[alert.drift_type.value] += 1
            severity_counts[alert.severity.value] += 1
        
        return {
            'model_id': model_id,
            'total_alerts': len(alerts),
            'recent_alerts': len(recent_alerts),
            'drift_types': dict(type_counts),
            'severity_distribution': dict(severity_counts),
            'last_alert': alerts[-1].timestamp if alerts else None,
            'retraining_recommended': any(alert.retraining_recommended for alert in recent_alerts)
        }


# Export for external use
__all__ = [
    'ModelDriftDetector',
    'DriftAlert',
    'DriftType',
    'DriftSeverity'
]