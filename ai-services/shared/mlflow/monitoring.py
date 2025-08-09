"""
Production-Grade Model Monitoring and Alerting for iSECTECH AI Services

Provides comprehensive monitoring including:
- Real-time model performance tracking and drift detection
- Data quality monitoring and anomaly detection
- Automated alerting and notification systems
- Model health dashboards and reporting
- Compliance monitoring and audit trails
- Predictive performance degradation analysis
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import warnings

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
from prometheus_client import Counter, Histogram, Gauge

from ..config.settings import SecuritySettings, MonitoringSettings
from ..security.audit import AuditLogger


class DriftDetectionMethod:
    """Data drift detection methods"""
    KOLMOGOROV_SMIRNOV = "kolmogorov_smirnov"
    JENSEN_SHANNON = "jensen_shannon"
    POPULATION_STABILITY = "population_stability"
    CHI_SQUARE = "chi_square"
    EARTH_MOVERS = "earth_movers"


class AlertSeverity:
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MonitoringAlert:
    """Model monitoring alert"""
    def __init__(self, alert_id: str, model_name: str, alert_type: str, 
                 severity: str, message: str, details: Dict[str, Any],
                 tenant_id: str):
        self.alert_id = alert_id
        self.model_name = model_name
        self.alert_type = alert_type
        self.severity = severity
        self.message = message
        self.details = details
        self.tenant_id = tenant_id
        self.created_at = datetime.utcnow()
        self.status = "active"
        self.acknowledged_by = None
        self.acknowledged_at = None


class ModelHealthMetrics:
    """Model health tracking metrics"""
    def __init__(self, model_name: str, tenant_id: str):
        self.model_name = model_name
        self.tenant_id = tenant_id
        self.uptime_seconds = 0
        self.total_predictions = 0
        self.successful_predictions = 0
        self.failed_predictions = 0
        self.avg_response_time_ms = 0.0
        self.p95_response_time_ms = 0.0
        self.p99_response_time_ms = 0.0
        self.error_rate = 0.0
        self.availability = 100.0
        self.last_prediction_time = None
        self.health_score = 100.0
        self.start_time = datetime.utcnow()


class DataDriftAnalyzer:
    """Advanced data drift detection and analysis"""
    
    def __init__(self, settings: SecuritySettings):
        self.settings = settings
        self.audit_logger = AuditLogger(settings)
        
        # Drift detection thresholds
        self.drift_thresholds = {
            DriftDetectionMethod.KOLMOGOROV_SMIRNOV: 0.05,
            DriftDetectionMethod.JENSEN_SHANNON: 0.1,
            DriftDetectionMethod.POPULATION_STABILITY: 0.1,
            DriftDetectionMethod.CHI_SQUARE: 0.05,
            DriftDetectionMethod.EARTH_MOVERS: 0.1
        }
    
    async def detect_data_drift(self, reference_data: pd.DataFrame, 
                              current_data: pd.DataFrame,
                              feature_names: List[str],
                              model_name: str, tenant_id: str) -> Dict[str, Any]:
        """Comprehensive data drift detection"""
        
        try:
            drift_results = {
                "overall_drift_detected": False,
                "drift_score": 0.0,
                "feature_drift_scores": {},
                "drift_methods": {},
                "recommendations": []
            }
            
            feature_drift_scores = []
            
            for feature in feature_names:
                if feature not in reference_data.columns or feature not in current_data.columns:
                    continue
                
                ref_values = reference_data[feature].dropna()
                curr_values = current_data[feature].dropna()
                
                if len(ref_values) == 0 or len(curr_values) == 0:
                    continue
                
                # Detect feature drift using multiple methods
                feature_drift = await self._detect_feature_drift(
                    ref_values, curr_values, feature, model_name, tenant_id
                )
                
                drift_results["feature_drift_scores"][feature] = feature_drift
                feature_drift_scores.append(feature_drift["overall_score"])
            
            # Calculate overall drift score
            if feature_drift_scores:
                drift_results["drift_score"] = np.mean(feature_drift_scores)
                drift_results["overall_drift_detected"] = drift_results["drift_score"] > 0.1
            
            # Generate recommendations
            if drift_results["overall_drift_detected"]:
                drift_results["recommendations"] = self._generate_drift_recommendations(
                    drift_results["feature_drift_scores"]
                )
            
            # Log drift detection
            self.audit_logger.log_security_event(
                event_type="model_drift_detection",
                tenant_id=tenant_id,
                details={
                    "model_name": model_name,
                    "drift_detected": drift_results["overall_drift_detected"],
                    "drift_score": drift_results["drift_score"],
                    "features_analyzed": len(feature_names)
                }
            )
            
            return drift_results
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="model_drift_detection_error",
                tenant_id=tenant_id,
                details={
                    "model_name": model_name,
                    "error": str(e)
                }
            )
            
            return {
                "overall_drift_detected": False,
                "drift_score": 0.0,
                "error": str(e)
            }
    
    async def _detect_feature_drift(self, reference_values: pd.Series, 
                                   current_values: pd.Series, feature_name: str,
                                   model_name: str, tenant_id: str) -> Dict[str, Any]:
        """Detect drift for individual feature using multiple methods"""
        
        drift_scores = {}
        
        try:
            # Kolmogorov-Smirnov test
            ks_stat, ks_p_value = stats.ks_2samp(reference_values, current_values)
            drift_scores[DriftDetectionMethod.KOLMOGOROV_SMIRNOV] = {
                "statistic": ks_stat,
                "p_value": ks_p_value,
                "drift_detected": ks_p_value < self.drift_thresholds[DriftDetectionMethod.KOLMOGOROV_SMIRNOV]
            }
            
            # Population Stability Index (PSI)
            psi_score = self._calculate_psi(reference_values, current_values)
            drift_scores[DriftDetectionMethod.POPULATION_STABILITY] = {
                "score": psi_score,
                "drift_detected": psi_score > self.drift_thresholds[DriftDetectionMethod.POPULATION_STABILITY]
            }
            
            # Jensen-Shannon Divergence
            js_divergence = self._calculate_js_divergence(reference_values, current_values)
            drift_scores[DriftDetectionMethod.JENSEN_SHANNON] = {
                "divergence": js_divergence,
                "drift_detected": js_divergence > self.drift_thresholds[DriftDetectionMethod.JENSEN_SHANNON]
            }
            
            # Overall feature drift score
            drift_indicators = [
                score["drift_detected"] for score in drift_scores.values()
            ]
            
            overall_score = sum(drift_indicators) / len(drift_indicators)
            
            return {
                "feature_name": feature_name,
                "overall_score": overall_score,
                "drift_detected": overall_score > 0.5,
                "method_results": drift_scores,
                "statistical_summary": {
                    "reference_mean": float(reference_values.mean()),
                    "current_mean": float(current_values.mean()),
                    "reference_std": float(reference_values.std()),
                    "current_std": float(current_values.std()),
                    "mean_shift": float(current_values.mean() - reference_values.mean()),
                    "std_ratio": float(current_values.std() / reference_values.std()) if reference_values.std() > 0 else 1.0
                }
            }
            
        except Exception as e:
            return {
                "feature_name": feature_name,
                "overall_score": 0.0,
                "drift_detected": False,
                "error": str(e)
            }
    
    def _calculate_psi(self, reference: pd.Series, current: pd.Series, bins: int = 10) -> float:
        """Calculate Population Stability Index"""
        
        try:
            # Create bins based on reference data
            _, bin_edges = np.histogram(reference, bins=bins)
            
            # Calculate frequencies
            ref_freq, _ = np.histogram(reference, bins=bin_edges)
            curr_freq, _ = np.histogram(current, bins=bin_edges)
            
            # Normalize to probabilities
            ref_prob = ref_freq / len(reference)
            curr_prob = curr_freq / len(current)
            
            # Add small constant to avoid log(0)
            ref_prob = np.where(ref_prob == 0, 1e-6, ref_prob)
            curr_prob = np.where(curr_prob == 0, 1e-6, curr_prob)
            
            # Calculate PSI
            psi = np.sum((curr_prob - ref_prob) * np.log(curr_prob / ref_prob))
            
            return float(psi)
            
        except Exception:
            return 0.0
    
    def _calculate_js_divergence(self, reference: pd.Series, current: pd.Series, bins: int = 50) -> float:
        """Calculate Jensen-Shannon Divergence"""
        
        try:
            # Create common bins
            combined = pd.concat([reference, current])
            bin_edges = np.histogram_bin_edges(combined, bins=bins)
            
            # Calculate histograms
            ref_hist, _ = np.histogram(reference, bins=bin_edges, density=True)
            curr_hist, _ = np.histogram(current, bins=bin_edges, density=True)
            
            # Normalize to probabilities
            ref_prob = ref_hist / np.sum(ref_hist)
            curr_prob = curr_hist / np.sum(curr_hist)
            
            # Add small constant to avoid log(0)
            ref_prob = np.where(ref_prob == 0, 1e-10, ref_prob)
            curr_prob = np.where(curr_prob == 0, 1e-10, curr_prob)
            
            # Calculate JS divergence
            m = 0.5 * (ref_prob + curr_prob)
            
            kl_pm = np.sum(ref_prob * np.log(ref_prob / m))
            kl_qm = np.sum(curr_prob * np.log(curr_prob / m))
            
            js_divergence = 0.5 * (kl_pm + kl_qm)
            
            return float(js_divergence)
            
        except Exception:
            return 0.0
    
    def _generate_drift_recommendations(self, feature_drift_scores: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on drift analysis"""
        
        recommendations = []
        
        # Find features with highest drift
        high_drift_features = []
        for feature, scores in feature_drift_scores.items():
            if scores.get("drift_detected", False) and scores.get("overall_score", 0) > 0.7:
                high_drift_features.append(feature)
        
        if high_drift_features:
            recommendations.append(
                f"High drift detected in features: {', '.join(high_drift_features)}. "
                f"Consider retraining the model with recent data."
            )
            
            recommendations.append(
                "Investigate data collection processes for potential changes in "
                "data sources, preprocessing, or feature engineering."
            )
            
            recommendations.append(
                "Consider implementing adaptive model updates or online learning "
                "to handle evolving data patterns."
            )
        
        moderate_drift_features = []
        for feature, scores in feature_drift_scores.items():
            if (scores.get("drift_detected", False) and 
                0.3 < scores.get("overall_score", 0) <= 0.7):
                moderate_drift_features.append(feature)
        
        if moderate_drift_features:
            recommendations.append(
                f"Moderate drift detected in features: {', '.join(moderate_drift_features)}. "
                f"Monitor closely and consider model refresh."
            )
        
        return recommendations


class ModelPerformanceMonitor:
    """Real-time model performance monitoring"""
    
    def __init__(self, settings: SecuritySettings, monitoring_settings: MonitoringSettings):
        self.settings = settings
        self.monitoring_settings = monitoring_settings
        self.audit_logger = AuditLogger(settings)
        
        # Model health tracking
        self.model_health: Dict[str, ModelHealthMetrics] = {}
        
        # Active alerts
        self.active_alerts: Dict[str, MonitoringAlert] = {}
        
        # Performance history
        self.performance_history: Dict[str, List[Dict[str, Any]]] = {}
        
        # Prometheus metrics
        self.model_predictions_total = Counter(
            'model_predictions_total',
            'Total model predictions',
            ['model_name', 'tenant_id', 'status']
        )
        
        self.model_latency = Histogram(
            'model_latency_seconds',
            'Model prediction latency',
            ['model_name', 'tenant_id']
        )
        
        self.model_accuracy = Gauge(
            'model_accuracy',
            'Model accuracy score',
            ['model_name', 'tenant_id']
        )
        
        self.model_drift_score = Gauge(
            'model_drift_score',
            'Model data drift score',
            ['model_name', 'tenant_id']
        )
    
    async def record_prediction(self, model_name: str, tenant_id: str, 
                              prediction_time_ms: float, success: bool,
                              confidence: float = None):
        """Record individual prediction metrics"""
        
        try:
            # Get or create model health metrics
            key = f"{tenant_id}_{model_name}"
            if key not in self.model_health:
                self.model_health[key] = ModelHealthMetrics(model_name, tenant_id)
            
            health = self.model_health[key]
            
            # Update metrics
            health.total_predictions += 1
            if success:
                health.successful_predictions += 1
            else:
                health.failed_predictions += 1
            
            # Update response times
            health.avg_response_time_ms = (
                (health.avg_response_time_ms * (health.total_predictions - 1) + prediction_time_ms) /
                health.total_predictions
            )
            
            # Update error rate
            health.error_rate = health.failed_predictions / health.total_predictions
            
            # Update availability
            health.availability = (health.successful_predictions / health.total_predictions) * 100
            
            health.last_prediction_time = datetime.utcnow()
            
            # Record Prometheus metrics
            status = "success" if success else "error"
            self.model_predictions_total.labels(
                model_name=model_name,
                tenant_id=tenant_id,
                status=status
            ).inc()
            
            self.model_latency.labels(
                model_name=model_name,
                tenant_id=tenant_id
            ).observe(prediction_time_ms / 1000.0)
            
            # Check for performance alerts
            await self._check_performance_alerts(health)
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="model_prediction_recording_error",
                tenant_id=tenant_id,
                details={
                    "model_name": model_name,
                    "error": str(e)
                }
            )
    
    async def record_batch_performance(self, model_name: str, tenant_id: str,
                                     y_true: np.ndarray, y_pred: np.ndarray,
                                     y_prob: np.ndarray = None):
        """Record batch performance metrics"""
        
        try:
            # Calculate performance metrics
            accuracy = accuracy_score(y_true, y_pred)
            precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            
            # Store performance history
            key = f"{tenant_id}_{model_name}"
            if key not in self.performance_history:
                self.performance_history[key] = []
            
            performance_record = {
                "timestamp": datetime.utcnow().isoformat(),
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1_score": f1,
                "sample_count": len(y_true)
            }
            
            self.performance_history[key].append(performance_record)
            
            # Keep only recent history (last 100 records)
            if len(self.performance_history[key]) > 100:
                self.performance_history[key] = self.performance_history[key][-100:]
            
            # Update Prometheus metrics
            self.model_accuracy.labels(
                model_name=model_name,
                tenant_id=tenant_id
            ).set(accuracy)
            
            # Check for performance degradation
            await self._check_performance_degradation(model_name, tenant_id, performance_record)
            
            # Log performance update
            self.audit_logger.log_security_event(
                event_type="model_batch_performance_recorded",
                tenant_id=tenant_id,
                details={
                    "model_name": model_name,
                    "accuracy": accuracy,
                    "precision": precision,
                    "recall": recall,
                    "f1_score": f1,
                    "sample_count": len(y_true)
                }
            )
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="model_batch_performance_error",
                tenant_id=tenant_id,
                details={
                    "model_name": model_name,
                    "error": str(e)
                }
            )
    
    async def _check_performance_alerts(self, health: ModelHealthMetrics):
        """Check for performance-based alerts"""
        
        alerts = []
        
        # High error rate alert
        if health.error_rate > 0.05:  # 5% error rate threshold
            alerts.append({
                "type": "high_error_rate",
                "severity": AlertSeverity.HIGH if health.error_rate > 0.1 else AlertSeverity.MEDIUM,
                "message": f"High error rate detected: {health.error_rate:.2%}",
                "details": {"error_rate": health.error_rate}
            })
        
        # High latency alert
        if health.avg_response_time_ms > 1000:  # 1 second threshold
            alerts.append({
                "type": "high_latency",
                "severity": AlertSeverity.HIGH if health.avg_response_time_ms > 5000 else AlertSeverity.MEDIUM,
                "message": f"High latency detected: {health.avg_response_time_ms:.1f}ms",
                "details": {"avg_latency_ms": health.avg_response_time_ms}
            })
        
        # Low availability alert
        if health.availability < 95.0:  # 95% availability threshold
            alerts.append({
                "type": "low_availability",
                "severity": AlertSeverity.CRITICAL if health.availability < 90.0 else AlertSeverity.HIGH,
                "message": f"Low availability detected: {health.availability:.1f}%",
                "details": {"availability": health.availability}
            })
        
        # Create alerts
        for alert_data in alerts:
            await self._create_alert(
                model_name=health.model_name,
                tenant_id=health.tenant_id,
                alert_type=alert_data["type"],
                severity=alert_data["severity"],
                message=alert_data["message"],
                details=alert_data["details"]
            )
    
    async def _check_performance_degradation(self, model_name: str, tenant_id: str,
                                           current_performance: Dict[str, Any]):
        """Check for performance degradation trends"""
        
        key = f"{tenant_id}_{model_name}"
        history = self.performance_history.get(key, [])
        
        if len(history) < 5:  # Need at least 5 data points
            return
        
        # Get recent performance data
        recent_accuracy = [record["accuracy"] for record in history[-5:]]
        historical_accuracy = [record["accuracy"] for record in history[:-5]] if len(history) > 5 else []
        
        if not historical_accuracy:
            return
        
        # Check for significant degradation
        recent_avg = np.mean(recent_accuracy)
        historical_avg = np.mean(historical_accuracy)
        
        degradation = historical_avg - recent_avg
        degradation_pct = (degradation / historical_avg) * 100 if historical_avg > 0 else 0
        
        if degradation_pct > 5.0:  # 5% degradation threshold
            await self._create_alert(
                model_name=model_name,
                tenant_id=tenant_id,
                alert_type="performance_degradation",
                severity=AlertSeverity.HIGH if degradation_pct > 10.0 else AlertSeverity.MEDIUM,
                message=f"Performance degradation detected: {degradation_pct:.1f}% decrease in accuracy",
                details={
                    "degradation_percentage": degradation_pct,
                    "recent_accuracy": recent_avg,
                    "historical_accuracy": historical_avg
                }
            )
    
    async def _create_alert(self, model_name: str, tenant_id: str, alert_type: str,
                           severity: str, message: str, details: Dict[str, Any]):
        """Create and store monitoring alert"""
        
        from uuid import uuid4
        
        alert_id = str(uuid4())
        
        alert = MonitoringAlert(
            alert_id=alert_id,
            model_name=model_name,
            alert_type=alert_type,
            severity=severity,
            message=message,
            details=details,
            tenant_id=tenant_id
        )
        
        self.active_alerts[alert_id] = alert
        
        # Log alert
        self.audit_logger.log_security_event(
            event_type="model_monitoring_alert",
            tenant_id=tenant_id,
            details={
                "alert_id": alert_id,
                "model_name": model_name,
                "alert_type": alert_type,
                "severity": severity,
                "message": message,
                "alert_details": details
            }
        )
    
    async def get_model_health(self, model_name: str, tenant_id: str) -> Dict[str, Any]:
        """Get comprehensive model health status"""
        
        key = f"{tenant_id}_{model_name}"
        
        if key not in self.model_health:
            return {"status": "no_data"}
        
        health = self.model_health[key]
        
        # Calculate health score
        health_score = 100.0
        
        # Penalize for high error rate
        if health.error_rate > 0.01:
            health_score -= min(health.error_rate * 1000, 50)  # Max 50 point penalty
        
        # Penalize for high latency
        if health.avg_response_time_ms > 100:
            latency_penalty = min((health.avg_response_time_ms - 100) / 100 * 10, 30)
            health_score -= latency_penalty
        
        # Penalize for low availability
        if health.availability < 99.0:
            availability_penalty = (99.0 - health.availability) * 5
            health_score -= availability_penalty
        
        health_score = max(0, health_score)
        health.health_score = health_score
        
        # Determine status
        if health_score >= 90:
            status = "healthy"
        elif health_score >= 70:
            status = "degraded"
        else:
            status = "unhealthy"
        
        # Get active alerts for this model
        model_alerts = [
            alert for alert in self.active_alerts.values()
            if alert.model_name == model_name and alert.tenant_id == tenant_id and alert.status == "active"
        ]
        
        return {
            "status": status,
            "health_score": health_score,
            "uptime_seconds": (datetime.utcnow() - health.start_time).total_seconds(),
            "total_predictions": health.total_predictions,
            "successful_predictions": health.successful_predictions,
            "failed_predictions": health.failed_predictions,
            "error_rate": health.error_rate,
            "avg_response_time_ms": health.avg_response_time_ms,
            "availability": health.availability,
            "last_prediction_time": health.last_prediction_time.isoformat() if health.last_prediction_time else None,
            "active_alerts": len(model_alerts),
            "alert_details": [
                {
                    "alert_id": alert.alert_id,
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "created_at": alert.created_at.isoformat()
                } for alert in model_alerts
            ]
        }
    
    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge monitoring alert"""
        
        if alert_id not in self.active_alerts:
            return False
        
        alert = self.active_alerts[alert_id]
        alert.status = "acknowledged"
        alert.acknowledged_by = acknowledged_by
        alert.acknowledged_at = datetime.utcnow()
        
        # Log acknowledgment
        self.audit_logger.log_security_event(
            event_type="model_alert_acknowledged",
            tenant_id=alert.tenant_id,
            details={
                "alert_id": alert_id,
                "acknowledged_by": acknowledged_by,
                "model_name": alert.model_name,
                "alert_type": alert.alert_type
            }
        )
        
        return True
    
    async def get_performance_summary(self, tenant_id: str) -> Dict[str, Any]:
        """Get performance summary for all models"""
        
        summary = {
            "total_models": 0,
            "healthy_models": 0,
            "degraded_models": 0,
            "unhealthy_models": 0,
            "total_predictions": 0,
            "total_errors": 0,
            "overall_error_rate": 0.0,
            "active_alerts": 0,
            "model_details": {}
        }
        
        for key, health in self.model_health.items():
            if not key.startswith(f"{tenant_id}_"):
                continue
            
            model_name = key.replace(f"{tenant_id}_", "")
            summary["total_models"] += 1
            summary["total_predictions"] += health.total_predictions
            summary["total_errors"] += health.failed_predictions
            
            # Get model health status
            model_health_data = await self.get_model_health(model_name, tenant_id)
            
            if model_health_data["status"] == "healthy":
                summary["healthy_models"] += 1
            elif model_health_data["status"] == "degraded":
                summary["degraded_models"] += 1
            else:
                summary["unhealthy_models"] += 1
            
            summary["active_alerts"] += model_health_data["active_alerts"]
            summary["model_details"][model_name] = model_health_data
        
        # Calculate overall error rate
        if summary["total_predictions"] > 0:
            summary["overall_error_rate"] = summary["total_errors"] / summary["total_predictions"]
        
        return summary