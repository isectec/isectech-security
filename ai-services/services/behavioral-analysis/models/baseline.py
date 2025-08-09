"""
Behavioral baseline models for UEBA system.

This module provides baseline modeling capabilities to establish normal
behavioral patterns for entities and detect deviations from these patterns.
"""

import json
import pickle
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.cluster import DBSCAN, KMeans
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import RobustScaler

from .feature_engineering import BehavioralFeatures, FeatureExtractor


class BehavioralBaseline:
    """Container for behavioral baseline data and statistics."""
    
    def __init__(self, entity_id: str, entity_type: str):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.baseline_id = str(uuid.uuid4())
        self.created_at = datetime.utcnow()
        self.last_updated = datetime.utcnow()
        
        # Statistical baseline data
        self.feature_statistics: Dict[str, Dict[str, float]] = {}
        self.correlation_matrix: Optional[np.ndarray] = None
        self.feature_names: List[str] = []
        
        # Pattern-based baselines
        self.temporal_patterns: Dict[str, Any] = {}
        self.access_patterns: Dict[str, Any] = {}
        self.behavioral_clusters: Optional[Dict[str, Any]] = None
        
        # Adaptive parameters
        self.learning_rate = 0.1
        self.stability_threshold = 0.05
        self.min_samples_for_baseline = 100
        self.max_history_days = 90
        
        # Tracking data
        self.sample_count = 0
        self.update_history: List[datetime] = []
        self.stability_score = 0.0
        self.confidence_score = 0.0
    
    def add_feature_statistics(self, feature_name: str, mean: float, std: float,
                             median: float, q25: float, q75: float, 
                             min_val: float, max_val: float):
        """Add statistical baseline for a feature."""
        self.feature_statistics[feature_name] = {
            "mean": mean,
            "std": std,
            "median": median,
            "q25": q25,
            "q75": q75,
            "min": min_val,
            "max": max_val,
            "iqr": q75 - q25
        }
    
    def get_feature_bounds(self, feature_name: str, 
                          confidence_level: float = 0.95) -> Tuple[float, float]:
        """Get acceptable bounds for a feature based on baseline."""
        if feature_name not in self.feature_statistics:
            return float('-inf'), float('inf')
        
        stats_data = self.feature_statistics[feature_name]
        mean = stats_data["mean"]
        std = stats_data["std"]
        
        # Use confidence interval based on normal distribution
        z_score = stats.norm.ppf((1 + confidence_level) / 2)
        margin = z_score * std
        
        return mean - margin, mean + margin
    
    def calculate_deviation_score(self, feature_name: str, value: float) -> float:
        """Calculate deviation score for a feature value."""
        if feature_name not in self.feature_statistics:
            return 0.0
        
        stats_data = self.feature_statistics[feature_name]
        mean = stats_data["mean"]
        std = stats_data["std"]
        
        if std == 0:
            return 0.0 if value == mean else 1.0
        
        # Calculate z-score and normalize to [0, 1]
        z_score = abs(value - mean) / std
        return min(z_score / 3.0, 1.0)  # Cap at 1.0 for 3+ standard deviations
    
    def is_stable(self) -> bool:
        """Check if baseline is stable enough for anomaly detection."""
        return (
            self.sample_count >= self.min_samples_for_baseline and
            self.stability_score >= self.stability_threshold and
            self.confidence_score >= 0.7
        )
    
    def to_dict(self) -> Dict:
        """Convert baseline to dictionary for serialization."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "baseline_id": self.baseline_id,
            "created_at": self.created_at.isoformat(),
            "last_updated": self.last_updated.isoformat(),
            "feature_statistics": self.feature_statistics,
            "correlation_matrix": self.correlation_matrix.tolist() if self.correlation_matrix is not None else None,
            "feature_names": self.feature_names,
            "temporal_patterns": self.temporal_patterns,
            "access_patterns": self.access_patterns,
            "behavioral_clusters": self.behavioral_clusters,
            "learning_rate": self.learning_rate,
            "sample_count": self.sample_count,
            "stability_score": self.stability_score,
            "confidence_score": self.confidence_score,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'BehavioralBaseline':
        """Create baseline from dictionary."""
        baseline = cls(data["entity_id"], data["entity_type"])
        baseline.baseline_id = data["baseline_id"]
        baseline.created_at = datetime.fromisoformat(data["created_at"])
        baseline.last_updated = datetime.fromisoformat(data["last_updated"])
        baseline.feature_statistics = data["feature_statistics"]
        baseline.feature_names = data["feature_names"]
        baseline.temporal_patterns = data["temporal_patterns"]
        baseline.access_patterns = data["access_patterns"]
        baseline.behavioral_clusters = data["behavioral_clusters"]
        baseline.learning_rate = data["learning_rate"]
        baseline.sample_count = data["sample_count"]
        baseline.stability_score = data["stability_score"]
        baseline.confidence_score = data["confidence_score"]
        
        if data["correlation_matrix"]:
            baseline.correlation_matrix = np.array(data["correlation_matrix"])
        
        return baseline


class AdaptiveStatistics:
    """Adaptive statistics tracking for incremental baseline updates."""
    
    def __init__(self, learning_rate: float = 0.1):
        self.learning_rate = learning_rate
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0  # For variance calculation
        self.min_val = float('inf')
        self.max_val = float('-inf')
        self.quantiles = np.array([0.0, 0.0, 0.0])  # Q25, median, Q75
        self.history = deque(maxlen=1000)  # Keep recent history for quantiles
    
    def update(self, value: float):
        """Update statistics with new value using Welford's algorithm."""
        self.n += 1
        self.history.append(value)
        
        # Update min/max
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)
        
        # Update mean and variance using Welford's algorithm
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.m2 += delta * delta2
        
        # Update quantiles periodically
        if self.n % 10 == 0 and len(self.history) > 3:
            self.quantiles = np.percentile(list(self.history), [25, 50, 75])
    
    def get_statistics(self) -> Dict[str, float]:
        """Get current statistics."""
        variance = self.m2 / max(self.n - 1, 1) if self.n > 1 else 0
        std = np.sqrt(variance)
        
        return {
            "mean": self.mean,
            "std": std,
            "median": self.quantiles[1],
            "q25": self.quantiles[0],
            "q75": self.quantiles[2],
            "min": self.min_val if self.min_val != float('inf') else 0,
            "max": self.max_val if self.max_val != float('-inf') else 0,
        }


class TimeSeriesBaseline:
    """Time series baseline for temporal pattern analysis."""
    
    def __init__(self, window_size: int = 24):  # 24 hours default
        self.window_size = window_size
        self.hourly_patterns = [AdaptiveStatistics() for _ in range(24)]
        self.daily_patterns = [AdaptiveStatistics() for _ in range(7)]
        self.overall_pattern = AdaptiveStatistics()
    
    def update(self, timestamp: datetime, value: float):
        """Update time series patterns."""
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        
        self.hourly_patterns[hour].update(value)
        self.daily_patterns[day_of_week].update(value)
        self.overall_pattern.update(value)
    
    def get_expected_value(self, timestamp: datetime) -> Tuple[float, float]:
        """Get expected value and standard deviation for timestamp."""
        hour = timestamp.hour
        
        hourly_stats = self.hourly_patterns[hour].get_statistics()
        overall_stats = self.overall_pattern.get_statistics()
        
        # Blend hourly and overall patterns
        if self.hourly_patterns[hour].n >= 10:
            expected = hourly_stats["mean"]
            std = hourly_stats["std"]
        else:
            expected = overall_stats["mean"]
            std = overall_stats["std"]
        
        return expected, max(std, 0.1)  # Minimum std to avoid division by zero
    
    def calculate_temporal_anomaly_score(self, timestamp: datetime, value: float) -> float:
        """Calculate anomaly score based on temporal patterns."""
        expected, std = self.get_expected_value(timestamp)
        
        if std == 0:
            return 0.0 if value == expected else 1.0
        
        z_score = abs(value - expected) / std
        return min(z_score / 3.0, 1.0)  # Normalize to [0, 1]


class BaselineModel:
    """Main baseline model for behavioral analysis."""
    
    def __init__(self, feature_extractor: FeatureExtractor, config: Dict = None):
        self.feature_extractor = feature_extractor
        self.config = config or {}
        
        # Baseline storage
        self.baselines: Dict[str, BehavioralBaseline] = {}
        self.adaptive_stats: Dict[str, Dict[str, AdaptiveStatistics]] = defaultdict(dict)
        self.time_series_baselines: Dict[str, Dict[str, TimeSeriesBaseline]] = defaultdict(dict)
        
        # Model parameters
        self.min_samples_for_baseline = self.config.get("min_samples_for_baseline", 100)
        self.baseline_update_frequency = self.config.get("baseline_update_frequency", timedelta(hours=6))
        self.max_baseline_age_days = self.config.get("max_baseline_age_days", 90)
        self.stability_window_size = self.config.get("stability_window_size", 50)
        
        # Clustering for behavioral patterns
        self.cluster_models: Dict[str, Union[KMeans, DBSCAN, GaussianMixture]] = {}
        self.scaler = RobustScaler()
        
        # Update tracking
        self.last_baseline_update: Dict[str, datetime] = {}
        self.baseline_version: int = 1
    
    def create_baseline(self, entity_id: str, entity_type: str,
                       historical_features: List[BehavioralFeatures]) -> BehavioralBaseline:
        """Create initial baseline from historical data."""
        if len(historical_features) < self.min_samples_for_baseline:
            raise ValueError(f"Insufficient data for baseline. Need {self.min_samples_for_baseline}, got {len(historical_features)}")
        
        baseline = BehavioralBaseline(entity_id, entity_type)
        
        # Extract feature matrix
        feature_matrix, feature_names = self.feature_extractor.prepare_feature_matrix(historical_features)
        baseline.feature_names = feature_names
        
        # Calculate statistical baselines for each feature
        for i, feature_name in enumerate(feature_names):
            feature_values = feature_matrix[:, i]
            
            mean = np.mean(feature_values)
            std = np.std(feature_values)
            median = np.median(feature_values)
            q25, q75 = np.percentile(feature_values, [25, 75])
            min_val, max_val = np.min(feature_values), np.max(feature_values)
            
            baseline.add_feature_statistics(
                feature_name, mean, std, median, q25, q75, min_val, max_val
            )
        
        # Calculate correlation matrix
        if feature_matrix.shape[1] > 1:
            baseline.correlation_matrix = np.corrcoef(feature_matrix.T)
        
        # Extract temporal patterns
        baseline.temporal_patterns = self._extract_temporal_patterns(historical_features)
        
        # Extract access patterns
        baseline.access_patterns = self._extract_access_patterns(historical_features)
        
        # Create behavioral clusters
        baseline.behavioral_clusters = self._create_behavioral_clusters(
            entity_id, feature_matrix, feature_names
        )
        
        # Calculate baseline quality metrics
        baseline.sample_count = len(historical_features)
        baseline.stability_score = self._calculate_stability_score(feature_matrix)
        baseline.confidence_score = self._calculate_confidence_score(baseline)
        
        # Store baseline
        self.baselines[entity_id] = baseline
        self.last_baseline_update[entity_id] = datetime.utcnow()
        
        return baseline
    
    def update_baseline(self, entity_id: str, new_features: BehavioralFeatures,
                       incremental: bool = True) -> bool:
        """Update existing baseline with new data."""
        if entity_id not in self.baselines:
            return False
        
        baseline = self.baselines[entity_id]
        
        # Check if update is needed
        last_update = self.last_baseline_update.get(entity_id, datetime.min)
        if datetime.utcnow() - last_update < self.baseline_update_frequency:
            return False
        
        if incremental:
            # Incremental update using adaptive statistics
            self._update_baseline_incremental(baseline, new_features)
        else:
            # Full recalculation (more expensive but more accurate)
            return False  # Would need historical data for full recalculation
        
        baseline.last_updated = datetime.utcnow()
        self.last_baseline_update[entity_id] = datetime.utcnow()
        
        return True
    
    def _update_baseline_incremental(self, baseline: BehavioralBaseline,
                                   new_features: BehavioralFeatures):
        """Perform incremental baseline update."""
        entity_id = baseline.entity_id
        
        # Initialize adaptive statistics if needed
        if entity_id not in self.adaptive_stats:
            for feature_name in baseline.feature_names:
                self.adaptive_stats[entity_id][feature_name] = AdaptiveStatistics(
                    learning_rate=baseline.learning_rate
                )
        
        # Update adaptive statistics
        for feature_name in baseline.feature_names:
            if feature_name in new_features.features:
                value = new_features.features[feature_name]
                if isinstance(value, (int, float)):
                    self.adaptive_stats[entity_id][feature_name].update(float(value))
        
        # Update baseline statistics
        for feature_name, adaptive_stat in self.adaptive_stats[entity_id].items():
            if adaptive_stat.n >= 10:  # Minimum samples for reliable update
                stats = adaptive_stat.get_statistics()
                baseline.feature_statistics[feature_name] = stats
        
        # Update sample count and confidence
        baseline.sample_count += 1
        baseline.confidence_score = min(baseline.confidence_score + 0.01, 1.0)
    
    def get_baseline(self, entity_id: str) -> Optional[BehavioralBaseline]:
        """Get baseline for entity."""
        return self.baselines.get(entity_id)
    
    def calculate_baseline_deviation(self, entity_id: str, 
                                   features: BehavioralFeatures) -> Dict[str, float]:
        """Calculate deviation scores from baseline."""
        baseline = self.baselines.get(entity_id)
        if not baseline or not baseline.is_stable():
            return {}
        
        deviations = {}
        
        for feature_name, value in features.features.items():
            if isinstance(value, (int, float)) and feature_name in baseline.feature_statistics:
                deviation_score = baseline.calculate_deviation_score(feature_name, float(value))
                deviations[feature_name] = deviation_score
        
        return deviations
    
    def calculate_overall_anomaly_score(self, entity_id: str,
                                      features: BehavioralFeatures) -> float:
        """Calculate overall anomaly score based on baseline."""
        deviations = self.calculate_baseline_deviation(entity_id, features)
        
        if not deviations:
            return 0.0
        
        # Weight different types of features
        feature_weights = {
            "temporal": 0.3,
            "access_pattern": 0.4,
            "contextual": 0.3
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for feature_name, deviation in deviations.items():
            # Determine feature category from metadata
            feature_category = features.metadata.get(feature_name, {}).get("category", "general")
            weight = feature_weights.get(feature_category, 0.1)
            
            weighted_score += deviation * weight
            total_weight += weight
        
        return weighted_score / max(total_weight, 1.0)
    
    def _extract_temporal_patterns(self, features_list: List[BehavioralFeatures]) -> Dict[str, Any]:
        """Extract temporal patterns from historical features."""
        temporal_patterns = {
            "activity_by_hour": defaultdict(list),
            "activity_by_day": defaultdict(list),
            "peak_activity_hours": [],
            "typical_session_duration": 0,
        }
        
        for features in features_list:
            # Extract temporal features
            if "most_active_hour" in features.features:
                hour = features.features["most_active_hour"]
                temporal_patterns["activity_by_hour"][hour].append(features.features.get("event_count", 0))
            
            if "most_active_day" in features.features:
                day = features.features["most_active_day"]
                temporal_patterns["activity_by_day"][day].append(features.features.get("event_count", 0))
        
        # Calculate peak hours (hours with above-average activity)
        if temporal_patterns["activity_by_hour"]:
            hourly_avg = {
                hour: np.mean(counts) for hour, counts in temporal_patterns["activity_by_hour"].items()
            }
            overall_avg = np.mean(list(hourly_avg.values()))
            temporal_patterns["peak_activity_hours"] = [
                hour for hour, avg in hourly_avg.items() if avg > overall_avg * 1.2
            ]
        
        return dict(temporal_patterns)
    
    def _extract_access_patterns(self, features_list: List[BehavioralFeatures]) -> Dict[str, Any]:
        """Extract access patterns from historical features."""
        access_patterns = {
            "common_resources": [],
            "typical_ip_count": 0,
            "success_rate_range": (0.0, 1.0),
            "data_transfer_patterns": {},
        }
        
        # Extract common patterns
        resource_counts = []
        ip_counts = []
        success_rates = []
        
        for features in features_list:
            if "unique_resources" in features.features:
                resource_counts.append(features.features["unique_resources"])
            
            if "unique_ips" in features.features:
                ip_counts.append(features.features["unique_ips"])
            
            if "success_rate" in features.features:
                success_rates.append(features.features["success_rate"])
        
        if resource_counts:
            access_patterns["typical_resource_count"] = np.median(resource_counts)
        
        if ip_counts:
            access_patterns["typical_ip_count"] = np.median(ip_counts)
        
        if success_rates:
            access_patterns["success_rate_range"] = (
                np.percentile(success_rates, 5),
                np.percentile(success_rates, 95)
            )
        
        return access_patterns
    
    def _create_behavioral_clusters(self, entity_id: str, feature_matrix: np.ndarray,
                                  feature_names: List[str]) -> Dict[str, Any]:
        """Create behavioral clusters for pattern recognition."""
        if feature_matrix.shape[0] < 10:  # Need minimum samples for clustering
            return {"cluster_count": 0, "cluster_centers": [], "cluster_model": None}
        
        # Normalize features for clustering
        normalized_features = self.scaler.fit_transform(feature_matrix)
        
        # Try different clustering approaches
        cluster_results = {}
        
        # K-means clustering
        n_clusters = min(5, max(2, feature_matrix.shape[0] // 20))
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        kmeans_labels = kmeans.fit_predict(normalized_features)
        
        # DBSCAN for density-based clustering
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        dbscan_labels = dbscan.fit_predict(normalized_features)
        
        # Choose best clustering based on silhouette score
        from sklearn.metrics import silhouette_score
        
        try:
            kmeans_score = silhouette_score(normalized_features, kmeans_labels)
        except:
            kmeans_score = -1
        
        try:
            dbscan_score = silhouette_score(normalized_features, dbscan_labels) if len(set(dbscan_labels)) > 1 else -1
        except:
            dbscan_score = -1
        
        if kmeans_score > dbscan_score:
            best_model = kmeans
            best_labels = kmeans_labels
            cluster_centers = kmeans.cluster_centers_.tolist()
        else:
            best_model = dbscan
            best_labels = dbscan_labels
            cluster_centers = []
        
        # Store cluster model
        self.cluster_models[entity_id] = best_model
        
        return {
            "cluster_count": len(set(best_labels)) - (1 if -1 in best_labels else 0),
            "cluster_centers": cluster_centers,
            "cluster_labels": best_labels.tolist(),
            "feature_names": feature_names,
        }
    
    def _calculate_stability_score(self, feature_matrix: np.ndarray) -> float:
        """Calculate stability score for baseline."""
        if feature_matrix.shape[0] < self.stability_window_size:
            return 0.5  # Intermediate score for insufficient data
        
        # Calculate coefficient of variation for each feature
        stability_scores = []
        
        for i in range(feature_matrix.shape[1]):
            feature_values = feature_matrix[:, i]
            mean_val = np.mean(feature_values)
            std_val = np.std(feature_values)
            
            if mean_val != 0:
                cv = std_val / abs(mean_val)
                stability_score = max(0, 1 - cv)  # Lower CV = higher stability
            else:
                stability_score = 1.0 if std_val == 0 else 0.0
            
            stability_scores.append(stability_score)
        
        return np.mean(stability_scores)
    
    def _calculate_confidence_score(self, baseline: BehavioralBaseline) -> float:
        """Calculate confidence score for baseline."""
        factors = []
        
        # Sample size factor
        sample_factor = min(baseline.sample_count / self.min_samples_for_baseline, 1.0)
        factors.append(sample_factor)
        
        # Feature coverage factor
        feature_coverage = len(baseline.feature_statistics) / max(len(baseline.feature_names), 1)
        factors.append(feature_coverage)
        
        # Stability factor
        factors.append(baseline.stability_score)
        
        # Time factor (newer baselines are more confident)
        age_days = (datetime.utcnow() - baseline.created_at).days
        time_factor = max(0, 1 - (age_days / self.max_baseline_age_days))
        factors.append(time_factor)
        
        return np.mean(factors)
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get summary of all baselines for monitoring."""
        summary = {
            "total_baselines": len(self.baselines),
            "stable_baselines": sum(1 for b in self.baselines.values() if b.is_stable()),
            "avg_confidence": np.mean([b.confidence_score for b in self.baselines.values()]) if self.baselines else 0,
            "avg_stability": np.mean([b.stability_score for b in self.baselines.values()]) if self.baselines else 0,
            "baseline_versions": self.baseline_version,
            "entity_types": list(set(b.entity_type for b in self.baselines.values())),
        }
        
        return summary
    
    def cleanup_old_baselines(self):
        """Remove old or stale baselines."""
        current_time = datetime.utcnow()
        to_remove = []
        
        for entity_id, baseline in self.baselines.items():
            age = current_time - baseline.last_updated
            if age.days > self.max_baseline_age_days:
                to_remove.append(entity_id)
        
        for entity_id in to_remove:
            del self.baselines[entity_id]
            if entity_id in self.adaptive_stats:
                del self.adaptive_stats[entity_id]
            if entity_id in self.time_series_baselines:
                del self.time_series_baselines[entity_id]
            if entity_id in self.cluster_models:
                del self.cluster_models[entity_id]
    
    def export_baseline(self, entity_id: str) -> Optional[Dict]:
        """Export baseline for external storage."""
        baseline = self.baselines.get(entity_id)
        return baseline.to_dict() if baseline else None
    
    def import_baseline(self, baseline_data: Dict) -> bool:
        """Import baseline from external storage."""
        try:
            baseline = BehavioralBaseline.from_dict(baseline_data)
            self.baselines[baseline.entity_id] = baseline
            return True
        except Exception:
            return False