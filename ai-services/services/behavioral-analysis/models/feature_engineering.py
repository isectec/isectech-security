"""
Feature engineering for behavioral analysis and UEBA.

This module provides comprehensive feature extraction from security events,
user activities, and system logs for behavioral anomaly detection.
"""

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import LabelEncoder, RobustScaler, StandardScaler


class BehavioralFeatures:
    """Container for behavioral features extracted from events."""
    
    def __init__(self, entity_id: str, entity_type: str, time_window: timedelta):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.time_window = time_window
        self.features: Dict[str, Any] = {}
        self.metadata: Dict[str, Any] = {}
        self.extraction_timestamp = datetime.utcnow()
    
    def add_feature(self, name: str, value: Any, category: str = "general"):
        """Add a feature with optional category."""
        self.features[name] = value
        self.metadata[name] = {
            "category": category,
            "type": type(value).__name__,
            "timestamp": self.extraction_timestamp
        }
    
    def get_feature_vector(self, feature_names: List[str] = None) -> np.ndarray:
        """Get feature vector as numpy array."""
        if feature_names is None:
            feature_names = list(self.features.keys())
        
        vector = []
        for name in feature_names:
            value = self.features.get(name, 0)
            if isinstance(value, (int, float)):
                vector.append(value)
            elif isinstance(value, bool):
                vector.append(1 if value else 0)
            else:
                # Convert to hash for categorical features
                vector.append(hash(str(value)) % 1000000)
        
        return np.array(vector, dtype=np.float32)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "time_window_minutes": self.time_window.total_seconds() / 60,
            "features": self.features,
            "metadata": self.metadata,
            "extraction_timestamp": self.extraction_timestamp.isoformat()
        }


class TemporalFeatureExtractor:
    """Extract temporal behavioral features."""
    
    def extract_features(self, events: pd.DataFrame, entity_id: str, 
                        time_window: timedelta) -> Dict[str, Any]:
        """Extract temporal features from events."""
        if events.empty:
            return self._get_empty_features()
        
        features = {}
        
        # Basic temporal statistics
        event_times = pd.to_datetime(events['timestamp'])
        time_diffs = event_times.diff().dropna().dt.total_seconds()
        
        features.update({
            "event_count": len(events),
            "events_per_hour": len(events) / (time_window.total_seconds() / 3600),
            "avg_time_between_events": time_diffs.mean() if len(time_diffs) > 0 else 0,
            "std_time_between_events": time_diffs.std() if len(time_diffs) > 0 else 0,
            "min_time_between_events": time_diffs.min() if len(time_diffs) > 0 else 0,
            "max_time_between_events": time_diffs.max() if len(time_diffs) > 0 else 0,
        })
        
        # Time-of-day patterns
        hours = event_times.dt.hour
        features.update({
            "most_active_hour": hours.mode().iloc[0] if not hours.empty else 12,
            "hour_entropy": self._calculate_entropy(hours.value_counts()),
            "business_hours_ratio": len(hours[(hours >= 9) & (hours <= 17)]) / len(hours),
            "night_activity_ratio": len(hours[(hours >= 22) | (hours <= 6)]) / len(hours),
        })
        
        # Day-of-week patterns
        days = event_times.dt.dayofweek
        features.update({
            "most_active_day": days.mode().iloc[0] if not days.empty else 1,
            "weekday_ratio": len(days[days < 5]) / len(days),
            "weekend_ratio": len(days[days >= 5]) / len(days),
            "day_entropy": self._calculate_entropy(days.value_counts()),
        })
        
        # Burst detection
        features.update(self._detect_activity_bursts(event_times))
        
        return features
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """Get default features when no events are present."""
        return {
            "event_count": 0,
            "events_per_hour": 0,
            "avg_time_between_events": 0,
            "std_time_between_events": 0,
            "min_time_between_events": 0,
            "max_time_between_events": 0,
            "most_active_hour": 12,
            "hour_entropy": 0,
            "business_hours_ratio": 0,
            "night_activity_ratio": 0,
            "most_active_day": 1,
            "weekday_ratio": 0,
            "weekend_ratio": 0,
            "day_entropy": 0,
            "burst_count": 0,
            "max_burst_size": 0,
            "avg_burst_duration": 0,
        }
    
    def _calculate_entropy(self, value_counts: pd.Series) -> float:
        """Calculate entropy of value distribution."""
        if value_counts.empty:
            return 0
        
        probabilities = value_counts / value_counts.sum()
        return -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    def _detect_activity_bursts(self, event_times: pd.Series) -> Dict[str, float]:
        """Detect bursts of activity."""
        if len(event_times) < 3:
            return {"burst_count": 0, "max_burst_size": 0, "avg_burst_duration": 0}
        
        # Define burst as period with >3x normal activity rate
        time_diffs = event_times.diff().dropna().dt.total_seconds()
        normal_rate = 1 / time_diffs.mean() if time_diffs.mean() > 0 else 0
        burst_threshold = normal_rate * 3
        
        bursts = []
        current_burst = []
        
        for i, time_diff in enumerate(time_diffs):
            if time_diff > 0 and (1 / time_diff) > burst_threshold:
                current_burst.append(i)
            else:
                if len(current_burst) >= 3:  # Minimum burst size
                    bursts.append(current_burst)
                current_burst = []
        
        if len(current_burst) >= 3:
            bursts.append(current_burst)
        
        if not bursts:
            return {"burst_count": 0, "max_burst_size": 0, "avg_burst_duration": 0}
        
        burst_sizes = [len(burst) for burst in bursts]
        burst_durations = [
            (event_times.iloc[burst[-1]] - event_times.iloc[burst[0]]).total_seconds()
            for burst in bursts
        ]
        
        return {
            "burst_count": len(bursts),
            "max_burst_size": max(burst_sizes),
            "avg_burst_duration": np.mean(burst_durations),
        }


class AccessPatternExtractor:
    """Extract access pattern features."""
    
    def extract_features(self, events: pd.DataFrame, entity_id: str) -> Dict[str, Any]:
        """Extract access pattern features."""
        if events.empty:
            return self._get_empty_features()
        
        features = {}
        
        # Resource access patterns
        if 'resource' in events.columns:
            resources = events['resource'].dropna()
            features.update({
                "unique_resources": resources.nunique(),
                "resource_entropy": self._calculate_entropy(resources.value_counts()),
                "most_accessed_resource": resources.mode().iloc[0] if not resources.empty else "",
                "resource_access_concentration": self._calculate_concentration(resources),
            })
        
        # Action patterns
        if 'action' in events.columns:
            actions = events['action'].dropna()
            features.update({
                "unique_actions": actions.nunique(),
                "action_entropy": self._calculate_entropy(actions.value_counts()),
                "most_common_action": actions.mode().iloc[0] if not actions.empty else "",
                "read_write_ratio": self._calculate_read_write_ratio(actions),
            })
        
        # IP address patterns
        if 'source_ip' in events.columns:
            ips = events['source_ip'].dropna()
            features.update(self._extract_ip_features(ips))
        
        # User agent patterns
        if 'user_agent' in events.columns:
            user_agents = events['user_agent'].dropna()
            features.update(self._extract_user_agent_features(user_agents))
        
        # Success/failure patterns
        if 'success' in events.columns:
            successes = events['success']
            features.update({
                "success_rate": successes.mean() if not successes.empty else 1.0,
                "failure_count": (~successes).sum(),
                "consecutive_failures": self._calculate_max_consecutive_failures(successes),
            })
        
        return features
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """Get default features when no events are present."""
        return {
            "unique_resources": 0,
            "resource_entropy": 0,
            "most_accessed_resource": "",
            "resource_access_concentration": 0,
            "unique_actions": 0,
            "action_entropy": 0,
            "most_common_action": "",
            "read_write_ratio": 1.0,
            "unique_ips": 0,
            "ip_entropy": 0,
            "private_ip_ratio": 0,
            "foreign_ip_ratio": 0,
            "unique_user_agents": 0,
            "mobile_ratio": 0,
            "bot_indicator_score": 0,
            "success_rate": 1.0,
            "failure_count": 0,
            "consecutive_failures": 0,
        }
    
    def _calculate_entropy(self, value_counts: pd.Series) -> float:
        """Calculate entropy of value distribution."""
        if value_counts.empty:
            return 0
        
        probabilities = value_counts / value_counts.sum()
        return -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    def _calculate_concentration(self, values: pd.Series) -> float:
        """Calculate concentration ratio (Gini coefficient)."""
        if values.empty:
            return 0
        
        counts = values.value_counts().values
        counts_sorted = np.sort(counts)
        n = len(counts_sorted)
        index = np.arange(1, n + 1)
        
        return (2 * np.sum(index * counts_sorted)) / (n * np.sum(counts_sorted)) - (n + 1) / n
    
    def _calculate_read_write_ratio(self, actions: pd.Series) -> float:
        """Calculate ratio of read to write operations."""
        read_actions = {"read", "get", "select", "view", "download", "list"}
        write_actions = {"write", "post", "put", "create", "update", "delete", "upload"}
        
        read_count = sum(1 for action in actions if str(action).lower() in read_actions)
        write_count = sum(1 for action in actions if str(action).lower() in write_actions)
        
        return read_count / (write_count + 1)  # Add 1 to avoid division by zero
    
    def _extract_ip_features(self, ips: pd.Series) -> Dict[str, Any]:
        """Extract IP address related features."""
        if ips.empty:
            return {
                "unique_ips": 0,
                "ip_entropy": 0,
                "private_ip_ratio": 0,
                "foreign_ip_ratio": 0,
            }
        
        unique_ips = ips.unique()
        private_count = 0
        foreign_count = 0
        
        for ip in unique_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    private_count += 1
                elif not ip_obj.is_loopback and not ip_obj.is_link_local:
                    foreign_count += 1
            except ValueError:
                continue
        
        total_unique = len(unique_ips)
        
        return {
            "unique_ips": total_unique,
            "ip_entropy": self._calculate_entropy(ips.value_counts()),
            "private_ip_ratio": private_count / max(total_unique, 1),
            "foreign_ip_ratio": foreign_count / max(total_unique, 1),
        }
    
    def _extract_user_agent_features(self, user_agents: pd.Series) -> Dict[str, Any]:
        """Extract user agent related features."""
        if user_agents.empty:
            return {
                "unique_user_agents": 0,
                "mobile_ratio": 0,
                "bot_indicator_score": 0,
            }
        
        mobile_indicators = ["mobile", "android", "iphone", "ipad", "tablet"]
        bot_indicators = ["bot", "crawler", "spider", "scraper", "curl", "wget"]
        
        mobile_count = 0
        bot_score = 0
        
        for ua in user_agents:
            ua_lower = str(ua).lower()
            
            if any(indicator in ua_lower for indicator in mobile_indicators):
                mobile_count += 1
            
            bot_matches = sum(1 for indicator in bot_indicators if indicator in ua_lower)
            bot_score += bot_matches
        
        return {
            "unique_user_agents": user_agents.nunique(),
            "mobile_ratio": mobile_count / len(user_agents),
            "bot_indicator_score": bot_score / len(user_agents),
        }
    
    def _calculate_max_consecutive_failures(self, successes: pd.Series) -> int:
        """Calculate maximum consecutive failures."""
        if successes.empty:
            return 0
        
        failures = ~successes
        max_consecutive = 0
        current_consecutive = 0
        
        for failure in failures:
            if failure:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0
        
        return max_consecutive


class ContextualFeatureExtractor:
    """Extract contextual behavioral features."""
    
    def extract_features(self, events: pd.DataFrame, entity_id: str,
                        historical_baseline: Optional[Dict] = None) -> Dict[str, Any]:
        """Extract contextual features."""
        if events.empty:
            return self._get_empty_features()
        
        features = {}
        
        # Data volume features
        if 'data_size' in events.columns:
            data_sizes = events['data_size'].dropna()
            if not data_sizes.empty:
                features.update({
                    "total_data_transferred": data_sizes.sum(),
                    "avg_data_per_event": data_sizes.mean(),
                    "max_data_transfer": data_sizes.max(),
                    "data_transfer_variance": data_sizes.var(),
                })
        
        # Geographic features
        if 'location' in events.columns:
            locations = events['location'].dropna()
            features.update({
                "unique_locations": locations.nunique(),
                "location_entropy": self._calculate_entropy(locations.value_counts()),
                "location_changes": self._count_location_changes(locations),
            })
        
        # Application/service features
        if 'application' in events.columns:
            applications = events['application'].dropna()
            features.update({
                "unique_applications": applications.nunique(),
                "application_entropy": self._calculate_entropy(applications.value_counts()),
                "most_used_application": applications.mode().iloc[0] if not applications.empty else "",
            })
        
        # Security level features
        if 'security_classification' in events.columns:
            classifications = events['security_classification'].dropna()
            features.update(self._extract_security_features(classifications))
        
        # Deviation from baseline
        if historical_baseline:
            features.update(self._calculate_baseline_deviations(features, historical_baseline))
        
        return features
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """Get default features when no events are present."""
        return {
            "total_data_transferred": 0,
            "avg_data_per_event": 0,
            "max_data_transfer": 0,
            "data_transfer_variance": 0,
            "unique_locations": 0,
            "location_entropy": 0,
            "location_changes": 0,
            "unique_applications": 0,
            "application_entropy": 0,
            "most_used_application": "",
            "classified_data_ratio": 0,
            "highest_classification_accessed": "UNCLASSIFIED",
            "classification_diversity": 0,
        }
    
    def _calculate_entropy(self, value_counts: pd.Series) -> float:
        """Calculate entropy of value distribution."""
        if value_counts.empty:
            return 0
        
        probabilities = value_counts / value_counts.sum()
        return -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    def _count_location_changes(self, locations: pd.Series) -> int:
        """Count number of location changes."""
        if len(locations) < 2:
            return 0
        
        changes = 0
        prev_location = locations.iloc[0]
        
        for location in locations.iloc[1:]:
            if location != prev_location:
                changes += 1
                prev_location = location
        
        return changes
    
    def _extract_security_features(self, classifications: pd.Series) -> Dict[str, Any]:
        """Extract security classification features."""
        classification_levels = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP_SECRET": 3
        }
        
        classified_count = sum(1 for c in classifications if c != "UNCLASSIFIED")
        highest_level = max(
            (classification_levels.get(c, 0) for c in classifications),
            default=0
        )
        highest_name = next(
            (name for name, level in classification_levels.items() if level == highest_level),
            "UNCLASSIFIED"
        )
        
        return {
            "classified_data_ratio": classified_count / len(classifications),
            "highest_classification_accessed": highest_name,
            "classification_diversity": classifications.nunique(),
        }
    
    def _calculate_baseline_deviations(self, current_features: Dict[str, Any],
                                     baseline: Dict[str, Any]) -> Dict[str, float]:
        """Calculate deviations from historical baseline."""
        deviations = {}
        
        numeric_features = [
            "event_count", "events_per_hour", "unique_resources", "unique_ips",
            "success_rate", "total_data_transferred"
        ]
        
        for feature in numeric_features:
            current_value = current_features.get(feature, 0)
            baseline_value = baseline.get(feature, 0)
            baseline_std = baseline.get(f"{feature}_std", 1)
            
            if baseline_std > 0:
                z_score = abs(current_value - baseline_value) / baseline_std
                deviations[f"{feature}_deviation"] = z_score
            else:
                deviations[f"{feature}_deviation"] = 0
        
        return deviations


class FeatureExtractor:
    """Main feature extraction class for behavioral analysis."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.temporal_extractor = TemporalFeatureExtractor()
        self.access_extractor = AccessPatternExtractor()
        self.contextual_extractor = ContextualFeatureExtractor()
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.scalers: Dict[str, Union[StandardScaler, RobustScaler]] = {}
    
    def extract_features(self, events: pd.DataFrame, entity_id: str,
                        entity_type: str, time_window: timedelta,
                        historical_baseline: Optional[Dict] = None) -> BehavioralFeatures:
        """Extract comprehensive behavioral features."""
        
        features = BehavioralFeatures(entity_id, entity_type, time_window)
        
        # Extract temporal features
        temporal_features = self.temporal_extractor.extract_features(
            events, entity_id, time_window
        )
        for name, value in temporal_features.items():
            features.add_feature(name, value, "temporal")
        
        # Extract access pattern features
        access_features = self.access_extractor.extract_features(events, entity_id)
        for name, value in access_features.items():
            features.add_feature(name, value, "access_pattern")
        
        # Extract contextual features
        contextual_features = self.contextual_extractor.extract_features(
            events, entity_id, historical_baseline
        )
        for name, value in contextual_features.items():
            features.add_feature(name, value, "contextual")
        
        # Add entity-specific features
        features.add_feature("entity_type_encoded", self._encode_entity_type(entity_type), "entity")
        features.add_feature("time_window_hours", time_window.total_seconds() / 3600, "entity")
        
        return features
    
    def extract_batch_features(self, events_dict: Dict[str, pd.DataFrame],
                             entity_types: Dict[str, str],
                             time_window: timedelta,
                             baselines: Optional[Dict[str, Dict]] = None) -> Dict[str, BehavioralFeatures]:
        """Extract features for multiple entities in batch."""
        results = {}
        
        for entity_id, events in events_dict.items():
            entity_type = entity_types.get(entity_id, "unknown")
            baseline = baselines.get(entity_id) if baselines else None
            
            features = self.extract_features(
                events, entity_id, entity_type, time_window, baseline
            )
            results[entity_id] = features
        
        return results
    
    def prepare_feature_matrix(self, features_list: List[BehavioralFeatures],
                             feature_names: Optional[List[str]] = None) -> Tuple[np.ndarray, List[str]]:
        """Prepare feature matrix for ML models."""
        if not features_list:
            return np.array([]), []
        
        if feature_names is None:
            # Get all unique feature names
            all_features = set()
            for features in features_list:
                all_features.update(features.features.keys())
            feature_names = sorted(list(all_features))
        
        # Create feature matrix
        matrix = np.array([
            features.get_feature_vector(feature_names)
            for features in features_list
        ])
        
        return matrix, feature_names
    
    def normalize_features(self, feature_matrix: np.ndarray, 
                          method: str = "robust") -> np.ndarray:
        """Normalize feature matrix."""
        if feature_matrix.size == 0:
            return feature_matrix
        
        scaler_key = f"{method}_{feature_matrix.shape[1]}"
        
        if scaler_key not in self.scalers:
            if method == "robust":
                self.scalers[scaler_key] = RobustScaler()
            else:
                self.scalers[scaler_key] = StandardScaler()
        
        scaler = self.scalers[scaler_key]
        
        if not hasattr(scaler, 'scale_'):
            # First time fitting
            return scaler.fit_transform(feature_matrix)
        else:
            # Already fitted
            return scaler.transform(feature_matrix)
    
    def _encode_entity_type(self, entity_type: str) -> int:
        """Encode entity type as integer."""
        if "entity_type" not in self.label_encoders:
            self.label_encoders["entity_type"] = LabelEncoder()
            # Pre-fit with known entity types
            known_types = ["user", "device", "application", "network", "service", "unknown"]
            self.label_encoders["entity_type"].fit(known_types)
        
        try:
            return self.label_encoders["entity_type"].transform([entity_type])[0]
        except ValueError:
            # Unknown entity type, return encoding for "unknown"
            return self.label_encoders["entity_type"].transform(["unknown"])[0]
    
    def get_feature_importance(self, feature_matrix: np.ndarray,
                             feature_names: List[str]) -> Dict[str, float]:
        """Calculate feature importance using statistical methods."""
        if feature_matrix.size == 0:
            return {}
        
        importance_scores = {}
        
        for i, feature_name in enumerate(feature_names):
            feature_values = feature_matrix[:, i]
            
            # Calculate variance as importance measure
            variance = np.var(feature_values)
            
            # Normalize by range to handle different scales
            value_range = np.ptp(feature_values)  # peak-to-peak (max - min)
            normalized_importance = variance / (value_range + 1e-10)
            
            importance_scores[feature_name] = normalized_importance
        
        # Normalize importance scores to sum to 1
        total_importance = sum(importance_scores.values())
        if total_importance > 0:
            importance_scores = {
                name: score / total_importance
                for name, score in importance_scores.items()
            }
        
        return importance_scores