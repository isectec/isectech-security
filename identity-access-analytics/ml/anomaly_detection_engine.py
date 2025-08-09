"""
Anomaly Detection and Machine Learning Engine
Production-grade ML system for identity behavior anomaly detection in ISECTECH platform
Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import logging
import time
import json
import pickle
import hashlib
import uuid
from typing import Dict, List, Optional, Any, Union, Tuple, Callable, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
import numpy as np
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
import sqlite3
import aiosqlite
import redis.asyncio as redis
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder, MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import OneClassSVM, SVC
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import DBSCAN
from sklearn.neighbors import LocalOutlierFactor
from sklearn.decomposition import PCA
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import warnings
from scipy import stats
from scipy.spatial.distance import euclidean, cosine
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import xgboost as xgb
import lightgbm as lgb
from hmmlearn import hmm
import networkx as nx
from collections import defaultdict, deque
import math


# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')
tf.get_logger().setLevel('ERROR')


class ModelType(Enum):
    """Machine learning model types"""
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    LOCAL_OUTLIER_FACTOR = "lof"
    DBSCAN = "dbscan"
    AUTOENCODER = "autoencoder"
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    NEURAL_NETWORK = "neural_network"
    LOGISTIC_REGRESSION = "logistic_regression"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    ENSEMBLE = "ensemble"
    HMM = "hidden_markov_model"


class AnomalyType(Enum):
    """Types of anomalies detected"""
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    GEOSPATIAL = "geospatial"
    ACCESS_PATTERN = "access_pattern"
    DEVICE = "device"
    NETWORK = "network"
    PRIVILEGE = "privilege"
    SESSION = "session"
    AUTHENTICATION = "authentication"
    COMPOSITE = "composite"


class ModelStatus(Enum):
    """Model lifecycle status"""
    TRAINING = "training"
    TRAINED = "trained"
    DEPLOYED = "deployed"
    RETRAINING = "retraining"
    DEPRECATED = "deprecated"
    FAILED = "failed"


@dataclass
class Feature:
    """Feature definition and metadata"""
    name: str
    type: str  # 'numerical', 'categorical', 'binary', 'temporal'
    description: str
    importance: float = 0.0
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    categories: Optional[List[str]] = None
    transformation: Optional[str] = None  # 'log', 'sqrt', 'standardize'
    source_table: Optional[str] = None
    extraction_query: Optional[str] = None


@dataclass
class AnomalyScore:
    """Anomaly detection result"""
    user_id: str
    timestamp: datetime
    anomaly_type: AnomalyType
    score: float  # 0-1 scale, higher = more anomalous
    confidence: float  # 0-1 scale, higher = more confident
    model_type: ModelType
    model_version: str
    features_used: List[str]
    feature_values: Dict[str, Any]
    explanation: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    threshold: float
    is_anomaly: bool
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ModelMetrics:
    """Model performance metrics"""
    model_id: str
    model_type: ModelType
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    auc_roc: Optional[float] = None
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    training_time: float = 0.0
    inference_time: float = 0.0
    data_points: int = 0
    feature_count: int = 0
    training_date: Optional[datetime] = None
    validation_date: Optional[datetime] = None


@dataclass
class ModelConfiguration:
    """ML model configuration"""
    model_id: str
    model_type: ModelType
    hyperparameters: Dict[str, Any]
    features: List[Feature]
    target_anomaly_types: List[AnomalyType]
    update_frequency: str  # 'hourly', 'daily', 'weekly'
    retrain_threshold: float  # Performance degradation threshold
    contamination_rate: float = 0.1  # Expected anomaly rate
    use_feature_selection: bool = True
    feature_selection_k: int = 20
    cross_validation_folds: int = 5
    enable_online_learning: bool = False
    enable_ensemble: bool = True
    ensemble_weights: Optional[Dict[str, float]] = None


class FeatureEngine:
    """Advanced feature engineering for identity behavior analysis"""
    
    def __init__(self):
        self.feature_extractors = {
            'temporal': self._extract_temporal_features,
            'behavioral': self._extract_behavioral_features,
            'geospatial': self._extract_geospatial_features,
            'access_pattern': self._extract_access_pattern_features,
            'device': self._extract_device_features,
            'network': self._extract_network_features,
            'session': self._extract_session_features,
            'sequence': self._extract_sequence_features
        }
        
        self.scalers = {}
        self.encoders = {}
        self.feature_stats = {}
        
    def extract_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract comprehensive feature set for anomaly detection"""
        features = {}
        
        # Extract features from each category
        for category, extractor in self.feature_extractors.items():
            try:
                category_features = extractor(user_data, context)
                features.update(category_features)
            except Exception as e:
                logging.warning(f"Feature extraction failed for {category}: {e}")
        
        # Handle missing values
        features = self._handle_missing_values(features)
        
        # Apply transformations
        features = self._apply_transformations(features)
        
        return features
    
    def _extract_temporal_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract time-based features"""
        current_time = context.get('timestamp', datetime.now(timezone.utc))
        
        features = {
            'hour_of_day': current_time.hour,
            'day_of_week': current_time.weekday(),
            'day_of_month': current_time.day,
            'week_of_year': current_time.isocalendar()[1],
            'month_of_year': current_time.month,
            'is_weekend': float(current_time.weekday() >= 5),
            'is_business_hours': float(9 <= current_time.hour <= 17),
            'is_off_hours': float(current_time.hour < 6 or current_time.hour > 22),
            'quarter_of_year': (current_time.month - 1) // 3 + 1
        }
        
        # Time since last login
        last_login = user_data.get('last_login_time')
        if last_login:
            if isinstance(last_login, str):
                last_login = datetime.fromisoformat(last_login.replace('Z', '+00:00'))
            time_since_last = (current_time - last_login).total_seconds()
            features.update({
                'hours_since_last_login': time_since_last / 3600,
                'days_since_last_login': time_since_last / 86400,
                'log_hours_since_last_login': math.log1p(time_since_last / 3600)
            })
        else:
            features.update({
                'hours_since_last_login': 999999,
                'days_since_last_login': 999999,
                'log_hours_since_last_login': math.log1p(999999)
            })
        
        # Seasonal features using cyclical encoding
        features.update({
            'hour_sin': math.sin(2 * math.pi * current_time.hour / 24),
            'hour_cos': math.cos(2 * math.pi * current_time.hour / 24),
            'day_sin': math.sin(2 * math.pi * current_time.weekday() / 7),
            'day_cos': math.cos(2 * math.pi * current_time.weekday() / 7),
            'month_sin': math.sin(2 * math.pi * current_time.month / 12),
            'month_cos': math.cos(2 * math.pi * current_time.month / 12)
        })
        
        return features
    
    def _extract_behavioral_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract user behavior patterns"""
        features = {}
        
        # Login frequency features
        login_history = user_data.get('login_history', [])
        if login_history:
            login_count_7d = len([l for l in login_history if (datetime.now(timezone.utc) - datetime.fromisoformat(l.replace('Z', '+00:00'))).days <= 7])
            login_count_30d = len([l for l in login_history if (datetime.now(timezone.utc) - datetime.fromisoformat(l.replace('Z', '+00:00'))).days <= 30])
            
            features.update({
                'avg_logins_per_day_7d': login_count_7d / 7,
                'avg_logins_per_day_30d': login_count_30d / 30,
                'total_logins': len(login_history),
                'login_frequency_ratio': login_count_7d / max(login_count_30d, 1)
            })
        else:
            features.update({
                'avg_logins_per_day_7d': 0,
                'avg_logins_per_day_30d': 0,
                'total_logins': 0,
                'login_frequency_ratio': 0
            })
        
        # Access pattern features
        accessed_resources = user_data.get('accessed_resources', [])
        unique_resources = len(set(accessed_resources))
        
        features.update({
            'unique_resources_accessed': unique_resources,
            'total_resource_accesses': len(accessed_resources),
            'resource_diversity': unique_resources / max(len(accessed_resources), 1),
            'avg_resource_accesses': len(accessed_resources) / max(unique_resources, 1)
        })
        
        # Session behavior
        session_durations = user_data.get('session_durations', [])
        if session_durations:
            features.update({
                'avg_session_duration': np.mean(session_durations),
                'median_session_duration': np.median(session_durations),
                'std_session_duration': np.std(session_durations),
                'max_session_duration': np.max(session_durations),
                'min_session_duration': np.min(session_durations),
                'session_duration_cv': np.std(session_durations) / max(np.mean(session_durations), 1)
            })
        else:
            features.update({
                'avg_session_duration': 0,
                'median_session_duration': 0,
                'std_session_duration': 0,
                'max_session_duration': 0,
                'min_session_duration': 0,
                'session_duration_cv': 0
            })
        
        # Authentication patterns
        failed_logins = user_data.get('failed_login_count', 0)
        successful_logins = user_data.get('successful_login_count', 0)
        total_attempts = failed_logins + successful_logins
        
        features.update({
            'failed_login_count': failed_logins,
            'successful_login_count': successful_logins,
            'login_failure_rate': failed_logins / max(total_attempts, 1),
            'login_success_rate': successful_logins / max(total_attempts, 1)
        })
        
        return features
    
    def _extract_geospatial_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract location-based features"""
        features = {}
        
        # Current location
        current_country = context.get('country', 'Unknown')
        current_city = context.get('city', 'Unknown')
        current_lat = context.get('latitude', 0.0)
        current_lon = context.get('longitude', 0.0)
        
        # Historical locations
        location_history = user_data.get('location_history', [])
        unique_countries = len(set([loc.get('country', 'Unknown') for loc in location_history]))
        unique_cities = len(set([loc.get('city', 'Unknown') for loc in location_history]))
        
        features.update({
            'unique_countries': unique_countries,
            'unique_cities': unique_cities,
            'location_diversity': unique_cities / max(len(location_history), 1),
            'is_new_country': float(current_country not in [loc.get('country', 'Unknown') for loc in location_history]),
            'is_new_city': float(current_city not in [loc.get('city', 'Unknown') for loc in location_history])
        })
        
        # Distance from usual locations
        if location_history:
            distances = []
            for loc in location_history[-10:]:  # Last 10 locations
                if loc.get('latitude') and loc.get('longitude'):
                    dist = self._haversine_distance(
                        current_lat, current_lon,
                        float(loc['latitude']), float(loc['longitude'])
                    )
                    distances.append(dist)
            
            if distances:
                features.update({
                    'avg_distance_from_usual': np.mean(distances),
                    'min_distance_from_usual': np.min(distances),
                    'max_distance_from_usual': np.max(distances),
                    'std_distance_from_usual': np.std(distances)
                })
            else:
                features.update({
                    'avg_distance_from_usual': 0,
                    'min_distance_from_usual': 0,
                    'max_distance_from_usual': 0,
                    'std_distance_from_usual': 0
                })
        else:
            features.update({
                'avg_distance_from_usual': 0,
                'min_distance_from_usual': 0,
                'max_distance_from_usual': 0,
                'std_distance_from_usual': 0
            })
        
        # Impossible travel detection
        last_location = location_history[-1] if location_history else None
        if last_location and last_location.get('timestamp'):
            last_time = datetime.fromisoformat(last_location['timestamp'].replace('Z', '+00:00'))
            current_time = context.get('timestamp', datetime.now(timezone.utc))
            time_diff_hours = (current_time - last_time).total_seconds() / 3600
            
            if last_location.get('latitude') and last_location.get('longitude'):
                distance_km = self._haversine_distance(
                    current_lat, current_lon,
                    float(last_location['latitude']), float(last_location['longitude'])
                )
                max_speed_kmh = 1000  # Maximum reasonable speed (including flights)
                features['impossible_travel'] = float(distance_km > (max_speed_kmh * time_diff_hours))
                features['travel_velocity'] = distance_km / max(time_diff_hours, 0.1)
            else:
                features['impossible_travel'] = 0.0
                features['travel_velocity'] = 0.0
        else:
            features['impossible_travel'] = 0.0
            features['travel_velocity'] = 0.0
        
        return features
    
    def _extract_access_pattern_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract access pattern features"""
        features = {}
        
        # Application usage patterns
        app_usage = user_data.get('application_usage', {})
        total_app_usage = sum(app_usage.values())
        
        features.update({
            'unique_applications': len(app_usage),
            'total_application_usage': total_app_usage,
            'application_diversity': len(app_usage) / max(total_app_usage, 1),
            'most_used_app_ratio': max(app_usage.values()) / max(total_app_usage, 1) if app_usage else 0
        })
        
        # Resource access patterns
        resource_types = user_data.get('resource_types_accessed', [])
        resource_type_counts = {}
        for rt in resource_types:
            resource_type_counts[rt] = resource_type_counts.get(rt, 0) + 1
        
        features.update({
            'unique_resource_types': len(resource_type_counts),
            'resource_type_entropy': self._calculate_entropy(list(resource_type_counts.values())),
            'most_common_resource_ratio': max(resource_type_counts.values()) / max(len(resource_types), 1) if resource_types else 0
        })
        
        # Permission and privilege patterns
        permissions = user_data.get('permissions', [])
        roles = user_data.get('roles', [])
        
        features.update({
            'permission_count': len(permissions),
            'role_count': len(roles),
            'admin_permissions': sum(1 for p in permissions if 'admin' in p.lower()),
            'privileged_roles': sum(1 for r in roles if any(priv in r.lower() for priv in ['admin', 'super', 'root', 'manager']))
        })
        
        # Time-based access patterns
        access_times = user_data.get('access_times', [])
        if access_times:
            hours = [datetime.fromisoformat(t.replace('Z', '+00:00')).hour for t in access_times]
            features.update({
                'access_time_diversity': len(set(hours)) / 24,
                'avg_access_hour': np.mean(hours),
                'access_time_std': np.std(hours),
                'business_hours_ratio': sum(1 for h in hours if 9 <= h <= 17) / len(hours)
            })
        else:
            features.update({
                'access_time_diversity': 0,
                'avg_access_hour': 12,  # Default to noon
                'access_time_std': 0,
                'business_hours_ratio': 0
            })
        
        return features
    
    def _extract_device_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract device and client features"""
        features = {}
        
        # Current device info
        current_device = context.get('device_id', 'unknown')
        current_os = context.get('os', 'unknown')
        current_browser = context.get('browser', 'unknown')
        is_mobile = context.get('is_mobile', False)
        is_trusted = context.get('is_trusted', False)
        
        # Device history
        device_history = user_data.get('device_history', [])
        unique_devices = len(set([d.get('device_id', 'unknown') for d in device_history]))
        unique_os = len(set([d.get('os', 'unknown') for d in device_history]))
        unique_browsers = len(set([d.get('browser', 'unknown') for d in device_history]))
        
        features.update({
            'unique_devices': unique_devices,
            'unique_operating_systems': unique_os,
            'unique_browsers': unique_browsers,
            'device_diversity': unique_devices / max(len(device_history), 1),
            'is_new_device': float(current_device not in [d.get('device_id', 'unknown') for d in device_history]),
            'is_new_os': float(current_os not in [d.get('os', 'unknown') for d in device_history]),
            'is_new_browser': float(current_browser not in [d.get('browser', 'unknown') for d in device_history]),
            'is_mobile_device': float(is_mobile),
            'is_trusted_device': float(is_trusted)
        })
        
        # Device usage frequency
        device_usage = {}
        for device in device_history:
            device_id = device.get('device_id', 'unknown')
            device_usage[device_id] = device_usage.get(device_id, 0) + 1
        
        current_device_usage = device_usage.get(current_device, 0)
        total_device_usage = sum(device_usage.values())
        
        features.update({
            'current_device_usage_ratio': current_device_usage / max(total_device_usage, 1),
            'device_usage_entropy': self._calculate_entropy(list(device_usage.values())),
            'most_used_device_ratio': max(device_usage.values()) / max(total_device_usage, 1) if device_usage else 0
        })
        
        return features
    
    def _extract_network_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract network-based features"""
        features = {}
        
        # Current network info
        source_ip = context.get('source_ip', '0.0.0.0')
        vpn_detected = context.get('vpn_detected', False)
        proxy_detected = context.get('proxy_detected', False)
        tor_detected = context.get('tor_detected', False)
        
        # Network history
        ip_history = user_data.get('ip_history', [])
        unique_ips = len(set(ip_history))
        
        features.update({
            'unique_ip_addresses': unique_ips,
            'ip_diversity': unique_ips / max(len(ip_history), 1),
            'is_new_ip': float(source_ip not in ip_history),
            'vpn_detected': float(vpn_detected),
            'proxy_detected': float(proxy_detected),
            'tor_detected': float(tor_detected),
            'anonymization_tools': float(vpn_detected or proxy_detected or tor_detected)
        })
        
        # IP reputation and classification
        ip_class = self._classify_ip_address(source_ip)
        features.update({
            'is_private_ip': float(ip_class == 'private'),
            'is_public_ip': float(ip_class == 'public'),
            'is_reserved_ip': float(ip_class == 'reserved')
        })
        
        # Network timing patterns
        network_access_times = user_data.get('network_access_times', [])
        if network_access_times:
            time_diffs = []
            for i in range(1, len(network_access_times)):
                prev_time = datetime.fromisoformat(network_access_times[i-1].replace('Z', '+00:00'))
                curr_time = datetime.fromisoformat(network_access_times[i].replace('Z', '+00:00'))
                time_diffs.append((curr_time - prev_time).total_seconds())
            
            if time_diffs:
                features.update({
                    'avg_network_access_interval': np.mean(time_diffs),
                    'network_access_regularity': np.std(time_diffs),
                    'min_network_access_interval': np.min(time_diffs),
                    'max_network_access_interval': np.max(time_diffs)
                })
            else:
                features.update({
                    'avg_network_access_interval': 0,
                    'network_access_regularity': 0,
                    'min_network_access_interval': 0,
                    'max_network_access_interval': 0
                })
        else:
            features.update({
                'avg_network_access_interval': 0,
                'network_access_regularity': 0,
                'min_network_access_interval': 0,
                'max_network_access_interval': 0
            })
        
        return features
    
    def _extract_session_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract session-based features"""
        features = {}
        
        # Current session info
        session_id = context.get('session_id', 'unknown')
        concurrent_sessions = context.get('concurrent_sessions', 1)
        idle_time = context.get('idle_time', 0)
        
        features.update({
            'concurrent_sessions': concurrent_sessions,
            'current_idle_time': idle_time,
            'has_multiple_sessions': float(concurrent_sessions > 1),
            'high_concurrent_sessions': float(concurrent_sessions > 3)
        })
        
        # Session history analysis
        session_history = user_data.get('session_history', [])
        if session_history:
            session_durations = [s.get('duration', 0) for s in session_history]
            session_idle_times = [s.get('idle_time', 0) for s in session_history]
            max_concurrent = [s.get('concurrent_sessions', 1) for s in session_history]
            
            features.update({
                'avg_historical_session_duration': np.mean(session_durations),
                'session_duration_variance': np.var(session_durations),
                'avg_historical_idle_time': np.mean(session_idle_times),
                'max_historical_concurrent': np.max(max_concurrent),
                'avg_historical_concurrent': np.mean(max_concurrent),
                'session_termination_rate': sum(1 for s in session_history if s.get('terminated_abnormally', False)) / len(session_history)
            })
        else:
            features.update({
                'avg_historical_session_duration': 0,
                'session_duration_variance': 0,
                'avg_historical_idle_time': 0,
                'max_historical_concurrent': 1,
                'avg_historical_concurrent': 1,
                'session_termination_rate': 0
            })
        
        # Session activity patterns
        session_events = user_data.get('session_events', [])
        if session_events:
            event_types = [e.get('type', 'unknown') for e in session_events]
            event_type_counts = {}
            for et in event_types:
                event_type_counts[et] = event_type_counts.get(et, 0) + 1
            
            features.update({
                'session_event_count': len(session_events),
                'session_event_diversity': len(event_type_counts),
                'session_event_rate': len(session_events) / max(user_data.get('avg_session_duration', 1), 1),
                'session_event_entropy': self._calculate_entropy(list(event_type_counts.values()))
            })
        else:
            features.update({
                'session_event_count': 0,
                'session_event_diversity': 0,
                'session_event_rate': 0,
                'session_event_entropy': 0
            })
        
        return features
    
    def _extract_sequence_features(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, float]:
        """Extract sequence-based behavioral features"""
        features = {}
        
        # Action sequences
        action_sequence = user_data.get('recent_actions', [])
        if len(action_sequence) >= 2:
            # N-gram analysis
            bigrams = [(action_sequence[i], action_sequence[i+1]) for i in range(len(action_sequence)-1)]
            trigrams = [(action_sequence[i], action_sequence[i+1], action_sequence[i+2]) for i in range(len(action_sequence)-2)]
            
            bigram_counts = {}
            for bigram in bigrams:
                bigram_counts[bigram] = bigram_counts.get(bigram, 0) + 1
            
            features.update({
                'sequence_length': len(action_sequence),
                'unique_bigrams': len(bigram_counts),
                'bigram_repetition_rate': len(bigrams) / max(len(bigram_counts), 1),
                'sequence_entropy': self._calculate_entropy([action_sequence.count(a) for a in set(action_sequence)])
            })
        else:
            features.update({
                'sequence_length': len(action_sequence),
                'unique_bigrams': 0,
                'bigram_repetition_rate': 0,
                'sequence_entropy': 0
            })
        
        # Temporal sequence patterns
        event_timestamps = user_data.get('event_timestamps', [])
        if len(event_timestamps) >= 2:
            timestamps = [datetime.fromisoformat(ts.replace('Z', '+00:00')) for ts in event_timestamps]
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
            
            features.update({
                'avg_event_interval': np.mean(intervals),
                'event_interval_variance': np.var(intervals),
                'event_timing_regularity': np.std(intervals) / max(np.mean(intervals), 1),
                'burst_activity': sum(1 for interval in intervals if interval < 60) / len(intervals)  # Events within 1 minute
            })
        else:
            features.update({
                'avg_event_interval': 0,
                'event_interval_variance': 0,
                'event_timing_regularity': 0,
                'burst_activity': 0
            })
        
        return features
    
    def _handle_missing_values(self, features: Dict[str, float]) -> Dict[str, float]:
        """Handle missing values in features"""
        cleaned_features = {}
        
        for key, value in features.items():
            if value is None or (isinstance(value, float) and (np.isnan(value) or np.isinf(value))):
                # Use feature-specific defaults or statistical imputation
                if 'ratio' in key or 'rate' in key:
                    cleaned_features[key] = 0.0
                elif 'count' in key:
                    cleaned_features[key] = 0.0
                elif 'diversity' in key:
                    cleaned_features[key] = 0.0
                elif 'entropy' in key:
                    cleaned_features[key] = 0.0
                else:
                    cleaned_features[key] = 0.0
            else:
                cleaned_features[key] = float(value)
        
        return cleaned_features
    
    def _apply_transformations(self, features: Dict[str, float]) -> Dict[str, float]:
        """Apply feature transformations"""
        transformed_features = features.copy()
        
        # Log transformation for highly skewed features
        log_transform_features = [
            'total_logins', 'total_resource_accesses', 'unique_resources_accessed',
            'unique_devices', 'unique_ip_addresses', 'permission_count'
        ]
        
        for feature_name in log_transform_features:
            if feature_name in transformed_features:
                value = transformed_features[feature_name]
                transformed_features[f'{feature_name}_log'] = math.log1p(value)
        
        # Square root transformation for count features
        sqrt_transform_features = [
            'session_event_count', 'concurrent_sessions', 'unique_applications'
        ]
        
        for feature_name in sqrt_transform_features:
            if feature_name in transformed_features:
                value = transformed_features[feature_name]
                transformed_features[f'{feature_name}_sqrt'] = math.sqrt(value)
        
        return transformed_features
    
    def _haversine_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate haversine distance between two points"""
        R = 6371  # Earth's radius in kilometers
        
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lon1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lon2)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        return R * c
    
    def _calculate_entropy(self, values: List[float]) -> float:
        """Calculate Shannon entropy"""
        if not values or sum(values) == 0:
            return 0.0
        
        total = sum(values)
        probabilities = [v / total for v in values if v > 0]
        
        entropy = -sum(p * math.log2(p) for p in probabilities)
        return entropy
    
    def _classify_ip_address(self, ip: str) -> str:
        """Classify IP address type"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private:
                return 'private'
            elif ip_obj.is_reserved:
                return 'reserved'
            else:
                return 'public'
        except:
            return 'unknown'


class ModelManager:
    """Machine learning model management and orchestration"""
    
    def __init__(self, model_storage_path: str = "models/"):
        self.model_storage_path = model_storage_path
        self.models = {}
        self.model_configs = {}
        self.model_metrics = {}
        self.feature_engine = FeatureEngine()
        self.is_training = {}
        self.model_lock = threading.Lock()
        
        # Create storage directory
        import os
        os.makedirs(model_storage_path, exist_ok=True)
        
        # Model factories
        self.model_factories = {
            ModelType.ISOLATION_FOREST: self._create_isolation_forest,
            ModelType.ONE_CLASS_SVM: self._create_one_class_svm,
            ModelType.LOCAL_OUTLIER_FACTOR: self._create_lof,
            ModelType.DBSCAN: self._create_dbscan,
            ModelType.AUTOENCODER: self._create_autoencoder,
            ModelType.RANDOM_FOREST: self._create_random_forest,
            ModelType.GRADIENT_BOOSTING: self._create_gradient_boosting,
            ModelType.NEURAL_NETWORK: self._create_neural_network,
            ModelType.LOGISTIC_REGRESSION: self._create_logistic_regression,
            ModelType.XGBOOST: self._create_xgboost,
            ModelType.LIGHTGBM: self._create_lightgbm,
            ModelType.HMM: self._create_hmm
        }
    
    def create_model(self, config: ModelConfiguration) -> bool:
        """Create and train a new model"""
        try:
            with self.model_lock:
                if config.model_id in self.models:
                    logging.warning(f"Model {config.model_id} already exists")
                    return False
                
                # Create model instance
                model_factory = self.model_factories.get(config.model_type)
                if not model_factory:
                    logging.error(f"Unsupported model type: {config.model_type}")
                    return False
                
                model = model_factory(config.hyperparameters)
                
                self.models[config.model_id] = model
                self.model_configs[config.model_id] = config
                self.is_training[config.model_id] = False
                
                logging.info(f"Model {config.model_id} created successfully")
                return True
                
        except Exception as e:
            logging.error(f"Failed to create model {config.model_id}: {e}")
            return False
    
    async def train_model(self, model_id: str, training_data: pd.DataFrame, labels: Optional[pd.Series] = None) -> bool:
        """Train a model with provided data"""
        if model_id not in self.models:
            logging.error(f"Model {model_id} not found")
            return False
        
        try:
            self.is_training[model_id] = True
            start_time = time.time()
            
            config = self.model_configs[model_id]
            model = self.models[model_id]
            
            # Feature selection
            if config.use_feature_selection and labels is not None:
                selector = SelectKBest(f_classif, k=min(config.feature_selection_k, training_data.shape[1]))
                training_data = pd.DataFrame(
                    selector.fit_transform(training_data, labels),
                    columns=training_data.columns[selector.get_support()]
                )
                
                # Store feature selector
                self.models[f"{model_id}_feature_selector"] = selector
            
            # Handle different model types
            if config.model_type in [ModelType.ISOLATION_FOREST, ModelType.ONE_CLASS_SVM, 
                                   ModelType.LOCAL_OUTLIER_FACTOR, ModelType.DBSCAN]:
                # Unsupervised models
                model.fit(training_data)
            elif config.model_type == ModelType.AUTOENCODER:
                # Deep learning autoencoder
                model.fit(training_data.values, training_data.values, 
                         epochs=config.hyperparameters.get('epochs', 100),
                         batch_size=config.hyperparameters.get('batch_size', 32),
                         validation_split=0.2, verbose=0)
            elif config.model_type == ModelType.HMM:
                # Hidden Markov Model for sequence data
                if 'sequence_data' in training_data.columns:
                    sequences = training_data['sequence_data'].apply(eval).tolist()
                    model.fit(sequences)
                else:
                    logging.error("HMM requires sequence_data column")
                    return False
            else:
                # Supervised models
                if labels is None:
                    logging.error(f"Supervised model {model_id} requires labels")
                    return False
                model.fit(training_data, labels)
            
            # Calculate metrics
            training_time = time.time() - start_time
            metrics = await self._calculate_model_metrics(model_id, training_data, labels, training_time)
            self.model_metrics[model_id] = metrics
            
            # Save model
            await self._save_model(model_id)
            
            logging.info(f"Model {model_id} trained successfully in {training_time:.2f}s")
            return True
            
        except Exception as e:
            logging.error(f"Failed to train model {model_id}: {e}")
            return False
        finally:
            self.is_training[model_id] = False
    
    async def predict_anomaly(self, model_id: str, user_data: Dict[str, Any], context: Dict[str, Any]) -> Optional[AnomalyScore]:
        """Predict anomaly score for given data"""
        if model_id not in self.models:
            logging.error(f"Model {model_id} not found")
            return None
        
        if self.is_training.get(model_id, False):
            logging.warning(f"Model {model_id} is currently training")
            return None
        
        try:
            start_time = time.time()
            
            # Extract features
            features = self.feature_engine.extract_features(user_data, context)
            feature_vector = pd.DataFrame([features])
            
            config = self.model_configs[model_id]
            model = self.models[model_id]
            
            # Apply feature selection if used during training
            selector_key = f"{model_id}_feature_selector"
            if selector_key in self.models:
                feature_vector = pd.DataFrame(
                    self.models[selector_key].transform(feature_vector),
                    columns=feature_vector.columns[self.models[selector_key].get_support()]
                )
            
            # Make prediction based on model type
            score = 0.0
            is_anomaly = False
            confidence = 0.0
            
            if config.model_type == ModelType.ISOLATION_FOREST:
                anomaly_score = model.decision_function(feature_vector)[0]
                score = max(0, -anomaly_score)  # Convert to positive score
                is_anomaly = model.predict(feature_vector)[0] == -1
                confidence = abs(anomaly_score) / 2.0  # Normalize confidence
                
            elif config.model_type == ModelType.ONE_CLASS_SVM:
                anomaly_score = model.decision_function(feature_vector)[0]
                score = max(0, -anomaly_score)
                is_anomaly = model.predict(feature_vector)[0] == -1
                confidence = abs(anomaly_score) / 2.0
                
            elif config.model_type == ModelType.LOCAL_OUTLIER_FACTOR:
                # LOF requires fit_predict for new data
                combined_data = np.vstack([model._fit_X, feature_vector.values])
                lof_scores = model.fit_predict(combined_data)
                score = max(0, 2 - model.negative_outlier_factor_[-1])
                is_anomaly = lof_scores[-1] == -1
                confidence = abs(model.negative_outlier_factor_[-1] - 1)
                
            elif config.model_type == ModelType.AUTOENCODER:
                reconstruction = model.predict(feature_vector.values, verbose=0)
                mse = np.mean((feature_vector.values - reconstruction) ** 2)
                score = min(1.0, mse * 10)  # Scale MSE to 0-1
                threshold = config.hyperparameters.get('anomaly_threshold', 0.5)
                is_anomaly = score > threshold
                confidence = min(1.0, score * 2)
                
            elif config.model_type in [ModelType.RANDOM_FOREST, ModelType.GRADIENT_BOOSTING, 
                                     ModelType.NEURAL_NETWORK, ModelType.LOGISTIC_REGRESSION,
                                     ModelType.XGBOOST, ModelType.LIGHTGBM]:
                # Supervised models - get probability of anomaly class
                try:
                    probabilities = model.predict_proba(feature_vector)[0]
                    score = probabilities[1] if len(probabilities) > 1 else probabilities[0]
                    is_anomaly = score > 0.5
                    confidence = max(probabilities)
                except:
                    # Fallback to decision function
                    score = model.decision_function(feature_vector)[0]
                    score = 1 / (1 + np.exp(-score))  # Sigmoid transformation
                    is_anomaly = score > 0.5
                    confidence = abs(score - 0.5) * 2
            
            # Determine severity
            if score >= 0.8:
                severity = 'critical'
            elif score >= 0.6:
                severity = 'high'
            elif score >= 0.4:
                severity = 'medium'
            else:
                severity = 'low'
            
            # Generate explanation
            explanation = self._generate_explanation(features, config, score)
            
            # Determine anomaly type
            anomaly_type = self._determine_anomaly_type(features, config)
            
            inference_time = (time.time() - start_time) * 1000
            
            return AnomalyScore(
                user_id=user_data.get('user_id', 'unknown'),
                timestamp=context.get('timestamp', datetime.now(timezone.utc)),
                anomaly_type=anomaly_type,
                score=score,
                confidence=confidence,
                model_type=config.model_type,
                model_version=f"{model_id}_v1.0",
                features_used=list(features.keys()),
                feature_values=features,
                explanation=explanation,
                severity=severity,
                threshold=config.hyperparameters.get('anomaly_threshold', 0.5),
                is_anomaly=is_anomaly,
                metadata={'inference_time_ms': inference_time}
            )
            
        except Exception as e:
            logging.error(f"Prediction failed for model {model_id}: {e}")
            return None
    
    async def ensemble_predict(self, model_ids: List[str], user_data: Dict[str, Any], 
                             context: Dict[str, Any], weights: Optional[Dict[str, float]] = None) -> Optional[AnomalyScore]:
        """Ensemble prediction from multiple models"""
        if not model_ids:
            return None
        
        # Get predictions from all models
        predictions = []
        for model_id in model_ids:
            pred = await self.predict_anomaly(model_id, user_data, context)
            if pred:
                predictions.append(pred)
        
        if not predictions:
            return None
        
        # Weight the predictions
        if weights is None:
            weights = {pred.model_version: 1.0 for pred in predictions}
        
        total_weight = sum(weights.get(pred.model_version, 1.0) for pred in predictions)
        
        # Calculate weighted average
        weighted_score = sum(
            pred.score * weights.get(pred.model_version, 1.0) for pred in predictions
        ) / total_weight
        
        weighted_confidence = sum(
            pred.confidence * weights.get(pred.model_version, 1.0) for pred in predictions
        ) / total_weight
        
        # Determine final anomaly decision
        is_anomaly = weighted_score > 0.5
        
        # Combine explanations
        explanations = [pred.explanation for pred in predictions]
        combined_explanation = f"Ensemble of {len(predictions)} models: " + "; ".join(explanations[:3])
        
        # Determine severity
        if weighted_score >= 0.8:
            severity = 'critical'
        elif weighted_score >= 0.6:
            severity = 'high'
        elif weighted_score >= 0.4:
            severity = 'medium'
        else:
            severity = 'low'
        
        return AnomalyScore(
            user_id=user_data.get('user_id', 'unknown'),
            timestamp=context.get('timestamp', datetime.now(timezone.utc)),
            anomaly_type=AnomalyType.COMPOSITE,
            score=weighted_score,
            confidence=weighted_confidence,
            model_type=ModelType.ENSEMBLE,
            model_version="ensemble_v1.0",
            features_used=predictions[0].features_used,  # Use features from first model
            feature_values=predictions[0].feature_values,
            explanation=combined_explanation,
            severity=severity,
            threshold=0.5,
            is_anomaly=is_anomaly,
            metadata={
                'ensemble_size': len(predictions),
                'model_versions': [pred.model_version for pred in predictions],
                'individual_scores': [pred.score for pred in predictions]
            }
        )
    
    def _create_isolation_forest(self, params: Dict[str, Any]):
        """Create Isolation Forest model"""
        return IsolationForest(
            n_estimators=params.get('n_estimators', 100),
            contamination=params.get('contamination', 0.1),
            random_state=params.get('random_state', 42),
            n_jobs=-1
        )
    
    def _create_one_class_svm(self, params: Dict[str, Any]):
        """Create One-Class SVM model"""
        return OneClassSVM(
            kernel=params.get('kernel', 'rbf'),
            gamma=params.get('gamma', 'scale'),
            nu=params.get('nu', 0.1)
        )
    
    def _create_lof(self, params: Dict[str, Any]):
        """Create Local Outlier Factor model"""
        return LocalOutlierFactor(
            n_neighbors=params.get('n_neighbors', 20),
            contamination=params.get('contamination', 0.1),
            novelty=params.get('novelty', True),
            n_jobs=-1
        )
    
    def _create_dbscan(self, params: Dict[str, Any]):
        """Create DBSCAN clustering model"""
        return DBSCAN(
            eps=params.get('eps', 0.5),
            min_samples=params.get('min_samples', 5),
            n_jobs=-1
        )
    
    def _create_autoencoder(self, params: Dict[str, Any]):
        """Create Autoencoder neural network"""
        input_dim = params.get('input_dim', 50)
        hidden_dims = params.get('hidden_dims', [32, 16, 32])
        
        model = keras.Sequential([
            layers.Input(shape=(input_dim,)),
            layers.Dense(hidden_dims[0], activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(hidden_dims[1], activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(hidden_dims[2], activation='relu'),
            layers.Dense(input_dim, activation='linear')
        ])
        
        model.compile(
            optimizer='adam',
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def _create_random_forest(self, params: Dict[str, Any]):
        """Create Random Forest classifier"""
        return RandomForestClassifier(
            n_estimators=params.get('n_estimators', 100),
            max_depth=params.get('max_depth', None),
            min_samples_split=params.get('min_samples_split', 2),
            min_samples_leaf=params.get('min_samples_leaf', 1),
            random_state=params.get('random_state', 42),
            n_jobs=-1
        )
    
    def _create_gradient_boosting(self, params: Dict[str, Any]):
        """Create Gradient Boosting classifier"""
        return GradientBoostingClassifier(
            n_estimators=params.get('n_estimators', 100),
            learning_rate=params.get('learning_rate', 0.1),
            max_depth=params.get('max_depth', 3),
            random_state=params.get('random_state', 42)
        )
    
    def _create_neural_network(self, params: Dict[str, Any]):
        """Create MLP Neural Network classifier"""
        return MLPClassifier(
            hidden_layer_sizes=params.get('hidden_layer_sizes', (100, 50)),
            activation=params.get('activation', 'relu'),
            solver=params.get('solver', 'adam'),
            alpha=params.get('alpha', 0.0001),
            learning_rate=params.get('learning_rate', 'constant'),
            max_iter=params.get('max_iter', 500),
            random_state=params.get('random_state', 42)
        )
    
    def _create_logistic_regression(self, params: Dict[str, Any]):
        """Create Logistic Regression classifier"""
        return LogisticRegression(
            C=params.get('C', 1.0),
            penalty=params.get('penalty', 'l2'),
            solver=params.get('solver', 'liblinear'),
            random_state=params.get('random_state', 42),
            n_jobs=-1
        )
    
    def _create_xgboost(self, params: Dict[str, Any]):
        """Create XGBoost classifier"""
        return xgb.XGBClassifier(
            n_estimators=params.get('n_estimators', 100),
            learning_rate=params.get('learning_rate', 0.1),
            max_depth=params.get('max_depth', 6),
            subsample=params.get('subsample', 1.0),
            colsample_bytree=params.get('colsample_bytree', 1.0),
            random_state=params.get('random_state', 42),
            n_jobs=-1
        )
    
    def _create_lightgbm(self, params: Dict[str, Any]):
        """Create LightGBM classifier"""
        return lgb.LGBMClassifier(
            n_estimators=params.get('n_estimators', 100),
            learning_rate=params.get('learning_rate', 0.1),
            max_depth=params.get('max_depth', -1),
            subsample=params.get('subsample', 1.0),
            colsample_bytree=params.get('colsample_bytree', 1.0),
            random_state=params.get('random_state', 42),
            n_jobs=-1,
            verbose=-1
        )
    
    def _create_hmm(self, params: Dict[str, Any]):
        """Create Hidden Markov Model"""
        return hmm.GaussianHMM(
            n_components=params.get('n_components', 3),
            covariance_type=params.get('covariance_type', 'full'),
            random_state=params.get('random_state', 42)
        )
    
    async def _calculate_model_metrics(self, model_id: str, X: pd.DataFrame, 
                                     y: Optional[pd.Series], training_time: float) -> ModelMetrics:
        """Calculate model performance metrics"""
        config = self.model_configs[model_id]
        model = self.models[model_id]
        
        metrics = ModelMetrics(
            model_id=model_id,
            model_type=config.model_type,
            precision=0.0,
            recall=0.0,
            f1_score=0.0,
            accuracy=0.0,
            training_time=training_time,
            data_points=len(X),
            feature_count=X.shape[1],
            training_date=datetime.now(timezone.utc)
        )
        
        # Calculate metrics based on model type
        if config.model_type in [ModelType.ISOLATION_FOREST, ModelType.ONE_CLASS_SVM]:
            # For unsupervised models, use contamination rate as baseline
            predictions = model.predict(X)
            anomaly_rate = sum(1 for p in predictions if p == -1) / len(predictions)
            metrics.accuracy = 1 - abs(anomaly_rate - config.contamination_rate)
            
        elif y is not None:
            # For supervised models with labels
            if hasattr(model, 'predict'):
                try:
                    predictions = model.predict(X)
                    
                    # Calculate classification metrics
                    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
                    
                    metrics.accuracy = accuracy_score(y, predictions)
                    metrics.precision = precision_score(y, predictions, average='weighted', zero_division=0)
                    metrics.recall = recall_score(y, predictions, average='weighted', zero_division=0)
                    metrics.f1_score = f1_score(y, predictions, average='weighted', zero_division=0)
                    
                    # Calculate AUC-ROC if model supports probability prediction
                    if hasattr(model, 'predict_proba'):
                        try:
                            probabilities = model.predict_proba(X)
                            if probabilities.shape[1] == 2:  # Binary classification
                                metrics.auc_roc = roc_auc_score(y, probabilities[:, 1])
                        except:
                            pass
                    
                    # Calculate error rates
                    confusion = confusion_matrix(y, predictions)
                    if confusion.shape == (2, 2):
                        tn, fp, fn, tp = confusion.ravel()
                        metrics.false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
                        metrics.false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
                        
                except Exception as e:
                    logging.warning(f"Could not calculate detailed metrics for {model_id}: {e}")
        
        return metrics
    
    async def _save_model(self, model_id: str):
        """Save model to disk"""
        try:
            model_path = f"{self.model_storage_path}/{model_id}.pkl"
            config_path = f"{self.model_storage_path}/{model_id}_config.json"
            metrics_path = f"{self.model_storage_path}/{model_id}_metrics.json"
            
            # Save model
            joblib.dump(self.models[model_id], model_path)
            
            # Save configuration
            config_dict = asdict(self.model_configs[model_id])
            # Convert enums to strings for JSON serialization
            config_dict['model_type'] = config_dict['model_type'].value
            config_dict['target_anomaly_types'] = [at.value for at in config_dict['target_anomaly_types']]
            
            with open(config_path, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)
            
            # Save metrics
            if model_id in self.model_metrics:
                metrics_dict = asdict(self.model_metrics[model_id])
                metrics_dict['model_type'] = metrics_dict['model_type'].value
                
                with open(metrics_path, 'w') as f:
                    json.dump(metrics_dict, f, indent=2, default=str)
            
            logging.info(f"Model {model_id} saved successfully")
            
        except Exception as e:
            logging.error(f"Failed to save model {model_id}: {e}")
    
    def _generate_explanation(self, features: Dict[str, float], config: ModelConfiguration, score: float) -> str:
        """Generate human-readable explanation for anomaly score"""
        explanations = []
        
        # Analyze top contributing features
        feature_importance = {}
        
        # Identify unusual patterns
        if features.get('is_new_location', 0) > 0.5:
            explanations.append("accessing from new location")
        
        if features.get('is_off_hours', 0) > 0.5:
            explanations.append("accessing outside business hours")
        
        if features.get('impossible_travel', 0) > 0.5:
            explanations.append("impossible travel detected")
        
        if features.get('is_new_device', 0) > 0.5:
            explanations.append("using new device")
        
        if features.get('failed_login_count', 0) > 5:
            explanations.append("high number of failed login attempts")
        
        if features.get('concurrent_sessions', 1) > 3:
            explanations.append("multiple concurrent sessions")
        
        if features.get('vpn_detected', 0) > 0.5:
            explanations.append("VPN usage detected")
        
        if features.get('anonymization_tools', 0) > 0.5:
            explanations.append("anonymization tools detected")
        
        # Behavioral anomalies
        avg_duration = features.get('avg_session_duration', 0)
        if avg_duration > 14400:  # > 4 hours
            explanations.append("unusually long session duration")
        elif avg_duration < 300:  # < 5 minutes
            explanations.append("unusually short session duration")
        
        # Access patterns
        if features.get('resource_diversity', 0) > 0.8:
            explanations.append("accessing diverse resources")
        
        if features.get('admin_permissions', 0) > 0:
            explanations.append("using administrative permissions")
        
        # Generate final explanation
        if explanations:
            return f"Anomaly detected (score: {score:.2f}): " + ", ".join(explanations[:3])
        else:
            return f"Anomaly detected based on behavioral patterns (score: {score:.2f})"
    
    def _determine_anomaly_type(self, features: Dict[str, float], config: ModelConfiguration) -> AnomalyType:
        """Determine the primary type of anomaly"""
        # Check for different anomaly indicators
        if features.get('impossible_travel', 0) > 0.5 or features.get('is_new_location', 0) > 0.5:
            return AnomalyType.GEOSPATIAL
        
        if features.get('is_off_hours', 0) > 0.5 or features.get('is_weekend', 0) > 0.5:
            return AnomalyType.TEMPORAL
        
        if features.get('is_new_device', 0) > 0.5 or features.get('device_diversity', 0) > 0.8:
            return AnomalyType.DEVICE
        
        if features.get('vpn_detected', 0) > 0.5 or features.get('anonymization_tools', 0) > 0.5:
            return AnomalyType.NETWORK
        
        if features.get('failed_login_count', 0) > 5 or features.get('login_failure_rate', 0) > 0.3:
            return AnomalyType.AUTHENTICATION
        
        if features.get('concurrent_sessions', 1) > 3 or features.get('session_duration_cv', 0) > 2:
            return AnomalyType.SESSION
        
        if features.get('admin_permissions', 0) > 0 or features.get('privileged_roles', 0) > 0:
            return AnomalyType.PRIVILEGE
        
        if features.get('resource_diversity', 0) > 0.8 or features.get('unique_applications', 0) > 10:
            return AnomalyType.ACCESS_PATTERN
        
        return AnomalyType.BEHAVIORAL


class AnomalyDetectionEngine:
    """Main anomaly detection engine orchestrating all ML components"""
    
    def __init__(self, 
                 db_path: str = "anomaly_detection.db",
                 redis_url: str = "redis://localhost:6379",
                 model_storage_path: str = "models/"):
        
        self.db_path = db_path
        self.redis_url = redis_url
        self.model_manager = ModelManager(model_storage_path)
        self.redis_client = None
        self.initialized = False
        
        # Processing statistics
        self.stats = {
            'predictions_made': 0,
            'anomalies_detected': 0,
            'false_positives': 0,
            'models_trained': 0,
            'start_time': datetime.now(timezone.utc)
        }
        
        # Default model configurations
        self.default_configs = self._create_default_configs()
        
        logging.info("Anomaly Detection Engine initialized")
    
    async def initialize(self):
        """Initialize all components"""
        if self.initialized:
            return
        
        # Initialize database
        await self._initialize_database()
        
        # Initialize Redis connection
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logging.info("Redis connection established")
        except Exception as e:
            logging.warning(f"Redis connection failed: {e}")
        
        # Create default models
        await self._create_default_models()
        
        self.initialized = True
        logging.info("Anomaly Detection Engine fully initialized")
    
    async def detect_anomaly(self, user_data: Dict[str, Any], context: Dict[str, Any]) -> List[AnomalyScore]:
        """Detect anomalies using all available models"""
        if not self.initialized:
            await self.initialize()
        
        results = []
        user_id = user_data.get('user_id', 'unknown')
        
        try:
            # Get predictions from all models
            model_ids = list(self.model_manager.models.keys())
            
            # Filter out auxiliary models (feature selectors, etc.)
            primary_models = [mid for mid in model_ids if not mid.endswith('_feature_selector')]
            
            # Run individual model predictions
            for model_id in primary_models:
                prediction = await self.model_manager.predict_anomaly(model_id, user_data, context)
                if prediction:
                    results.append(prediction)
            
            # Run ensemble prediction if multiple models available
            if len(primary_models) > 1:
                ensemble_prediction = await self.model_manager.ensemble_predict(
                    primary_models, user_data, context
                )
                if ensemble_prediction:
                    results.append(ensemble_prediction)
            
            # Store results
            for result in results:
                await self._store_anomaly_result(result)
            
            # Update statistics
            self.stats['predictions_made'] += len(results)
            self.stats['anomalies_detected'] += sum(1 for r in results if r.is_anomaly)
            
            # Cache results
            if self.redis_client:
                await self._cache_results(user_id, results)
            
            logging.debug(f"Anomaly detection completed for user {user_id}: {len(results)} results")
            
            return results
            
        except Exception as e:
            logging.error(f"Anomaly detection failed for user {user_id}: {e}")
            return []
    
    async def train_models(self, training_data: pd.DataFrame, labels: Optional[pd.Series] = None):
        """Train all models with new data"""
        if not self.initialized:
            await self.initialize()
        
        successful_trainings = 0
        
        for model_id in self.model_manager.models.keys():
            if not model_id.endswith('_feature_selector'):
                try:
                    success = await self.model_manager.train_model(model_id, training_data, labels)
                    if success:
                        successful_trainings += 1
                        logging.info(f"Successfully trained model {model_id}")
                    else:
                        logging.error(f"Failed to train model {model_id}")
                except Exception as e:
                    logging.error(f"Training error for model {model_id}: {e}")
        
        self.stats['models_trained'] += successful_trainings
        logging.info(f"Training completed: {successful_trainings} models trained successfully")
        
        return successful_trainings
    
    async def get_user_risk_profile(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive risk profile for a user"""
        if not self.initialized:
            await self.initialize()
        
        try:
            # Get recent anomaly scores
            recent_scores = await self._get_user_anomalies(user_id, days)
            
            if not recent_scores:
                return {
                    'user_id': user_id,
                    'risk_level': 'low',
                    'average_score': 0.0,
                    'anomaly_count': 0,
                    'risk_factors': [],
                    'recommendations': ['Continue normal monitoring']
                }
            
            # Calculate risk metrics
            scores = [score['score'] for score in recent_scores]
            avg_score = np.mean(scores)
            max_score = np.max(scores)
            anomaly_count = sum(1 for score in recent_scores if score['is_anomaly'])
            
            # Determine risk level
            if avg_score >= 0.7 or anomaly_count >= 10:
                risk_level = 'critical'
            elif avg_score >= 0.5 or anomaly_count >= 5:
                risk_level = 'high'
            elif avg_score >= 0.3 or anomaly_count >= 2:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            # Identify risk factors
            risk_factors = []
            anomaly_types = [score['anomaly_type'] for score in recent_scores if score['is_anomaly']]
            
            for anomaly_type in set(anomaly_types):
                count = anomaly_types.count(anomaly_type)
                risk_factors.append(f"{anomaly_type}: {count} occurrences")
            
            # Generate recommendations
            recommendations = self._generate_recommendations(risk_level, risk_factors, recent_scores)
            
            return {
                'user_id': user_id,
                'risk_level': risk_level,
                'average_score': avg_score,
                'max_score': max_score,
                'anomaly_count': anomaly_count,
                'total_events': len(recent_scores),
                'risk_factors': risk_factors,
                'recommendations': recommendations,
                'trend': self._calculate_risk_trend(scores),
                'last_anomaly': max([datetime.fromisoformat(score['timestamp']) for score in recent_scores if score['is_anomaly']], default=None)
            }
            
        except Exception as e:
            logging.error(f"Failed to get risk profile for user {user_id}: {e}")
            return {
                'user_id': user_id,
                'risk_level': 'unknown',
                'error': str(e)
            }
    
    async def get_system_statistics(self) -> Dict[str, Any]:
        """Get system-wide anomaly detection statistics"""
        uptime = datetime.now(timezone.utc) - self.stats['start_time']
        
        # Model statistics
        model_stats = {}
        for model_id, metrics in self.model_manager.model_metrics.items():
            model_stats[model_id] = {
                'type': metrics.model_type.value,
                'accuracy': metrics.accuracy,
                'f1_score': metrics.f1_score,
                'training_time': metrics.training_time,
                'data_points': metrics.data_points
            }
        
        return {
            'uptime_seconds': uptime.total_seconds(),
            'predictions_made': self.stats['predictions_made'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'false_positives': self.stats['false_positives'],
            'models_trained': self.stats['models_trained'],
            'active_models': len(self.model_manager.models),
            'model_statistics': model_stats,
            'detection_accuracy': (
                self.stats['predictions_made'] - self.stats['false_positives']
            ) / max(self.stats['predictions_made'], 1)
        }
    
    def _create_default_configs(self) -> List[ModelConfiguration]:
        """Create default model configurations"""
        configs = []
        
        # Isolation Forest for general anomaly detection
        configs.append(ModelConfiguration(
            model_id="isolation_forest_general",
            model_type=ModelType.ISOLATION_FOREST,
            hyperparameters={
                'n_estimators': 100,
                'contamination': 0.1,
                'random_state': 42
            },
            features=[],  # Will be populated during training
            target_anomaly_types=[AnomalyType.BEHAVIORAL, AnomalyType.ACCESS_PATTERN],
            update_frequency='daily',
            retrain_threshold=0.8
        ))
        
        # One-Class SVM for behavioral analysis
        configs.append(ModelConfiguration(
            model_id="svm_behavioral",
            model_type=ModelType.ONE_CLASS_SVM,
            hyperparameters={
                'kernel': 'rbf',
                'gamma': 'scale',
                'nu': 0.1
            },
            features=[],
            target_anomaly_types=[AnomalyType.BEHAVIORAL, AnomalyType.TEMPORAL],
            update_frequency='daily',
            retrain_threshold=0.8
        ))
        
        # Autoencoder for complex pattern detection
        configs.append(ModelConfiguration(
            model_id="autoencoder_patterns",
            model_type=ModelType.AUTOENCODER,
            hyperparameters={
                'input_dim': 50,
                'hidden_dims': [32, 16, 32],
                'epochs': 100,
                'batch_size': 32,
                'anomaly_threshold': 0.5
            },
            features=[],
            target_anomaly_types=[AnomalyType.BEHAVIORAL, AnomalyType.ACCESS_PATTERN],
            update_frequency='weekly',
            retrain_threshold=0.75
        ))
        
        # Random Forest for supervised detection
        configs.append(ModelConfiguration(
            model_id="random_forest_supervised",
            model_type=ModelType.RANDOM_FOREST,
            hyperparameters={
                'n_estimators': 100,
                'max_depth': 10,
                'random_state': 42
            },
            features=[],
            target_anomaly_types=[AnomalyType.AUTHENTICATION, AnomalyType.PRIVILEGE],
            update_frequency='daily',
            retrain_threshold=0.85
        ))
        
        return configs
    
    async def _create_default_models(self):
        """Create default models"""
        for config in self.default_configs:
            success = self.model_manager.create_model(config)
            if success:
                logging.info(f"Created default model: {config.model_id}")
            else:
                logging.error(f"Failed to create default model: {config.model_id}")
    
    async def _initialize_database(self):
        """Initialize SQLite database for storing results"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    anomaly_type TEXT NOT NULL,
                    score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    model_type TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    is_anomaly BOOLEAN NOT NULL,
                    severity TEXT NOT NULL,
                    explanation TEXT,
                    features_used TEXT,
                    feature_values TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomaly_user_timestamp 
                ON anomaly_scores(user_id, timestamp)
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomaly_score 
                ON anomaly_scores(score)
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomaly_type 
                ON anomaly_scores(anomaly_type)
            """)
            
            await db.commit()
        
        logging.info("Anomaly detection database initialized")
    
    async def _store_anomaly_result(self, result: AnomalyScore):
        """Store anomaly detection result in database"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO anomaly_scores (
                        user_id, timestamp, anomaly_type, score, confidence,
                        model_type, model_version, is_anomaly, severity,
                        explanation, features_used, feature_values, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.user_id,
                    result.timestamp.isoformat(),
                    result.anomaly_type.value,
                    result.score,
                    result.confidence,
                    result.model_type.value,
                    result.model_version,
                    result.is_anomaly,
                    result.severity,
                    result.explanation,
                    json.dumps(result.features_used),
                    json.dumps(result.feature_values),
                    json.dumps(result.metadata) if result.metadata else None
                ))
                await db.commit()
        except Exception as e:
            logging.error(f"Failed to store anomaly result: {e}")
    
    async def _get_user_anomalies(self, user_id: str, days: int) -> List[Dict[str, Any]]:
        """Get user's anomaly scores from the last N days"""
        try:
            cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("""
                    SELECT user_id, timestamp, anomaly_type, score, confidence,
                           is_anomaly, severity, explanation
                    FROM anomaly_scores
                    WHERE user_id = ? AND timestamp >= ?
                    ORDER BY timestamp DESC
                """, (user_id, cutoff_date)) as cursor:
                    rows = await cursor.fetchall()
                    
                    return [
                        {
                            'user_id': row[0],
                            'timestamp': row[1],
                            'anomaly_type': row[2],
                            'score': row[3],
                            'confidence': row[4],
                            'is_anomaly': bool(row[5]),
                            'severity': row[6],
                            'explanation': row[7]
                        }
                        for row in rows
                    ]
        except Exception as e:
            logging.error(f"Failed to get user anomalies: {e}")
            return []
    
    async def _cache_results(self, user_id: str, results: List[AnomalyScore]):
        """Cache results in Redis"""
        if not self.redis_client:
            return
        
        try:
            # Cache latest results for user
            cache_key = f"anomaly_results:{user_id}"
            cache_data = [asdict(result) for result in results]
            
            # Convert datetime objects to strings
            for result_dict in cache_data:
                for key, value in result_dict.items():
                    if isinstance(value, datetime):
                        result_dict[key] = value.isoformat()
                    elif hasattr(value, 'value'):  # Enum
                        result_dict[key] = value.value
            
            await self.redis_client.setex(
                cache_key,
                3600,  # 1 hour TTL
                json.dumps(cache_data, default=str)
            )
            
            # Update user's anomaly count
            anomaly_count = sum(1 for r in results if r.is_anomaly)
            if anomaly_count > 0:
                await self.redis_client.hincrby("user_anomaly_counts", user_id, anomaly_count)
            
        except Exception as e:
            logging.error(f"Failed to cache results: {e}")
    
    def _generate_recommendations(self, risk_level: str, risk_factors: List[str], 
                                recent_scores: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on risk profile"""
        recommendations = []
        
        if risk_level == 'critical':
            recommendations.extend([
                "Immediately review all recent access activities",
                "Consider temporarily restricting account privileges",
                "Enforce multi-factor authentication for all access",
                "Conduct thorough security investigation"
            ])
        elif risk_level == 'high':
            recommendations.extend([
                "Increase monitoring frequency for this user",
                "Review recent privilege changes",
                "Verify identity through additional authentication",
                "Notify security team for further analysis"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Monitor user activity more closely",
                "Review access patterns for unusual behavior",
                "Consider periodic identity verification"
            ])
        else:
            recommendations.extend([
                "Continue normal monitoring",
                "Maintain current security policies"
            ])
        
        # Add specific recommendations based on risk factors
        for factor in risk_factors:
            if 'geospatial' in factor.lower():
                recommendations.append("Verify geographic access patterns")
            elif 'device' in factor.lower():
                recommendations.append("Review device registration and trust status")
            elif 'temporal' in factor.lower():
                recommendations.append("Review off-hours access policies")
            elif 'authentication' in factor.lower():
                recommendations.append("Strengthen authentication requirements")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _calculate_risk_trend(self, scores: List[float]) -> str:
        """Calculate risk trend direction"""
        if len(scores) < 2:
            return 'stable'
        
        # Compare recent scores to older scores
        half_point = len(scores) // 2
        recent_avg = np.mean(scores[:half_point])
        older_avg = np.mean(scores[half_point:])
        
        diff = recent_avg - older_avg
        
        if diff > 0.1:
            return 'increasing'
        elif diff < -0.1:
            return 'decreasing'
        else:
            return 'stable'
    
    async def shutdown(self):
        """Gracefully shutdown the engine"""
        logging.info("Shutting down Anomaly Detection Engine")
        
        if self.redis_client:
            await self.redis_client.close()
        
        logging.info("Anomaly Detection Engine shutdown complete")


# Example usage and testing
async def example_usage():
    """Example usage of the Anomaly Detection Engine"""
    
    # Initialize engine
    engine = AnomalyDetectionEngine(
        db_path="test_anomaly_detection.db",
        redis_url="redis://localhost:6379",
        model_storage_path="test_models/"
    )
    
    await engine.initialize()
    
    # Create sample user data
    user_data = {
        'user_id': 'user123',
        'login_history': [
            (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()
            for i in range(30)
        ],
        'location_history': [
            {
                'country': 'US',
                'city': 'New York',
                'latitude': 40.7128,
                'longitude': -74.0060,
                'timestamp': (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()
            }
            for i in range(10)
        ],
        'device_history': [
            {
                'device_id': 'device123',
                'os': 'Windows',
                'browser': 'Chrome'
            }
        ],
        'accessed_resources': ['dashboard', 'reports', 'settings'],
        'session_durations': [3600, 7200, 1800, 5400],
        'failed_login_count': 2,
        'successful_login_count': 28
    }
    
    # Create context for current access
    context = {
        'timestamp': datetime.now(timezone.utc),
        'source_ip': '192.168.1.100',
        'country': 'US',
        'city': 'New York',
        'latitude': 40.7128,
        'longitude': -74.0060,
        'device_id': 'device123',
        'os': 'Windows',
        'browser': 'Chrome',
        'session_id': 'session123',
        'vpn_detected': False,
        'is_mobile': False,
        'is_trusted': True
    }
    
    # Detect anomalies
    anomaly_results = await engine.detect_anomaly(user_data, context)
    
    print(f"Detected {len(anomaly_results)} potential anomalies:")
    for result in anomaly_results:
        print(f"- {result.model_type.value}: Score {result.score:.3f}, "
              f"{'ANOMALY' if result.is_anomaly else 'NORMAL'} - {result.explanation}")
    
    # Get user risk profile
    risk_profile = await engine.get_user_risk_profile('user123')
    print(f"\nUser Risk Profile:")
    print(f"Risk Level: {risk_profile['risk_level']}")
    print(f"Average Score: {risk_profile['average_score']:.3f}")
    print(f"Recommendations: {risk_profile['recommendations']}")
    
    # Get system statistics
    stats = await engine.get_system_statistics()
    print(f"\nSystem Statistics:")
    print(f"Predictions Made: {stats['predictions_made']}")
    print(f"Anomalies Detected: {stats['anomalies_detected']}")
    print(f"Active Models: {stats['active_models']}")
    
    await engine.shutdown()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run example
    asyncio.run(example_usage())