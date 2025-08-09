#!/usr/bin/env python3
# iSECTECH Anomaly Detection Engine
# Production-grade anomaly and behavioral detection system

import json
import yaml
import asyncio
import aioredis
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import re
import hashlib
import pickle
import sqlite3
from collections import defaultdict, deque
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess
import psutil
import socket
import struct
import statistics
from scipy import stats
import joblib

# Machine Learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
from sklearn.neighbors import LocalOutlierFactor
import tensorflow as tf
from tensorflow.keras import Sequential, layers
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/anomaly-detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class NetworkFlow:
    """Represents a network flow for analysis"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration: float
    flags: Set[str] = None
    application: Optional[str] = None
    user: Optional[str] = None
    
@dataclass
class BaselineMetrics:
    """Baseline metrics for normal behavior"""
    metric_name: str
    mean_value: float
    std_deviation: float
    median_value: float
    percentile_95: float
    percentile_99: float
    min_value: float
    max_value: float
    sample_count: int
    last_updated: datetime
    confidence_interval: Tuple[float, float]
    
@dataclass
class AnomalyAlert:
    """Represents an anomaly detection alert"""
    alert_id: str
    timestamp: datetime
    anomaly_type: str  # 'statistical', 'behavioral', 'clustering', 'ml'
    entity: str  # IP, user, service, etc.
    entity_type: str  # 'host', 'user', 'service', 'network'
    anomaly_score: float
    confidence: float
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    baseline_deviation: float
    supporting_evidence: Dict[str, Any]
    mitre_tactics: List[str] = None
    recommended_actions: List[str] = None

class NetworkBaselineEngine:
    """Establishes and maintains baselines for normal network behavior"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_path = "/var/lib/nsm/baselines.db"
        self.baselines: Dict[str, BaselineMetrics] = {}
        self._init_database()
        
        # Baseline categories
        self.baseline_categories = {
            'traffic_volume': ['bytes_per_hour', 'packets_per_hour', 'flows_per_hour'],
            'communication_patterns': ['unique_destinations', 'unique_sources', 'port_diversity'],
            'protocol_distribution': ['tcp_ratio', 'udp_ratio', 'icmp_ratio', 'dns_ratio'],
            'temporal_patterns': ['hourly_traffic', 'daily_traffic', 'weekly_patterns'],
            'service_behavior': ['service_response_time', 'service_availability', 'service_errors']
        }
        
        # Historical data buffer
        self.historical_data = defaultdict(deque)
        self.max_history_size = 10000
        
    def _init_database(self):
        """Initialize baseline tracking database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    metric_name TEXT PRIMARY KEY,
                    mean_value REAL,
                    std_deviation REAL,
                    median_value REAL,
                    percentile_95 REAL,
                    percentile_99 REAL,
                    min_value REAL,
                    max_value REAL,
                    sample_count INTEGER,
                    last_updated TIMESTAMP,
                    confidence_lower REAL,
                    confidence_upper REAL,
                    baseline_data TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS historical_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    metric_name TEXT,
                    metric_value REAL,
                    entity_id TEXT,
                    metadata TEXT
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_historical_timestamp ON historical_metrics(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_historical_metric ON historical_metrics(metric_name)")
    
    def calculate_baseline_metrics(self, data: List[float], metric_name: str) -> BaselineMetrics:
        """Calculate baseline statistics for a metric"""
        if not data:
            raise ValueError("No data provided for baseline calculation")
        
        np_data = np.array(data)
        
        # Basic statistics
        mean_val = np.mean(np_data)
        std_val = np.std(np_data)
        median_val = np.median(np_data)
        
        # Percentiles
        p95 = np.percentile(np_data, 95)
        p99 = np.percentile(np_data, 99)
        min_val = np.min(np_data)
        max_val = np.max(np_data)
        
        # Confidence interval (95%)
        confidence_level = 0.95
        alpha = 1 - confidence_level
        df = len(data) - 1
        t_critical = stats.t.ppf(1 - alpha/2, df)
        margin_error = t_critical * (std_val / np.sqrt(len(data)))
        confidence_interval = (mean_val - margin_error, mean_val + margin_error)
        
        return BaselineMetrics(
            metric_name=metric_name,
            mean_value=mean_val,
            std_deviation=std_val,
            median_value=median_val,
            percentile_95=p95,
            percentile_99=p99,
            min_value=min_val,
            max_value=max_val,
            sample_count=len(data),
            last_updated=datetime.now(),
            confidence_interval=confidence_interval
        )
    
    def update_baseline(self, metric_name: str, value: float, entity_id: str = None):
        """Update baseline with new data point"""
        # Add to historical data
        self.historical_data[metric_name].append({
            'timestamp': datetime.now(),
            'value': value,
            'entity_id': entity_id
        })
        
        # Maintain buffer size
        if len(self.historical_data[metric_name]) > self.max_history_size:
            self.historical_data[metric_name].popleft()
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO historical_metrics 
                (timestamp, metric_name, metric_value, entity_id)
                VALUES (?, ?, ?, ?)
            """, (datetime.now(), metric_name, value, entity_id))
    
    def recalculate_baselines(self):
        """Recalculate all baselines from historical data"""
        logger.info("Recalculating network baselines")
        
        for metric_name, data_points in self.historical_data.items():
            if len(data_points) < self.config.get('min_baseline_samples', 100):
                logger.warning(f"Insufficient data for baseline {metric_name}: {len(data_points)} samples")
                continue
            
            values = [point['value'] for point in data_points]
            baseline = self.calculate_baseline_metrics(values, metric_name)
            self.baselines[metric_name] = baseline
            
            # Store in database
            self._store_baseline(baseline)
    
    def _store_baseline(self, baseline: BaselineMetrics):
        """Store baseline in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO baselines 
                (metric_name, mean_value, std_deviation, median_value, 
                 percentile_95, percentile_99, min_value, max_value, 
                 sample_count, last_updated, confidence_lower, confidence_upper)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                baseline.metric_name,
                baseline.mean_value,
                baseline.std_deviation,
                baseline.median_value,
                baseline.percentile_95,
                baseline.percentile_99,
                baseline.min_value,
                baseline.max_value,
                baseline.sample_count,
                baseline.last_updated,
                baseline.confidence_interval[0],
                baseline.confidence_interval[1]
            ))
    
    def get_baseline(self, metric_name: str) -> Optional[BaselineMetrics]:
        """Get baseline for a metric"""
        if metric_name in self.baselines:
            return self.baselines[metric_name]
        
        # Try loading from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM baselines WHERE metric_name = ?
            """, (metric_name,))
            
            row = cursor.fetchone()
            if row:
                baseline = BaselineMetrics(
                    metric_name=row[0],
                    mean_value=row[1],
                    std_deviation=row[2],
                    median_value=row[3],
                    percentile_95=row[4],
                    percentile_99=row[5],
                    min_value=row[6],
                    max_value=row[7],
                    sample_count=row[8],
                    last_updated=datetime.fromisoformat(row[9]),
                    confidence_interval=(row[10], row[11])
                )
                self.baselines[metric_name] = baseline
                return baseline
        
        return None
    
    def is_anomalous(self, metric_name: str, value: float, threshold_sigma: float = 3.0) -> Tuple[bool, float]:
        """Check if a value is anomalous based on baseline"""
        baseline = self.get_baseline(metric_name)
        if not baseline:
            return False, 0.0
        
        # Z-score calculation
        z_score = abs(value - baseline.mean_value) / baseline.std_deviation if baseline.std_deviation > 0 else 0
        
        # Check if beyond threshold
        is_anomaly = z_score > threshold_sigma
        
        return is_anomaly, z_score

class StatisticalAnomalyDetector:
    """Statistical methods for anomaly detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.detection_methods = {
            'zscore': self._zscore_detection,
            'iqr': self._iqr_detection,
            'grubbs': self._grubbs_test,
            'mad': self._mad_detection,
            'percentile': self._percentile_detection
        }
    
    def _zscore_detection(self, data: np.ndarray, threshold: float = 3.0) -> List[int]:
        """Z-score based anomaly detection"""
        z_scores = np.abs(stats.zscore(data))
        return np.where(z_scores > threshold)[0].tolist()
    
    def _iqr_detection(self, data: np.ndarray, k: float = 1.5) -> List[int]:
        """Interquartile Range (IQR) based detection"""
        Q1 = np.percentile(data, 25)
        Q3 = np.percentile(data, 75)
        IQR = Q3 - Q1
        
        lower_bound = Q1 - k * IQR
        upper_bound = Q3 + k * IQR
        
        return np.where((data < lower_bound) | (data > upper_bound))[0].tolist()
    
    def _grubbs_test(self, data: np.ndarray, alpha: float = 0.05) -> List[int]:
        """Grubbs test for outliers"""
        outliers = []
        data_copy = data.copy()
        
        while len(data_copy) > 3:
            mean = np.mean(data_copy)
            std = np.std(data_copy)
            
            # Calculate Grubbs statistic
            grubbs_stats = np.abs(data_copy - mean) / std
            max_grubbs = np.max(grubbs_stats)
            max_idx = np.argmax(grubbs_stats)
            
            # Critical value
            n = len(data_copy)
            t_critical = stats.t.ppf(1 - alpha / (2 * n), n - 2)
            critical_value = ((n - 1) / np.sqrt(n)) * np.sqrt(t_critical**2 / (n - 2 + t_critical**2))
            
            if max_grubbs > critical_value:
                # Find original index
                orig_idx = np.where(data == data_copy[max_idx])[0][0]
                outliers.append(orig_idx)
                data_copy = np.delete(data_copy, max_idx)
            else:
                break
        
        return outliers
    
    def _mad_detection(self, data: np.ndarray, threshold: float = 3.5) -> List[int]:
        """Median Absolute Deviation (MAD) based detection"""
        median = np.median(data)
        mad = np.median(np.abs(data - median))
        
        if mad == 0:
            return []
        
        modified_z_scores = 0.6745 * (data - median) / mad
        return np.where(np.abs(modified_z_scores) > threshold)[0].tolist()
    
    def _percentile_detection(self, data: np.ndarray, lower_percentile: float = 1, upper_percentile: float = 99) -> List[int]:
        """Percentile-based outlier detection"""
        lower_bound = np.percentile(data, lower_percentile)
        upper_bound = np.percentile(data, upper_percentile)
        
        return np.where((data < lower_bound) | (data > upper_bound))[0].tolist()
    
    def detect_anomalies(self, data: np.ndarray, method: str = 'zscore', **kwargs) -> List[int]:
        """Detect anomalies using specified method"""
        if method not in self.detection_methods:
            raise ValueError(f"Unknown detection method: {method}")
        
        return self.detection_methods[method](data, **kwargs)
    
    def ensemble_detection(self, data: np.ndarray, methods: List[str] = None, consensus_threshold: int = 2) -> List[int]:
        """Ensemble anomaly detection using multiple methods"""
        if methods is None:
            methods = ['zscore', 'iqr', 'mad']
        
        all_outliers = defaultdict(int)
        
        for method in methods:
            try:
                outliers = self.detect_anomalies(data, method)
                for outlier_idx in outliers:
                    all_outliers[outlier_idx] += 1
            except Exception as e:
                logger.warning(f"Error in {method} detection: {e}")
        
        # Return indices that were detected by at least 'consensus_threshold' methods
        return [idx for idx, count in all_outliers.items() if count >= consensus_threshold]

class MachineLearningBehavioralAnalyzer:
    """Machine learning-based behavioral analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models_dir = Path("/var/lib/nsm/models/behavioral")
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize models
        self.isolation_forest = None
        self.local_outlier_factor = None
        self.autoencoder = None
        self.clustering_model = None
        self.scaler = StandardScaler()
        
        self._load_or_initialize_models()
    
    def _load_or_initialize_models(self):
        """Load existing models or initialize new ones"""
        # Isolation Forest
        isolation_path = self.models_dir / "isolation_forest.pkl"
        if isolation_path.exists():
            self.isolation_forest = joblib.load(isolation_path)
        else:
            self.isolation_forest = IsolationForest(
                contamination=self.config.get('contamination_rate', 0.1),
                random_state=42,
                n_estimators=200
            )
        
        # Local Outlier Factor
        self.local_outlier_factor = LocalOutlierFactor(
            n_neighbors=self.config.get('lof_neighbors', 20),
            contamination=self.config.get('contamination_rate', 0.1)
        )
        
        # DBSCAN for clustering
        self.clustering_model = DBSCAN(
            eps=self.config.get('dbscan_eps', 0.5),
            min_samples=self.config.get('dbscan_min_samples', 5)
        )
        
        # Autoencoder for anomaly detection
        self._build_autoencoder()
    
    def _build_autoencoder(self):
        """Build autoencoder neural network for anomaly detection"""
        input_dim = self.config.get('autoencoder_input_dim', 20)
        encoding_dim = self.config.get('autoencoder_encoding_dim', 10)
        
        self.autoencoder = Sequential([
            layers.Dense(encoding_dim * 2, activation='relu', input_shape=(input_dim,)),
            layers.Dense(encoding_dim, activation='relu'),
            layers.Dense(encoding_dim * 2, activation='relu'),
            layers.Dense(input_dim, activation='sigmoid')
        ])
        
        self.autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae'])
    
    def extract_behavioral_features(self, flows: List[NetworkFlow]) -> np.ndarray:
        """Extract behavioral features from network flows"""
        if not flows:
            return np.array([])
        
        features = []
        
        for flow in flows:
            flow_features = [
                flow.bytes_sent,
                flow.bytes_received,
                flow.packets_sent,
                flow.packets_received,
                flow.duration,
                flow.source_port,
                flow.destination_port,
                len(flow.flags) if flow.flags else 0,
                # Protocol encoding
                1 if flow.protocol == 'tcp' else 0,
                1 if flow.protocol == 'udp' else 0,
                1 if flow.protocol == 'icmp' else 0,
                # Time-based features
                flow.timestamp.hour,
                flow.timestamp.weekday(),
                # Derived features
                flow.bytes_sent / max(flow.packets_sent, 1),  # Avg bytes per packet sent
                flow.bytes_received / max(flow.packets_received, 1),  # Avg bytes per packet received
                flow.bytes_sent / max(flow.duration, 0.001),  # Bytes per second sent
                flow.bytes_received / max(flow.duration, 0.001),  # Bytes per second received
                (flow.bytes_sent + flow.bytes_received) / max(flow.duration, 0.001),  # Total throughput
                flow.packets_sent / max(flow.duration, 0.001),  # Packets per second sent
                flow.packets_received / max(flow.duration, 0.001)  # Packets per second received
            ]
            
            features.append(flow_features)
        
        return np.array(features)
    
    def detect_isolation_forest_anomalies(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using Isolation Forest"""
        if features.shape[0] == 0:
            return np.array([]), np.array([])
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Fit and predict
        anomaly_labels = self.isolation_forest.fit_predict(features_scaled)
        anomaly_scores = self.isolation_forest.decision_function(features_scaled)
        
        return anomaly_labels, anomaly_scores
    
    def detect_lof_anomalies(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using Local Outlier Factor"""
        if features.shape[0] == 0:
            return np.array([]), np.array([])
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Fit and predict
        anomaly_labels = self.local_outlier_factor.fit_predict(features_scaled)
        anomaly_scores = self.local_outlier_factor.negative_outlier_factor_
        
        return anomaly_labels, anomaly_scores
    
    def detect_autoencoder_anomalies(self, features: np.ndarray, threshold_percentile: float = 95) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using autoencoder reconstruction error"""
        if features.shape[0] == 0:
            return np.array([]), np.array([])
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train autoencoder if not trained
        if not hasattr(self.autoencoder, 'history'):
            self.autoencoder.fit(
                features_scaled, features_scaled,
                epochs=self.config.get('autoencoder_epochs', 100),
                batch_size=self.config.get('autoencoder_batch_size', 32),
                validation_split=0.2,
                verbose=0
            )
        
        # Calculate reconstruction error
        reconstructed = self.autoencoder.predict(features_scaled, verbose=0)
        reconstruction_errors = np.mean(np.square(features_scaled - reconstructed), axis=1)
        
        # Determine threshold
        threshold = np.percentile(reconstruction_errors, threshold_percentile)
        
        # Classify anomalies
        anomaly_labels = (reconstruction_errors > threshold).astype(int)
        anomaly_labels[anomaly_labels == 0] = -1  # Convert to -1/1 format
        
        return anomaly_labels, reconstruction_errors
    
    def perform_behavioral_clustering(self, features: np.ndarray) -> Dict[str, Any]:
        """Perform clustering analysis to identify behavioral groups"""
        if features.shape[0] == 0:
            return {}
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # DBSCAN clustering
        cluster_labels = self.clustering_model.fit_predict(features_scaled)
        
        # Calculate cluster statistics
        unique_labels = set(cluster_labels)
        n_clusters = len(unique_labels) - (1 if -1 in cluster_labels else 0)
        n_noise_points = list(cluster_labels).count(-1)
        
        # Silhouette score (if we have more than one cluster)
        silhouette_avg = 0
        if n_clusters > 1:
            silhouette_avg = silhouette_score(features_scaled, cluster_labels)
        
        return {
            'cluster_labels': cluster_labels,
            'n_clusters': n_clusters,
            'n_noise_points': n_noise_points,
            'silhouette_score': silhouette_avg,
            'cluster_centers': self._calculate_cluster_centers(features_scaled, cluster_labels)
        }
    
    def _calculate_cluster_centers(self, features: np.ndarray, labels: np.ndarray) -> Dict[int, np.ndarray]:
        """Calculate cluster centers"""
        centers = {}
        for label in set(labels):
            if label != -1:  # Ignore noise points
                mask = labels == label
                centers[label] = np.mean(features[mask], axis=0)
        return centers
    
    def save_models(self):
        """Save trained models"""
        joblib.dump(self.isolation_forest, self.models_dir / "isolation_forest.pkl")
        joblib.dump(self.scaler, self.models_dir / "scaler.pkl")
        
        if hasattr(self.autoencoder, 'history'):
            self.autoencoder.save(self.models_dir / "autoencoder.h5")

class UserEntityBehaviorAnalytics:
    """User and Entity Behavior Analytics (UEBA)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_path = "/var/lib/nsm/ueba.db"
        self.user_profiles = {}
        self.entity_profiles = {}
        self._init_database()
    
    def _init_database(self):
        """Initialize UEBA database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id TEXT PRIMARY KEY,
                    profile_data TEXT,
                    last_updated TIMESTAMP,
                    risk_score REAL,
                    behavior_model TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entity_profiles (
                    entity_id TEXT PRIMARY KEY,
                    entity_type TEXT,
                    profile_data TEXT,
                    last_updated TIMESTAMP,
                    risk_score REAL,
                    behavior_model TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS behavioral_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    entity_id TEXT,
                    entity_type TEXT,
                    event_type TEXT,
                    anomaly_score REAL,
                    risk_increase REAL,
                    details TEXT
                )
            """)
    
    def build_user_profile(self, user_id: str, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Build behavioral profile for a user"""
        if not flows:
            return {}
        
        profile = {
            'user_id': user_id,
            'total_flows': len(flows),
            'time_patterns': self._analyze_time_patterns(flows),
            'communication_patterns': self._analyze_communication_patterns(flows),
            'data_patterns': self._analyze_data_patterns(flows),
            'protocol_patterns': self._analyze_protocol_patterns(flows),
            'anomaly_indicators': [],
            'risk_factors': [],
            'peer_group': None
        }
        
        return profile
    
    def _analyze_time_patterns(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze temporal behavior patterns"""
        hours = [flow.timestamp.hour for flow in flows]
        weekdays = [flow.timestamp.weekday() for flow in flows]
        
        return {
            'active_hours': {
                'mean': statistics.mean(hours),
                'std': statistics.stdev(hours) if len(hours) > 1 else 0,
                'distribution': dict(zip(*np.unique(hours, return_counts=True)))
            },
            'active_weekdays': {
                'distribution': dict(zip(*np.unique(weekdays, return_counts=True)))
            },
            'session_duration': {
                'mean': statistics.mean([flow.duration for flow in flows]),
                'std': statistics.stdev([flow.duration for flow in flows]) if len(flows) > 1 else 0
            }
        }
    
    def _analyze_communication_patterns(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze communication behavior patterns"""
        destinations = [flow.destination_ip for flow in flows]
        ports = [flow.destination_port for flow in flows]
        
        return {
            'unique_destinations': len(set(destinations)),
            'top_destinations': dict(zip(*np.unique(destinations, return_counts=True))),
            'port_usage': dict(zip(*np.unique(ports, return_counts=True))),
            'communication_diversity': len(set(destinations)) / len(flows) if flows else 0
        }
    
    def _analyze_data_patterns(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze data transfer patterns"""
        bytes_sent = [flow.bytes_sent for flow in flows]
        bytes_received = [flow.bytes_received for flow in flows]
        
        return {
            'data_sent': {
                'total': sum(bytes_sent),
                'mean': statistics.mean(bytes_sent),
                'std': statistics.stdev(bytes_sent) if len(bytes_sent) > 1 else 0
            },
            'data_received': {
                'total': sum(bytes_received),
                'mean': statistics.mean(bytes_received),
                'std': statistics.stdev(bytes_received) if len(bytes_received) > 1 else 0
            },
            'transfer_ratio': sum(bytes_sent) / max(sum(bytes_received), 1)
        }
    
    def _analyze_protocol_patterns(self, flows: List[NetworkFlow]) -> Dict[str, Any]:
        """Analyze protocol usage patterns"""
        protocols = [flow.protocol for flow in flows]
        
        return {
            'protocol_distribution': dict(zip(*np.unique(protocols, return_counts=True))),
            'protocol_diversity': len(set(protocols))
        }
    
    def calculate_anomaly_score(self, current_profile: Dict[str, Any], baseline_profile: Dict[str, Any]) -> float:
        """Calculate anomaly score based on profile deviation"""
        score = 0.0
        
        # Time pattern anomalies
        if 'time_patterns' in both_profiles:
            time_deviation = self._compare_time_patterns(
                current_profile['time_patterns'],
                baseline_profile['time_patterns']
            )
            score += time_deviation * 0.25
        
        # Communication pattern anomalies
        if 'communication_patterns' in both_profiles:
            comm_deviation = self._compare_communication_patterns(
                current_profile['communication_patterns'],
                baseline_profile['communication_patterns']
            )
            score += comm_deviation * 0.35
        
        # Data pattern anomalies
        if 'data_patterns' in both_profiles:
            data_deviation = self._compare_data_patterns(
                current_profile['data_patterns'],
                baseline_profile['data_patterns']
            )
            score += data_deviation * 0.25
        
        # Protocol pattern anomalies
        if 'protocol_patterns' in both_profiles:
            protocol_deviation = self._compare_protocol_patterns(
                current_profile['protocol_patterns'],
                baseline_profile['protocol_patterns']
            )
            score += protocol_deviation * 0.15
        
        return min(1.0, score)
    
    def _compare_time_patterns(self, current: Dict, baseline: Dict) -> float:
        """Compare time patterns and return deviation score"""
        deviation = 0.0
        
        # Compare active hours
        if 'active_hours' in both_patterns:
            hour_diff = abs(current['active_hours']['mean'] - baseline['active_hours']['mean'])
            deviation += min(1.0, hour_diff / 12.0)  # Normalize by 12 hours
        
        return deviation
    
    def _compare_communication_patterns(self, current: Dict, baseline: Dict) -> float:
        """Compare communication patterns and return deviation score"""
        deviation = 0.0
        
        # Compare destination diversity
        if 'unique_destinations' in both_patterns:
            current_diversity = current['communication_diversity']
            baseline_diversity = baseline['communication_diversity']
            deviation += abs(current_diversity - baseline_diversity)
        
        return min(1.0, deviation)
    
    def _compare_data_patterns(self, current: Dict, baseline: Dict) -> float:
        """Compare data transfer patterns and return deviation score"""
        deviation = 0.0
        
        # Compare data volumes
        if 'data_sent' in both_patterns:
            current_sent = current['data_sent']['mean']
            baseline_sent = baseline['data_sent']['mean']
            if baseline_sent > 0:
                sent_ratio = abs(current_sent - baseline_sent) / baseline_sent
                deviation += min(1.0, sent_ratio)
        
        return min(1.0, deviation)
    
    def _compare_protocol_patterns(self, current: Dict, baseline: Dict) -> float:
        """Compare protocol usage patterns and return deviation score"""
        deviation = 0.0
        
        # Compare protocol diversity
        if 'protocol_diversity' in both_patterns:
            diversity_diff = abs(current['protocol_diversity'] - baseline['protocol_diversity'])
            deviation += min(1.0, diversity_diff / 10.0)  # Normalize
        
        return deviation

class AnomalyDetectionEngine:
    """Main anomaly detection engine orchestrating all components"""
    
    def __init__(self, config_path: str = "/etc/nsm/anomaly-detection.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.baseline_engine = NetworkBaselineEngine(self.config.get('baseline', {}))
        self.statistical_detector = StatisticalAnomalyDetector(self.config.get('statistical', {}))
        self.ml_analyzer = MachineLearningBehavioralAnalyzer(self.config.get('ml', {}))
        self.ueba = UserEntityBehaviorAnalytics(self.config.get('ueba', {}))
        
        # Redis for real-time data
        self.redis_client = None
        
        # Alert storage
        self.db_path = "/var/lib/nsm/anomaly_alerts.db"
        self._init_database()
        
        # Processing state
        self.is_running = False
        self.processing_queue = asyncio.Queue(maxsize=10000)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {self.config_path} not found, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 3
            },
            'baseline': {
                'min_baseline_samples': 100,
                'update_frequency': 3600
            },
            'statistical': {
                'threshold_sigma': 3.0,
                'methods': ['zscore', 'iqr', 'mad']
            },
            'ml': {
                'contamination_rate': 0.1,
                'autoencoder_epochs': 100,
                'model_update_frequency': 86400
            },
            'ueba': {
                'profile_update_frequency': 3600,
                'risk_threshold': 0.7
            },
            'alerting': {
                'min_confidence': 0.6,
                'severity_thresholds': {
                    'low': 0.3,
                    'medium': 0.5,
                    'high': 0.7,
                    'critical': 0.9
                }
            }
        }
    
    def _init_database(self):
        """Initialize anomaly alerts database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP,
                    anomaly_type TEXT,
                    entity TEXT,
                    entity_type TEXT,
                    anomaly_score REAL,
                    confidence REAL,
                    severity TEXT,
                    description TEXT,
                    baseline_deviation REAL,
                    supporting_evidence TEXT,
                    mitre_tactics TEXT,
                    recommended_actions TEXT,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    resolved BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON anomaly_alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON anomaly_alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_entity ON anomaly_alerts(entity)")
    
    async def initialize_redis(self):
        """Initialize Redis connection"""
        redis_config = self.config.get('redis', {})
        self.redis_client = await aioredis.create_redis_pool(
            f"redis://{redis_config.get('host', 'localhost')}:{redis_config.get('port', 6379)}",
            db=redis_config.get('db', 3)
        )
    
    async def process_network_flows(self, flows: List[NetworkFlow]) -> List[AnomalyAlert]:
        """Process network flows and detect anomalies"""
        alerts = []
        
        if not flows:
            return alerts
        
        # Extract features for ML analysis
        features = self.ml_analyzer.extract_behavioral_features(flows)
        
        # Statistical anomaly detection
        if len(features) > 0:
            # Isolation Forest
            isolation_labels, isolation_scores = self.ml_analyzer.detect_isolation_forest_anomalies(features)
            
            # LOF
            lof_labels, lof_scores = self.ml_analyzer.detect_lof_anomalies(features)
            
            # Autoencoder
            ae_labels, ae_scores = self.ml_analyzer.detect_autoencoder_anomalies(features)
            
            # Process anomalies
            for i, flow in enumerate(flows):
                anomaly_detected = False
                anomaly_scores = {}
                
                if i < len(isolation_labels) and isolation_labels[i] == -1:
                    anomaly_detected = True
                    anomaly_scores['isolation_forest'] = abs(isolation_scores[i])
                
                if i < len(lof_labels) and lof_labels[i] == -1:
                    anomaly_detected = True
                    anomaly_scores['lof'] = abs(lof_scores[i])
                
                if i < len(ae_labels) and ae_labels[i] == 1:
                    anomaly_detected = True
                    anomaly_scores['autoencoder'] = ae_scores[i]
                
                if anomaly_detected:
                    alert = self._create_anomaly_alert(flow, anomaly_scores, 'ml')
                    alerts.append(alert)
        
        # Behavioral clustering analysis
        if len(features) > 10:  # Need minimum samples for clustering
            clustering_result = self.ml_analyzer.perform_behavioral_clustering(features)
            
            # Identify flows in noise cluster as anomalies
            if 'cluster_labels' in clustering_result:
                for i, (flow, label) in enumerate(zip(flows, clustering_result['cluster_labels'])):
                    if label == -1:  # Noise point
                        alert = self._create_anomaly_alert(
                            flow, 
                            {'clustering': 1.0}, 
                            'behavioral',
                            description=f"Flow exhibits unusual behavioral pattern (noise cluster)"
                        )
                        alerts.append(alert)
        
        # Update baselines with current flows
        self._update_baselines_from_flows(flows)
        
        return alerts
    
    def _create_anomaly_alert(self, flow: NetworkFlow, anomaly_scores: Dict[str, float], 
                            anomaly_type: str, description: str = None) -> AnomalyAlert:
        """Create anomaly alert from flow and scores"""
        # Calculate overall anomaly score
        overall_score = max(anomaly_scores.values()) if anomaly_scores else 0.5
        
        # Determine severity
        severity = self._determine_severity(overall_score)
        
        # Generate alert ID
        alert_id = hashlib.md5(
            f"{flow.timestamp}{flow.source_ip}{flow.destination_ip}{anomaly_type}".encode()
        ).hexdigest()[:16]
        
        # Generate description if not provided
        if not description:
            description = f"Anomalous {anomaly_type} behavior detected from {flow.source_ip} to {flow.destination_ip}"
        
        alert = AnomalyAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            anomaly_type=anomaly_type,
            entity=flow.source_ip,
            entity_type='host',
            anomaly_score=overall_score,
            confidence=min(0.95, overall_score + 0.2),
            severity=severity,
            description=description,
            baseline_deviation=overall_score,
            supporting_evidence={
                'flow_details': asdict(flow),
                'anomaly_scores': anomaly_scores,
                'detection_timestamp': datetime.now().isoformat()
            }
        )
        
        return alert
    
    def _determine_severity(self, score: float) -> str:
        """Determine alert severity based on anomaly score"""
        thresholds = self.config.get('alerting', {}).get('severity_thresholds', {})
        
        if score >= thresholds.get('critical', 0.9):
            return 'critical'
        elif score >= thresholds.get('high', 0.7):
            return 'high'
        elif score >= thresholds.get('medium', 0.5):
            return 'medium'
        else:
            return 'low'
    
    def _update_baselines_from_flows(self, flows: List[NetworkFlow]):
        """Update baselines with metrics from current flows"""
        if not flows:
            return
        
        # Calculate flow metrics
        bytes_per_flow = [flow.bytes_sent + flow.bytes_received for flow in flows]
        packets_per_flow = [flow.packets_sent + flow.packets_received for flow in flows]
        flow_durations = [flow.duration for flow in flows]
        
        # Update baselines
        for bytes_val in bytes_per_flow:
            self.baseline_engine.update_baseline('flow_bytes', bytes_val)
        
        for packets_val in packets_per_flow:
            self.baseline_engine.update_baseline('flow_packets', packets_val)
        
        for duration in flow_durations:
            self.baseline_engine.update_baseline('flow_duration', duration)
    
    async def store_alert(self, alert: AnomalyAlert):
        """Store anomaly alert in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO anomaly_alerts 
                (alert_id, timestamp, anomaly_type, entity, entity_type, anomaly_score,
                 confidence, severity, description, baseline_deviation, supporting_evidence,
                 mitre_tactics, recommended_actions)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.timestamp,
                alert.anomaly_type,
                alert.entity,
                alert.entity_type,
                alert.anomaly_score,
                alert.confidence,
                alert.severity,
                alert.description,
                alert.baseline_deviation,
                json.dumps(alert.supporting_evidence, default=str),
                json.dumps(alert.mitre_tactics) if alert.mitre_tactics else None,
                json.dumps(alert.recommended_actions) if alert.recommended_actions else None
            ))
        
        # Send to Redis for real-time access
        if self.redis_client:
            await self.redis_client.lpush(
                'anomaly_alerts',
                json.dumps(asdict(alert), default=str)
            )
            await self.redis_client.ltrim('anomaly_alerts', 0, 9999)
    
    async def start_processing(self):
        """Start the anomaly detection engine"""
        logger.info("Starting anomaly detection engine")
        
        await self.initialize_redis()
        self.is_running = True
        
        # Start background tasks
        asyncio.create_task(self._baseline_updater())
        asyncio.create_task(self._model_updater())
        
        # Main processing loop
        while self.is_running:
            try:
                # Get flows from queue (would be populated by network capture)
                flows_data = await asyncio.wait_for(
                    self.processing_queue.get(),
                    timeout=1.0
                )
                
                # Convert to NetworkFlow objects
                flows = [NetworkFlow(**flow_data) for flow_data in flows_data]
                
                # Process flows and detect anomalies
                alerts = await self.process_network_flows(flows)
                
                # Store alerts
                for alert in alerts:
                    await self.store_alert(alert)
                
                # Mark task as done
                self.processing_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _baseline_updater(self):
        """Periodically update baselines"""
        update_frequency = self.config.get('baseline', {}).get('update_frequency', 3600)
        
        while self.is_running:
            try:
                await asyncio.sleep(update_frequency)
                logger.info("Updating network baselines")
                self.baseline_engine.recalculate_baselines()
                
            except Exception as e:
                logger.error(f"Error updating baselines: {e}")
    
    async def _model_updater(self):
        """Periodically update ML models"""
        update_frequency = self.config.get('ml', {}).get('model_update_frequency', 86400)
        
        while self.is_running:
            try:
                await asyncio.sleep(update_frequency)
                logger.info("Updating ML models")
                self.ml_analyzer.save_models()
                
            except Exception as e:
                logger.error(f"Error updating models: {e}")
    
    def stop_processing(self):
        """Stop the anomaly detection engine"""
        logger.info("Stopping anomaly detection engine")
        self.is_running = False

async def main():
    """Main function for anomaly detection engine"""
    engine = AnomalyDetectionEngine()
    
    try:
        await engine.start_processing()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        engine.stop_processing()

if __name__ == "__main__":
    asyncio.run(main())