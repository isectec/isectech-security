#!/usr/bin/env python3
"""
iSECTECH SIEM Machine Learning Anomaly Detection Engine
Production-grade anomaly detection with multiple ML algorithms
Implements behavioral analysis, statistical anomaly detection, and ML-based threat hunting
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
import yaml
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class AnomalyResult:
    """Anomaly detection result"""
    event_id: str
    anomaly_type: str
    confidence_score: float
    risk_level: str
    features_analyzed: List[str]
    anomaly_details: Dict[str, Any]
    model_used: str
    timestamp: datetime
    baseline_period: str
    recommended_actions: List[str]

@dataclass
class ModelMetrics:
    """Model performance metrics"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    last_trained: datetime
    training_data_size: int
    feature_importance: Dict[str, float]

class MLAnomalyDetectionEngine:
    """
    Advanced ML-based anomaly detection engine for SIEM
    Supports multiple detection algorithms and real-time analysis
    """
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_extractors = {}
        self.baseline_profiles = {}
        self.redis_client = None
        self.db_connection = None
        self.model_cache = {}
        self.training_data_cache = deque(maxlen=10000)
        
        # Anomaly thresholds
        self.anomaly_thresholds = {
            'isolation_forest': -0.1,
            'clustering': 0.5,
            'statistical': 2.5,  # Z-score threshold
            'behavioral': 0.3,
            'time_series': 0.4
        }
        
        # Model update intervals (in minutes)
        self.model_update_intervals = {
            'isolation_forest': 60,
            'clustering': 120,
            'statistical': 30,
            'behavioral': 180,
            'time_series': 240
        }
        
    async def initialize(self):
        """Initialize the anomaly detection engine"""
        try:
            await self._load_config()
            await self._setup_database_connection()
            await self._setup_redis_connection()
            await self._initialize_models()
            await self._load_baseline_profiles()
            logger.info("ML Anomaly Detection Engine initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ML engine: {e}")
            raise
            
    async def _load_config(self):
        """Load ML configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load ML config: {e}")
            # Use default configuration
            self.config = {
                'models': {
                    'isolation_forest': {'contamination': 0.1, 'n_estimators': 100},
                    'clustering': {'eps': 0.5, 'min_samples': 5},
                    'statistical': {'window_size': 1000, 'threshold': 2.5},
                    'behavioral': {'learning_rate': 0.01, 'window_size': 24},
                    'time_series': {'seasonality': 24, 'trend_threshold': 0.3}
                },
                'features': {
                    'numerical': ['event_count', 'bytes_transferred', 'duration'],
                    'categorical': ['event_action', 'source_ip', 'user_name'],
                    'temporal': ['hour_of_day', 'day_of_week', 'is_weekend']
                },
                'training': {
                    'batch_size': 1000,
                    'retrain_threshold': 0.8,
                    'validation_split': 0.2
                }
            }
            
    async def _setup_database_connection(self):
        """Setup PostgreSQL connection for storing results"""
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'siem_ml'),
                user=db_config.get('user', 'ml_user'),
                password=db_config.get('password', 'ml_password'),
                cursor_factory=RealDictCursor
            )
            self.db_connection.autocommit = True
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            self.db_connection = None
            
    async def _setup_redis_connection(self):
        """Setup Redis connection for caching"""
        try:
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 2),
                decode_responses=True
            )
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.ping
            )
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
            
    async def _initialize_models(self):
        """Initialize ML models"""
        model_config = self.config.get('models', {})
        
        # Isolation Forest for outlier detection
        self.models['isolation_forest'] = IsolationForest(
            contamination=model_config.get('isolation_forest', {}).get('contamination', 0.1),
            n_estimators=model_config.get('isolation_forest', {}).get('n_estimators', 100),
            random_state=42,
            n_jobs=-1
        )
        
        # DBSCAN for clustering-based anomaly detection
        self.models['clustering'] = DBSCAN(
            eps=model_config.get('clustering', {}).get('eps', 0.5),
            min_samples=model_config.get('clustering', {}).get('min_samples', 5),
            n_jobs=-1
        )
        
        # Statistical anomaly detection
        self.models['statistical'] = {
            'window_size': model_config.get('statistical', {}).get('window_size', 1000),
            'threshold': model_config.get('statistical', {}).get('threshold', 2.5),
            'baseline_stats': {}
        }
        
        # Behavioral analysis model
        self.models['behavioral'] = {
            'user_profiles': defaultdict(lambda: {
                'normal_hours': set(),
                'common_ips': set(),
                'typical_actions': defaultdict(int),
                'avg_session_duration': 0,
                'login_frequency': defaultdict(int)
            }),
            'asset_profiles': defaultdict(lambda: {
                'normal_traffic_volume': 0,
                'common_connections': set(),
                'service_patterns': defaultdict(int),
                'baseline_cpu_memory': {}
            })
        }
        
        # Time series anomaly detection
        self.models['time_series'] = {
            'seasonality': model_config.get('time_series', {}).get('seasonality', 24),
            'trend_threshold': model_config.get('time_series', {}).get('trend_threshold', 0.3),
            'time_series_data': defaultdict(deque)
        }
        
        # Initialize scalers and encoders
        self.scalers['numerical'] = StandardScaler()
        self.scalers['behavioral'] = StandardScaler()
        
        feature_config = self.config.get('features', {})
        for feature in feature_config.get('categorical', []):
            self.encoders[feature] = LabelEncoder()
            
        logger.info("ML models initialized")
        
    async def _load_baseline_profiles(self):
        """Load existing baseline profiles from storage"""
        try:
            if self.redis_client:
                # Load from Redis cache
                profiles = await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.get, 'ml_baseline_profiles'
                )
                if profiles:
                    self.baseline_profiles = json.loads(profiles)
                    logger.info("Loaded baseline profiles from cache")
                    return
                    
            if self.db_connection:
                # Load from database
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT profile_type, profile_data 
                    FROM ml_baseline_profiles 
                    WHERE active = true
                """)
                
                for row in cursor.fetchall():
                    profile_type = row['profile_type']
                    profile_data = json.loads(row['profile_data'])
                    self.baseline_profiles[profile_type] = profile_data
                    
                cursor.close()
                logger.info("Loaded baseline profiles from database")
                
        except Exception as e:
            logger.warning(f"Failed to load baseline profiles: {e}")
            
    async def detect_anomalies(self, events: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """
        Detect anomalies in a batch of events using multiple ML approaches
        """
        if not events:
            return []
            
        results = []
        
        try:
            # Extract features from events
            features_df = await self._extract_features(events)
            
            if features_df.empty:
                return results
                
            # Run different anomaly detection algorithms
            detection_tasks = [
                self._isolation_forest_detection(events, features_df),
                self._clustering_based_detection(events, features_df),
                self._statistical_anomaly_detection(events, features_df),
                self._behavioral_anomaly_detection(events),
                self._time_series_anomaly_detection(events)
            ]
            
            detection_results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            
            # Combine results from all detection methods
            for i, detection_result in enumerate(detection_results):
                if isinstance(detection_result, Exception):
                    logger.error(f"Detection method {i} failed: {detection_result}")
                    continue
                if detection_result:
                    results.extend(detection_result)
                    
            # Apply ensemble scoring and deduplication
            results = await self._ensemble_scoring(results)
            
            # Store results and update training data
            await self._store_anomaly_results(results)
            await self._update_training_data(events, features_df)
            
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
            
        return results
        
    async def _extract_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """Extract ML features from events"""
        try:
            features_list = []
            
            for event in events:
                features = {}
                
                # Extract basic event features
                features['event_id'] = event.get('@metadata', {}).get('_id', '')
                features['timestamp'] = event.get('@timestamp', '')
                
                # Numerical features
                features['event_count'] = 1
                features['bytes_transferred'] = self._safe_int(event.get('network', {}).get('bytes', 0))
                features['duration'] = self._safe_float(event.get('event', {}).get('duration', 0))
                features['source_port'] = self._safe_int(event.get('source', {}).get('port', 0))
                features['destination_port'] = self._safe_int(event.get('destination', {}).get('port', 0))
                
                # Categorical features
                features['event_action'] = event.get('event', {}).get('action', 'unknown')
                features['source_ip'] = event.get('source', {}).get('ip', '')
                features['destination_ip'] = event.get('destination', {}).get('ip', '')
                features['user_name'] = event.get('user', {}).get('name', '')
                features['host_name'] = event.get('host', {}).get('name', '')
                features['process_name'] = event.get('process', {}).get('name', '')
                
                # Temporal features
                if features['timestamp']:
                    try:
                        dt = datetime.fromisoformat(features['timestamp'].replace('Z', '+00:00'))
                        features['hour_of_day'] = dt.hour
                        features['day_of_week'] = dt.weekday()
                        features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
                        features['is_business_hours'] = 1 if 9 <= dt.hour <= 17 else 0
                    except:
                        features['hour_of_day'] = 0
                        features['day_of_week'] = 0
                        features['is_weekend'] = 0
                        features['is_business_hours'] = 0
                
                # Security-specific features
                features['threat_detected'] = 1 if event.get('threat', {}).get('indicator', {}).get('matched') else 0
                features['asset_criticality_score'] = self._get_criticality_score(event.get('asset', {}).get('criticality', 'low'))
                features['user_risk_score'] = self._safe_float(event.get('user', {}).get('risk_score', 0))
                features['network_security_level'] = self._get_security_level_score(
                    event.get('source', {}).get('network', {}).get('security_level', 'low')
                )
                
                # Enrichment-based features
                features['enrichment_score'] = self._safe_float(event.get('enrichment', {}).get('score', 0))
                features['risk_factors_count'] = len(event.get('enrichment', {}).get('risk_factors', []))
                
                features_list.append(features)
                
            df = pd.DataFrame(features_list)
            
            # Handle missing values
            numerical_columns = ['bytes_transferred', 'duration', 'source_port', 'destination_port', 
                               'user_risk_score', 'enrichment_score']
            for col in numerical_columns:
                if col in df.columns:
                    df[col] = df[col].fillna(0)
                    
            categorical_columns = ['event_action', 'source_ip', 'destination_ip', 'user_name', 
                                 'host_name', 'process_name']
            for col in categorical_columns:
                if col in df.columns:
                    df[col] = df[col].fillna('unknown')
                    
            return df
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return pd.DataFrame()
            
    async def _isolation_forest_detection(self, events: List[Dict[str, Any]], 
                                        features_df: pd.DataFrame) -> List[AnomalyResult]:
        """Isolation Forest based anomaly detection"""
        results = []
        
        try:
            if len(features_df) < 10:  # Need minimum samples
                return results
                
            # Select numerical features for isolation forest
            numerical_features = ['bytes_transferred', 'duration', 'source_port', 'destination_port',
                                'hour_of_day', 'day_of_week', 'user_risk_score', 'enrichment_score',
                                'threat_detected', 'asset_criticality_score', 'network_security_level']
            
            feature_matrix = features_df[numerical_features].values
            
            # Scale features
            feature_matrix_scaled = self.scalers['numerical'].fit_transform(feature_matrix)
            
            # Predict anomalies
            anomaly_scores = self.models['isolation_forest'].fit_predict(feature_matrix_scaled)
            decision_scores = self.models['isolation_forest'].decision_function(feature_matrix_scaled)
            
            # Process results
            for i, (score, decision_score) in enumerate(zip(anomaly_scores, decision_scores)):
                if score == -1:  # Anomaly detected
                    confidence = abs(decision_score)
                    risk_level = self._calculate_risk_level(confidence, 'isolation_forest')
                    
                    result = AnomalyResult(
                        event_id=features_df.iloc[i]['event_id'],
                        anomaly_type='outlier_detection',
                        confidence_score=confidence,
                        risk_level=risk_level,
                        features_analyzed=numerical_features,
                        anomaly_details={
                            'isolation_score': float(decision_score),
                            'feature_deviations': self._get_feature_deviations(
                                feature_matrix_scaled[i], numerical_features
                            )
                        },
                        model_used='isolation_forest',
                        timestamp=datetime.now(timezone.utc),
                        baseline_period='last_1000_events',
                        recommended_actions=self._get_isolation_forest_recommendations(decision_score)
                    )
                    results.append(result)
                    
        except Exception as e:
            logger.error(f"Isolation forest detection failed: {e}")
            
        return results
        
    async def _clustering_based_detection(self, events: List[Dict[str, Any]], 
                                        features_df: pd.DataFrame) -> List[AnomalyResult]:
        """DBSCAN clustering based anomaly detection"""
        results = []
        
        try:
            if len(features_df) < 20:  # Need minimum samples for clustering
                return results
                
            # Select features for clustering
            clustering_features = ['bytes_transferred', 'duration', 'hour_of_day', 'source_port',
                                 'destination_port', 'user_risk_score', 'enrichment_score']
            
            feature_matrix = features_df[clustering_features].values
            feature_matrix_scaled = self.scalers['numerical'].fit_transform(feature_matrix)
            
            # Apply PCA for dimensionality reduction
            pca = PCA(n_components=min(5, len(clustering_features)))
            feature_matrix_pca = pca.fit_transform(feature_matrix_scaled)
            
            # Perform clustering
            cluster_labels = self.models['clustering'].fit_predict(feature_matrix_pca)
            
            # Identify outliers (label = -1 in DBSCAN)
            for i, label in enumerate(cluster_labels):
                if label == -1:  # Outlier/anomaly
                    # Calculate distance to nearest cluster
                    distances = []
                    for cluster_id in set(cluster_labels):
                        if cluster_id != -1:
                            cluster_points = feature_matrix_pca[cluster_labels == cluster_id]
                            if len(cluster_points) > 0:
                                min_distance = np.min(np.linalg.norm(
                                    cluster_points - feature_matrix_pca[i], axis=1
                                ))
                                distances.append(min_distance)
                    
                    if distances:
                        confidence = min(distances) / 10.0  # Normalize confidence
                        risk_level = self._calculate_risk_level(confidence, 'clustering')
                        
                        result = AnomalyResult(
                            event_id=features_df.iloc[i]['event_id'],
                            anomaly_type='clustering_outlier',
                            confidence_score=confidence,
                            risk_level=risk_level,
                            features_analyzed=clustering_features,
                            anomaly_details={
                                'cluster_distance': float(min(distances)),
                                'pca_components': pca.components_.tolist(),
                                'explained_variance': pca.explained_variance_ratio_.tolist()
                            },
                            model_used='dbscan_clustering',
                            timestamp=datetime.now(timezone.utc),
                            baseline_period='current_batch',
                            recommended_actions=self._get_clustering_recommendations(min(distances))
                        )
                        results.append(result)
                        
        except Exception as e:
            logger.error(f"Clustering detection failed: {e}")
            
        return results
        
    async def _statistical_anomaly_detection(self, events: List[Dict[str, Any]], 
                                           features_df: pd.DataFrame) -> List[AnomalyResult]:
        """Statistical anomaly detection using Z-score and percentile analysis"""
        results = []
        
        try:
            statistical_features = ['bytes_transferred', 'duration', 'enrichment_score', 'user_risk_score']
            threshold = self.models['statistical']['threshold']
            
            for feature in statistical_features:
                if feature in features_df.columns:
                    values = features_df[feature].values
                    
                    if len(values) > 10:  # Need sufficient data for statistics
                        mean_val = np.mean(values)
                        std_val = np.std(values)
                        
                        if std_val > 0:
                            z_scores = np.abs((values - mean_val) / std_val)
                            
                            # Find anomalies
                            anomaly_indices = np.where(z_scores > threshold)[0]
                            
                            for idx in anomaly_indices:
                                confidence = min(z_scores[idx] / threshold, 1.0)
                                risk_level = self._calculate_risk_level(confidence, 'statistical')
                                
                                result = AnomalyResult(
                                    event_id=features_df.iloc[idx]['event_id'],
                                    anomaly_type='statistical_outlier',
                                    confidence_score=confidence,
                                    risk_level=risk_level,
                                    features_analyzed=[feature],
                                    anomaly_details={
                                        'z_score': float(z_scores[idx]),
                                        'value': float(values[idx]),
                                        'mean': float(mean_val),
                                        'std': float(std_val),
                                        'percentile': float(np.percentile(values, 95))
                                    },
                                    model_used='statistical_zscore',
                                    timestamp=datetime.now(timezone.utc),
                                    baseline_period='current_window',
                                    recommended_actions=self._get_statistical_recommendations(feature, z_scores[idx])
                                )
                                results.append(result)
                                
        except Exception as e:
            logger.error(f"Statistical detection failed: {e}")
            
        return results
        
    async def _behavioral_anomaly_detection(self, events: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """Behavioral anomaly detection based on user and asset profiles"""
        results = []
        
        try:
            for event in events:
                anomalies = []
                
                # User behavioral analysis
                user_name = event.get('user', {}).get('name', '')
                if user_name:
                    user_anomalies = await self._analyze_user_behavior(event, user_name)
                    anomalies.extend(user_anomalies)
                
                # Asset behavioral analysis
                host_name = event.get('host', {}).get('name', '')
                source_ip = event.get('source', {}).get('ip', '')
                
                if host_name or source_ip:
                    asset_id = host_name or source_ip
                    asset_anomalies = await self._analyze_asset_behavior(event, asset_id)
                    anomalies.extend(asset_anomalies)
                
                # Convert behavioral anomalies to results
                for anomaly in anomalies:
                    result = AnomalyResult(
                        event_id=event.get('@metadata', {}).get('_id', ''),
                        anomaly_type='behavioral_anomaly',
                        confidence_score=anomaly['confidence'],
                        risk_level=self._calculate_risk_level(anomaly['confidence'], 'behavioral'),
                        features_analyzed=anomaly['features'],
                        anomaly_details=anomaly['details'],
                        model_used='behavioral_profiling',
                        timestamp=datetime.now(timezone.utc),
                        baseline_period='historical_profile',
                        recommended_actions=anomaly['recommendations']
                    )
                    results.append(result)
                    
        except Exception as e:
            logger.error(f"Behavioral detection failed: {e}")
            
        return results
        
    async def _time_series_anomaly_detection(self, events: List[Dict[str, Any]]) -> List[AnomalyResult]:
        """Time series based anomaly detection for temporal patterns"""
        results = []
        
        try:
            # Group events by time windows (e.g., hourly)
            time_windows = defaultdict(list)
            
            for event in events:
                timestamp_str = event.get('@timestamp', '')
                if timestamp_str:
                    try:
                        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        hour_window = dt.replace(minute=0, second=0, microsecond=0)
                        time_windows[hour_window].append(event)
                    except:
                        continue
                        
            # Analyze each time window
            for time_window, window_events in time_windows.items():
                event_count = len(window_events)
                
                # Simple time series anomaly: unusual event volume
                historical_counts = self.models['time_series']['time_series_data']['event_counts']
                historical_counts.append(event_count)
                
                if len(historical_counts) > 24:  # Need at least 24 hours of data
                    mean_count = np.mean(list(historical_counts)[-24:])
                    std_count = np.std(list(historical_counts)[-24:])
                    
                    if std_count > 0:
                        z_score = abs(event_count - mean_count) / std_count
                        
                        if z_score > 2.0:  # Significant deviation
                            confidence = min(z_score / 5.0, 1.0)
                            
                            # Create anomaly result for the most significant event in this window
                            if window_events:
                                representative_event = max(window_events, 
                                    key=lambda e: e.get('enrichment', {}).get('score', 0))
                                
                                result = AnomalyResult(
                                    event_id=representative_event.get('@metadata', {}).get('_id', ''),
                                    anomaly_type='temporal_anomaly',
                                    confidence_score=confidence,
                                    risk_level=self._calculate_risk_level(confidence, 'time_series'),
                                    features_analyzed=['event_volume', 'time_pattern'],
                                    anomaly_details={
                                        'time_window': time_window.isoformat(),
                                        'event_count': event_count,
                                        'expected_count': float(mean_count),
                                        'z_score': float(z_score),
                                        'historical_mean': float(mean_count),
                                        'historical_std': float(std_count)
                                    },
                                    model_used='time_series_analysis',
                                    timestamp=datetime.now(timezone.utc),
                                    baseline_period='last_24_hours',
                                    recommended_actions=self._get_time_series_recommendations(z_score, event_count)
                                )
                                results.append(result)
                                
        except Exception as e:
            logger.error(f"Time series detection failed: {e}")
            
        return results
        
    async def _analyze_user_behavior(self, event: Dict[str, Any], user_name: str) -> List[Dict[str, Any]]:
        """Analyze user behavioral patterns"""
        anomalies = []
        
        try:
            user_profile = self.models['behavioral']['user_profiles'][user_name]
            
            # Get event details
            timestamp_str = event.get('@timestamp', '')
            source_ip = event.get('source', {}).get('ip', '')
            event_action = event.get('event', {}).get('action', '')
            
            if timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                hour = dt.hour
                
                # Check unusual login hours
                if event_action in ['login', 'authentication']:
                    if len(user_profile['normal_hours']) > 5:  # Have sufficient baseline
                        if hour not in user_profile['normal_hours']:
                            anomalies.append({
                                'confidence': 0.7,
                                'features': ['login_time'],
                                'details': {
                                    'unusual_hour': hour,
                                    'normal_hours': list(user_profile['normal_hours']),
                                    'anomaly_type': 'off_hours_login'
                                },
                                'recommendations': ['Verify user identity', 'Check for concurrent sessions']
                            })
                    
                    # Update profile
                    user_profile['normal_hours'].add(hour)
                    
                # Check unusual source IP
                if source_ip:
                    if len(user_profile['common_ips']) > 3:  # Have baseline
                        if source_ip not in user_profile['common_ips']:
                            anomalies.append({
                                'confidence': 0.6,
                                'features': ['source_ip'],
                                'details': {
                                    'unusual_ip': source_ip,
                                    'known_ips': list(user_profile['common_ips']),
                                    'anomaly_type': 'unusual_source_ip'
                                },
                                'recommendations': ['Verify IP geolocation', 'Check for VPN usage']
                            })
                    
                    # Update profile (keep only recent IPs)
                    user_profile['common_ips'].add(source_ip)
                    if len(user_profile['common_ips']) > 10:
                        user_profile['common_ips'] = set(list(user_profile['common_ips'])[-10:])
                
                # Check unusual actions
                if event_action:
                    user_profile['typical_actions'][event_action] += 1
                    total_actions = sum(user_profile['typical_actions'].values())
                    
                    if total_actions > 50:  # Have sufficient baseline
                        action_frequency = user_profile['typical_actions'][event_action] / total_actions
                        if action_frequency < 0.05:  # Very rare action for this user
                            anomalies.append({
                                'confidence': 0.5,
                                'features': ['event_action'],
                                'details': {
                                    'unusual_action': event_action,
                                    'frequency': action_frequency,
                                    'anomaly_type': 'unusual_user_action'
                                },
                                'recommendations': ['Review action legitimacy', 'Check user permissions']
                            })
                            
        except Exception as e:
            logger.error(f"User behavior analysis failed: {e}")
            
        return anomalies
        
    async def _analyze_asset_behavior(self, event: Dict[str, Any], asset_id: str) -> List[Dict[str, Any]]:
        """Analyze asset behavioral patterns"""
        anomalies = []
        
        try:
            asset_profile = self.models['behavioral']['asset_profiles'][asset_id]
            
            # Network traffic analysis
            bytes_transferred = self._safe_int(event.get('network', {}).get('bytes', 0))
            destination_ip = event.get('destination', {}).get('ip', '')
            
            if bytes_transferred > 0:
                if asset_profile['normal_traffic_volume'] > 0:
                    traffic_ratio = bytes_transferred / asset_profile['normal_traffic_volume']
                    
                    if traffic_ratio > 5.0:  # 5x normal traffic
                        anomalies.append({
                            'confidence': 0.8,
                            'features': ['network_traffic'],
                            'details': {
                                'bytes_transferred': bytes_transferred,
                                'normal_volume': asset_profile['normal_traffic_volume'],
                                'ratio': traffic_ratio,
                                'anomaly_type': 'unusual_traffic_volume'
                            },
                            'recommendations': ['Investigate data exfiltration', 'Check for malware activity']
                        })
                
                # Update baseline (moving average)
                if asset_profile['normal_traffic_volume'] == 0:
                    asset_profile['normal_traffic_volume'] = bytes_transferred
                else:
                    asset_profile['normal_traffic_volume'] = (
                        asset_profile['normal_traffic_volume'] * 0.9 + bytes_transferred * 0.1
                    )
            
            # Connection pattern analysis
            if destination_ip:
                if len(asset_profile['common_connections']) > 5:  # Have baseline
                    if destination_ip not in asset_profile['common_connections']:
                        anomalies.append({
                            'confidence': 0.4,
                            'features': ['network_connections'],
                            'details': {
                                'new_destination': destination_ip,
                                'known_destinations': list(asset_profile['common_connections']),
                                'anomaly_type': 'new_network_connection'
                            },
                            'recommendations': ['Verify connection legitimacy', 'Check destination reputation']
                        })
                
                # Update profile
                asset_profile['common_connections'].add(destination_ip)
                if len(asset_profile['common_connections']) > 20:
                    asset_profile['common_connections'] = set(
                        list(asset_profile['common_connections'])[-20:]
                    )
                    
        except Exception as e:
            logger.error(f"Asset behavior analysis failed: {e}")
            
        return anomalies
        
    async def _ensemble_scoring(self, results: List[AnomalyResult]) -> List[AnomalyResult]:
        """Apply ensemble scoring to combine results from multiple models"""
        if not results:
            return results
            
        # Group results by event_id
        event_results = defaultdict(list)
        for result in results:
            event_results[result.event_id].append(result)
            
        final_results = []
        
        for event_id, event_anomalies in event_results.items():
            if len(event_anomalies) == 1:
                final_results.append(event_anomalies[0])
            else:
                # Combine multiple anomalies for the same event
                combined_confidence = 0
                combined_features = []
                combined_details = {}
                models_used = []
                anomaly_types = []
                recommendations = []
                
                # Weight different models
                model_weights = {
                    'isolation_forest': 0.3,
                    'dbscan_clustering': 0.25,
                    'statistical_zscore': 0.2,
                    'behavioral_profiling': 0.15,
                    'time_series_analysis': 0.1
                }
                
                for anomaly in event_anomalies:
                    weight = model_weights.get(anomaly.model_used, 0.1)
                    combined_confidence += anomaly.confidence_score * weight
                    combined_features.extend(anomaly.features_analyzed)
                    combined_details[anomaly.model_used] = anomaly.anomaly_details
                    models_used.append(anomaly.model_used)
                    anomaly_types.append(anomaly.anomaly_type)
                    recommendations.extend(anomaly.recommended_actions)
                
                # Create combined result
                combined_result = AnomalyResult(
                    event_id=event_id,
                    anomaly_type='ensemble_' + '_'.join(set(anomaly_types)),
                    confidence_score=min(combined_confidence, 1.0),
                    risk_level=self._calculate_risk_level(combined_confidence, 'ensemble'),
                    features_analyzed=list(set(combined_features)),
                    anomaly_details={
                        'ensemble_score': combined_confidence,
                        'model_results': combined_details,
                        'contributing_models': models_used
                    },
                    model_used='ensemble_' + '_'.join(set(models_used)),
                    timestamp=datetime.now(timezone.utc),
                    baseline_period='combined',
                    recommended_actions=list(set(recommendations))
                )
                
                final_results.append(combined_result)
                
        return final_results
        
    async def _store_anomaly_results(self, results: List[AnomalyResult]):
        """Store anomaly detection results"""
        if not results or not self.db_connection:
            return
            
        try:
            cursor = self.db_connection.cursor()
            
            for result in results:
                cursor.execute("""
                    INSERT INTO ml_anomaly_results 
                    (event_id, anomaly_type, confidence_score, risk_level, features_analyzed,
                     anomaly_details, model_used, timestamp, baseline_period, recommended_actions)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (event_id, model_used) DO UPDATE SET
                    confidence_score = EXCLUDED.confidence_score,
                    anomaly_details = EXCLUDED.anomaly_details,
                    timestamp = EXCLUDED.timestamp
                """, (
                    result.event_id,
                    result.anomaly_type,
                    result.confidence_score,
                    result.risk_level,
                    json.dumps(result.features_analyzed),
                    json.dumps(result.anomaly_details),
                    result.model_used,
                    result.timestamp,
                    result.baseline_period,
                    json.dumps(result.recommended_actions)
                ))
            
            cursor.close()
            logger.info(f"Stored {len(results)} anomaly results")
            
        except Exception as e:
            logger.error(f"Failed to store anomaly results: {e}")
            
    async def _update_training_data(self, events: List[Dict[str, Any]], features_df: pd.DataFrame):
        """Update training data cache for model retraining"""
        try:
            for event in events:
                self.training_data_cache.append({
                    'event': event,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'features': features_df[features_df['event_id'] == 
                                         event.get('@metadata', {}).get('_id', '')].to_dict('records')
                })
                
        except Exception as e:
            logger.error(f"Failed to update training data: {e}")
            
    def _safe_int(self, value, default=0):
        """Safely convert value to int"""
        try:
            return int(value)
        except:
            return default
            
    def _safe_float(self, value, default=0.0):
        """Safely convert value to float"""
        try:
            return float(value)
        except:
            return default
            
    def _get_criticality_score(self, criticality: str) -> int:
        """Convert criticality to numerical score"""
        scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return scores.get(criticality.lower(), 1)
        
    def _get_security_level_score(self, security_level: str) -> int:
        """Convert security level to numerical score"""
        scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return scores.get(security_level.lower(), 1)
        
    def _calculate_risk_level(self, confidence: float, model_type: str) -> str:
        """Calculate risk level based on confidence and model type"""
        if confidence >= 0.8:
            return 'critical'
        elif confidence >= 0.6:
            return 'high'
        elif confidence >= 0.4:
            return 'medium'
        else:
            return 'low'
            
    def _get_feature_deviations(self, scaled_features: np.ndarray, feature_names: List[str]) -> Dict[str, float]:
        """Get feature deviations for isolation forest"""
        deviations = {}
        for i, feature_name in enumerate(feature_names):
            if i < len(scaled_features):
                deviations[feature_name] = float(abs(scaled_features[i]))
        return deviations
        
    def _get_isolation_forest_recommendations(self, decision_score: float) -> List[str]:
        """Get recommendations for isolation forest anomalies"""
        recommendations = ['Investigate unusual behavior patterns']
        
        if decision_score < -0.2:
            recommendations.extend([
                'High priority investigation required',
                'Check for data exfiltration or malware'
            ])
        elif decision_score < -0.1:
            recommendations.extend([
                'Review user activity logs',
                'Verify system integrity'
            ])
        else:
            recommendations.append('Monitor for recurring patterns')
            
        return recommendations
        
    def _get_clustering_recommendations(self, distance: float) -> List[str]:
        """Get recommendations for clustering anomalies"""
        recommendations = ['Analyze event in context of normal patterns']
        
        if distance > 2.0:
            recommendations.extend([
                'Immediate investigation recommended',
                'Potential security incident'
            ])
        elif distance > 1.0:
            recommendations.extend([
                'Enhanced monitoring required',
                'Review related events'
            ])
        else:
            recommendations.append('Continue monitoring')
            
        return recommendations
        
    def _get_statistical_recommendations(self, feature: str, z_score: float) -> List[str]:
        """Get recommendations for statistical anomalies"""
        recommendations = [f'Investigate unusual {feature} values']
        
        if z_score > 4.0:
            recommendations.extend([
                'Critical deviation detected',
                'Immediate response required'
            ])
        elif z_score > 3.0:
            recommendations.extend([
                'Significant anomaly detected',
                'Priority investigation'
            ])
        else:
            recommendations.append('Monitor trend')
            
        return recommendations
        
    def _get_time_series_recommendations(self, z_score: float, event_count: int) -> List[str]:
        """Get recommendations for time series anomalies"""
        recommendations = ['Investigate unusual temporal patterns']
        
        if z_score > 3.0:
            recommendations.extend([
                'Significant volume anomaly',
                'Check for DDoS or system issues'
            ])
        elif event_count > 1000:
            recommendations.extend([
                'High event volume detected',
                'Review system capacity'
            ])
        else:
            recommendations.append('Monitor volume trends')
            
        return recommendations
        
    async def retrain_models(self) -> Dict[str, ModelMetrics]:
        """Retrain ML models with accumulated data"""
        metrics = {}
        
        try:
            if len(self.training_data_cache) < 100:
                logger.info("Insufficient training data for retraining")
                return metrics
                
            # Prepare training data
            training_events = [item['event'] for item in self.training_data_cache]
            features_df = await self._extract_features(training_events)
            
            if features_df.empty:
                return metrics
                
            # Retrain isolation forest
            metrics['isolation_forest'] = await self._retrain_isolation_forest(features_df)
            
            # Update behavioral profiles
            await self._update_behavioral_profiles(training_events)
            
            # Save updated models
            await self._save_models()
            
            logger.info("Model retraining completed")
            
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")
            
        return metrics
        
    async def _retrain_isolation_forest(self, features_df: pd.DataFrame) -> ModelMetrics:
        """Retrain isolation forest model"""
        try:
            numerical_features = ['bytes_transferred', 'duration', 'source_port', 'destination_port',
                                'hour_of_day', 'day_of_week', 'user_risk_score', 'enrichment_score']
            
            feature_matrix = features_df[numerical_features].values
            feature_matrix_scaled = self.scalers['numerical'].fit_transform(feature_matrix)
            
            # Retrain model
            self.models['isolation_forest'].fit(feature_matrix_scaled)
            
            # Calculate basic metrics (simplified for unsupervised learning)
            anomaly_scores = self.models['isolation_forest'].decision_function(feature_matrix_scaled)
            outlier_fraction = len(anomaly_scores[anomaly_scores < -0.1]) / len(anomaly_scores)
            
            return ModelMetrics(
                model_name='isolation_forest',
                accuracy=1.0 - outlier_fraction,  # Simplified metric
                precision=0.0,  # Not applicable for unsupervised
                recall=0.0,     # Not applicable for unsupervised
                f1_score=0.0,   # Not applicable for unsupervised
                last_trained=datetime.now(timezone.utc),
                training_data_size=len(features_df),
                feature_importance=dict(zip(numerical_features, [1.0] * len(numerical_features)))
            )
            
        except Exception as e:
            logger.error(f"Isolation forest retraining failed: {e}")
            return ModelMetrics(
                model_name='isolation_forest',
                accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
                last_trained=datetime.now(timezone.utc),
                training_data_size=0, feature_importance={}
            )
            
    async def _update_behavioral_profiles(self, events: List[Dict[str, Any]]):
        """Update behavioral profiles with new data"""
        try:
            for event in events:
                # Update user profiles
                user_name = event.get('user', {}).get('name', '')
                if user_name:
                    await self._analyze_user_behavior(event, user_name)
                
                # Update asset profiles
                host_name = event.get('host', {}).get('name', '')
                source_ip = event.get('source', {}).get('ip', '')
                
                if host_name or source_ip:
                    asset_id = host_name or source_ip
                    await self._analyze_asset_behavior(event, asset_id)
                    
        except Exception as e:
            logger.error(f"Behavioral profile update failed: {e}")
            
    async def _save_models(self):
        """Save trained models to storage"""
        try:
            # Save to Redis cache
            if self.redis_client:
                model_data = {
                    'behavioral_profiles': {
                        'user_profiles': {k: dict(v) for k, v in self.models['behavioral']['user_profiles'].items()},
                        'asset_profiles': {k: dict(v) for k, v in self.models['behavioral']['asset_profiles'].items()}
                    },
                    'last_updated': datetime.now(timezone.utc).isoformat()
                }
                
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.setex, 'ml_models', 3600, json.dumps(model_data)
                )
                
        except Exception as e:
            logger.error(f"Model saving failed: {e}")
            
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.db_connection:
                self.db_connection.close()
            if self.redis_client:
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.close
                )
            logger.info("ML Anomaly Detection Engine cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

if __name__ == "__main__":
    # Example usage
    async def main():
        engine = MLAnomalyDetectionEngine("/path/to/ml_config.yaml")
        await engine.initialize()
        
        # Example events for testing
        test_events = [
            {
                "@timestamp": "2024-01-15T10:30:00Z",
                "@metadata": {"_id": "test-001"},
                "event": {"action": "login"},
                "user": {"name": "test_user", "risk_score": 75},
                "source": {"ip": "192.168.1.100"},
                "network": {"bytes": 5000000},  # Unusually high
                "enrichment": {"score": 85}
            }
        ]
        
        # Detect anomalies
        results = await engine.detect_anomalies(test_events)
        
        for result in results:
            print(f"Anomaly detected: {result.anomaly_type}")
            print(f"Confidence: {result.confidence_score}")
            print(f"Risk Level: {result.risk_level}")
            print(f"Recommendations: {result.recommended_actions}")
            print("---")
            
        await engine.cleanup()
        
    # Run example
    # asyncio.run(main())