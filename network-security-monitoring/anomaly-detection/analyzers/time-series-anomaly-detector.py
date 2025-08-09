#!/usr/bin/env python3
# iSECTECH Time Series Anomaly Detector
# Production-grade temporal anomaly detection for network security monitoring

import numpy as np
import pandas as pd
import logging
import asyncio
import json
import yaml
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import pickle
import joblib

# Time series analysis imports
from scipy import stats
from statsmodels.tsa.seasonal import seasonal_decompose
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima.model import ARIMA
from statsmodels.tsa.holtwinters import ExponentialSmoothing
import matplotlib.pyplot as plt
import seaborn as sns

# Machine learning imports
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.metrics import mean_squared_error, mean_absolute_error
import tensorflow as tf
from tensorflow.keras import Sequential, layers, callbacks

# Signal processing imports
from scipy.signal import find_peaks, savgol_filter
from scipy.fft import fft, fftfreq
import pychangepoint as pcp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/time-series-anomaly.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TimeSeriesMetric:
    """Time series metric definition"""
    name: str
    timestamp: datetime
    value: float
    metadata: Dict[str, Any] = None
    tags: Dict[str, str] = None

@dataclass
class TimeSeriesAnomaly:
    """Time series anomaly detection result"""
    metric_name: str
    timestamp: datetime
    actual_value: float
    expected_value: float
    anomaly_score: float
    detection_method: str
    severity: str
    confidence: float
    change_point: bool = False
    trend_direction: Optional[str] = None
    seasonal_component: Optional[float] = None
    context: Dict[str, Any] = None

@dataclass
class SeasonalPattern:
    """Seasonal pattern definition"""
    pattern_type: str  # 'hourly', 'daily', 'weekly', 'monthly'
    period: int
    amplitude: float
    phase: float
    strength: float
    last_updated: datetime

class StatisticalTimeSeriesAnalyzer:
    """Statistical methods for time series anomaly detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.window_size = config.get('window_size', 100)
        self.seasonal_periods = {
            'hourly': 24,
            'daily': 7,
            'weekly': 52,
            'monthly': 12
        }
    
    def detect_z_score_anomalies(self, data: pd.Series, threshold: float = 3.0) -> List[int]:
        """Detect anomalies using Z-score method"""
        z_scores = np.abs(stats.zscore(data.fillna(data.mean())))
        return data.index[z_scores > threshold].tolist()
    
    def detect_iqr_anomalies(self, data: pd.Series, k: float = 1.5) -> List[int]:
        """Detect anomalies using Interquartile Range method"""
        Q1 = data.quantile(0.25)
        Q3 = data.quantile(0.75)
        IQR = Q3 - Q1
        
        lower_bound = Q1 - k * IQR
        upper_bound = Q3 + k * IQR
        
        anomalies = data[(data < lower_bound) | (data > upper_bound)]
        return anomalies.index.tolist()
    
    def detect_grubbs_anomalies(self, data: pd.Series, alpha: float = 0.05) -> List[int]:
        """Detect outliers using Grubbs test"""
        outliers = []
        data_clean = data.dropna().copy()
        
        while len(data_clean) > 3:
            mean_val = data_clean.mean()
            std_val = data_clean.std()
            
            if std_val == 0:
                break
            
            # Calculate Grubbs statistic
            grubbs_stats = np.abs(data_clean - mean_val) / std_val
            max_grubbs = grubbs_stats.max()
            max_idx = grubbs_stats.idxmax()
            
            # Critical value
            n = len(data_clean)
            t_critical = stats.t.ppf(1 - alpha / (2 * n), n - 2)
            critical_value = ((n - 1) / np.sqrt(n)) * np.sqrt(t_critical**2 / (n - 2 + t_critical**2))
            
            if max_grubbs > critical_value:
                outliers.append(max_idx)
                data_clean = data_clean.drop(max_idx)
            else:
                break
        
        return outliers
    
    def detect_change_points(self, data: pd.Series, method: str = 'pelt') -> List[int]:
        """Detect change points in time series"""
        try:
            if method == 'pelt':
                # PELT (Pruned Exact Linear Time) algorithm
                signal = data.fillna(data.mean()).values
                algo = pcp.algorithms.PeltNormalMean()
                change_points = algo.fit_predict(signal)
                return change_points
            
            elif method == 'binary_segmentation':
                # Binary segmentation
                signal = data.fillna(data.mean()).values
                algo = pcp.algorithms.BinarySegmentationNormalMean()
                change_points = algo.fit_predict(signal)
                return change_points
            
            elif method == 'window':
                # Window-based change detection
                change_points = []
                window_size = min(20, len(data) // 5)
                
                for i in range(window_size, len(data) - window_size):
                    left_window = data.iloc[i-window_size:i]
                    right_window = data.iloc[i:i+window_size]
                    
                    # Statistical test for mean difference
                    if len(left_window) > 1 and len(right_window) > 1:
                        t_stat, p_value = stats.ttest_ind(left_window, right_window)
                        if p_value < 0.01:  # Significant change
                            change_points.append(i)
                
                return change_points
            
        except Exception as e:
            logger.warning(f"Error detecting change points: {e}")
            return []
        
        return []
    
    def seasonal_decomposition(self, data: pd.Series, period: int = None) -> Dict[str, pd.Series]:
        """Perform seasonal decomposition"""
        try:
            if period is None:
                # Estimate period using autocorrelation
                autocorr = pd.Series([data.autocorr(lag=i) for i in range(1, min(len(data)//2, 100))])
                period = autocorr.idxmax() + 1
            
            if len(data) < 2 * period:
                logger.warning("Insufficient data for seasonal decomposition")
                return {}
            
            decomposition = seasonal_decompose(
                data.fillna(data.mean()),
                model='additive',
                period=period,
                extrapolate_trend='freq'
            )
            
            return {
                'trend': decomposition.trend,
                'seasonal': decomposition.seasonal,
                'residual': decomposition.resid,
                'observed': decomposition.observed
            }
            
        except Exception as e:
            logger.error(f"Error in seasonal decomposition: {e}")
            return {}
    
    def detect_trend_anomalies(self, data: pd.Series, window: int = 20) -> Dict[str, Any]:
        """Detect trend-based anomalies"""
        try:
            # Calculate rolling statistics
            rolling_mean = data.rolling(window=window).mean()
            rolling_std = data.rolling(window=window).std()
            
            # Detect trend changes
            trend_changes = []
            for i in range(window, len(data) - window):
                before_trend = np.polyfit(range(window), data.iloc[i-window:i], 1)[0]
                after_trend = np.polyfit(range(window), data.iloc[i:i+window], 1)[0]
                
                # Significant trend change
                if abs(before_trend - after_trend) > rolling_std.iloc[i] * 2:
                    trend_changes.append({
                        'index': i,
                        'before_trend': before_trend,
                        'after_trend': after_trend,
                        'magnitude': abs(before_trend - after_trend)
                    })
            
            # Detect anomalous values relative to trend
            detrended = data - rolling_mean
            anomalous_indices = self.detect_z_score_anomalies(detrended, threshold=2.5)
            
            return {
                'trend_changes': trend_changes,
                'anomalous_indices': anomalous_indices,
                'rolling_mean': rolling_mean,
                'rolling_std': rolling_std
            }
            
        except Exception as e:
            logger.error(f"Error detecting trend anomalies: {e}")
            return {}

class MLTimeSeriesAnomalyDetector:
    """Machine learning-based time series anomaly detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.models_dir = Path("/var/lib/nsm/models/time-series")
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize models
        self.isolation_forest = None
        self.lstm_autoencoder = None
        self.vae_model = None
        self.scaler = StandardScaler()
        
        self._load_or_initialize_models()
    
    def _load_or_initialize_models(self):
        """Load existing models or initialize new ones"""
        # Isolation Forest for univariate anomaly detection
        isolation_path = self.models_dir / "ts_isolation_forest.pkl"
        if isolation_path.exists():
            self.isolation_forest = joblib.load(isolation_path)
        else:
            self.isolation_forest = IsolationForest(
                contamination=self.config.get('contamination_rate', 0.1),
                random_state=42,
                n_estimators=200
            )
        
        # Build LSTM Autoencoder
        self._build_lstm_autoencoder()
        
        # Build VAE if enabled
        if self.config.get('enable_vae', False):
            self._build_vae()
    
    def _build_lstm_autoencoder(self):
        """Build LSTM autoencoder for sequence anomaly detection"""
        sequence_length = self.config.get('sequence_length', 50)
        n_features = self.config.get('n_features', 1)
        
        # Encoder
        encoder_inputs = layers.Input(shape=(sequence_length, n_features))
        encoder_lstm1 = layers.LSTM(64, return_sequences=True)(encoder_inputs)
        encoder_lstm2 = layers.LSTM(32, return_sequences=False)(encoder_lstm1)
        
        # Decoder
        decoder_lstm1 = layers.RepeatVector(sequence_length)(encoder_lstm2)
        decoder_lstm2 = layers.LSTM(32, return_sequences=True)(decoder_lstm1)
        decoder_lstm3 = layers.LSTM(64, return_sequences=True)(decoder_lstm2)
        decoder_outputs = layers.TimeDistributed(layers.Dense(n_features))(decoder_lstm3)
        
        # Create model
        self.lstm_autoencoder = tf.keras.Model(encoder_inputs, decoder_outputs)
        self.lstm_autoencoder.compile(optimizer='adam', loss='mse', metrics=['mae'])
    
    def _build_vae(self):
        """Build Variational Autoencoder for anomaly detection"""
        sequence_length = self.config.get('sequence_length', 50)
        latent_dim = self.config.get('vae_latent_dim', 10)
        
        # Encoder
        encoder_inputs = layers.Input(shape=(sequence_length,))
        h = layers.Dense(64, activation='relu')(encoder_inputs)
        h = layers.Dense(32, activation='relu')(h)
        
        z_mean = layers.Dense(latent_dim)(h)
        z_log_var = layers.Dense(latent_dim)(h)
        
        # Sampling function
        def sampling(args):
            z_mean, z_log_var = args
            batch = tf.shape(z_mean)[0]
            dim = tf.shape(z_mean)[1]
            epsilon = tf.keras.backend.random_normal(shape=(batch, dim))
            return z_mean + tf.exp(0.5 * z_log_var) * epsilon
        
        z = layers.Lambda(sampling)([z_mean, z_log_var])
        
        # Decoder
        decoder_h = layers.Dense(32, activation='relu')(z)
        decoder_h = layers.Dense(64, activation='relu')(decoder_h)
        decoder_outputs = layers.Dense(sequence_length, activation='sigmoid')(decoder_h)
        
        # Create models
        encoder = tf.keras.Model(encoder_inputs, [z_mean, z_log_var, z])
        decoder_inputs = layers.Input(shape=(latent_dim,))
        decoder_h = layers.Dense(32, activation='relu')(decoder_inputs)
        decoder_h = layers.Dense(64, activation='relu')(decoder_h)
        decoder_outputs = layers.Dense(sequence_length, activation='sigmoid')(decoder_h)
        decoder = tf.keras.Model(decoder_inputs, decoder_outputs)
        
        # VAE model
        outputs = decoder(encoder(encoder_inputs)[2])
        self.vae_model = tf.keras.Model(encoder_inputs, outputs)
        
        # Custom loss function
        def vae_loss(inputs, outputs):
            reconstruction_loss = tf.keras.losses.binary_crossentropy(inputs, outputs)
            reconstruction_loss *= sequence_length
            kl_loss = 1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var)
            kl_loss = tf.reduce_mean(kl_loss)
            kl_loss *= -0.5
            return tf.reduce_mean(reconstruction_loss + kl_loss)
        
        self.vae_model.compile(optimizer='adam', loss=vae_loss)
    
    def create_sequences(self, data: pd.Series, sequence_length: int) -> np.ndarray:
        """Create sequences for LSTM processing"""
        sequences = []
        for i in range(len(data) - sequence_length + 1):
            sequences.append(data.iloc[i:i + sequence_length].values)
        return np.array(sequences)
    
    def detect_isolation_forest_anomalies(self, data: pd.Series) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using Isolation Forest"""
        # Prepare features (value, hour of day, day of week, etc.)
        features = []
        for i, (timestamp, value) in enumerate(data.items()):
            if isinstance(timestamp, datetime):
                hour = timestamp.hour
                day_of_week = timestamp.weekday()
                day_of_month = timestamp.day
            else:
                # Use index if timestamp is not datetime
                hour = i % 24
                day_of_week = (i // 24) % 7
                day_of_month = (i // 24) % 30
            
            features.append([value, hour, day_of_week, day_of_month])
        
        features = np.array(features)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Detect anomalies
        anomaly_labels = self.isolation_forest.fit_predict(features_scaled)
        anomaly_scores = self.isolation_forest.decision_function(features_scaled)
        
        return anomaly_labels, anomaly_scores
    
    def detect_lstm_anomalies(self, data: pd.Series, threshold_percentile: float = 95) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using LSTM autoencoder"""
        sequence_length = self.config.get('sequence_length', 50)
        
        if len(data) < sequence_length:
            logger.warning("Insufficient data for LSTM anomaly detection")
            return np.array([]), np.array([])
        
        # Normalize data
        data_scaled = self.scaler.fit_transform(data.values.reshape(-1, 1)).flatten()
        
        # Create sequences
        sequences = self.create_sequences(pd.Series(data_scaled), sequence_length)
        sequences = sequences.reshape((sequences.shape[0], sequences.shape[1], 1))
        
        # Train if model hasn't been trained
        if not hasattr(self.lstm_autoencoder, 'history'):
            self.lstm_autoencoder.fit(
                sequences, sequences,
                epochs=self.config.get('lstm_epochs', 50),
                batch_size=self.config.get('lstm_batch_size', 32),
                validation_split=0.2,
                verbose=0,
                callbacks=[
                    callbacks.EarlyStopping(patience=10, restore_best_weights=True)
                ]
            )
        
        # Calculate reconstruction errors
        predictions = self.lstm_autoencoder.predict(sequences, verbose=0)
        reconstruction_errors = np.mean(np.square(sequences - predictions), axis=(1, 2))
        
        # Determine threshold
        threshold = np.percentile(reconstruction_errors, threshold_percentile)
        
        # Classify anomalies
        anomaly_labels = (reconstruction_errors > threshold).astype(int)
        
        # Pad to match original data length
        padded_labels = np.zeros(len(data))
        padded_scores = np.zeros(len(data))
        
        padded_labels[sequence_length-1:] = anomaly_labels
        padded_scores[sequence_length-1:] = reconstruction_errors
        
        return padded_labels, padded_scores
    
    def detect_vae_anomalies(self, data: pd.Series, threshold_percentile: float = 95) -> Tuple[np.ndarray, np.ndarray]:
        """Detect anomalies using Variational Autoencoder"""
        if self.vae_model is None:
            logger.warning("VAE model not available")
            return np.array([]), np.array([])
        
        sequence_length = self.config.get('sequence_length', 50)
        
        if len(data) < sequence_length:
            logger.warning("Insufficient data for VAE anomaly detection")
            return np.array([]), np.array([])
        
        # Normalize data
        data_scaled = self.scaler.fit_transform(data.values.reshape(-1, 1)).flatten()
        
        # Create sequences
        sequences = self.create_sequences(pd.Series(data_scaled), sequence_length)
        
        # Train if model hasn't been trained
        if not hasattr(self.vae_model, 'history'):
            self.vae_model.fit(
                sequences, sequences,
                epochs=self.config.get('vae_epochs', 100),
                batch_size=self.config.get('vae_batch_size', 32),
                validation_split=0.2,
                verbose=0
            )
        
        # Calculate reconstruction errors
        reconstructions = self.vae_model.predict(sequences, verbose=0)
        reconstruction_errors = np.mean(np.square(sequences - reconstructions), axis=1)
        
        # Determine threshold
        threshold = np.percentile(reconstruction_errors, threshold_percentile)
        
        # Classify anomalies
        anomaly_labels = (reconstruction_errors > threshold).astype(int)
        
        # Pad to match original data length
        padded_labels = np.zeros(len(data))
        padded_scores = np.zeros(len(data))
        
        padded_labels[sequence_length-1:] = anomaly_labels
        padded_scores[sequence_length-1:] = reconstruction_errors
        
        return padded_labels, padded_scores
    
    def save_models(self):
        """Save trained models"""
        joblib.dump(self.isolation_forest, self.models_dir / "ts_isolation_forest.pkl")
        joblib.dump(self.scaler, self.models_dir / "ts_scaler.pkl")
        
        if hasattr(self.lstm_autoencoder, 'history'):
            self.lstm_autoencoder.save(self.models_dir / "lstm_autoencoder.h5")
        
        if self.vae_model and hasattr(self.vae_model, 'history'):
            self.vae_model.save(self.models_dir / "vae_model.h5")

class SeasonalityAnalyzer:
    """Analyze and detect seasonal patterns in time series"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.seasonal_patterns = {}
    
    def detect_seasonality(self, data: pd.Series) -> Dict[str, SeasonalPattern]:
        """Detect seasonal patterns in the time series"""
        patterns = {}
        
        # Test different periods
        test_periods = [24, 168, 8760]  # hourly, weekly, yearly (in hours)
        
        for period in test_periods:
            if len(data) >= 2 * period:
                strength = self._calculate_seasonal_strength(data, period)
                
                if strength > 0.3:  # Significant seasonality
                    # Extract seasonal component
                    try:
                        decomposition = seasonal_decompose(
                            data.fillna(data.mean()),
                            model='additive',
                            period=period,
                            extrapolate_trend='freq'
                        )
                        
                        seasonal_component = decomposition.seasonal
                        amplitude = seasonal_component.std()
                        phase = seasonal_component.idxmax() % period
                        
                        pattern_type = self._get_pattern_type(period)
                        
                        patterns[pattern_type] = SeasonalPattern(
                            pattern_type=pattern_type,
                            period=period,
                            amplitude=amplitude,
                            phase=phase,
                            strength=strength,
                            last_updated=datetime.now()
                        )
                        
                    except Exception as e:
                        logger.warning(f"Error extracting seasonal pattern for period {period}: {e}")
        
        return patterns
    
    def _calculate_seasonal_strength(self, data: pd.Series, period: int) -> float:
        """Calculate the strength of seasonal pattern"""
        try:
            if len(data) < 2 * period:
                return 0.0
            
            # Use autocorrelation at seasonal lag
            seasonal_autocorr = data.autocorr(lag=period)
            
            # Use F-test for seasonal significance
            n_seasons = len(data) // period
            seasonal_means = []
            
            for i in range(period):
                seasonal_values = [data.iloc[i + j * period] for j in range(n_seasons) 
                                 if i + j * period < len(data)]
                if seasonal_values:
                    seasonal_means.append(np.mean(seasonal_values))
            
            if len(seasonal_means) > 1:
                overall_mean = data.mean()
                between_variance = np.var(seasonal_means) * len(seasonal_means)
                within_variance = data.var()
                
                if within_variance > 0:
                    f_statistic = between_variance / within_variance
                    # Normalize F-statistic to 0-1 range
                    strength = min(1.0, f_statistic / 10.0)
                    return max(0.0, strength)
            
            # Fallback to autocorrelation
            return max(0.0, seasonal_autocorr) if not np.isnan(seasonal_autocorr) else 0.0
            
        except Exception as e:
            logger.warning(f"Error calculating seasonal strength: {e}")
            return 0.0
    
    def _get_pattern_type(self, period: int) -> str:
        """Determine pattern type based on period"""
        if period <= 24:
            return 'hourly'
        elif period <= 168:
            return 'daily'
        elif period <= 8760:
            return 'weekly'
        else:
            return 'yearly'
    
    def detect_seasonal_anomalies(self, data: pd.Series, patterns: Dict[str, SeasonalPattern]) -> List[int]:
        """Detect anomalies in seasonal patterns"""
        anomalous_indices = []
        
        for pattern_type, pattern in patterns.items():
            try:
                # Decompose the series
                decomposition = seasonal_decompose(
                    data.fillna(data.mean()),
                    model='additive',
                    period=pattern.period,
                    extrapolate_trend='freq'
                )
                
                # Analyze residuals for anomalies
                residuals = decomposition.resid.dropna()
                
                # Use statistical methods on residuals
                threshold = 3 * residuals.std()
                seasonal_anomalies = residuals[np.abs(residuals) > threshold]
                
                anomalous_indices.extend(seasonal_anomalies.index.tolist())
                
            except Exception as e:
                logger.warning(f"Error detecting seasonal anomalies for {pattern_type}: {e}")
        
        return list(set(anomalous_indices))  # Remove duplicates

class TimeSeriesAnomalyDetector:
    """Main time series anomaly detection engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/time-series-anomaly.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.statistical_analyzer = StatisticalTimeSeriesAnalyzer(self.config.get('statistical', {}))
        self.ml_detector = MLTimeSeriesAnomalyDetector(self.config.get('ml', {}))
        self.seasonality_analyzer = SeasonalityAnalyzer(self.config.get('seasonality', {}))
        
        # Database for storing results
        self.db_path = "/var/lib/nsm/time_series_anomalies.db"
        self._init_database()
        
        # Time series data cache
        self.time_series_cache = {}
        self.max_cache_size = self.config.get('max_cache_size', 10000)
    
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
            'statistical': {
                'window_size': 100,
                'z_score_threshold': 3.0,
                'iqr_k_factor': 1.5
            },
            'ml': {
                'contamination_rate': 0.1,
                'sequence_length': 50,
                'lstm_epochs': 50,
                'enable_vae': False
            },
            'seasonality': {
                'min_seasonal_strength': 0.3
            },
            'detection': {
                'ensemble_threshold': 2,
                'confidence_boost': 0.2
            }
        }
    
    def _init_database(self):
        """Initialize database for storing anomalies"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS time_series_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT,
                    timestamp TIMESTAMP,
                    actual_value REAL,
                    expected_value REAL,
                    anomaly_score REAL,
                    detection_method TEXT,
                    severity TEXT,
                    confidence REAL,
                    change_point BOOLEAN,
                    trend_direction TEXT,
                    seasonal_component REAL,
                    context TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS seasonal_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT,
                    pattern_type TEXT,
                    period INTEGER,
                    amplitude REAL,
                    phase REAL,
                    strength REAL,
                    last_updated TIMESTAMP
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts_anomalies_metric ON time_series_anomalies(metric_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts_anomalies_timestamp ON time_series_anomalies(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_seasonal_patterns_metric ON seasonal_patterns(metric_name)")
    
    def add_metric_data(self, metric: TimeSeriesMetric):
        """Add metric data to time series cache"""
        if metric.name not in self.time_series_cache:
            self.time_series_cache[metric.name] = []
        
        self.time_series_cache[metric.name].append({
            'timestamp': metric.timestamp,
            'value': metric.value,
            'metadata': metric.metadata or {},
            'tags': metric.tags or {}
        })
        
        # Maintain cache size
        if len(self.time_series_cache[metric.name]) > self.max_cache_size:
            self.time_series_cache[metric.name] = self.time_series_cache[metric.name][-self.max_cache_size:]
    
    def detect_anomalies(self, metric_name: str, method: str = 'ensemble') -> List[TimeSeriesAnomaly]:
        """Detect anomalies in time series data"""
        if metric_name not in self.time_series_cache:
            logger.warning(f"No data available for metric: {metric_name}")
            return []
        
        # Convert cache to pandas Series
        data_points = self.time_series_cache[metric_name]
        timestamps = [point['timestamp'] for point in data_points]
        values = [point['value'] for point in data_points]
        
        ts_data = pd.Series(values, index=pd.DatetimeIndex(timestamps))
        ts_data = ts_data.sort_index()
        
        anomalies = []
        
        if method == 'ensemble' or method == 'all':
            # Run multiple detection methods
            detection_results = {}
            
            # Statistical methods
            z_score_anomalies = self.statistical_analyzer.detect_z_score_anomalies(ts_data)
            iqr_anomalies = self.statistical_analyzer.detect_iqr_anomalies(ts_data)
            grubbs_anomalies = self.statistical_analyzer.detect_grubbs_anomalies(ts_data)
            change_points = self.statistical_analyzer.detect_change_points(ts_data)
            
            # Machine learning methods
            isolation_labels, isolation_scores = self.ml_detector.detect_isolation_forest_anomalies(ts_data)
            lstm_labels, lstm_scores = self.ml_detector.detect_lstm_anomalies(ts_data)
            
            # Seasonal analysis
            seasonal_patterns = self.seasonality_analyzer.detect_seasonality(ts_data)
            seasonal_anomalies = self.seasonality_analyzer.detect_seasonal_anomalies(ts_data, seasonal_patterns)
            
            # Store seasonal patterns
            self._store_seasonal_patterns(metric_name, seasonal_patterns)
            
            # Combine results
            all_anomalous_indices = set()
            detection_methods = {}
            
            # Statistical anomalies
            for idx in z_score_anomalies:
                all_anomalous_indices.add(idx)
                detection_methods[idx] = detection_methods.get(idx, []) + ['z_score']
            
            for idx in iqr_anomalies:
                all_anomalous_indices.add(idx)
                detection_methods[idx] = detection_methods.get(idx, []) + ['iqr']
            
            for idx in grubbs_anomalies:
                all_anomalous_indices.add(idx)
                detection_methods[idx] = detection_methods.get(idx, []) + ['grubbs']
            
            # ML anomalies
            for i, label in enumerate(isolation_labels):
                if label == -1:  # Anomaly
                    idx = ts_data.index[i]
                    all_anomalous_indices.add(idx)
                    detection_methods[idx] = detection_methods.get(idx, []) + ['isolation_forest']
            
            for i, label in enumerate(lstm_labels):
                if label == 1:  # Anomaly
                    idx = ts_data.index[i]
                    all_anomalous_indices.add(idx)
                    detection_methods[idx] = detection_methods.get(idx, []) + ['lstm']
            
            # Seasonal anomalies
            for idx in seasonal_anomalies:
                if idx in ts_data.index:
                    all_anomalous_indices.add(idx)
                    detection_methods[idx] = detection_methods.get(idx, []) + ['seasonal']
            
            # Filter by ensemble threshold
            ensemble_threshold = self.config.get('detection', {}).get('ensemble_threshold', 2)
            
            for idx in all_anomalous_indices:
                methods = detection_methods.get(idx, [])
                
                if len(methods) >= ensemble_threshold:
                    # Calculate expected value (moving average)
                    window_size = min(20, len(ts_data) // 4)
                    expected_value = ts_data.rolling(window=window_size, center=True).mean().loc[idx]
                    if pd.isna(expected_value):
                        expected_value = ts_data.mean()
                    
                    # Calculate anomaly score
                    actual_value = ts_data.loc[idx]
                    anomaly_score = abs(actual_value - expected_value) / max(ts_data.std(), 0.001)
                    
                    # Determine severity
                    severity = self._determine_severity(anomaly_score)
                    
                    # Calculate confidence
                    confidence = min(0.95, len(methods) / len(detection_methods) + 
                                   self.config.get('detection', {}).get('confidence_boost', 0.2))
                    
                    # Check if it's a change point
                    is_change_point = idx in change_points
                    
                    # Get seasonal component if available
                    seasonal_component = None
                    for pattern in seasonal_patterns.values():
                        try:
                            decomposition = seasonal_decompose(
                                ts_data.fillna(ts_data.mean()),
                                model='additive',
                                period=pattern.period,
                                extrapolate_trend='freq'
                            )
                            seasonal_component = decomposition.seasonal.loc[idx]
                            break
                        except:
                            continue
                    
                    anomaly = TimeSeriesAnomaly(
                        metric_name=metric_name,
                        timestamp=idx,
                        actual_value=actual_value,
                        expected_value=expected_value,
                        anomaly_score=anomaly_score,
                        detection_method=','.join(methods),
                        severity=severity,
                        confidence=confidence,
                        change_point=is_change_point,
                        seasonal_component=seasonal_component,
                        context={
                            'window_size': window_size,
                            'methods_count': len(methods),
                            'seasonal_patterns': len(seasonal_patterns)
                        }
                    )
                    
                    anomalies.append(anomaly)
        
        # Store anomalies in database
        for anomaly in anomalies:
            self._store_anomaly(anomaly)
        
        return anomalies
    
    def _determine_severity(self, anomaly_score: float) -> str:
        """Determine severity based on anomaly score"""
        if anomaly_score >= 5.0:
            return 'critical'
        elif anomaly_score >= 3.0:
            return 'high'
        elif anomaly_score >= 2.0:
            return 'medium'
        else:
            return 'low'
    
    def _store_seasonal_patterns(self, metric_name: str, patterns: Dict[str, SeasonalPattern]):
        """Store seasonal patterns in database"""
        with sqlite3.connect(self.db_path) as conn:
            # Clear existing patterns for this metric
            conn.execute("DELETE FROM seasonal_patterns WHERE metric_name = ?", (metric_name,))
            
            # Insert new patterns
            for pattern in patterns.values():
                conn.execute("""
                    INSERT INTO seasonal_patterns 
                    (metric_name, pattern_type, period, amplitude, phase, strength, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    metric_name,
                    pattern.pattern_type,
                    pattern.period,
                    pattern.amplitude,
                    pattern.phase,
                    pattern.strength,
                    pattern.last_updated
                ))
    
    def _store_anomaly(self, anomaly: TimeSeriesAnomaly):
        """Store anomaly in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO time_series_anomalies 
                (metric_name, timestamp, actual_value, expected_value, anomaly_score,
                 detection_method, severity, confidence, change_point, trend_direction,
                 seasonal_component, context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                anomaly.metric_name,
                anomaly.timestamp,
                anomaly.actual_value,
                anomaly.expected_value,
                anomaly.anomaly_score,
                anomaly.detection_method,
                anomaly.severity,
                anomaly.confidence,
                anomaly.change_point,
                anomaly.trend_direction,
                anomaly.seasonal_component,
                json.dumps(anomaly.context, default=str)
            ))
    
    def get_anomalies(self, metric_name: str = None, start_time: datetime = None, 
                     end_time: datetime = None, severity: str = None) -> List[TimeSeriesAnomaly]:
        """Retrieve anomalies from database"""
        query = "SELECT * FROM time_series_anomalies WHERE 1=1"
        params = []
        
        if metric_name:
            query += " AND metric_name = ?"
            params.append(metric_name)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        query += " ORDER BY timestamp DESC"
        
        anomalies = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            
            for row in cursor.fetchall():
                anomaly = TimeSeriesAnomaly(
                    metric_name=row[1],
                    timestamp=datetime.fromisoformat(row[2]),
                    actual_value=row[3],
                    expected_value=row[4],
                    anomaly_score=row[5],
                    detection_method=row[6],
                    severity=row[7],
                    confidence=row[8],
                    change_point=bool(row[9]),
                    trend_direction=row[10],
                    seasonal_component=row[11],
                    context=json.loads(row[12]) if row[12] else {}
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def save_models(self):
        """Save trained models"""
        self.ml_detector.save_models()

async def main():
    """Main function for time series anomaly detector"""
    detector = TimeSeriesAnomalyDetector()
    
    # Example usage
    current_time = datetime.now()
    
    # Simulate adding time series data
    for i in range(1000):
        timestamp = current_time - timedelta(hours=1000-i)
        # Simulate normal pattern with anomalies
        base_value = 100 + 20 * np.sin(2 * np.pi * i / 24)  # Daily pattern
        noise = np.random.normal(0, 5)
        
        # Add some anomalies
        if i in [100, 200, 300, 500, 800]:
            value = base_value + np.random.normal(0, 50)  # Anomalous value
        else:
            value = base_value + noise
        
        metric = TimeSeriesMetric(
            name="network_traffic_volume",
            timestamp=timestamp,
            value=value
        )
        
        detector.add_metric_data(metric)
    
    # Detect anomalies
    anomalies = detector.detect_anomalies("network_traffic_volume")
    
    logger.info(f"Detected {len(anomalies)} anomalies")
    for anomaly in anomalies[:5]:  # Show first 5
        logger.info(f"Anomaly at {anomaly.timestamp}: {anomaly.actual_value:.2f} "
                   f"(expected: {anomaly.expected_value:.2f}, score: {anomaly.anomaly_score:.2f}, "
                   f"severity: {anomaly.severity})")

if __name__ == "__main__":
    asyncio.run(main())