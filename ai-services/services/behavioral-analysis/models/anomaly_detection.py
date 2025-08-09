"""
Advanced anomaly detection models for behavioral analysis.

This module provides comprehensive anomaly detection capabilities using
multiple ML algorithms and ensemble methods for robust threat detection.
"""

import pickle
import warnings
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import tensorflow as tf
from scipy import stats
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import MinMaxScaler, RobustScaler
from sklearn.svm import OneClassSVM
import torch
import torch.nn as nn
import torch.optim as optim

from .baseline import BehavioralBaseline, BaselineModel
from .feature_engineering import BehavioralFeatures

warnings.filterwarnings('ignore', category=UserWarning)


class AnomalyResult:
    """Container for anomaly detection results."""
    
    def __init__(self, entity_id: str, anomaly_score: float, 
                 is_anomaly: bool, confidence: float,
                 contributing_features: Dict[str, float] = None,
                 anomaly_type: str = "general"):
        self.entity_id = entity_id
        self.anomaly_score = anomaly_score  # 0.0 to 1.0
        self.is_anomaly = is_anomaly
        self.confidence = confidence  # 0.0 to 1.0
        self.contributing_features = contributing_features or {}
        self.anomaly_type = anomaly_type
        self.timestamp = datetime.utcnow()
        self.model_version = "1.0"
        self.detection_method = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "entity_id": self.entity_id,
            "anomaly_score": float(self.anomaly_score),
            "is_anomaly": self.is_anomaly,
            "confidence": float(self.confidence),
            "contributing_features": {k: float(v) for k, v in self.contributing_features.items()},
            "anomaly_type": self.anomaly_type,
            "timestamp": self.timestamp.isoformat(),
            "model_version": self.model_version,
            "detection_method": self.detection_method
        }


class BaseAnomalyDetector(ABC):
    """Base class for anomaly detectors."""
    
    def __init__(self, name: str, threshold: float = 0.5):
        self.name = name
        self.threshold = threshold
        self.is_trained = False
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = []
    
    @abstractmethod
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train the anomaly detector."""
        pass
    
    @abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores."""
        pass
    
    def fit_predict(self, X: np.ndarray, feature_names: List[str] = None) -> np.ndarray:
        """Fit model and predict anomalies."""
        self.fit(X, feature_names)
        return self.predict(X)
    
    def _normalize_features(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Normalize features for training/prediction."""
        if X.size == 0:
            return X
        
        if fit or self.scaler is None:
            self.scaler = RobustScaler()
            return self.scaler.fit_transform(X)
        else:
            return self.scaler.transform(X)


class IsolationForestDetector(BaseAnomalyDetector):
    """Isolation Forest based anomaly detector."""
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100):
        super().__init__("IsolationForest")
        self.contamination = contamination
        self.n_estimators = n_estimators
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train Isolation Forest model."""
        if X.size == 0:
            return
        
        self.feature_names = feature_names or []
        X_normalized = self._normalize_features(X, fit=True)
        
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_normalized)
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using Isolation Forest."""
        if not self.is_trained or X.size == 0:
            return np.zeros(X.shape[0])
        
        X_normalized = self._normalize_features(X)
        
        # Get anomaly scores (negative scores for outliers)
        scores = self.model.decision_function(X_normalized)
        
        # Normalize to [0, 1] range
        scores_normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        
        # Invert so higher scores indicate more anomalous
        return 1 - scores_normalized


class LocalOutlierFactorDetector(BaseAnomalyDetector):
    """Local Outlier Factor based anomaly detector."""
    
    def __init__(self, n_neighbors: int = 20, contamination: float = 0.1):
        super().__init__("LocalOutlierFactor")
        self.n_neighbors = n_neighbors
        self.contamination = contamination
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train LOF model."""
        if X.size == 0:
            return
        
        self.feature_names = feature_names or []
        X_normalized = self._normalize_features(X, fit=True)
        
        self.model = LocalOutlierFactor(
            n_neighbors=min(self.n_neighbors, X.shape[0] - 1),
            contamination=self.contamination,
            novelty=True  # For prediction on new data
        )
        
        self.model.fit(X_normalized)
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using LOF."""
        if not self.is_trained or X.size == 0:
            return np.zeros(X.shape[0])
        
        X_normalized = self._normalize_features(X)
        
        # Get anomaly scores
        scores = self.model.decision_function(X_normalized)
        
        # Normalize to [0, 1] range
        scores_normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        
        # Invert so higher scores indicate more anomalous
        return 1 - scores_normalized


class OneClassSVMDetector(BaseAnomalyDetector):
    """One-Class SVM based anomaly detector."""
    
    def __init__(self, kernel: str = 'rbf', gamma: str = 'scale', nu: float = 0.1):
        super().__init__("OneClassSVM")
        self.kernel = kernel
        self.gamma = gamma
        self.nu = nu
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train One-Class SVM model."""
        if X.size == 0:
            return
        
        self.feature_names = feature_names or []
        X_normalized = self._normalize_features(X, fit=True)
        
        self.model = OneClassSVM(
            kernel=self.kernel,
            gamma=self.gamma,
            nu=self.nu
        )
        
        self.model.fit(X_normalized)
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using One-Class SVM."""
        if not self.is_trained or X.size == 0:
            return np.zeros(X.shape[0])
        
        X_normalized = self._normalize_features(X)
        
        # Get anomaly scores
        scores = self.model.decision_function(X_normalized)
        
        # Normalize to [0, 1] range
        scores_normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        
        # Invert so higher scores indicate more anomalous
        return 1 - scores_normalized


class EllipticEnvelopeDetector(BaseAnomalyDetector):
    """Elliptic Envelope (Robust Covariance) based anomaly detector."""
    
    def __init__(self, contamination: float = 0.1, support_fraction: float = None):
        super().__init__("EllipticEnvelope")
        self.contamination = contamination
        self.support_fraction = support_fraction
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train Elliptic Envelope model."""
        if X.size == 0:
            return
        
        self.feature_names = feature_names or []
        X_normalized = self._normalize_features(X, fit=True)
        
        self.model = EllipticEnvelope(
            contamination=self.contamination,
            support_fraction=self.support_fraction,
            random_state=42
        )
        
        self.model.fit(X_normalized)
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using Elliptic Envelope."""
        if not self.is_trained or X.size == 0:
            return np.zeros(X.shape[0])
        
        X_normalized = self._normalize_features(X)
        
        # Get anomaly scores
        scores = self.model.decision_function(X_normalized)
        
        # Normalize to [0, 1] range
        scores_normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        
        # Invert so higher scores indicate more anomalous
        return 1 - scores_normalized


class AutoencoderDetector(BaseAnomalyDetector):
    """Autoencoder neural network based anomaly detector."""
    
    def __init__(self, latent_dim: int = 32, epochs: int = 100, batch_size: int = 32):
        super().__init__("Autoencoder")
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.input_dim = None
    
    def _build_model(self, input_dim: int):
        """Build autoencoder model."""
        # Encoder
        encoder_input = tf.keras.Input(shape=(input_dim,))
        x = tf.keras.layers.Dense(input_dim // 2, activation='relu')(encoder_input)
        x = tf.keras.layers.Dropout(0.2)(x)
        x = tf.keras.layers.Dense(input_dim // 4, activation='relu')(x)
        x = tf.keras.layers.Dropout(0.2)(x)
        encoded = tf.keras.layers.Dense(self.latent_dim, activation='relu')(x)
        
        # Decoder
        x = tf.keras.layers.Dense(input_dim // 4, activation='relu')(encoded)
        x = tf.keras.layers.Dropout(0.2)(x)
        x = tf.keras.layers.Dense(input_dim // 2, activation='relu')(x)
        x = tf.keras.layers.Dropout(0.2)(x)
        decoded = tf.keras.layers.Dense(input_dim, activation='sigmoid')(x)
        
        # Autoencoder model
        autoencoder = tf.keras.Model(encoder_input, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        return autoencoder
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train autoencoder model."""
        if X.size == 0:
            return
        
        self.feature_names = feature_names or []
        X_normalized = self._normalize_features(X, fit=True)
        
        self.input_dim = X_normalized.shape[1]
        self.model = self._build_model(self.input_dim)
        
        # Train the model
        self.model.fit(
            X_normalized, X_normalized,
            epochs=self.epochs,
            batch_size=min(self.batch_size, X.shape[0]),
            validation_split=0.1,
            verbose=0,
            shuffle=True
        )
        
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using autoencoder reconstruction error."""
        if not self.is_trained or X.size == 0:
            return np.zeros(X.shape[0])
        
        X_normalized = self._normalize_features(X)
        
        # Get reconstructions
        reconstructions = self.model.predict(X_normalized, verbose=0)
        
        # Calculate reconstruction errors
        mse = np.mean(np.power(X_normalized - reconstructions, 2), axis=1)
        
        # Normalize to [0, 1] range
        max_error = np.percentile(mse, 99)  # Use 99th percentile to avoid outliers
        scores = np.clip(mse / (max_error + 1e-10), 0, 1)
        
        return scores


class LSTMDetector(BaseAnomalyDetector):
    """LSTM-based sequence anomaly detector for temporal patterns."""
    
    def __init__(self, sequence_length: int = 10, hidden_dim: int = 64, 
                 epochs: int = 50, batch_size: int = 32):
        super().__init__("LSTM")
        self.sequence_length = sequence_length
        self.hidden_dim = hidden_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.input_dim = None
        
    def _create_sequences(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM training."""
        sequences = []
        targets = []
        
        for i in range(len(X) - self.sequence_length):
            sequences.append(X[i:i + self.sequence_length])
            targets.append(X[i + self.sequence_length])
        
        return np.array(sequences), np.array(targets)
    
    def _build_model(self, input_dim: int):
        """Build LSTM model."""
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(self.hidden_dim, return_sequences=True, 
                               input_shape=(self.sequence_length, input_dim)),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.LSTM(self.hidden_dim // 2, return_sequences=False),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(input_dim, activation='sigmoid')
        ])
        
        model.compile(optimizer='adam', loss='mse')
        return model
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train LSTM model."""
        if X.size == 0 or len(X) <= self.sequence_length:
            return
        
        self.feature_names = feature_names or []
        X_normalized = self._normalize_features(X, fit=True)
        
        self.input_dim = X_normalized.shape[1]
        
        # Create sequences
        X_seq, y_seq = self._create_sequences(X_normalized)
        
        if len(X_seq) == 0:
            return
        
        self.model = self._build_model(self.input_dim)
        
        # Train the model
        self.model.fit(
            X_seq, y_seq,
            epochs=self.epochs,
            batch_size=min(self.batch_size, len(X_seq)),
            validation_split=0.1,
            verbose=0,
            shuffle=True
        )
        
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using LSTM prediction error."""
        if not self.is_trained or X.size == 0 or len(X) <= self.sequence_length:
            return np.zeros(X.shape[0])
        
        X_normalized = self._normalize_features(X)
        scores = []
        
        # Calculate prediction errors for each possible sequence
        for i in range(len(X_normalized) - self.sequence_length + 1):
            sequence = X_normalized[i:i + self.sequence_length]
            sequence = sequence.reshape(1, self.sequence_length, -1)
            
            prediction = self.model.predict(sequence, verbose=0)
            actual = X_normalized[i + self.sequence_length - 1]
            
            # Calculate prediction error
            error = np.mean(np.power(actual - prediction[0], 2))
            scores.append(error)
        
        # Pad scores for missing initial points
        padded_scores = [0] * self.sequence_length + scores
        
        # Normalize to [0, 1] range
        if scores:
            max_error = np.percentile(scores, 99)
            padded_scores = [min(score / (max_error + 1e-10), 1.0) for score in padded_scores]
        
        return np.array(padded_scores[:len(X)])


class EnsembleAnomalyDetector:
    """Ensemble anomaly detector combining multiple algorithms."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.detectors: List[BaseAnomalyDetector] = []
        self.weights: List[float] = []
        self.is_trained = False
        self.feature_names: List[str] = []
        
        # Initialize detectors
        self._initialize_detectors()
    
    def _initialize_detectors(self):
        """Initialize ensemble detectors."""
        contamination = self.config.get("contamination", 0.1)
        
        # Traditional ML detectors
        self.detectors.extend([
            IsolationForestDetector(contamination=contamination, n_estimators=100),
            LocalOutlierFactorDetector(n_neighbors=20, contamination=contamination),
            OneClassSVMDetector(kernel='rbf', nu=contamination),
            EllipticEnvelopeDetector(contamination=contamination),
        ])
        
        # Deep learning detectors
        if self.config.get("use_deep_learning", True):
            self.detectors.extend([
                AutoencoderDetector(
                    latent_dim=self.config.get("autoencoder_latent_dim", 32),
                    epochs=self.config.get("autoencoder_epochs", 50)
                ),
                LSTMDetector(
                    sequence_length=self.config.get("lstm_sequence_length", 10),
                    epochs=self.config.get("lstm_epochs", 30)
                )
            ])
        
        # Initialize equal weights
        self.weights = [1.0] * len(self.detectors)
    
    def fit(self, X: np.ndarray, feature_names: List[str] = None):
        """Train all detectors in the ensemble."""
        if X.size == 0:
            return
        
        self.feature_names = feature_names or []
        
        # Train each detector
        for detector in self.detectors:
            try:
                detector.fit(X, feature_names)
            except Exception as e:
                print(f"Failed to train {detector.name}: {e}")
                # Set weight to 0 for failed detectors
                idx = self.detectors.index(detector)
                self.weights[idx] = 0.0
        
        # Normalize weights
        total_weight = sum(self.weights)
        if total_weight > 0:
            self.weights = [w / total_weight for w in self.weights]
        
        self.is_trained = True
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict anomaly scores using ensemble."""
        if not self.is_trained or X.size == 0:
            return np.zeros(X.shape[0])
        
        ensemble_scores = np.zeros(X.shape[0])
        
        for detector, weight in zip(self.detectors, self.weights):
            if weight > 0:
                try:
                    scores = detector.predict(X)
                    ensemble_scores += weight * scores
                except Exception as e:
                    print(f"Failed to predict with {detector.name}: {e}")
        
        return ensemble_scores
    
    def get_detector_contributions(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """Get individual detector contributions."""
        contributions = {}
        
        for detector, weight in zip(self.detectors, self.weights):
            if weight > 0:
                try:
                    scores = detector.predict(X)
                    contributions[detector.name] = scores * weight
                except Exception:
                    contributions[detector.name] = np.zeros(X.shape[0])
        
        return contributions


class AnomalyDetector:
    """Main anomaly detection class integrating with baseline models."""
    
    def __init__(self, baseline_model: BaselineModel, config: Dict = None):
        self.baseline_model = baseline_model
        self.config = config or {}
        
        # Ensemble detector
        self.ensemble = EnsembleAnomalyDetector(config)
        
        # Detection parameters
        self.anomaly_threshold = self.config.get("anomaly_threshold", 0.7)
        self.confidence_threshold = self.config.get("confidence_threshold", 0.8)
        
        # Tracking
        self.detection_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.last_training_time: Optional[datetime] = None
        self.training_frequency = timedelta(hours=self.config.get("training_frequency_hours", 24))
    
    def detect_anomalies(self, entity_id: str, features: BehavioralFeatures) -> AnomalyResult:
        """Detect anomalies for a single entity."""
        # Get baseline for entity
        baseline = self.baseline_model.get_baseline(entity_id)
        
        if not baseline or not baseline.is_stable():
            # No reliable baseline - return low confidence result
            return AnomalyResult(
                entity_id=entity_id,
                anomaly_score=0.0,
                is_anomaly=False,
                confidence=0.1,
                anomaly_type="insufficient_baseline"
            )
        
        # Calculate baseline deviations
        baseline_deviations = self.baseline_model.calculate_baseline_deviation(entity_id, features)
        overall_baseline_score = self.baseline_model.calculate_overall_anomaly_score(entity_id, features)
        
        # Get ensemble prediction if available
        ensemble_score = 0.0
        if self.ensemble.is_trained:
            feature_vector = features.get_feature_vector(self.ensemble.feature_names)
            if feature_vector.size > 0:
                ensemble_scores = self.ensemble.predict(feature_vector.reshape(1, -1))
                ensemble_score = ensemble_scores[0]
        
        # Combine scores
        combined_score = self._combine_anomaly_scores(
            baseline_score=overall_baseline_score,
            ensemble_score=ensemble_score,
            baseline_confidence=baseline.confidence_score
        )
        
        # Determine if anomalous
        is_anomaly = combined_score >= self.anomaly_threshold
        
        # Calculate confidence
        confidence = self._calculate_detection_confidence(
            baseline=baseline,
            combined_score=combined_score,
            baseline_deviations=baseline_deviations
        )
        
        # Create result
        result = AnomalyResult(
            entity_id=entity_id,
            anomaly_score=combined_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
            contributing_features=baseline_deviations,
            anomaly_type=self._classify_anomaly_type(baseline_deviations, features)
        )
        
        result.detection_method = "baseline+ensemble" if self.ensemble.is_trained else "baseline_only"
        
        # Update detection history
        self.detection_history[entity_id].append({
            "timestamp": datetime.utcnow(),
            "score": combined_score,
            "is_anomaly": is_anomaly
        })
        
        return result
    
    def detect_batch_anomalies(self, features_dict: Dict[str, BehavioralFeatures]) -> Dict[str, AnomalyResult]:
        """Detect anomalies for multiple entities."""
        results = {}
        
        for entity_id, features in features_dict.items():
            results[entity_id] = self.detect_anomalies(entity_id, features)
        
        return results
    
    def train_ensemble(self, training_data: Dict[str, List[BehavioralFeatures]]):
        """Train ensemble models with historical data."""
        # Prepare training data
        all_features = []
        all_feature_names = set()
        
        for entity_features_list in training_data.values():
            for features in entity_features_list:
                all_features.append(features)
                all_feature_names.update(features.features.keys())
        
        if not all_features:
            return
        
        # Extract feature matrix
        feature_names = sorted(list(all_feature_names))
        feature_matrix = np.array([
            features.get_feature_vector(feature_names)
            for features in all_features
        ])
        
        # Train ensemble
        self.ensemble.fit(feature_matrix, feature_names)
        self.last_training_time = datetime.utcnow()
    
    def _combine_anomaly_scores(self, baseline_score: float, ensemble_score: float,
                              baseline_confidence: float) -> float:
        """Combine different anomaly scores into final score."""
        if not self.ensemble.is_trained:
            return baseline_score
        
        # Weight based on baseline confidence
        baseline_weight = baseline_confidence
        ensemble_weight = 1.0 - baseline_confidence
        
        # Normalize weights
        total_weight = baseline_weight + ensemble_weight
        if total_weight > 0:
            baseline_weight /= total_weight
            ensemble_weight /= total_weight
        
        combined = baseline_weight * baseline_score + ensemble_weight * ensemble_score
        return min(combined, 1.0)
    
    def _calculate_detection_confidence(self, baseline: BehavioralBaseline,
                                      combined_score: float,
                                      baseline_deviations: Dict[str, float]) -> float:
        """Calculate confidence in anomaly detection."""
        confidence_factors = []
        
        # Baseline quality factor
        confidence_factors.append(baseline.confidence_score)
        
        # Score consistency factor (higher scores = more confident)
        score_confidence = min(combined_score * 2, 1.0)  # Scale to [0, 1]
        confidence_factors.append(score_confidence)
        
        # Feature agreement factor
        if baseline_deviations:
            significant_deviations = sum(1 for score in baseline_deviations.values() if score > 0.5)
            feature_agreement = significant_deviations / len(baseline_deviations)
            confidence_factors.append(feature_agreement)
        
        # Ensemble agreement factor
        if self.ensemble.is_trained:
            confidence_factors.append(0.8)  # Ensemble adds confidence
        
        return np.mean(confidence_factors)
    
    def _classify_anomaly_type(self, baseline_deviations: Dict[str, float],
                             features: BehavioralFeatures) -> str:
        """Classify the type of anomaly detected."""
        if not baseline_deviations:
            return "general"
        
        # Find the most contributing feature category
        category_scores = defaultdict(list)
        
        for feature_name, deviation in baseline_deviations.items():
            category = features.metadata.get(feature_name, {}).get("category", "general")
            category_scores[category].append(deviation)
        
        # Calculate average deviation per category
        category_averages = {
            category: np.mean(scores)
            for category, scores in category_scores.items()
        }
        
        # Return category with highest average deviation
        if category_averages:
            dominant_category = max(category_averages, key=category_averages.get)
            
            # Map to specific anomaly types
            type_mapping = {
                "temporal": "temporal_anomaly",
                "access_pattern": "access_anomaly", 
                "contextual": "behavioral_anomaly"
            }
            
            return type_mapping.get(dominant_category, "general_anomaly")
        
        return "general"
    
    def get_detection_statistics(self, entity_id: str = None) -> Dict[str, Any]:
        """Get detection statistics for monitoring."""
        if entity_id:
            history = list(self.detection_history.get(entity_id, []))
            if not history:
                return {"entity_id": entity_id, "detection_count": 0}
            
            recent_detections = [h for h in history if h["timestamp"] > datetime.utcnow() - timedelta(hours=24)]
            
            return {
                "entity_id": entity_id,
                "detection_count": len(history),
                "recent_detections": len(recent_detections),
                "recent_anomaly_rate": sum(1 for h in recent_detections if h["is_anomaly"]) / max(len(recent_detections), 1),
                "avg_anomaly_score": np.mean([h["score"] for h in recent_detections]) if recent_detections else 0,
            }
        else:
            # Global statistics
            total_detections = sum(len(history) for history in self.detection_history.values())
            
            return {
                "total_entities": len(self.detection_history),
                "total_detections": total_detections,
                "ensemble_trained": self.ensemble.is_trained,
                "last_training": self.last_training_time.isoformat() if self.last_training_time else None,
                "anomaly_threshold": self.anomaly_threshold,
                "active_detectors": len([d for d, w in zip(self.ensemble.detectors, self.ensemble.weights) if w > 0]),
            }
    
    def should_retrain(self) -> bool:
        """Check if ensemble should be retrained."""
        if not self.last_training_time:
            return True
        
        return datetime.utcnow() - self.last_training_time >= self.training_frequency
    
    def update_thresholds(self, anomaly_threshold: float = None,
                         confidence_threshold: float = None):
        """Update detection thresholds."""
        if anomaly_threshold is not None:
            self.anomaly_threshold = max(0.0, min(1.0, anomaly_threshold))
        
        if confidence_threshold is not None:
            self.confidence_threshold = max(0.0, min(1.0, confidence_threshold))