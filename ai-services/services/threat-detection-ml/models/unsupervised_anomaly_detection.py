"""
Unsupervised Anomaly Detection Models for AI/ML Threat Detection

This module implements advanced unsupervised learning models to detect deviations
from established behavioral baselines, identifying potential anomalies using
multiple detection approaches including autoencoders, isolation forests,
clustering-based outlier detection, and statistical methods.
"""

import asyncio
import logging
import json
import pickle
import joblib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN, KMeans
from sklearn.svm import OneClassSVM
from sklearn.covariance import EllipticEnvelope
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import mlflow
import mlflow.pytorch
import mlflow.sklearn
from pydantic import BaseModel, Field

from .behavioral_analytics import BehaviorProfile, BehavioralAnomaly, BehaviorType, AnomalyType
from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector
from ...shared.mlflow.integration import MLFlowManager


logger = logging.getLogger(__name__)


class AnomalyDetectionMethod(Enum):
    """Types of unsupervised anomaly detection methods."""
    AUTOENCODER = "autoencoder"
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    DBSCAN_OUTLIER = "dbscan_outlier"
    LOCAL_OUTLIER_FACTOR = "local_outlier_factor"
    ELLIPTIC_ENVELOPE = "elliptic_envelope"
    STATISTICAL_OUTLIER = "statistical_outlier"
    ENSEMBLE = "ensemble"


@dataclass
class AnomalyDetectionConfig:
    """Configuration for anomaly detection models."""
    # General settings
    contamination_rate: float = 0.1  # Expected proportion of anomalies
    random_state: int = 42
    n_jobs: int = -1
    
    # Isolation Forest settings
    n_estimators: int = 100
    max_samples: str = "auto"
    max_features: float = 1.0
    
    # One-Class SVM settings
    kernel: str = "rbf"
    gamma: str = "scale"
    nu: float = 0.1
    
    # DBSCAN settings
    eps: float = 0.5
    min_samples: int = 5
    
    # Local Outlier Factor settings
    n_neighbors: int = 20
    
    # Autoencoder settings
    encoding_dim: int = 32
    hidden_dims: List[int] = field(default_factory=lambda: [64, 32])
    batch_size: int = 32
    epochs: int = 100
    learning_rate: float = 0.001
    validation_split: float = 0.2
    
    # Ensemble settings
    voting_threshold: float = 0.5  # Fraction of models that must agree
    
    # Feature preprocessing
    feature_scaling: str = "robust"  # 'standard', 'robust', 'minmax'
    pca_components: Optional[int] = None  # Use PCA dimensionality reduction
    
    # Performance settings
    enable_gpu: bool = False
    model_cache_size: int = 10


class AnomalyScore(BaseModel):
    """Represents an anomaly score from detection models."""
    event_id: str
    method: AnomalyDetectionMethod
    anomaly_score: float = Field(ge=-1.0, le=1.0)  # Normalized score
    is_anomaly: bool
    confidence: float = Field(ge=0.0, le=1.0)
    feature_contributions: Dict[str, float] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            AnomalyDetectionMethod: lambda v: v.value
        }


class AutoEncoder(nn.Module):
    """Deep autoencoder for unsupervised anomaly detection."""
    
    def __init__(self, input_dim: int, encoding_dim: int, hidden_dims: List[int]):
        super(AutoEncoder, self).__init__()
        
        # Build encoder
        encoder_layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        encoder_layers.append(nn.Linear(prev_dim, encoding_dim))
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Build decoder (reverse of encoder)
        decoder_layers = []
        prev_dim = encoding_dim
        
        for hidden_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)
        
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        return self.encoder(x)
    
    def decode(self, encoded):
        return self.decoder(encoded)


class BaseAnomalyDetector(ABC):
    """Abstract base class for anomaly detection models."""
    
    def __init__(self, config: AnomalyDetectionConfig, method: AnomalyDetectionMethod):
        self.config = config
        self.method = method
        self.model = None
        self.scaler = None
        self.pca = None
        self.is_fitted = False
        self.feature_names = []
        
    @abstractmethod
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit the anomaly detection model."""
        pass
    
    @abstractmethod
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores for input data."""
        pass
    
    def _preprocess_features(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Preprocess features with scaling and optional PCA."""
        if fit:
            # Initialize scaler
            if self.config.feature_scaling == "standard":
                self.scaler = StandardScaler()
            elif self.config.feature_scaling == "robust":
                self.scaler = RobustScaler()
            elif self.config.feature_scaling == "minmax":
                self.scaler = MinMaxScaler()
            
            X_scaled = self.scaler.fit_transform(X)
            
            # Apply PCA if configured
            if self.config.pca_components and self.config.pca_components < X.shape[1]:
                self.pca = PCA(n_components=self.config.pca_components, random_state=self.config.random_state)
                X_scaled = self.pca.fit_transform(X_scaled)
                logger.info(f"Applied PCA: {X.shape[1]} -> {X_scaled.shape[1]} dimensions")
        else:
            if self.scaler is None:
                raise ValueError("Model must be fitted before preprocessing")
            
            X_scaled = self.scaler.transform(X)
            if self.pca is not None:
                X_scaled = self.pca.transform(X_scaled)
        
        return X_scaled
    
    def save_model(self, filepath: str) -> None:
        """Save the trained model to disk."""
        model_data = {
            'method': self.method.value,
            'config': self.config.__dict__,
            'scaler': self.scaler,
            'pca': self.pca,
            'is_fitted': self.is_fitted,
            'feature_names': self.feature_names
        }
        
        # Handle different model types
        if self.method == AnomalyDetectionMethod.AUTOENCODER:
            torch.save(self.model.state_dict(), filepath + '.pth')
            model_data['model_path'] = filepath + '.pth'
        else:
            model_data['model'] = self.model
        
        joblib.dump(model_data, filepath)
        logger.info(f"Saved {self.method.value} model to {filepath}")
    
    def load_model(self, filepath: str) -> None:
        """Load a trained model from disk."""
        model_data = joblib.load(filepath)
        
        self.config = AnomalyDetectionConfig(**model_data['config'])
        self.scaler = model_data['scaler']
        self.pca = model_data['pca']
        self.is_fitted = model_data['is_fitted']
        self.feature_names = model_data['feature_names']
        
        if self.method == AnomalyDetectionMethod.AUTOENCODER:
            # Reconstruct autoencoder architecture
            input_dim = len(self.feature_names)
            if self.pca:
                input_dim = self.pca.n_components_
            
            self.model = AutoEncoder(
                input_dim=input_dim,
                encoding_dim=self.config.encoding_dim,
                hidden_dims=self.config.hidden_dims
            )
            self.model.load_state_dict(torch.load(model_data['model_path']))
            self.model.eval()
        else:
            self.model = model_data['model']
        
        logger.info(f"Loaded {self.method.value} model from {filepath}")


class IsolationForestDetector(BaseAnomalyDetector):
    """Isolation Forest based anomaly detector."""
    
    def __init__(self, config: AnomalyDetectionConfig):
        super().__init__(config, AnomalyDetectionMethod.ISOLATION_FOREST)
    
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit the Isolation Forest model."""
        self.feature_names = feature_names
        X_processed = self._preprocess_features(X, fit=True)
        
        self.model = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            max_features=self.config.max_features,
            contamination=self.config.contamination_rate,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs
        )
        
        self.model.fit(X_processed)
        self.is_fitted = True
        logger.info(f"Fitted Isolation Forest with {X_processed.shape[0]} samples, {X_processed.shape[1]} features")
    
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores using Isolation Forest."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_processed = self._preprocess_features(X, fit=False)
        
        # Get anomaly scores and predictions
        anomaly_scores = self.model.decision_function(X_processed)
        predictions = self.model.predict(X_processed)
        
        results = []
        for i, (score, pred) in enumerate(zip(anomaly_scores, predictions)):
            # Normalize score to [0, 1] range
            normalized_score = (score - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min())
            
            results.append(AnomalyScore(
                event_id=f"event_{i}",
                method=self.method,
                anomaly_score=float(score),
                is_anomaly=pred == -1,
                confidence=float(normalized_score),
                feature_contributions={}
            ))
        
        return results


class OneClassSVMDetector(BaseAnomalyDetector):
    """One-Class SVM based anomaly detector."""
    
    def __init__(self, config: AnomalyDetectionConfig):
        super().__init__(config, AnomalyDetectionMethod.ONE_CLASS_SVM)
    
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit the One-Class SVM model."""
        self.feature_names = feature_names
        X_processed = self._preprocess_features(X, fit=True)
        
        self.model = OneClassSVM(
            kernel=self.config.kernel,
            gamma=self.config.gamma,
            nu=self.config.nu
        )
        
        self.model.fit(X_processed)
        self.is_fitted = True
        logger.info(f"Fitted One-Class SVM with {X_processed.shape[0]} samples, {X_processed.shape[1]} features")
    
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores using One-Class SVM."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_processed = self._preprocess_features(X, fit=False)
        
        # Get decision scores and predictions
        decision_scores = self.model.decision_function(X_processed)
        predictions = self.model.predict(X_processed)
        
        results = []
        for i, (score, pred) in enumerate(zip(decision_scores, predictions)):
            # Convert decision score to confidence
            confidence = 1.0 / (1.0 + np.exp(-abs(score)))  # Sigmoid transformation
            
            results.append(AnomalyScore(
                event_id=f"event_{i}",
                method=self.method,
                anomaly_score=float(score),
                is_anomaly=pred == -1,
                confidence=float(confidence),
                feature_contributions={}
            ))
        
        return results


class AutoEncoderDetector(BaseAnomalyDetector):
    """Autoencoder based anomaly detector."""
    
    def __init__(self, config: AnomalyDetectionConfig):
        super().__init__(config, AnomalyDetectionMethod.AUTOENCODER)
        self.reconstruction_threshold = None
    
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit the autoencoder model."""
        self.feature_names = feature_names
        X_processed = self._preprocess_features(X, fit=True)
        
        # Determine input dimension
        input_dim = X_processed.shape[1]
        
        # Create autoencoder model
        self.model = AutoEncoder(
            input_dim=input_dim,
            encoding_dim=self.config.encoding_dim,
            hidden_dims=self.config.hidden_dims
        )
        
        # Enable GPU if available and configured
        device = torch.device('cuda' if self.config.enable_gpu and torch.cuda.is_available() else 'cpu')
        self.model.to(device)
        
        # Prepare data
        X_tensor = torch.FloatTensor(X_processed).to(device)
        
        # Split data for training and validation
        n_val = int(len(X_tensor) * self.config.validation_split)
        X_train = X_tensor[n_val:]
        X_val = X_tensor[:n_val] if n_val > 0 else X_tensor
        
        train_dataset = TensorDataset(X_train, X_train)
        train_loader = DataLoader(train_dataset, batch_size=self.config.batch_size, shuffle=True)
        
        # Training setup
        criterion = nn.MSELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=self.config.learning_rate)
        
        # Training loop
        self.model.train()
        for epoch in range(self.config.epochs):
            total_loss = 0
            for batch_data, _ in train_loader:
                optimizer.zero_grad()
                reconstructed = self.model(batch_data)
                loss = criterion(reconstructed, batch_data)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            # Validation loss
            if epoch % 10 == 0 and len(X_val) > 0:
                self.model.eval()
                with torch.no_grad():
                    val_reconstructed = self.model(X_val)
                    val_loss = criterion(val_reconstructed, X_val).item()
                    logger.info(f"Epoch {epoch}: Train Loss: {total_loss/len(train_loader):.4f}, Val Loss: {val_loss:.4f}")
                self.model.train()
        
        # Calculate reconstruction threshold
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            reconstruction_errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
            # Use 95th percentile as threshold
            self.reconstruction_threshold = torch.quantile(reconstruction_errors, 0.95).item()
        
        self.is_fitted = True
        logger.info(f"Fitted Autoencoder with {X_processed.shape[0]} samples, threshold: {self.reconstruction_threshold:.4f}")
    
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores using autoencoder reconstruction error."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_processed = self._preprocess_features(X, fit=False)
        
        device = torch.device('cuda' if self.config.enable_gpu and torch.cuda.is_available() else 'cpu')
        X_tensor = torch.FloatTensor(X_processed).to(device)
        
        self.model.eval()
        results = []
        
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            reconstruction_errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).cpu().numpy()
            
            for i, error in enumerate(reconstruction_errors):
                # Normalize error relative to threshold
                anomaly_score = min(error / self.reconstruction_threshold, 2.0) - 1.0  # Range [-1, 1]
                is_anomaly = error > self.reconstruction_threshold
                confidence = min(error / (self.reconstruction_threshold * 2), 1.0)
                
                results.append(AnomalyScore(
                    event_id=f"event_{i}",
                    method=self.method,
                    anomaly_score=float(anomaly_score),
                    is_anomaly=is_anomaly,
                    confidence=float(confidence),
                    feature_contributions={}
                ))
        
        return results


class DBSCANOutlierDetector(BaseAnomalyDetector):
    """DBSCAN-based outlier detector."""
    
    def __init__(self, config: AnomalyDetectionConfig):
        super().__init__(config, AnomalyDetectionMethod.DBSCAN_OUTLIER)
    
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit the DBSCAN model."""
        self.feature_names = feature_names
        X_processed = self._preprocess_features(X, fit=True)
        
        self.model = DBSCAN(
            eps=self.config.eps,
            min_samples=self.config.min_samples,
            n_jobs=self.config.n_jobs
        )
        
        self.cluster_labels = self.model.fit_predict(X_processed)
        self.is_fitted = True
        
        n_clusters = len(set(self.cluster_labels)) - (1 if -1 in self.cluster_labels else 0)
        n_outliers = list(self.cluster_labels).count(-1)
        logger.info(f"DBSCAN found {n_clusters} clusters, {n_outliers} outliers")
    
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores based on distance to clusters."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_processed = self._preprocess_features(X, fit=False)
        
        # For new data, calculate distance to nearest cluster center
        cluster_centers = {}
        for label in set(self.cluster_labels):
            if label != -1:  # Ignore noise points
                mask = self.cluster_labels == label
                if np.any(mask):
                    cluster_centers[label] = np.mean(X_processed[mask], axis=0)
        
        results = []
        for i, x in enumerate(X_processed):
            if len(cluster_centers) == 0:
                # No clusters found, treat all as anomalies
                anomaly_score = 1.0
                confidence = 0.5
                is_anomaly = True
            else:
                # Find distance to nearest cluster center
                min_distance = float('inf')
                for center in cluster_centers.values():
                    distance = np.linalg.norm(x - center)
                    min_distance = min(min_distance, distance)
                
                # Normalize distance to anomaly score
                anomaly_score = min(min_distance, 2.0) - 1.0  # Range [-1, 1]
                is_anomaly = min_distance > 1.0  # Threshold for outlier
                confidence = 1.0 / (1.0 + min_distance)  # Higher confidence for closer points
            
            results.append(AnomalyScore(
                event_id=f"event_{i}",
                method=self.method,
                anomaly_score=float(anomaly_score),
                is_anomaly=is_anomaly,
                confidence=float(confidence),
                feature_contributions={}
            ))
        
        return results


class LocalOutlierFactorDetector(BaseAnomalyDetector):
    """Local Outlier Factor based anomaly detector."""
    
    def __init__(self, config: AnomalyDetectionConfig):
        super().__init__(config, AnomalyDetectionMethod.LOCAL_OUTLIER_FACTOR)
    
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit the LOF model."""
        self.feature_names = feature_names
        X_processed = self._preprocess_features(X, fit=True)
        
        self.model = LocalOutlierFactor(
            n_neighbors=self.config.n_neighbors,
            contamination=self.config.contamination_rate,
            n_jobs=self.config.n_jobs
        )
        
        # LOF requires fit_predict for training data
        self.outlier_labels = self.model.fit_predict(X_processed)
        self.training_data = X_processed  # Store for novelty detection
        self.is_fitted = True
        
        n_outliers = list(self.outlier_labels).count(-1)
        logger.info(f"LOF fitted with {X_processed.shape[0]} samples, {n_outliers} outliers detected")
    
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores using LOF."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_processed = self._preprocess_features(X, fit=False)
        
        # For new data, use decision_function (requires novelty detection setup)
        # Create new LOF instance for novelty detection
        lof_novelty = LocalOutlierFactor(
            n_neighbors=self.config.n_neighbors,
            contamination=self.config.contamination_rate,
            novelty=True,
            n_jobs=self.config.n_jobs
        )
        lof_novelty.fit(self.training_data)
        
        decision_scores = lof_novelty.decision_function(X_processed)
        predictions = lof_novelty.predict(X_processed)
        
        results = []
        for i, (score, pred) in enumerate(zip(decision_scores, predictions)):
            # Convert LOF score to normalized anomaly score
            anomaly_score = -score  # LOF uses negative scores for outliers
            confidence = 1.0 / (1.0 + np.exp(-abs(score)))  # Sigmoid transformation
            
            results.append(AnomalyScore(
                event_id=f"event_{i}",
                method=self.method,
                anomaly_score=float(anomaly_score),
                is_anomaly=pred == -1,
                confidence=float(confidence),
                feature_contributions={}
            ))
        
        return results


class EnsembleAnomalyDetector:
    """Ensemble of multiple anomaly detection methods."""
    
    def __init__(self, config: AnomalyDetectionConfig, methods: List[AnomalyDetectionMethod]):
        self.config = config
        self.methods = methods
        self.detectors: Dict[AnomalyDetectionMethod, BaseAnomalyDetector] = {}
        self.is_fitted = False
        
        # Initialize individual detectors
        for method in methods:
            if method == AnomalyDetectionMethod.ISOLATION_FOREST:
                self.detectors[method] = IsolationForestDetector(config)
            elif method == AnomalyDetectionMethod.ONE_CLASS_SVM:
                self.detectors[method] = OneClassSVMDetector(config)
            elif method == AnomalyDetectionMethod.AUTOENCODER:
                self.detectors[method] = AutoEncoderDetector(config)
            elif method == AnomalyDetectionMethod.DBSCAN_OUTLIER:
                self.detectors[method] = DBSCANOutlierDetector(config)
            elif method == AnomalyDetectionMethod.LOCAL_OUTLIER_FACTOR:
                self.detectors[method] = LocalOutlierFactorDetector(config)
    
    def fit(self, X: np.ndarray, feature_names: List[str]) -> None:
        """Fit all ensemble detectors."""
        logger.info(f"Fitting ensemble with {len(self.detectors)} detectors")
        
        for method, detector in self.detectors.items():
            try:
                logger.info(f"Fitting {method.value} detector...")
                detector.fit(X, feature_names)
            except Exception as e:
                logger.error(f"Failed to fit {method.value} detector: {e}")
                # Remove failed detector from ensemble
                del self.detectors[method]
        
        self.is_fitted = True
        logger.info(f"Ensemble fitted with {len(self.detectors)} successful detectors")
    
    def predict_anomaly_scores(self, X: np.ndarray) -> List[AnomalyScore]:
        """Predict anomaly scores using ensemble voting."""
        if not self.is_fitted:
            raise ValueError("Ensemble must be fitted before prediction")
        
        # Collect predictions from all detectors
        all_predictions: Dict[AnomalyDetectionMethod, List[AnomalyScore]] = {}
        
        for method, detector in self.detectors.items():
            try:
                predictions = detector.predict_anomaly_scores(X)
                all_predictions[method] = predictions
            except Exception as e:
                logger.error(f"Failed to get predictions from {method.value}: {e}")
                continue
        
        if not all_predictions:
            raise ValueError("No detectors produced valid predictions")
        
        # Ensemble voting
        n_samples = len(X)
        ensemble_results = []
        
        for i in range(n_samples):
            # Collect scores from all detectors for this sample
            scores = []
            anomaly_votes = 0
            confidence_sum = 0.0
            
            for method, predictions in all_predictions.items():
                if i < len(predictions):
                    score_obj = predictions[i]
                    scores.append(score_obj.anomaly_score)
                    if score_obj.is_anomaly:
                        anomaly_votes += 1
                    confidence_sum += score_obj.confidence
            
            if not scores:
                continue
            
            # Calculate ensemble metrics
            mean_score = np.mean(scores)
            voting_ratio = anomaly_votes / len(scores)
            is_anomaly = voting_ratio >= self.config.voting_threshold
            ensemble_confidence = confidence_sum / len(scores)
            
            ensemble_results.append(AnomalyScore(
                event_id=f"event_{i}",
                method=AnomalyDetectionMethod.ENSEMBLE,
                anomaly_score=float(mean_score),
                is_anomaly=is_anomaly,
                confidence=float(ensemble_confidence),
                feature_contributions={
                    'voting_ratio': voting_ratio,
                    'n_detectors': len(scores)
                }
            ))
        
        return ensemble_results
    
    def get_detector_weights(self, X_val: np.ndarray, y_val: np.ndarray) -> Dict[AnomalyDetectionMethod, float]:
        """Calculate detector weights based on validation performance."""
        weights = {}
        
        for method, detector in self.detectors.items():
            try:
                predictions = detector.predict_anomaly_scores(X_val)
                
                # Calculate simple accuracy
                pred_labels = [1 if p.is_anomaly else 0 for p in predictions]
                accuracy = np.mean(np.array(pred_labels) == y_val)
                weights[method] = accuracy
                
            except Exception as e:
                logger.warning(f"Failed to calculate weight for {method.value}: {e}")
                weights[method] = 0.1  # Minimum weight
        
        # Normalize weights
        total_weight = sum(weights.values())
        if total_weight > 0:
            weights = {k: v / total_weight for k, v in weights.items()}
        
        return weights


class UnsupervisedAnomalyDetectionManager:
    """Main manager for unsupervised anomaly detection."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("unsupervised_anomaly_detection")
        self.mlflow_manager = MLFlowManager(settings)
        
        # Default configuration
        self.config = AnomalyDetectionConfig()
        
        # Storage for trained models
        self.trained_models: Dict[str, Union[BaseAnomalyDetector, EnsembleAnomalyDetector]] = {}
        
    async def train_anomaly_detectors(
        self,
        training_data: pd.DataFrame,
        model_name: str = "default",
        methods: Optional[List[AnomalyDetectionMethod]] = None,
        config: Optional[AnomalyDetectionConfig] = None
    ) -> Dict[str, Any]:
        """Train anomaly detection models on normal behavior data."""
        
        if config:
            self.config = config
        
        if methods is None:
            methods = [
                AnomalyDetectionMethod.ISOLATION_FOREST,
                AnomalyDetectionMethod.ONE_CLASS_SVM,
                AnomalyDetectionMethod.LOCAL_OUTLIER_FACTOR
            ]
        
        logger.info(f"Training anomaly detectors: {[m.value for m in methods]}")
        
        # Prepare feature matrix
        feature_columns = [col for col in training_data.columns 
                          if col not in ['event_id', 'timestamp', 'target']]
        X = training_data[feature_columns].fillna(0).values
        
        training_results = {}
        
        with mlflow.start_run(run_name=f"unsupervised_anomaly_training_{model_name}"):
            # Train ensemble if multiple methods
            if len(methods) > 1:
                ensemble = EnsembleAnomalyDetector(self.config, methods)
                start_time = datetime.utcnow()
                
                ensemble.fit(X, feature_columns)
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.trained_models[model_name] = ensemble
                
                # Log ensemble metrics
                mlflow.log_param("model_type", "ensemble")
                mlflow.log_param("methods", [m.value for m in methods])
                mlflow.log_param("n_detectors", len(ensemble.detectors))
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("training_samples", len(X))
                mlflow.log_metric("n_features", len(feature_columns))
                
                training_results = {
                    'model_name': model_name,
                    'model_type': 'ensemble',
                    'methods': [m.value for m in methods],
                    'n_detectors_fitted': len(ensemble.detectors),
                    'training_time': training_time,
                    'training_samples': len(X),
                    'n_features': len(feature_columns)
                }
                
            else:
                # Train single detector
                method = methods[0]
                start_time = datetime.utcnow()
                
                if method == AnomalyDetectionMethod.ISOLATION_FOREST:
                    detector = IsolationForestDetector(self.config)
                elif method == AnomalyDetectionMethod.ONE_CLASS_SVM:
                    detector = OneClassSVMDetector(self.config)
                elif method == AnomalyDetectionMethod.AUTOENCODER:
                    detector = AutoEncoderDetector(self.config)
                elif method == AnomalyDetectionMethod.DBSCAN_OUTLIER:
                    detector = DBSCANOutlierDetector(self.config)
                elif method == AnomalyDetectionMethod.LOCAL_OUTLIER_FACTOR:
                    detector = LocalOutlierFactorDetector(self.config)
                else:
                    raise ValueError(f"Unsupported detection method: {method}")
                
                detector.fit(X, feature_columns)
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.trained_models[model_name] = detector
                
                # Log single detector metrics
                mlflow.log_param("model_type", method.value)
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("training_samples", len(X))
                mlflow.log_metric("n_features", len(feature_columns))
                
                training_results = {
                    'model_name': model_name,
                    'model_type': method.value,
                    'training_time': training_time,
                    'training_samples': len(X),
                    'n_features': len(feature_columns)
                }
        
        logger.info(f"Completed training anomaly detectors for model '{model_name}'")
        return training_results
    
    async def detect_anomalies(
        self,
        events: List[SecurityEvent],
        model_name: str = "default"
    ) -> List[BehavioralAnomaly]:
        """Detect anomalies in new security events."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        detector = self.trained_models[model_name]
        
        # Convert events to feature matrix
        events_df = pd.DataFrame([self._extract_features(event) for event in events])
        feature_columns = [col for col in events_df.columns 
                          if col not in ['event_id', 'timestamp']]
        X = events_df[feature_columns].fillna(0).values
        
        # Get anomaly scores
        anomaly_scores = detector.predict_anomaly_scores(X)
        
        # Convert to BehavioralAnomaly objects
        behavioral_anomalies = []
        for i, (event, score) in enumerate(zip(events, anomaly_scores)):
            if score.is_anomaly:
                anomaly = BehavioralAnomaly(
                    entity_id=self._get_entity_id(event),
                    entity_type=self._infer_entity_type(event),
                    behavior_type=BehaviorType.NETWORK_ACCESS,  # Default, could be inferred
                    anomaly_type=AnomalyType.CLUSTERING_OUTLIER,
                    severity_score=min(abs(score.anomaly_score), 1.0),
                    confidence_score=score.confidence,
                    observed_values=self._extract_features(event),
                    expected_values={"normal_behavior": "baseline"},
                    deviations={"anomaly_score": score.anomaly_score},
                    timestamp=event.timestamp,
                    related_events=[event.event_id],
                    description=f"Unsupervised anomaly detected using {score.method.value} (score: {score.anomaly_score:.3f})"
                )
                behavioral_anomalies.append(anomaly)
                
                # Log detection metrics
                self.metrics.increment_counter(
                    "anomalies_detected",
                    tags={"method": score.method.value, "model": model_name}
                )
        
        logger.info(f"Detected {len(behavioral_anomalies)} anomalies using model '{model_name}'")
        return behavioral_anomalies
    
    def _extract_features(self, event: SecurityEvent) -> Dict[str, Any]:
        """Extract features from security event for anomaly detection."""
        return {
            'event_id': event.event_id,
            'timestamp': event.timestamp,
            'hour': event.timestamp.hour,
            'day_of_week': event.timestamp.weekday(),
            'severity_high': 1 if event.severity == 'high' else 0,
            'severity_medium': 1 if event.severity == 'medium' else 0,
            'severity_low': 1 if event.severity == 'low' else 0,
            'has_source_ip': 1 if event.source_ip else 0,
            'has_dest_ip': 1 if event.dest_ip else 0,
            'has_username': 1 if event.username else 0,
            'has_hostname': 1 if event.hostname else 0,
            'has_process': 1 if event.process_name else 0,
            'has_command': 1 if event.command_line else 0,
            'has_file': 1 if event.file_path else 0,
            'port': event.port or 0,
            'is_weekend': 1 if event.timestamp.weekday() >= 5 else 0,
            'is_night': 1 if event.timestamp.hour < 6 or event.timestamp.hour > 22 else 0,
            'command_length': len(event.command_line) if event.command_line else 0,
            'file_path_depth': len(event.file_path.split('/')) if event.file_path else 0
        }
    
    def _get_entity_id(self, event: SecurityEvent) -> str:
        """Extract entity ID from security event."""
        return event.username or event.hostname or event.source_ip or 'unknown'
    
    def _infer_entity_type(self, event: SecurityEvent) -> str:
        """Infer entity type from security event."""
        if event.username:
            return 'user'
        elif event.hostname:
            return 'host'
        else:
            return 'unknown'
    
    async def evaluate_model_performance(
        self,
        test_data: pd.DataFrame,
        ground_truth_labels: List[int],
        model_name: str = "default"
    ) -> Dict[str, Any]:
        """Evaluate anomaly detection model performance."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        detector = self.trained_models[model_name]
        
        # Prepare test data
        feature_columns = [col for col in test_data.columns 
                          if col not in ['event_id', 'timestamp', 'target']]
        X_test = test_data[feature_columns].fillna(0).values
        
        # Get predictions
        anomaly_scores = detector.predict_anomaly_scores(X_test)
        predictions = [1 if score.is_anomaly else 0 for score in anomaly_scores]
        
        # Calculate metrics
        from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
        
        precision = precision_score(ground_truth_labels, predictions, zero_division=0)
        recall = recall_score(ground_truth_labels, predictions, zero_division=0)
        f1 = f1_score(ground_truth_labels, predictions, zero_division=0)
        
        # Calculate AUC using confidence scores
        confidence_scores = [score.confidence for score in anomaly_scores]
        try:
            auc = roc_auc_score(ground_truth_labels, confidence_scores)
        except ValueError:
            auc = 0.5  # Default AUC for edge cases
        
        evaluation_results = {
            'model_name': model_name,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc_score': auc,
            'test_samples': len(X_test),
            'anomalies_detected': sum(predictions),
            'true_anomalies': sum(ground_truth_labels)
        }
        
        # Log evaluation metrics
        with mlflow.start_run(run_name=f"unsupervised_evaluation_{model_name}"):
            mlflow.log_metrics({
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc_score': auc
            })
        
        logger.info(f"Model evaluation completed: {evaluation_results}")
        return evaluation_results
    
    async def save_models(self, base_path: str) -> Dict[str, str]:
        """Save all trained models to disk."""
        saved_models = {}
        
        for model_name, model in self.trained_models.items():
            try:
                model_path = f"{base_path}/{model_name}.joblib"
                
                if isinstance(model, EnsembleAnomalyDetector):
                    # Save ensemble metadata
                    ensemble_data = {
                        'type': 'ensemble',
                        'config': model.config.__dict__,
                        'methods': [m.value for m in model.methods],
                        'is_fitted': model.is_fitted
                    }
                    
                    # Save individual detectors
                    detector_paths = {}
                    for method, detector in model.detectors.items():
                        detector_path = f"{base_path}/{model_name}_{method.value}.joblib"
                        detector.save_model(detector_path)
                        detector_paths[method.value] = detector_path
                    
                    ensemble_data['detector_paths'] = detector_paths
                    joblib.dump(ensemble_data, model_path)
                    
                else:
                    # Save single detector
                    model.save_model(model_path)
                
                saved_models[model_name] = model_path
                logger.info(f"Saved model '{model_name}' to {model_path}")
                
            except Exception as e:
                logger.error(f"Failed to save model '{model_name}': {e}")
        
        return saved_models
    
    async def load_models(self, model_paths: Dict[str, str]) -> Dict[str, Any]:
        """Load trained models from disk."""
        loaded_models = {}
        
        for model_name, model_path in model_paths.items():
            try:
                # Check if it's an ensemble model
                if model_path.endswith('.joblib'):
                    model_data = joblib.load(model_path)
                    
                    if isinstance(model_data, dict) and model_data.get('type') == 'ensemble':
                        # Load ensemble
                        config = AnomalyDetectionConfig(**model_data['config'])
                        methods = [AnomalyDetectionMethod(m) for m in model_data['methods']]
                        
                        ensemble = EnsembleAnomalyDetector(config, methods)
                        
                        # Load individual detectors
                        for method_name, detector_path in model_data['detector_paths'].items():
                            method = AnomalyDetectionMethod(method_name)
                            detector = ensemble.detectors[method]
                            detector.load_model(detector_path)
                        
                        ensemble.is_fitted = model_data['is_fitted']
                        self.trained_models[model_name] = ensemble
                        
                    else:
                        # Load single detector - need to determine type
                        # This would require additional metadata in saved models
                        logger.warning(f"Cannot determine detector type for {model_name}")
                        continue
                
                loaded_models[model_name] = model_path
                logger.info(f"Loaded model '{model_name}' from {model_path}")
                
            except Exception as e:
                logger.error(f"Failed to load model '{model_name}': {e}")
        
        return loaded_models
    
    async def get_detection_metrics(self) -> Dict[str, Any]:
        """Get detection performance metrics."""
        return {
            'trained_models': list(self.trained_models.keys()),
            'model_count': len(self.trained_models),
            'detection_metrics': await self.metrics.get_metrics() if hasattr(self.metrics, 'get_metrics') else {}
        }