"""
Zero-Day and Unknown Threat Detection Models

This module implements semi-supervised and unsupervised models to identify
zero-day and unknown threats not present in labeled datasets. It combines
multiple detection strategies including semi-supervised learning, clustering,
outlier detection, and novel pattern identification for detecting previously
unseen attack patterns and novel threat vectors.
"""

import asyncio
import logging
import json
import pickle
import joblib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum
from collections import defaultdict, deque
import warnings

import pandas as pd
import numpy as np
from sklearn.semi_supervised import LabelPropagation, LabelSpreading
from sklearn.cluster import DBSCAN, KMeans, SpectralClustering
from sklearn.mixture import GaussianMixture
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.decomposition import PCA, FastICA
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import silhouette_score, adjusted_rand_score
from sklearn.model_selection import train_test_split
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import mlflow
import mlflow.sklearn
import mlflow.pytorch
from pydantic import BaseModel, Field

from .behavioral_analytics import BehaviorType, AnomalyType
from .supervised_threat_classification import ThreatCategory, ThreatPrediction
from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector
from ...shared.mlflow.integration import MLFlowManager

logger = logging.getLogger(__name__)
warnings.filterwarnings('ignore', category=UserWarning)


class ZeroDayDetectionMethod(Enum):
    """Methods for zero-day and unknown threat detection."""
    SEMI_SUPERVISED = "semi_supervised"
    CLUSTERING_OUTLIER = "clustering_outlier"
    NOVELTY_DETECTION = "novelty_detection"
    PATTERN_DEVIATION = "pattern_deviation"
    ENSEMBLE_HYBRID = "ensemble_hybrid"
    VARIATIONAL_AUTOENCODER = "variational_autoencoder"
    ADVERSARIAL_DETECTION = "adversarial_detection"


class NoveltyType(Enum):
    """Types of novelty in threat patterns."""
    UNKNOWN_ATTACK_VECTOR = "unknown_attack_vector"
    NOVEL_BEHAVIOR_PATTERN = "novel_behavior_pattern"
    ZERO_DAY_EXPLOIT = "zero_day_exploit"
    ADVANCED_EVASION = "advanced_evasion"
    HYBRID_ATTACK = "hybrid_attack"
    EMERGING_MALWARE = "emerging_malware"


@dataclass
class ZeroDayDetectionConfig:
    """Configuration for zero-day detection models."""
    # General settings
    contamination_rate: float = 0.05  # Expected rate of zero-day threats
    confidence_threshold: float = 0.7  # Minimum confidence for detection
    novelty_threshold: float = 2.0    # Standard deviations for novelty
    random_state: int = 42
    
    # Semi-supervised learning settings
    ssl_kernel: str = "rbf"          # 'knn', 'rbf'
    ssl_gamma: float = 20            # RBF kernel parameter
    ssl_max_iter: int = 1000         # Maximum iterations
    ssl_alpha: float = 0.2           # Clamping factor
    
    # Clustering settings
    dbscan_eps: float = 0.5          # DBSCAN epsilon
    dbscan_min_samples: int = 5      # DBSCAN minimum samples
    kmeans_clusters: int = 8         # Number of clusters for K-means
    gmm_components: int = 8          # Gaussian mixture components
    
    # Novelty detection settings
    novelty_nu: float = 0.05         # One-class SVM parameter
    isolation_forest_estimators: int = 200
    lof_neighbors: int = 20          # LOF neighbors
    
    # Pattern analysis settings
    pattern_window_size: int = 10    # Temporal pattern window
    pattern_similarity_threshold: float = 0.8
    sequence_min_length: int = 3     # Minimum sequence length
    
    # VAE settings
    vae_latent_dim: int = 16         # Latent space dimension
    vae_hidden_dims: List[int] = field(default_factory=lambda: [128, 64, 32])
    vae_learning_rate: float = 0.001
    vae_epochs: int = 100
    vae_batch_size: int = 32
    vae_beta: float = 1.0            # Beta-VAE parameter
    
    # Ensemble settings
    ensemble_voting_threshold: float = 0.6  # Fraction of models agreeing
    ensemble_weights: Dict[str, float] = field(default_factory=dict)
    
    # Performance settings
    enable_gpu: bool = False
    batch_processing: bool = True
    max_memory_gb: float = 4.0


class ZeroDayThreat(BaseModel):
    """Represents a detected zero-day or unknown threat."""
    event_id: str
    detection_method: ZeroDayDetectionMethod
    novelty_type: NoveltyType
    threat_score: float = Field(ge=0.0, le=1.0)
    confidence_score: float = Field(ge=0.0, le=1.0)
    
    # Analysis details
    anomaly_features: Dict[str, float] = Field(default_factory=dict)
    cluster_info: Dict[str, Any] = Field(default_factory=dict)
    pattern_deviations: Dict[str, float] = Field(default_factory=dict)
    similar_threats: List[str] = Field(default_factory=list)
    
    # Context
    timestamp: datetime
    related_events: List[str] = Field(default_factory=list)
    attack_signature: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            ZeroDayDetectionMethod: lambda v: v.value,
            NoveltyType: lambda v: v.value
        }


class VariationalAutoEncoder(nn.Module):
    """Variational Autoencoder for detecting novel threat patterns."""
    
    def __init__(self, input_dim: int, latent_dim: int, hidden_dims: List[int]):
        super(VariationalAutoEncoder, self).__init__()
        
        self.latent_dim = latent_dim
        
        # Encoder
        encoder_layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Latent space
        self.fc_mu = nn.Linear(prev_dim, latent_dim)
        self.fc_logvar = nn.Linear(prev_dim, latent_dim)
        
        # Decoder
        decoder_layers = []
        prev_dim = latent_dim
        
        for hidden_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2)
            ])
            prev_dim = hidden_dim
        
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)
    
    def encode(self, x):
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar
    
    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
    
    def decode(self, z):
        return self.decoder(z)
    
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        recon_x = self.decode(z)
        return recon_x, mu, logvar
    
    def get_latent_representation(self, x):
        mu, logvar = self.encode(x)
        return mu  # Use mean as latent representation


class BaseZeroDayDetector(ABC):
    """Abstract base class for zero-day detection models."""
    
    def __init__(self, config: ZeroDayDetectionConfig, method: ZeroDayDetectionMethod):
        self.config = config
        self.method = method
        self.model = None
        self.scaler = None
        self.is_fitted = False
        self.feature_names = []
        self.normal_patterns = []
        self.threat_signatures = {}
    
    @abstractmethod
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit the zero-day detection model."""
        pass
    
    @abstractmethod
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect zero-day threats in input data."""
        pass
    
    def _preprocess_features(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Preprocess features with scaling."""
        if fit:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            if self.scaler is None:
                raise ValueError("Model must be fitted before preprocessing")
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def _generate_threat_signature(self, features: Dict[str, float]) -> str:
        """Generate a signature for the detected threat pattern."""
        # Create a hash-based signature from key features
        import hashlib
        
        # Sort features by importance/value
        sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
        top_features = sorted_features[:5]  # Top 5 features
        
        signature_str = "_".join([f"{k}:{v:.3f}" for k, v in top_features])
        signature_hash = hashlib.md5(signature_str.encode()).hexdigest()[:8]
        
        return f"zd_{signature_hash}"
    
    def _recommend_actions(self, novelty_type: NoveltyType, threat_score: float) -> List[str]:
        """Generate recommended actions based on threat type and score."""
        actions = ["Isolate affected systems immediately"]
        
        if threat_score > 0.8:
            actions.extend([
                "Escalate to security incident response team",
                "Collect forensic evidence",
                "Update threat intelligence feeds"
            ])
        
        if novelty_type == NoveltyType.ZERO_DAY_EXPLOIT:
            actions.extend([
                "Check for available patches",
                "Implement emergency firewall rules",
                "Monitor for lateral movement"
            ])
        elif novelty_type == NoveltyType.ADVANCED_EVASION:
            actions.extend([
                "Review detection rules and signatures",
                "Enhance monitoring coverage",
                "Analyze evasion techniques"
            ])
        elif novelty_type == NoveltyType.EMERGING_MALWARE:
            actions.extend([
                "Submit samples to malware analysis",
                "Update antivirus signatures",
                "Scan all endpoints for indicators"
            ])
        
        return actions


class SemiSupervisedZeroDayDetector(BaseZeroDayDetector):
    """Semi-supervised learning based zero-day detector."""
    
    def __init__(self, config: ZeroDayDetectionConfig):
        super().__init__(config, ZeroDayDetectionMethod.SEMI_SUPERVISED)
    
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit semi-supervised model with limited labeled data."""
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_normal.shape[1])]
        
        # Preprocess features
        X_combined = np.vstack([X_normal, X_labeled]) if X_labeled is not None else X_normal
        X_scaled = self._preprocess_features(X_combined, fit=True)
        
        if X_labeled is not None:
            X_normal_scaled = X_scaled[:len(X_normal)]
            X_labeled_scaled = X_scaled[len(X_normal):]
            
            # Create semi-supervised dataset
            # Label normal data as 0 (benign), unknown threats as -1 (unlabeled)
            y_combined = np.concatenate([
                np.zeros(len(X_normal)),  # Normal data labeled as benign
                y_labeled  # Known threat labels
            ])
            
            # Mark some normal data as unlabeled for semi-supervised learning
            unlabeled_indices = np.random.choice(
                len(X_normal), 
                size=int(len(X_normal) * 0.3), 
                replace=False
            )
            y_combined[unlabeled_indices] = -1  # Unlabeled
            
            # Initialize semi-supervised model
            if self.config.ssl_kernel == "knn":
                self.model = LabelPropagation(
                    kernel='knn',
                    n_neighbors=7,
                    max_iter=self.config.ssl_max_iter,
                    alpha=self.config.ssl_alpha
                )
            else:
                self.model = LabelSpreading(
                    kernel='rbf',
                    gamma=self.config.ssl_gamma,
                    max_iter=self.config.ssl_max_iter,
                    alpha=self.config.ssl_alpha
                )
            
            # Fit model
            self.model.fit(X_scaled, y_combined)
            
        else:
            # Use unsupervised approach if no labeled data
            from sklearn.cluster import KMeans
            self.model = KMeans(
                n_clusters=self.config.kmeans_clusters,
                random_state=self.config.random_state
            )
            self.model.fit(X_scaled)
        
        # Store normal patterns for comparison
        self.normal_patterns = X_scaled[:len(X_normal)]
        self.is_fitted = True
        
        logger.info(f"Fitted semi-supervised zero-day detector with {len(X_combined)} samples")
    
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect zero-day threats using semi-supervised learning."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before detection")
        
        X_scaled = self._preprocess_features(X, fit=False)
        
        threats = []
        
        if hasattr(self.model, 'predict_proba'):
            # Semi-supervised classifier
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)
            
            for i, (pred, proba) in enumerate(zip(predictions, probabilities)):
                # Check if prediction indicates anomaly or low confidence
                max_prob = np.max(proba)
                entropy = -np.sum(proba * np.log(proba + 1e-10))  # Prediction entropy
                
                # High entropy or low confidence suggests unknown threat
                if entropy > 1.5 or max_prob < self.config.confidence_threshold:
                    threat_score = min(entropy / 2.0, 1.0)  # Normalize entropy
                    confidence = 1.0 - max_prob
                    
                    # Determine novelty type based on prediction characteristics
                    if entropy > 2.0:
                        novelty_type = NoveltyType.UNKNOWN_ATTACK_VECTOR
                    elif max_prob < 0.3:
                        novelty_type = NoveltyType.NOVEL_BEHAVIOR_PATTERN
                    else:
                        novelty_type = NoveltyType.ADVANCED_EVASION
                    
                    # Analyze feature contributions
                    feature_vector = X_scaled[i]
                    anomaly_features = {}
                    
                    # Compare with normal patterns
                    distances = np.linalg.norm(self.normal_patterns - feature_vector, axis=1)
                    min_distance = np.min(distances)
                    
                    if min_distance > self.config.novelty_threshold:
                        # Identify most anomalous features
                        normal_mean = np.mean(self.normal_patterns, axis=0)
                        feature_deviations = np.abs(feature_vector - normal_mean)
                        
                        for j, (feat_name, deviation) in enumerate(zip(self.feature_names, feature_deviations)):
                            if deviation > np.std(self.normal_patterns[:, j]) * 2:
                                anomaly_features[feat_name] = float(deviation)
                    
                    signature = self._generate_threat_signature(anomaly_features)
                    actions = self._recommend_actions(novelty_type, threat_score)
                    
                    threats.append(ZeroDayThreat(
                        event_id=f"event_{i}",
                        detection_method=self.method,
                        novelty_type=novelty_type,
                        threat_score=threat_score,
                        confidence_score=confidence,
                        anomaly_features=anomaly_features,
                        pattern_deviations={"distance_to_normal": float(min_distance)},
                        timestamp=datetime.utcnow(),
                        attack_signature=signature,
                        recommended_actions=actions
                    ))
        
        else:
            # Clustering-based approach
            cluster_labels = self.model.predict(X_scaled)
            cluster_centers = self.model.cluster_centers_
            
            for i, (label, features) in enumerate(zip(cluster_labels, X_scaled)):
                # Calculate distance to cluster center
                center_distance = np.linalg.norm(features - cluster_centers[label])
                
                # Calculate distance to nearest normal pattern
                normal_distances = np.linalg.norm(self.normal_patterns - features, axis=1)
                min_normal_distance = np.min(normal_distances)
                
                # Threat if far from both cluster center and normal patterns
                if (center_distance > self.config.novelty_threshold or 
                    min_normal_distance > self.config.novelty_threshold * 1.5):
                    
                    threat_score = min((center_distance + min_normal_distance) / 4.0, 1.0)
                    confidence = min(center_distance / self.config.novelty_threshold, 1.0)
                    
                    novelty_type = NoveltyType.NOVEL_BEHAVIOR_PATTERN
                    
                    # Feature analysis
                    anomaly_features = {}
                    normal_mean = np.mean(self.normal_patterns, axis=0)
                    feature_deviations = np.abs(features - normal_mean)
                    
                    for j, (feat_name, deviation) in enumerate(zip(self.feature_names, feature_deviations)):
                        if deviation > np.std(self.normal_patterns[:, j]) * 2:
                            anomaly_features[feat_name] = float(deviation)
                    
                    signature = self._generate_threat_signature(anomaly_features)
                    actions = self._recommend_actions(novelty_type, threat_score)
                    
                    threats.append(ZeroDayThreat(
                        event_id=f"event_{i}",
                        detection_method=self.method,
                        novelty_type=novelty_type,
                        threat_score=threat_score,
                        confidence_score=confidence,
                        anomaly_features=anomaly_features,
                        cluster_info={"cluster_id": int(label), "distance_to_center": float(center_distance)},
                        pattern_deviations={"distance_to_normal": float(min_normal_distance)},
                        timestamp=datetime.utcnow(),
                        attack_signature=signature,
                        recommended_actions=actions
                    ))
        
        return threats


class ClusteringOutlierDetector(BaseZeroDayDetector):
    """Clustering-based outlier detection for zero-day threats."""
    
    def __init__(self, config: ZeroDayDetectionConfig):
        super().__init__(config, ZeroDayDetectionMethod.CLUSTERING_OUTLIER)
        self.cluster_models = {}
        
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit clustering models on normal behavior data."""
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_normal.shape[1])]
        X_scaled = self._preprocess_features(X_normal, fit=True)
        
        # Fit multiple clustering algorithms
        # DBSCAN for density-based clustering
        dbscan = DBSCAN(
            eps=self.config.dbscan_eps,
            min_samples=self.config.dbscan_min_samples
        )
        dbscan_labels = dbscan.fit_predict(X_scaled)
        self.cluster_models['dbscan'] = dbscan
        
        # K-means for centroid-based clustering
        kmeans = KMeans(
            n_clusters=self.config.kmeans_clusters,
            random_state=self.config.random_state
        )
        kmeans.fit(X_scaled)
        self.cluster_models['kmeans'] = kmeans
        
        # Gaussian Mixture Model for probabilistic clustering
        gmm = GaussianMixture(
            n_components=self.config.gmm_components,
            random_state=self.config.random_state
        )
        gmm.fit(X_scaled)
        self.cluster_models['gmm'] = gmm
        
        # Store normal patterns and cluster information
        self.normal_patterns = X_scaled
        self.cluster_info = {
            'dbscan_labels': dbscan_labels,
            'kmeans_centers': kmeans.cluster_centers_,
            'gmm_means': gmm.means_
        }
        
        self.is_fitted = True
        
        # Log cluster statistics
        n_dbscan_clusters = len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0)
        n_outliers = list(dbscan_labels).count(-1)
        
        logger.info(f"Fitted clustering models: DBSCAN found {n_dbscan_clusters} clusters "
                   f"with {n_outliers} outliers")
    
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect zero-day threats using clustering outlier analysis."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before detection")
        
        X_scaled = self._preprocess_features(X, fit=False)
        threats = []
        
        for i, features in enumerate(X_scaled):
            threat_indicators = []
            
            # DBSCAN outlier detection
            dbscan_pred = self.cluster_models['dbscan'].fit_predict([features])
            if dbscan_pred[0] == -1:  # Outlier
                threat_indicators.append(("dbscan_outlier", 0.8))
            
            # K-means distance analysis
            kmeans_distances = [
                np.linalg.norm(features - center) 
                for center in self.cluster_info['kmeans_centers']
            ]
            min_kmeans_dist = min(kmeans_distances)
            
            # Calculate threshold as 95th percentile of training distances
            training_distances = []
            for pattern in self.normal_patterns:
                dists = [np.linalg.norm(pattern - center) for center in self.cluster_info['kmeans_centers']]
                training_distances.append(min(dists))
            
            distance_threshold = np.percentile(training_distances, 95)
            
            if min_kmeans_dist > distance_threshold:
                outlier_score = min(min_kmeans_dist / (distance_threshold * 2), 1.0)
                threat_indicators.append(("kmeans_outlier", outlier_score))
            
            # GMM likelihood analysis
            gmm_log_likelihood = self.cluster_models['gmm'].score_samples([features])[0]
            gmm_threshold = np.percentile(
                self.cluster_models['gmm'].score_samples(self.normal_patterns), 5
            )
            
            if gmm_log_likelihood < gmm_threshold:
                likelihood_score = min(abs(gmm_log_likelihood - gmm_threshold) / 10, 1.0)
                threat_indicators.append(("gmm_outlier", likelihood_score))
            
            # Aggregate threat indicators
            if threat_indicators:
                threat_score = np.mean([score for _, score in threat_indicators])
                confidence = len(threat_indicators) / 3.0  # Based on number of agreeing models
                
                # Determine novelty type
                if len(threat_indicators) >= 2:
                    novelty_type = NoveltyType.UNKNOWN_ATTACK_VECTOR
                elif any("dbscan" in indicator for indicator, _ in threat_indicators):
                    novelty_type = NoveltyType.NOVEL_BEHAVIOR_PATTERN
                else:
                    novelty_type = NoveltyType.ADVANCED_EVASION
                
                # Feature analysis
                anomaly_features = {}
                normal_mean = np.mean(self.normal_patterns, axis=0)
                normal_std = np.std(self.normal_patterns, axis=0)
                feature_deviations = np.abs((features - normal_mean) / (normal_std + 1e-10))
                
                for j, (feat_name, deviation) in enumerate(zip(self.feature_names, feature_deviations)):
                    if deviation > 2.0:  # More than 2 standard deviations
                        anomaly_features[feat_name] = float(deviation)
                
                cluster_info = {
                    "threat_indicators": [indicator for indicator, _ in threat_indicators],
                    "dbscan_outlier": dbscan_pred[0] == -1,
                    "min_kmeans_distance": float(min_kmeans_dist),
                    "gmm_log_likelihood": float(gmm_log_likelihood)
                }
                
                signature = self._generate_threat_signature(anomaly_features)
                actions = self._recommend_actions(novelty_type, threat_score)
                
                threats.append(ZeroDayThreat(
                    event_id=f"event_{i}",
                    detection_method=self.method,
                    novelty_type=novelty_type,
                    threat_score=threat_score,
                    confidence_score=confidence,
                    anomaly_features=anomaly_features,
                    cluster_info=cluster_info,
                    timestamp=datetime.utcnow(),
                    attack_signature=signature,
                    recommended_actions=actions
                ))
        
        return threats


class PatternDeviationDetector(BaseZeroDayDetector):
    """Pattern deviation based zero-day threat detector."""
    
    def __init__(self, config: ZeroDayDetectionConfig):
        super().__init__(config, ZeroDayDetectionMethod.PATTERN_DEVIATION)
        self.temporal_patterns = {}
        self.sequence_models = {}
        self.deviation_thresholds = {}
        
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit pattern deviation models on normal behavior sequences."""
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_normal.shape[1])]
        X_scaled = self._preprocess_features(X_normal, fit=True)
        
        # Build temporal pattern models
        self._build_temporal_patterns(X_scaled)
        
        # Build sequence models
        self._build_sequence_models(X_scaled)
        
        # Calculate deviation thresholds
        self._calculate_deviation_thresholds(X_scaled)
        
        self.normal_patterns = X_scaled
        self.is_fitted = True
        
        logger.info(f"Fitted pattern deviation detector with {len(X_scaled)} patterns")
    
    def _build_temporal_patterns(self, X: np.ndarray) -> None:
        """Build temporal pattern models."""
        window_size = self.config.pattern_window_size
        
        for i in range(len(X) - window_size + 1):
            window = X[i:i + window_size]
            
            # Calculate pattern statistics
            pattern_stats = {
                'mean': np.mean(window, axis=0),
                'std': np.std(window, axis=0),
                'trend': np.polyfit(range(window_size), window.mean(axis=1), 1)[0],
                'variance': np.var(window, axis=0),
                'autocorr': self._calculate_autocorrelation(window)
            }
            
            pattern_id = f"temporal_{i}"
            self.temporal_patterns[pattern_id] = pattern_stats
    
    def _build_sequence_models(self, X: np.ndarray) -> None:
        """Build sequence-based pattern models."""
        from sklearn.cluster import KMeans
        from collections import Counter
        
        # Create subsequences
        subsequences = []
        min_length = self.config.sequence_min_length
        
        for i in range(len(X) - min_length + 1):
            subseq = X[i:i + min_length]
            subsequences.append(subseq.flatten())
        
        if subsequences:
            # Cluster subsequences to find common patterns
            n_clusters = min(8, len(subsequences) // 3)
            if n_clusters > 0:
                kmeans = KMeans(n_clusters=n_clusters, random_state=self.config.random_state)
                cluster_labels = kmeans.fit_predict(subsequences)
                
                self.sequence_models['kmeans'] = kmeans
                self.sequence_models['cluster_frequencies'] = Counter(cluster_labels)
                
                # Calculate typical distances for each cluster
                cluster_distances = defaultdict(list)
                for i, label in enumerate(cluster_labels):
                    center = kmeans.cluster_centers_[label]
                    distance = np.linalg.norm(subsequences[i] - center)
                    cluster_distances[label].append(distance)
                
                # Store distance statistics for each cluster
                self.sequence_models['cluster_distance_stats'] = {}
                for cluster_id, distances in cluster_distances.items():
                    self.sequence_models['cluster_distance_stats'][cluster_id] = {
                        'mean': np.mean(distances),
                        'std': np.std(distances),
                        'percentile_95': np.percentile(distances, 95)
                    }
    
    def _calculate_autocorrelation(self, window: np.ndarray) -> float:
        """Calculate autocorrelation of window patterns."""
        if len(window) < 2:
            return 0.0
        
        # Calculate average autocorrelation across features
        autocorrs = []
        for feature_idx in range(window.shape[1]):
            feature_series = window[:, feature_idx]
            if len(set(feature_series)) > 1:  # Check for variance
                autocorr = np.corrcoef(feature_series[:-1], feature_series[1:])[0, 1]
                if not np.isnan(autocorr):
                    autocorrs.append(abs(autocorr))
        
        return np.mean(autocorrs) if autocorrs else 0.0
    
    def _calculate_deviation_thresholds(self, X: np.ndarray) -> None:
        """Calculate thresholds for pattern deviations."""
        # Statistical thresholds
        self.deviation_thresholds['statistical'] = {
            'mean_deviation': np.std(np.mean(X, axis=1)) * self.config.novelty_threshold,
            'variance_deviation': np.std(np.var(X, axis=1)) * self.config.novelty_threshold,
            'pattern_similarity': self.config.pattern_similarity_threshold
        }
        
        # Temporal thresholds
        if self.temporal_patterns:
            trend_values = [p['trend'] for p in self.temporal_patterns.values()]
            autocorr_values = [p['autocorr'] for p in self.temporal_patterns.values()]
            
            self.deviation_thresholds['temporal'] = {
                'trend_deviation': np.std(trend_values) * self.config.novelty_threshold,
                'autocorr_deviation': np.std(autocorr_values) * self.config.novelty_threshold
            }
    
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect zero-day threats using pattern deviation analysis."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before detection")
        
        X_scaled = self._preprocess_features(X, fit=False)
        threats = []
        
        for i, features in enumerate(X_scaled):
            deviation_scores = []
            
            # Statistical deviation analysis
            stat_deviations = self._analyze_statistical_deviations(features)
            deviation_scores.extend(stat_deviations)
            
            # Temporal pattern analysis (if enough historical context)
            if i >= self.config.pattern_window_size - 1:
                window_start = max(0, i - self.config.pattern_window_size + 1)
                temporal_window = X_scaled[window_start:i+1]
                temporal_deviations = self._analyze_temporal_deviations(temporal_window)
                deviation_scores.extend(temporal_deviations)
            
            # Sequence pattern analysis
            if i >= self.config.sequence_min_length - 1:
                seq_start = max(0, i - self.config.sequence_min_length + 1)
                sequence = X_scaled[seq_start:i+1]
                sequence_deviations = self._analyze_sequence_deviations(sequence)
                deviation_scores.extend(sequence_deviations)
            
            # Evaluate threat based on deviation scores
            if deviation_scores:
                avg_deviation = np.mean([score for _, score in deviation_scores])
                max_deviation = max([score for _, score in deviation_scores])
                
                if avg_deviation > 0.5 or max_deviation > 0.8:
                    threat_score = min(avg_deviation * 1.2, 1.0)
                    confidence = len(deviation_scores) / 6.0  # Normalize by max possible deviations
                    
                    # Determine novelty type based on deviation characteristics
                    deviation_types = [dtype for dtype, _ in deviation_scores]
                    
                    if 'sequence_anomaly' in deviation_types:
                        novelty_type = NoveltyType.NOVEL_BEHAVIOR_PATTERN
                    elif 'temporal_trend' in deviation_types:
                        novelty_type = NoveltyType.ADVANCED_EVASION
                    else:
                        novelty_type = NoveltyType.UNKNOWN_ATTACK_VECTOR
                    
                    # Feature analysis
                    anomaly_features = {}
                    normal_mean = np.mean(self.normal_patterns, axis=0)
                    feature_deviations = np.abs(features - normal_mean)
                    
                    for j, (feat_name, deviation) in enumerate(zip(self.feature_names, feature_deviations)):
                        if deviation > np.std(self.normal_patterns[:, j]) * 2:
                            anomaly_features[feat_name] = float(deviation)
                    
                    pattern_deviations = {dev_type: score for dev_type, score in deviation_scores}
                    signature = self._generate_threat_signature(anomaly_features)
                    actions = self._recommend_actions(novelty_type, threat_score)
                    
                    threats.append(ZeroDayThreat(
                        event_id=f"event_{i}",
                        detection_method=self.method,
                        novelty_type=novelty_type,
                        threat_score=threat_score,
                        confidence_score=confidence,
                        anomaly_features=anomaly_features,
                        pattern_deviations=pattern_deviations,
                        timestamp=datetime.utcnow(),
                        attack_signature=signature,
                        recommended_actions=actions
                    ))
        
        return threats
    
    def _analyze_statistical_deviations(self, features: np.ndarray) -> List[Tuple[str, float]]:
        """Analyze statistical deviations from normal patterns."""
        deviations = []
        
        normal_mean = np.mean(self.normal_patterns, axis=0)
        normal_std = np.std(self.normal_patterns, axis=0)
        
        # Mean deviation
        mean_dev = np.linalg.norm(features - normal_mean)
        if mean_dev > self.deviation_thresholds['statistical']['mean_deviation']:
            score = min(mean_dev / (self.deviation_thresholds['statistical']['mean_deviation'] * 2), 1.0)
            deviations.append(('statistical_mean', score))
        
        # Feature-wise z-score analysis
        z_scores = np.abs((features - normal_mean) / (normal_std + 1e-10))
        extreme_z_count = np.sum(z_scores > 3.0)  # More than 3 std deviations
        
        if extreme_z_count > 2:  # Multiple extreme features
            score = min(extreme_z_count / len(features), 1.0)
            deviations.append(('statistical_zscore', score))
        
        return deviations
    
    def _analyze_temporal_deviations(self, temporal_window: np.ndarray) -> List[Tuple[str, float]]:
        """Analyze temporal pattern deviations."""
        deviations = []
        
        if 'temporal' not in self.deviation_thresholds:
            return deviations
        
        # Calculate current window statistics
        current_trend = np.polyfit(range(len(temporal_window)), temporal_window.mean(axis=1), 1)[0]
        current_autocorr = self._calculate_autocorrelation(temporal_window)
        
        # Compare with historical patterns
        historical_trends = [p['trend'] for p in self.temporal_patterns.values()]
        historical_autocorr = [p['autocorr'] for p in self.temporal_patterns.values()]
        
        # Trend deviation
        trend_deviation = abs(current_trend - np.mean(historical_trends))
        if trend_deviation > self.deviation_thresholds['temporal']['trend_deviation']:
            score = min(trend_deviation / (self.deviation_thresholds['temporal']['trend_deviation'] * 2), 1.0)
            deviations.append(('temporal_trend', score))
        
        # Autocorrelation deviation
        autocorr_deviation = abs(current_autocorr - np.mean(historical_autocorr))
        if autocorr_deviation > self.deviation_thresholds['temporal']['autocorr_deviation']:
            score = min(autocorr_deviation / (self.deviation_thresholds['temporal']['autocorr_deviation'] * 2), 1.0)
            deviations.append(('temporal_autocorr', score))
        
        return deviations
    
    def _analyze_sequence_deviations(self, sequence: np.ndarray) -> List[Tuple[str, float]]:
        """Analyze sequence pattern deviations."""
        deviations = []
        
        if 'kmeans' not in self.sequence_models:
            return deviations
        
        # Flatten sequence for comparison
        sequence_flat = sequence.flatten()
        
        # Find nearest cluster
        kmeans = self.sequence_models['kmeans']
        cluster_distances = [np.linalg.norm(sequence_flat - center) 
                           for center in kmeans.cluster_centers_]
        nearest_cluster = np.argmin(cluster_distances)
        min_distance = cluster_distances[nearest_cluster]
        
        # Check if distance exceeds typical range for this cluster
        if nearest_cluster in self.sequence_models['cluster_distance_stats']:
            cluster_stats = self.sequence_models['cluster_distance_stats'][nearest_cluster]
            threshold = cluster_stats['percentile_95']
            
            if min_distance > threshold:
                score = min(min_distance / (threshold * 2), 1.0)
                deviations.append(('sequence_anomaly', score))
        
        # Check frequency of this cluster pattern
        cluster_freq = self.sequence_models['cluster_frequencies'].get(nearest_cluster, 0)
        total_patterns = sum(self.sequence_models['cluster_frequencies'].values())
        
        if cluster_freq / total_patterns < 0.05:  # Very rare pattern
            score = 1.0 - (cluster_freq / total_patterns) * 20  # Scale rarity
            deviations.append(('sequence_rarity', min(score, 1.0)))
        
        return deviations


class VariationalAENoveltyDetector(BaseZeroDayDetector):
    """Variational Autoencoder based novelty detection."""
    
    def __init__(self, config: ZeroDayDetectionConfig):
        super().__init__(config, ZeroDayDetectionMethod.VARIATIONAL_AUTOENCODER)
        self.device = torch.device('cuda' if config.enable_gpu and torch.cuda.is_available() else 'cpu')
        self.reconstruction_threshold = None
        self.latent_space_model = None
        
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit VAE model on normal behavior data."""
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_normal.shape[1])]
        X_scaled = self._preprocess_features(X_normal, fit=True)
        
        # Create VAE model
        input_dim = X_scaled.shape[1]
        self.model = VariationalAutoEncoder(
            input_dim=input_dim,
            latent_dim=self.config.vae_latent_dim,
            hidden_dims=self.config.vae_hidden_dims
        ).to(self.device)
        
        # Prepare training data
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        dataset = TensorDataset(X_tensor, X_tensor)
        dataloader = DataLoader(dataset, batch_size=self.config.vae_batch_size, shuffle=True)
        
        # Training setup
        optimizer = optim.Adam(self.model.parameters(), lr=self.config.vae_learning_rate)
        
        # VAE loss function
        def vae_loss(recon_x, x, mu, logvar, beta=1.0):
            recon_loss = nn.MSELoss()(recon_x, x)
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            return recon_loss + beta * kl_loss / x.size(0)
        
        # Training loop
        self.model.train()
        for epoch in range(self.config.vae_epochs):
            total_loss = 0
            for batch_data, _ in dataloader:
                optimizer.zero_grad()
                
                recon_batch, mu, logvar = self.model(batch_data)
                loss = vae_loss(recon_batch, batch_data, mu, logvar, self.config.vae_beta)
                
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            
            if epoch % 20 == 0:
                avg_loss = total_loss / len(dataloader)
                logger.info(f"VAE Epoch {epoch}: Average Loss = {avg_loss:.4f}")
        
        # Calculate reconstruction threshold
        self.model.eval()
        with torch.no_grad():
            recon_errors = []
            for batch_data, _ in dataloader:
                recon_batch, _, _ = self.model(batch_data)
                batch_errors = torch.mean((batch_data - recon_batch) ** 2, dim=1)
                recon_errors.extend(batch_errors.cpu().numpy())
            
            # Use 95th percentile as threshold
            self.reconstruction_threshold = np.percentile(recon_errors, 95)
        
        # Build latent space model for anomaly detection
        with torch.no_grad():
            latent_representations = []
            for batch_data, _ in dataloader:
                mu, _ = self.model.encode(batch_data)
                latent_representations.extend(mu.cpu().numpy())
            
            # Fit isolation forest in latent space
            self.latent_space_model = IsolationForest(
                contamination=self.config.contamination_rate,
                random_state=self.config.random_state
            )
            self.latent_space_model.fit(latent_representations)
        
        self.normal_patterns = X_scaled
        self.is_fitted = True
        
        logger.info(f"Fitted VAE novelty detector: threshold = {self.reconstruction_threshold:.4f}")
    
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect zero-day threats using VAE reconstruction error and latent space analysis."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before detection")
        
        X_scaled = self._preprocess_features(X, fit=False)
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        
        self.model.eval()
        threats = []
        
        with torch.no_grad():
            # Get reconstructions and latent representations
            recon_batch, mu_batch, logvar_batch = self.model(X_tensor)
            latent_representations = mu_batch.cpu().numpy()
            
            # Calculate reconstruction errors
            recon_errors = torch.mean((X_tensor - recon_batch) ** 2, dim=1).cpu().numpy()
            
            # Get latent space anomaly scores
            latent_anomaly_scores = self.latent_space_model.decision_function(latent_representations)
            latent_predictions = self.latent_space_model.predict(latent_representations)
            
            for i, (recon_error, latent_score, latent_pred) in enumerate(
                zip(recon_errors, latent_anomaly_scores, latent_predictions)
            ):
                threat_indicators = []
                
                # Reconstruction-based anomaly
                if recon_error > self.reconstruction_threshold:
                    recon_score = min(recon_error / (self.reconstruction_threshold * 2), 1.0)
                    threat_indicators.append(("reconstruction_anomaly", recon_score))
                
                # Latent space anomaly
                if latent_pred == -1:
                    # Normalize anomaly score
                    normalized_score = 1.0 / (1.0 + np.exp(latent_score))  # Sigmoid
                    threat_indicators.append(("latent_anomaly", normalized_score))
                
                if threat_indicators:
                    threat_score = np.mean([score for _, score in threat_indicators])
                    confidence = len(threat_indicators) / 2.0  # Based on both methods agreeing
                    
                    # Determine novelty type based on error characteristics
                    if recon_error > self.reconstruction_threshold * 2:
                        novelty_type = NoveltyType.ZERO_DAY_EXPLOIT
                    elif latent_pred == -1 and recon_error > self.reconstruction_threshold:
                        novelty_type = NoveltyType.UNKNOWN_ATTACK_VECTOR
                    else:
                        novelty_type = NoveltyType.NOVEL_BEHAVIOR_PATTERN
                    
                    # Feature importance analysis using gradients
                    X_sample = X_tensor[i:i+1].requires_grad_(True)
                    recon_sample, _, _ = self.model(X_sample)
                    loss = nn.MSELoss()(recon_sample, X_sample)
                    loss.backward()
                    
                    feature_importances = X_sample.grad.abs().squeeze().cpu().numpy()
                    anomaly_features = {}
                    
                    # Get top anomalous features
                    top_indices = np.argsort(feature_importances)[-5:]  # Top 5 features
                    for idx in top_indices:
                        if idx < len(self.feature_names):
                            anomaly_features[self.feature_names[idx]] = float(feature_importances[idx])
                    
                    signature = self._generate_threat_signature(anomaly_features)
                    actions = self._recommend_actions(novelty_type, threat_score)
                    
                    threats.append(ZeroDayThreat(
                        event_id=f"event_{i}",
                        detection_method=self.method,
                        novelty_type=novelty_type,
                        threat_score=threat_score,
                        confidence_score=confidence,
                        anomaly_features=anomaly_features,
                        pattern_deviations={
                            "reconstruction_error": float(recon_error),
                            "latent_anomaly_score": float(latent_score)
                        },
                        timestamp=datetime.utcnow(),
                        attack_signature=signature,
                        recommended_actions=actions
                    ))
        
        return threats


class AdversarialThreatDetector(BaseZeroDayDetector):
    """Adversarial attack detection using adversarial training techniques."""
    
    def __init__(self, config: ZeroDayDetectionConfig):
        super().__init__(config, ZeroDayDetectionMethod.ADVERSARIAL_DETECTION)
        self.adversarial_examples = []
        self.boundary_models = {}
        self.feature_sensitivity = {}
        
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit adversarial detection model."""
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X_normal.shape[1])]
        X_scaled = self._preprocess_features(X_normal, fit=True)
        
        # Generate adversarial examples for boundary learning
        self._generate_adversarial_examples(X_scaled)
        
        # Train boundary detection models
        self._train_boundary_models(X_scaled)
        
        # Analyze feature sensitivity to adversarial perturbations
        self._analyze_feature_sensitivity(X_scaled)
        
        self.normal_patterns = X_scaled
        self.is_fitted = True
        
        logger.info(f"Fitted adversarial detection model with {len(self.adversarial_examples)} adversarial examples")
    
    def _generate_adversarial_examples(self, X_normal: np.ndarray) -> None:
        """Generate adversarial examples using gradient-based methods."""
        from sklearn.svm import OneClassSVM
        
        # Train a one-class SVM for normal behavior
        ocsvm = OneClassSVM(nu=self.config.contamination_rate)
        ocsvm.fit(X_normal)
        
        # Generate adversarial examples using FGSM-like approach
        for sample in X_normal[:min(100, len(X_normal))]:  # Limit for performance
            # Create perturbations in different directions
            for epsilon in [0.1, 0.2, 0.3]:
                for direction in ['random', 'gradient_based']:
                    if direction == 'random':
                        # Random perturbation
                        noise = np.random.normal(0, epsilon, sample.shape)
                        adversarial = sample + noise
                    else:
                        # Gradient-based perturbation (simplified)
                        gradient = self._estimate_gradient(sample, ocsvm)
                        adversarial = sample + epsilon * np.sign(gradient)
                    
                    # Check if adversarial example is outside decision boundary
                    if ocsvm.predict([adversarial])[0] == -1:  # Outlier
                        self.adversarial_examples.append({
                            'original': sample.copy(),
                            'adversarial': adversarial.copy(),
                            'perturbation': adversarial - sample,
                            'epsilon': epsilon,
                            'method': direction
                        })
    
    def _estimate_gradient(self, sample: np.ndarray, model: Any) -> np.ndarray:
        """Estimate gradient using finite differences."""
        gradient = np.zeros_like(sample)
        epsilon = 1e-6
        
        original_score = model.decision_function([sample])[0]
        
        for i in range(len(sample)):
            # Perturb feature i
            perturbed = sample.copy()
            perturbed[i] += epsilon
            
            perturbed_score = model.decision_function([perturbed])[0]
            gradient[i] = (perturbed_score - original_score) / epsilon
        
        return gradient
    
    def _train_boundary_models(self, X_normal: np.ndarray) -> None:
        """Train models to detect adversarial boundary violations."""
        from sklearn.neighbors import NearestNeighbors
        from sklearn.ensemble import IsolationForest
        
        # Nearest neighbors for local boundary detection
        nn_model = NearestNeighbors(n_neighbors=5)
        nn_model.fit(X_normal)
        self.boundary_models['nearest_neighbors'] = nn_model
        
        # Calculate typical distances to k nearest neighbors
        distances, _ = nn_model.kneighbors(X_normal)
        typical_distances = np.mean(distances, axis=1)
        self.boundary_models['distance_threshold'] = np.percentile(typical_distances, 95)
        
        # Isolation forest for global anomaly detection
        isolation_forest = IsolationForest(
            contamination=self.config.contamination_rate * 2,  # More sensitive for adversarial
            random_state=self.config.random_state
        )
        isolation_forest.fit(X_normal)
        self.boundary_models['isolation_forest'] = isolation_forest
    
    def _analyze_feature_sensitivity(self, X_normal: np.ndarray) -> None:
        """Analyze which features are most sensitive to adversarial perturbations."""
        if not self.adversarial_examples:
            return
        
        # Calculate feature-wise perturbation statistics
        feature_perturbations = defaultdict(list)
        
        for adv_example in self.adversarial_examples:
            perturbation = adv_example['perturbation']
            for i, (feature_name, pert_value) in enumerate(zip(self.feature_names, perturbation)):
                feature_perturbations[feature_name].append(abs(pert_value))
        
        # Calculate sensitivity metrics
        for feature_name, perturbations in feature_perturbations.items():
            self.feature_sensitivity[feature_name] = {
                'mean_perturbation': np.mean(perturbations),
                'max_perturbation': np.max(perturbations),
                'std_perturbation': np.std(perturbations),
                'sensitivity_score': np.mean(perturbations) * np.std(perturbations)  # Combined metric
            }
    
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect adversarial attacks and evasion attempts."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before detection")
        
        X_scaled = self._preprocess_features(X, fit=False)
        threats = []
        
        for i, features in enumerate(X_scaled):
            threat_indicators = []
            
            # Boundary violation detection
            boundary_violations = self._detect_boundary_violations(features)
            threat_indicators.extend(boundary_violations)
            
            # Adversarial pattern detection
            adversarial_patterns = self._detect_adversarial_patterns(features)
            threat_indicators.extend(adversarial_patterns)
            
            # Feature sensitivity analysis
            sensitivity_anomalies = self._detect_sensitivity_anomalies(features)
            threat_indicators.extend(sensitivity_anomalies)
            
            if threat_indicators:
                threat_score = np.mean([score for _, score in threat_indicators])
                confidence = len(threat_indicators) / 5.0  # Normalize by max indicators
                
                # Determine novelty type
                indicator_types = [itype for itype, _ in threat_indicators]
                
                if 'boundary_violation' in indicator_types:
                    novelty_type = NoveltyType.ADVANCED_EVASION
                elif 'adversarial_pattern' in indicator_types:
                    novelty_type = NoveltyType.ZERO_DAY_EXPLOIT
                else:
                    novelty_type = NoveltyType.HYBRID_ATTACK
                
                # Feature analysis
                anomaly_features = {}
                for j, (feat_name, feat_value) in enumerate(zip(self.feature_names, features)):
                    if feat_name in self.feature_sensitivity:
                        sensitivity = self.feature_sensitivity[feat_name]['sensitivity_score']
                        if sensitivity > np.mean(list(s['sensitivity_score'] for s in self.feature_sensitivity.values())):
                            anomaly_features[feat_name] = float(feat_value)
                
                pattern_deviations = {ind_type: score for ind_type, score in threat_indicators}
                signature = self._generate_threat_signature(anomaly_features)
                actions = self._recommend_actions(novelty_type, threat_score)
                
                threats.append(ZeroDayThreat(
                    event_id=f"event_{i}",
                    detection_method=self.method,
                    novelty_type=novelty_type,
                    threat_score=threat_score,
                    confidence_score=confidence,
                    anomaly_features=anomaly_features,
                    pattern_deviations=pattern_deviations,
                    timestamp=datetime.utcnow(),
                    attack_signature=signature,
                    recommended_actions=actions
                ))
        
        return threats
    
    def _detect_boundary_violations(self, features: np.ndarray) -> List[Tuple[str, float]]:
        """Detect violations of decision boundaries."""
        violations = []
        
        # Nearest neighbor boundary check
        if 'nearest_neighbors' in self.boundary_models:
            nn_model = self.boundary_models['nearest_neighbors']
            distances, _ = nn_model.kneighbors([features])
            avg_distance = np.mean(distances)
            
            threshold = self.boundary_models['distance_threshold']
            if avg_distance > threshold:
                score = min(avg_distance / (threshold * 2), 1.0)
                violations.append(('boundary_violation', score))
        
        # Isolation forest boundary check
        if 'isolation_forest' in self.boundary_models:
            isolation_score = self.boundary_models['isolation_forest'].decision_function([features])[0]
            if isolation_score < 0:  # Anomaly
                score = min(abs(isolation_score), 1.0)
                violations.append(('isolation_anomaly', score))
        
        return violations
    
    def _detect_adversarial_patterns(self, features: np.ndarray) -> List[Tuple[str, float]]:
        """Detect patterns similar to known adversarial examples."""
        patterns = []
        
        if not self.adversarial_examples:
            return patterns
        
        # Compare with known adversarial examples
        min_distance = float('inf')
        for adv_example in self.adversarial_examples:
            distance = np.linalg.norm(features - adv_example['adversarial'])
            min_distance = min(min_distance, distance)
        
        # If very similar to a known adversarial example
        if min_distance < 1.0:  # Threshold for similarity
            score = 1.0 - min_distance
            patterns.append(('adversarial_pattern', score))
        
        return patterns
    
    def _detect_sensitivity_anomalies(self, features: np.ndarray) -> List[Tuple[str, float]]:
        """Detect anomalies in sensitive feature regions."""
        anomalies = []
        
        if not self.feature_sensitivity:
            return anomalies
        
        # Check if features values are in high-sensitivity regions
        normal_mean = np.mean(self.normal_patterns, axis=0)
        feature_deviations = features - normal_mean
        
        sensitive_deviations = 0
        total_sensitivity = 0
        
        for i, (feat_name, deviation) in enumerate(zip(self.feature_names, feature_deviations)):
            if feat_name in self.feature_sensitivity:
                sensitivity = self.feature_sensitivity[feat_name]['sensitivity_score']
                total_sensitivity += sensitivity
                
                # Weight deviation by sensitivity
                weighted_deviation = abs(deviation) * sensitivity
                if weighted_deviation > 1.0:  # Threshold for significant sensitive deviation
                    sensitive_deviations += weighted_deviation
        
        if total_sensitivity > 0 and sensitive_deviations > 2.0:
            score = min(sensitive_deviations / total_sensitivity, 1.0)
            anomalies.append(('sensitivity_anomaly', score))
        
        return anomalies


class EnsembleZeroDayDetector:
    """Ensemble of multiple zero-day detection methods."""
    
    def __init__(self, config: ZeroDayDetectionConfig, methods: List[ZeroDayDetectionMethod]):
        self.config = config
        self.methods = methods
        self.detectors: Dict[ZeroDayDetectionMethod, BaseZeroDayDetector] = {}
        self.is_fitted = False
        
        # Initialize individual detectors
        for method in methods:
            if method == ZeroDayDetectionMethod.SEMI_SUPERVISED:
                self.detectors[method] = SemiSupervisedZeroDayDetector(config)
            elif method == ZeroDayDetectionMethod.CLUSTERING_OUTLIER:
                self.detectors[method] = ClusteringOutlierDetector(config)
            elif method == ZeroDayDetectionMethod.VARIATIONAL_AUTOENCODER:
                self.detectors[method] = VariationalAENoveltyDetector(config)
            elif method == ZeroDayDetectionMethod.PATTERN_DEVIATION:
                self.detectors[method] = PatternDeviationDetector(config)
            elif method == ZeroDayDetectionMethod.ADVERSARIAL_DETECTION:
                self.detectors[method] = AdversarialThreatDetector(config)
    
    def fit(self, X_normal: np.ndarray, X_labeled: Optional[np.ndarray] = None, 
            y_labeled: Optional[np.ndarray] = None, feature_names: Optional[List[str]] = None) -> None:
        """Fit all ensemble detectors."""
        logger.info(f"Fitting ensemble with {len(self.detectors)} detectors")
        
        successful_detectors = {}
        
        for method, detector in self.detectors.items():
            try:
                logger.info(f"Training {method.value} detector...")
                detector.fit(X_normal, X_labeled, y_labeled, feature_names)
                successful_detectors[method] = detector
            except Exception as e:
                logger.error(f"Failed to train {method.value} detector: {e}")
                continue
        
        self.detectors = successful_detectors
        self.is_fitted = True
        
        logger.info(f"Ensemble fitted with {len(self.detectors)} successful detectors")
    
    def detect_zero_day_threats(self, X: np.ndarray) -> List[ZeroDayThreat]:
        """Detect zero-day threats using ensemble voting."""
        if not self.is_fitted:
            raise ValueError("Ensemble must be fitted before detection")
        
        # Collect detections from all detectors
        all_detections: Dict[ZeroDayDetectionMethod, List[ZeroDayThreat]] = {}
        
        for method, detector in self.detectors.items():
            try:
                detections = detector.detect_zero_day_threats(X)
                all_detections[method] = detections
            except Exception as e:
                logger.error(f"Failed to get detections from {method.value}: {e}")
                continue
        
        if not all_detections:
            return []
        
        # Ensemble aggregation
        n_samples = len(X)
        ensemble_threats = []
        
        for i in range(n_samples):
            # Collect detections for this sample
            sample_detections = []
            threat_scores = []
            confidence_scores = []
            
            for method, detections in all_detections.items():
                for detection in detections:
                    if detection.event_id == f"event_{i}":
                        sample_detections.append(detection)
                        threat_scores.append(detection.threat_score)
                        confidence_scores.append(detection.confidence_score)
                        break
            
            # Apply ensemble voting
            if len(sample_detections) >= len(self.detectors) * self.config.ensemble_voting_threshold:
                # Aggregate detection results
                avg_threat_score = np.mean(threat_scores)
                avg_confidence = np.mean(confidence_scores)
                
                # Choose most severe novelty type
                novelty_types = [det.novelty_type for det in sample_detections]
                severity_order = [
                    NoveltyType.ZERO_DAY_EXPLOIT,
                    NoveltyType.UNKNOWN_ATTACK_VECTOR,
                    NoveltyType.ADVANCED_EVASION,
                    NoveltyType.HYBRID_ATTACK,
                    NoveltyType.EMERGING_MALWARE,
                    NoveltyType.NOVEL_BEHAVIOR_PATTERN
                ]
                
                ensemble_novelty_type = NoveltyType.NOVEL_BEHAVIOR_PATTERN
                for severity_type in severity_order:
                    if severity_type in novelty_types:
                        ensemble_novelty_type = severity_type
                        break
                
                # Combine anomaly features
                combined_features = defaultdict(float)
                for detection in sample_detections:
                    weight = 1.0 / len(sample_detections)
                    for feature, value in detection.anomaly_features.items():
                        combined_features[feature] += value * weight
                
                # Combine recommended actions
                all_actions = set()
                for detection in sample_detections:
                    all_actions.update(detection.recommended_actions)
                
                ensemble_threats.append(ZeroDayThreat(
                    event_id=f"event_{i}",
                    detection_method=ZeroDayDetectionMethod.ENSEMBLE_HYBRID,
                    novelty_type=ensemble_novelty_type,
                    threat_score=avg_threat_score,
                    confidence_score=avg_confidence,
                    anomaly_features=dict(combined_features),
                    cluster_info={
                        "ensemble_detectors": len(sample_detections),
                        "detection_methods": [det.detection_method.value for det in sample_detections]
                    },
                    timestamp=datetime.utcnow(),
                    attack_signature=sample_detections[0].attack_signature,  # Use first signature
                    recommended_actions=list(all_actions)
                ))
        
        return ensemble_threats


class ZeroDayDetectionManager:
    """Main manager for zero-day and unknown threat detection."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("zero_day_detection")
        self.mlflow_manager = MLFlowManager(settings)
        
        # Default configuration
        self.config = ZeroDayDetectionConfig()
        
        # Storage for trained models
        self.trained_models: Dict[str, Union[BaseZeroDayDetector, EnsembleZeroDayDetector]] = {}
        
        # Threat signature database
        self.known_signatures = set()
        self.signature_history = deque(maxlen=10000)
        
    async def train_zero_day_detectors(
        self,
        normal_events: List[SecurityEvent],
        labeled_events: Optional[List[SecurityEvent]] = None,
        threat_labels: Optional[Dict[str, str]] = None,
        model_name: str = "default",
        methods: Optional[List[ZeroDayDetectionMethod]] = None,
        config: Optional[ZeroDayDetectionConfig] = None
    ) -> Dict[str, Any]:
        """Train zero-day detection models."""
        
        if config:
            self.config = config
        
        if methods is None:
            methods = [
                ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
                ZeroDayDetectionMethod.VARIATIONAL_AUTOENCODER,
                ZeroDayDetectionMethod.SEMI_SUPERVISED,
                ZeroDayDetectionMethod.PATTERN_DEVIATION,
                ZeroDayDetectionMethod.ADVERSARIAL_DETECTION
            ]
        
        logger.info(f"Training zero-day detectors: {[m.value for m in methods]}")
        
        # Prepare training data
        normal_features = [self._extract_zero_day_features(event) for event in normal_events]
        normal_df = pd.DataFrame(normal_features)
        feature_columns = [col for col in normal_df.columns if col != 'event_id']
        X_normal = normal_df[feature_columns].fillna(0).values
        
        X_labeled = None
        y_labeled = None
        
        if labeled_events and threat_labels:
            labeled_features = [self._extract_zero_day_features(event) for event in labeled_events 
                              if event.event_id in threat_labels]
            if labeled_features:
                labeled_df = pd.DataFrame(labeled_features)
                X_labeled = labeled_df[feature_columns].fillna(0).values
                y_labeled = np.array([threat_labels[event.event_id] for event in labeled_events 
                                    if event.event_id in threat_labels])
        
        training_results = {}
        
        with mlflow.start_run(run_name=f"zero_day_training_{model_name}"):
            if len(methods) > 1:
                # Train ensemble
                ensemble = EnsembleZeroDayDetector(self.config, methods)
                start_time = datetime.utcnow()
                
                ensemble.fit(X_normal, X_labeled, y_labeled, feature_columns)
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.trained_models[model_name] = ensemble
                
                # Log ensemble metrics
                mlflow.log_param("model_type", "ensemble")
                mlflow.log_param("methods", [m.value for m in methods])
                mlflow.log_param("n_detectors", len(ensemble.detectors))
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("normal_samples", len(X_normal))
                mlflow.log_metric("labeled_samples", len(X_labeled) if X_labeled is not None else 0)
                
                training_results = {
                    'model_name': model_name,
                    'model_type': 'ensemble',
                    'methods': [m.value for m in methods],
                    'training_time': training_time,
                    'successful_detectors': len(ensemble.detectors)
                }
                
            else:
                # Train single detector
                method = methods[0]
                start_time = datetime.utcnow()
                
                if method == ZeroDayDetectionMethod.SEMI_SUPERVISED:
                    detector = SemiSupervisedZeroDayDetector(self.config)
                elif method == ZeroDayDetectionMethod.CLUSTERING_OUTLIER:
                    detector = ClusteringOutlierDetector(self.config)
                elif method == ZeroDayDetectionMethod.VARIATIONAL_AUTOENCODER:
                    detector = VariationalAENoveltyDetector(self.config)
                elif method == ZeroDayDetectionMethod.PATTERN_DEVIATION:
                    detector = PatternDeviationDetector(self.config)
                elif method == ZeroDayDetectionMethod.ADVERSARIAL_DETECTION:
                    detector = AdversarialThreatDetector(self.config)
                else:
                    raise ValueError(f"Unsupported detection method: {method}")
                
                detector.fit(X_normal, X_labeled, y_labeled, feature_columns)
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.trained_models[model_name] = detector
                
                # Log single detector metrics
                mlflow.log_param("model_type", method.value)
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("normal_samples", len(X_normal))
                
                training_results = {
                    'model_name': model_name,
                    'model_type': method.value,
                    'training_time': training_time
                }
        
        logger.info(f"Completed training zero-day detectors for '{model_name}'")
        return training_results
    
    def _extract_zero_day_features(self, event: SecurityEvent) -> Dict[str, Any]:
        """Extract features optimized for zero-day detection."""
        features = {
            # Temporal anomaly features
            'hour': event.timestamp.hour,
            'minute': event.timestamp.minute,
            'day_of_week': event.timestamp.weekday(),
            'is_weekend': int(event.timestamp.weekday() >= 5),
            'is_night': int(event.timestamp.hour < 6 or event.timestamp.hour > 22),
            'is_holiday': 0,  # Could be enhanced with holiday detection
            
            # Behavioral deviation features
            'severity_numeric': {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(event.severity, 0),
            'event_type_hash': hash(event.event_type) % 1000,  # Compact representation
            'source_entropy': self._calculate_entropy(event.source_ip) if event.source_ip else 0,
            'dest_entropy': self._calculate_entropy(event.dest_ip) if event.dest_ip else 0,
            
            # Network pattern features
            'port': event.port or 0,
            'port_category': self._categorize_port(event.port),
            'protocol_numeric': self._encode_protocol(event.network_protocol),
            'has_unusual_port': int((event.port or 0) > 50000),
            
            # Process and command features
            'command_complexity': self._calculate_command_complexity(event.command_line),
            'process_path_depth': len(event.process_name.split('/')) if event.process_name else 0,
            'has_suspicious_keywords': self._check_suspicious_keywords(event.command_line),
            'command_entropy': self._calculate_entropy(event.command_line) if event.command_line else 0,
            
            # File system features
            'file_path_depth': len(event.file_path.split('/')) if event.file_path else 0,
            'file_in_system_dir': int('/system' in (event.file_path or '').lower()),
            'file_in_temp_dir': int('/tmp' in (event.file_path or '').lower()),
            'file_extension_risk': self._assess_file_extension_risk(event.file_path),
            
            # User behavior features
            'username_length': len(event.username) if event.username else 0,
            'hostname_length': len(event.hostname) if event.hostname else 0,
            'is_service_account': int(self._is_service_account(event.username)),
            'is_admin_user': int(self._is_admin_user(event.username)),
            
            # Data volume and patterns
            'raw_data_complexity': len(str(event.raw_data)) if event.raw_data else 0,
            'has_base64': int('base64' in str(event.raw_data).lower()) if event.raw_data else 0,
            'has_encoded_data': self._detect_encoded_data(event.raw_data),
            'event_size_bytes': len(json.dumps(event.dict())),
            
            # Advanced pattern features
            'sequence_position': 0,  # Could be enhanced with sequence analysis
            'frequency_deviation': 0,  # Could be enhanced with frequency analysis
            'correlation_anomaly': 0   # Could be enhanced with correlation analysis
        }
        
        return features
    
    def _calculate_entropy(self, text: Optional[str]) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        import math
        from collections import Counter
        
        # Count character frequencies
        counter = Counter(text)
        total = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _categorize_port(self, port: Optional[int]) -> int:
        """Categorize port into risk levels."""
        if not port:
            return 0
        
        if port <= 1023:  # Well-known ports
            return 1
        elif port <= 49151:  # Registered ports
            return 2
        else:  # Dynamic/private ports
            return 3
    
    def _encode_protocol(self, protocol: Optional[str]) -> int:
        """Encode network protocol as numeric value."""
        protocol_map = {
            'tcp': 1, 'udp': 2, 'icmp': 3, 'http': 4, 'https': 5,
            'ftp': 6, 'ssh': 7, 'telnet': 8, 'smtp': 9, 'dns': 10
        }
        
        if not protocol:
            return 0
        
        return protocol_map.get(protocol.lower(), 99)  # 99 for unknown protocols
    
    def _calculate_command_complexity(self, command: Optional[str]) -> float:
        """Calculate complexity score of command line."""
        if not command:
            return 0.0
        
        complexity = 0.0
        
        # Length factor
        complexity += min(len(command) / 100, 1.0)
        
        # Special character density
        special_chars = sum(1 for c in command if c in '|&;<>(){}[]$`"\'')
        complexity += min(special_chars / len(command) * 10, 1.0)
        
        # Word count
        words = len(command.split())
        complexity += min(words / 20, 1.0)
        
        # Suspicious patterns
        suspicious_patterns = ['rm -rf', 'wget', 'curl', 'nc -', 'bash -i', '/dev/tcp']
        for pattern in suspicious_patterns:
            if pattern in command.lower():
                complexity += 0.5
        
        return min(complexity, 5.0)  # Cap at 5.0
    
    def _check_suspicious_keywords(self, command: Optional[str]) -> int:
        """Check for suspicious keywords in command."""
        if not command:
            return 0
        
        suspicious_keywords = [
            'powershell', 'cmd.exe', 'wscript', 'cscript', 'rundll32',
            'regsvr32', 'mshta', 'certutil', 'bitsadmin', 'wmic'
        ]
        
        command_lower = command.lower()
        return sum(1 for keyword in suspicious_keywords if keyword in command_lower)
    
    def _assess_file_extension_risk(self, file_path: Optional[str]) -> int:
        """Assess risk level based on file extension."""
        if not file_path:
            return 0
        
        high_risk_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr']
        medium_risk_extensions = ['.dll', '.sys', '.com', '.pif']
        
        file_lower = file_path.lower()
        
        for ext in high_risk_extensions:
            if file_lower.endswith(ext):
                return 3
        
        for ext in medium_risk_extensions:
            if file_lower.endswith(ext):
                return 2
        
        return 1  # Low risk for other files
    
    def _is_service_account(self, username: Optional[str]) -> bool:
        """Check if username appears to be a service account."""
        if not username:
            return False
        
        service_indicators = ['service', 'svc', 'system', 'daemon', 'bot', '$']
        username_lower = username.lower()
        
        return any(indicator in username_lower for indicator in service_indicators)
    
    def _is_admin_user(self, username: Optional[str]) -> bool:
        """Check if username appears to be an admin user."""
        if not username:
            return False
        
        admin_indicators = ['admin', 'root', 'administrator', 'sa', 'dba']
        username_lower = username.lower()
        
        return any(indicator in username_lower for indicator in admin_indicators)
    
    def _detect_encoded_data(self, raw_data: Any) -> int:
        """Detect presence of encoded data."""
        if not raw_data:
            return 0
        
        data_str = str(raw_data).lower()
        encoding_indicators = ['base64', 'hex', 'url%', 'unicode', '\\x']
        
        return sum(1 for indicator in encoding_indicators if indicator in data_str)
    
    async def detect_zero_day_threats(
        self,
        events: List[SecurityEvent],
        model_name: str = "default"
    ) -> List[ZeroDayThreat]:
        """Detect zero-day threats in security events."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        detector = self.trained_models[model_name]
        
        # Extract features
        features_data = [self._extract_zero_day_features(event) for event in events]
        features_df = pd.DataFrame(features_data)
        feature_columns = [col for col in features_df.columns if col != 'event_id']
        X = features_df[feature_columns].fillna(0).values
        
        # Get zero-day detections
        zero_day_threats = detector.detect_zero_day_threats(X)
        
        # Update event IDs and track signatures
        for i, (event, threat) in enumerate(zip(events, zero_day_threats)):
            if threat:
                threat.event_id = event.event_id
                threat.related_events = [event.event_id]
                
                # Track signature
                if threat.attack_signature not in self.known_signatures:
                    self.known_signatures.add(threat.attack_signature)
                    self.signature_history.append({
                        'signature': threat.attack_signature,
                        'timestamp': threat.timestamp,
                        'novelty_type': threat.novelty_type.value
                    })
                
                # Log detection metrics
                self.metrics.increment_counter(
                    "zero_day_threats_detected",
                    tags={
                        "novelty_type": threat.novelty_type.value,
                        "detection_method": threat.detection_method.value,
                        "model": model_name,
                        "threat_level": "high" if threat.threat_score > 0.7 else "medium" if threat.threat_score > 0.4 else "low"
                    }
                )
        
        # Filter out None values
        valid_threats = [t for t in zero_day_threats if t is not None]
        
        logger.info(f"Detected {len(valid_threats)} zero-day threats using model '{model_name}'")
        return valid_threats
    
    async def get_threat_intelligence_summary(self) -> Dict[str, Any]:
        """Get summary of detected zero-day threat intelligence."""
        
        # Analyze signature patterns
        recent_signatures = [s for s in self.signature_history 
                           if s['timestamp'] > datetime.utcnow() - timedelta(days=7)]
        
        # Count novelty types
        novelty_counts = defaultdict(int)
        for sig in recent_signatures:
            novelty_counts[sig['novelty_type']] += 1
        
        summary = {
            'total_signatures': len(self.known_signatures),
            'recent_signatures': len(recent_signatures),
            'novelty_type_distribution': dict(novelty_counts),
            'trained_models': list(self.trained_models.keys()),
            'detection_metrics': await self.metrics.get_metrics() if hasattr(self.metrics, 'get_metrics') else {}
        }
        
        return summary
    
    async def validate_zero_day_models(
        self,
        test_events: List[SecurityEvent],
        ground_truth_labels: Dict[str, bool],  # True for zero-day, False for normal
        model_name: str = "default"
    ) -> Dict[str, Any]:
        """Validate zero-day detection models against ground truth."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        logger.info(f"Validating zero-day model '{model_name}' with {len(test_events)} test events")
        
        # Get predictions
        predicted_threats = await self.detect_zero_day_threats(test_events, model_name)
        
        # Build prediction results
        y_true = []
        y_pred = []
        y_scores = []
        
        for event in test_events:
            true_label = ground_truth_labels.get(event.event_id, False)
            y_true.append(1 if true_label else 0)
            
            # Check if this event was flagged as zero-day threat
            threat_detected = any(t.event_id == event.event_id for t in predicted_threats)
            y_pred.append(1 if threat_detected else 0)
            
            # Get threat score if detected
            threat_score = 0.0
            for threat in predicted_threats:
                if threat.event_id == event.event_id:
                    threat_score = threat.threat_score
                    break
            y_scores.append(threat_score)
        
        # Calculate metrics
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, f1_score,
            roc_auc_score, confusion_matrix, classification_report
        )
        
        validation_results = {
            'model_name': model_name,
            'test_samples': len(test_events),
            'zero_day_samples': sum(y_true),
            'normal_samples': len(y_true) - sum(y_true),
            'detected_threats': sum(y_pred),
            
            # Classification metrics
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1_score': f1_score(y_true, y_pred, zero_division=0),
            
            # Additional metrics
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
            'classification_report': classification_report(y_true, y_pred, output_dict=True)
        }
        
        # AUC-ROC if we have threat scores
        if max(y_scores) > 0:
            try:
                validation_results['roc_auc'] = roc_auc_score(y_true, y_scores)
            except ValueError:
                validation_results['roc_auc'] = None
        
        # Log validation results
        with mlflow.start_run(run_name=f"zero_day_validation_{model_name}"):
            mlflow.log_metrics({
                'validation_accuracy': validation_results['accuracy'],
                'validation_precision': validation_results['precision'],
                'validation_recall': validation_results['recall'],
                'validation_f1': validation_results['f1_score']
            })
            
            if validation_results.get('roc_auc'):
                mlflow.log_metric('validation_roc_auc', validation_results['roc_auc'])
        
        logger.info(f"Model validation completed: Accuracy={validation_results['accuracy']:.3f}, "
                   f"Precision={validation_results['precision']:.3f}, "
                   f"Recall={validation_results['recall']:.3f}")
        
        return validation_results
    
    async def benchmark_detection_methods(
        self,
        test_events: List[SecurityEvent],
        ground_truth_labels: Dict[str, bool],
        methods: Optional[List[ZeroDayDetectionMethod]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Benchmark different zero-day detection methods."""
        
        if methods is None:
            methods = [
                ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
                ZeroDayDetectionMethod.VARIATIONAL_AUTOENCODER,
                ZeroDayDetectionMethod.SEMI_SUPERVISED,
                ZeroDayDetectionMethod.PATTERN_DEVIATION,
                ZeroDayDetectionMethod.ADVERSARIAL_DETECTION
            ]
        
        logger.info(f"Benchmarking {len(methods)} detection methods")
        
        # Prepare normal data for training (events labeled as False)
        normal_events = [e for e in test_events[:200] if not ground_truth_labels.get(e.event_id, True)]
        
        benchmark_results = {}
        
        for method in methods:
            try:
                method_name = f"benchmark_{method.value}"
                logger.info(f"Training and testing {method.value} method...")
                
                # Train individual method
                training_result = await self.train_zero_day_detectors(
                    normal_events=normal_events,
                    model_name=method_name,
                    methods=[method]
                )
                
                # Validate method
                validation_result = await self.validate_zero_day_models(
                    test_events=test_events,
                    ground_truth_labels=ground_truth_labels,
                    model_name=method_name
                )
                
                # Combine results
                benchmark_results[method.value] = {
                    **training_result,
                    **validation_result,
                    'method': method.value
                }
                
            except Exception as e:
                logger.error(f"Benchmarking failed for {method.value}: {e}")
                benchmark_results[method.value] = {
                    'method': method.value,
                    'error': str(e),
                    'status': 'failed'
                }
        
        # Compare methods
        successful_methods = {k: v for k, v in benchmark_results.items() if 'error' not in v}
        
        if successful_methods:
            comparison = {
                'best_accuracy': max(successful_methods.items(), key=lambda x: x[1].get('accuracy', 0)),
                'best_precision': max(successful_methods.items(), key=lambda x: x[1].get('precision', 0)),
                'best_recall': max(successful_methods.items(), key=lambda x: x[1].get('recall', 0)),
                'best_f1': max(successful_methods.items(), key=lambda x: x[1].get('f1_score', 0)),
                'fastest_training': min(successful_methods.items(), key=lambda x: x[1].get('training_time', float('inf')))
            }
            
            benchmark_results['comparison'] = comparison
        
        return benchmark_results
    
    async def generate_synthetic_zero_day_data(
        self,
        base_events: List[SecurityEvent],
        n_synthetic: int = 100,
        mutation_strategies: Optional[List[str]] = None
    ) -> Tuple[List[SecurityEvent], Dict[str, bool]]:
        """Generate synthetic zero-day threats for testing."""
        
        if mutation_strategies is None:
            mutation_strategies = ['feature_drift', 'temporal_shift', 'noise_injection', 'adversarial_perturbation']
        
        logger.info(f"Generating {n_synthetic} synthetic zero-day events using {len(mutation_strategies)} strategies")
        
        synthetic_events = []
        synthetic_labels = {}
        
        for i in range(n_synthetic):
            # Select random base event
            base_event = np.random.choice(base_events)
            strategy = np.random.choice(mutation_strategies)
            
            # Create synthetic event
            synthetic_event = self._create_synthetic_event(base_event, strategy, i)
            synthetic_events.append(synthetic_event)
            synthetic_labels[synthetic_event.event_id] = True  # All synthetic events are zero-day
        
        # Add some normal events to balance
        normal_count = min(len(base_events), n_synthetic // 2)
        normal_events = np.random.choice(base_events, normal_count, replace=False)
        
        for event in normal_events:
            if event.event_id not in synthetic_labels:  # Avoid duplicates
                synthetic_events.append(event)
                synthetic_labels[event.event_id] = False
        
        logger.info(f"Generated {len(synthetic_events)} synthetic events "
                   f"({sum(synthetic_labels.values())} zero-day, "
                   f"{len(synthetic_labels) - sum(synthetic_labels.values())} normal)")
        
        return synthetic_events, synthetic_labels
    
    def _create_synthetic_event(self, base_event: SecurityEvent, strategy: str, event_id: int) -> SecurityEvent:
        """Create a synthetic zero-day event using specified strategy."""
        
        # Create copy of base event
        synthetic_data = base_event.dict()
        synthetic_data['event_id'] = f"synthetic_zd_{event_id}_{strategy}"
        synthetic_data['timestamp'] = datetime.utcnow()
        
        # Apply mutation strategy
        if strategy == 'feature_drift':
            # Modify key features to simulate drift
            if synthetic_data.get('port'):
                synthetic_data['port'] = synthetic_data['port'] + np.random.randint(-1000, 1000)
            
            if synthetic_data.get('command_line'):
                # Add suspicious patterns
                suspicious_additions = ['powershell -enc', 'certutil -decode', 'wmic process']
                addition = np.random.choice(suspicious_additions)
                synthetic_data['command_line'] = f"{synthetic_data['command_line']} {addition}"
        
        elif strategy == 'temporal_shift':
            # Shift to unusual time patterns
            unusual_hour = np.random.choice([2, 3, 4, 23, 0, 1])  # Late night/early morning
            new_time = synthetic_data['timestamp'].replace(hour=unusual_hour)
            synthetic_data['timestamp'] = new_time
        
        elif strategy == 'noise_injection':
            # Add noise to network patterns
            if synthetic_data.get('source_ip'):
                # Modify IP slightly
                ip_parts = synthetic_data['source_ip'].split('.')
                if len(ip_parts) == 4 and ip_parts[-1].isdigit():
                    last_octet = int(ip_parts[-1])
                    new_octet = (last_octet + np.random.randint(1, 50)) % 256
                    ip_parts[-1] = str(new_octet)
                    synthetic_data['source_ip'] = '.'.join(ip_parts)
        
        elif strategy == 'adversarial_perturbation':
            # Create adversarial-like modifications
            if synthetic_data.get('file_path'):
                # Add hidden characters or modify extension
                synthetic_data['file_path'] = synthetic_data['file_path'].replace('.exe', '.ex e')
            
            if synthetic_data.get('process_name'):
                # Add zero-width characters or similar
                synthetic_data['process_name'] = synthetic_data['process_name'] + '\\x00'
        
        # Increase severity to make it more threat-like
        synthetic_data['severity'] = 'high'
        
        return SecurityEvent(**synthetic_data)
    
    async def continuous_learning_update(
        self,
        new_events: List[SecurityEvent],
        feedback: Dict[str, bool],  # event_id -> is_zero_day
        model_name: str = "default",
        retrain_threshold: int = 100
    ) -> Dict[str, Any]:
        """Update models with new data using continuous learning."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        logger.info(f"Performing continuous learning update for '{model_name}' with {len(new_events)} events")
        
        # Separate feedback into normal and zero-day events
        normal_events = [e for e in new_events if not feedback.get(e.event_id, True)]
        zero_day_events = [e for e in new_events if feedback.get(e.event_id, False)]
        
        update_results = {
            'model_name': model_name,
            'new_normal_events': len(normal_events),
            'new_zero_day_events': len(zero_day_events),
            'total_new_events': len(new_events),
            'retrained': False
        }
        
        # Update signature database with confirmed zero-day events
        for event in zero_day_events:
            features = self._extract_zero_day_features(event)
            signature = self._generate_threat_signature(features)
            
            if signature not in self.known_signatures:
                self.known_signatures.add(signature)
                self.signature_history.append({
                    'signature': signature,
                    'timestamp': datetime.utcnow(),
                    'novelty_type': 'confirmed_zero_day',
                    'event_id': event.event_id
                })
        
        # Check if retraining is needed
        if len(normal_events) >= retrain_threshold or len(zero_day_events) >= retrain_threshold // 4:
            logger.info(f"Retraining threshold reached, updating model...")
            
            # Retrain with combined data
            retrain_results = await self.train_zero_day_detectors(
                normal_events=normal_events,
                labeled_events=zero_day_events if zero_day_events else None,
                threat_labels={e.event_id: 'zero_day' for e in zero_day_events} if zero_day_events else None,
                model_name=f"{model_name}_updated_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            )
            
            update_results['retrained'] = True
            update_results['retrain_results'] = retrain_results
            
            # Replace old model with updated one
            old_model_name = f"{model_name}_old_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            self.trained_models[old_model_name] = self.trained_models[model_name]
            self.trained_models[model_name] = self.trained_models[retrain_results['model_name']]
            del self.trained_models[retrain_results['model_name']]
        
        # Log continuous learning metrics
        self.metrics.increment_counter(
            "continuous_learning_updates",
            tags={
                "model": model_name,
                "retrained": str(update_results['retrained']),
                "normal_events": str(len(normal_events)),
                "zero_day_events": str(len(zero_day_events))
            }
        )
        
        return update_results
    
    async def get_detection_metrics(self) -> Dict[str, Any]:
        """Get zero-day detection performance metrics."""
        return {
            'trained_models': list(self.trained_models.keys()),
            'model_count': len(self.trained_models),
            'known_signatures': len(self.known_signatures),
            'recent_detections': len([s for s in self.signature_history 
                                    if s['timestamp'] > datetime.utcnow() - timedelta(hours=24)]),
            'zero_day_metrics': await self.metrics.get_metrics() if hasattr(self.metrics, 'get_metrics') else {}
        }