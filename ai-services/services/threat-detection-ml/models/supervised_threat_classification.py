"""
Supervised Threat Classification Models for AI/ML Threat Detection

This module implements supervised machine learning models to classify known threats
using labeled security event data. It includes multiple classification algorithms,
feature engineering pipelines, model ensemble techniques, and comprehensive
evaluation metrics for production threat detection.
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
from collections import defaultdict

import pandas as pd
import numpy as np
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier, 
    ExtraTreesClassifier, VotingClassifier, AdaBoostClassifier
)
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler, RobustScaler
from sklearn.model_selection import (
    train_test_split, cross_val_score, GridSearchCV, 
    RandomizedSearchCV, StratifiedKFold
)
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    precision_recall_curve, roc_curve
)
from sklearn.utils.class_weight import compute_class_weight
import xgboost as xgb
import lightgbm as lgb
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import mlflow
import mlflow.sklearn
import mlflow.pytorch
from pydantic import BaseModel, Field

from .behavioral_analytics import BehaviorType
from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector
from ...shared.mlflow.integration import MLFlowManager


logger = logging.getLogger(__name__)


class ThreatCategory(Enum):
    """Categories of security threats for classification."""
    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    DENIAL_OF_SERVICE = "denial_of_service"
    INSIDER_THREAT = "insider_threat"
    APT = "advanced_persistent_threat"
    BENIGN = "benign"


class ClassificationMethod(Enum):
    """Types of supervised classification methods."""
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    XG_BOOST = "xgboost"
    LIGHT_GBM = "lightgbm"
    SVM = "support_vector_machine"
    LOGISTIC_REGRESSION = "logistic_regression"
    NEURAL_NETWORK = "neural_network"
    DEEP_NEURAL_NETWORK = "deep_neural_network"
    NAIVE_BAYES = "naive_bayes"
    KNN = "k_nearest_neighbors"
    ENSEMBLE_VOTING = "ensemble_voting"
    ENSEMBLE_STACKING = "ensemble_stacking"


@dataclass
class ClassificationConfig:
    """Configuration for threat classification models."""
    # General settings
    test_size: float = 0.2
    validation_size: float = 0.2
    random_state: int = 42
    n_jobs: int = -1
    class_balancing: str = "balanced"  # 'balanced', 'weighted', 'smote', 'none'
    
    # Cross-validation settings
    cv_folds: int = 5
    cv_scoring: str = "f1_macro"
    
    # Hyperparameter tuning
    enable_hyperparameter_tuning: bool = True
    tuning_method: str = "randomized"  # 'grid', 'randomized', 'bayesian'
    tuning_iterations: int = 50
    
    # Random Forest settings
    rf_n_estimators: int = 200
    rf_max_depth: Optional[int] = None
    rf_min_samples_split: int = 2
    rf_min_samples_leaf: int = 1
    
    # Gradient Boosting settings
    gb_n_estimators: int = 100
    gb_learning_rate: float = 0.1
    gb_max_depth: int = 6
    
    # XGBoost settings
    xgb_n_estimators: int = 100
    xgb_learning_rate: float = 0.1
    xgb_max_depth: int = 6
    xgb_subsample: float = 0.8
    
    # LightGBM settings
    lgb_n_estimators: int = 100
    lgb_learning_rate: float = 0.1
    lgb_max_depth: int = 6
    lgb_num_leaves: int = 31
    
    # SVM settings
    svm_kernel: str = "rbf"
    svm_C: float = 1.0
    svm_gamma: str = "scale"
    
    # Neural Network settings
    nn_hidden_layer_sizes: Tuple[int, ...] = (100, 50)
    nn_activation: str = "relu"
    nn_solver: str = "adam"
    nn_learning_rate: str = "adaptive"
    nn_max_iter: int = 300
    
    # Deep Neural Network settings
    dnn_hidden_dims: List[int] = field(default_factory=lambda: [256, 128, 64])
    dnn_dropout_rate: float = 0.3
    dnn_learning_rate: float = 0.001
    dnn_batch_size: int = 32
    dnn_epochs: int = 100
    dnn_patience: int = 10
    
    # Ensemble settings
    ensemble_methods: List[ClassificationMethod] = field(default_factory=lambda: [
        ClassificationMethod.RANDOM_FOREST,
        ClassificationMethod.XG_BOOST,
        ClassificationMethod.SVM
    ])
    ensemble_voting: str = "soft"  # 'hard', 'soft'
    
    # Feature settings
    feature_selection: bool = True
    feature_importance_threshold: float = 0.01
    max_features: Optional[int] = None
    
    # Performance settings
    enable_gpu: bool = False
    early_stopping: bool = True


class ThreatPrediction(BaseModel):
    """Represents a threat classification prediction."""
    event_id: str
    predicted_category: ThreatCategory
    confidence_score: float = Field(ge=0.0, le=1.0)
    probability_scores: Dict[str, float] = Field(default_factory=dict)
    feature_importance: Dict[str, float] = Field(default_factory=dict)
    method: ClassificationMethod
    timestamp: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            ThreatCategory: lambda v: v.value,
            ClassificationMethod: lambda v: v.value
        }


class DeepThreatClassifier(nn.Module):
    """Deep neural network for threat classification."""
    
    def __init__(self, input_dim: int, num_classes: int, hidden_dims: List[int], dropout_rate: float = 0.3):
        super(DeepThreatClassifier, self).__init__()
        
        layers = []
        prev_dim = input_dim
        
        # Hidden layers
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.BatchNorm1d(hidden_dim),
                nn.Dropout(dropout_rate)
            ])
            prev_dim = hidden_dim
        
        # Output layer
        layers.append(nn.Linear(prev_dim, num_classes))
        
        self.network = nn.Sequential(*layers)
        self.softmax = nn.Softmax(dim=1)
    
    def forward(self, x):
        logits = self.network(x)
        return logits
    
    def predict_proba(self, x):
        logits = self.forward(x)
        return self.softmax(logits)


class BaseThreatClassifier(ABC):
    """Abstract base class for threat classification models."""
    
    def __init__(self, config: ClassificationConfig, method: ClassificationMethod):
        self.config = config
        self.method = method
        self.model = None
        self.label_encoder = None
        self.scaler = None
        self.feature_selector = None
        self.is_fitted = False
        self.feature_names = []
        self.class_names = []
        self.metrics = {}
    
    @abstractmethod
    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Fit the classification model."""
        pass
    
    @abstractmethod
    def predict(self, X: np.ndarray) -> List[ThreatPrediction]:
        """Predict threat categories for input data."""
        pass
    
    def _preprocess_features(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Preprocess features with scaling."""
        if fit:
            self.scaler = RobustScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            if self.scaler is None:
                raise ValueError("Model must be fitted before preprocessing")
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def _encode_labels(self, y: np.ndarray, fit: bool = False) -> np.ndarray:
        """Encode threat category labels."""
        if fit:
            self.label_encoder = LabelEncoder()
            y_encoded = self.label_encoder.fit_transform(y)
            self.class_names = list(self.label_encoder.classes_)
        else:
            if self.label_encoder is None:
                raise ValueError("Model must be fitted before label encoding")
            y_encoded = self.label_encoder.transform(y)
        
        return y_encoded
    
    def _get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores."""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            # For linear models, use coefficient magnitudes
            if len(self.model.coef_.shape) > 1:
                importances = np.mean(np.abs(self.model.coef_), axis=0)
            else:
                importances = np.abs(self.model.coef_)
        else:
            return {}
        
        if len(self.feature_names) == len(importances):
            return dict(zip(self.feature_names, importances.astype(float)))
        else:
            return {}
    
    def evaluate_model(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate model performance on test data."""
        predictions = self.predict(X_test)
        y_pred = [pred.predicted_category.value for pred in predictions]
        y_pred_encoded = self.label_encoder.transform(y_pred)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred_encoded)
        precision = precision_score(y_test, y_pred_encoded, average='macro', zero_division=0)
        recall = recall_score(y_test, y_pred_encoded, average='macro', zero_division=0)
        f1 = f1_score(y_test, y_pred_encoded, average='macro', zero_division=0)
        
        # Calculate per-class metrics
        class_report = classification_report(
            y_test, y_pred_encoded, 
            target_names=self.class_names, 
            output_dict=True
        )
        
        # Calculate AUC for multiclass (one-vs-rest)
        try:
            probabilities = np.array([list(pred.probability_scores.values()) for pred in predictions])
            if len(self.class_names) == 2:
                auc = roc_auc_score(y_test, probabilities[:, 1])
            else:
                auc = roc_auc_score(y_test, probabilities, multi_class='ovr', average='macro')
        except Exception as e:
            logger.warning(f"Could not calculate AUC: {e}")
            auc = 0.0
        
        evaluation_metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc_score': auc,
            'confusion_matrix': confusion_matrix(y_test, y_pred_encoded).tolist(),
            'classification_report': class_report,
            'feature_importance': self._get_feature_importance()
        }
        
        self.metrics = evaluation_metrics
        return evaluation_metrics
    
    def save_model(self, filepath: str) -> None:
        """Save the trained model to disk."""
        model_data = {
            'method': self.method.value,
            'config': self.config.__dict__,
            'label_encoder': self.label_encoder,
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'is_fitted': self.is_fitted,
            'feature_names': self.feature_names,
            'class_names': self.class_names,
            'metrics': self.metrics
        }
        
        # Handle different model types
        if self.method == ClassificationMethod.DEEP_NEURAL_NETWORK:
            torch.save(self.model.state_dict(), filepath + '.pth')
            model_data['model_path'] = filepath + '.pth'
            model_data['model_architecture'] = {
                'input_dim': self.model.network[0].in_features,
                'num_classes': self.model.network[-1].out_features,
                'hidden_dims': [layer.out_features for layer in self.model.network[:-1] 
                               if isinstance(layer, nn.Linear)][1:],
                'dropout_rate': self.config.dnn_dropout_rate
            }
        else:
            model_data['model'] = self.model
        
        joblib.dump(model_data, filepath)
        logger.info(f"Saved {self.method.value} model to {filepath}")


class RandomForestThreatClassifier(BaseThreatClassifier):
    """Random Forest based threat classifier."""
    
    def __init__(self, config: ClassificationConfig):
        super().__init__(config, ClassificationMethod.RANDOM_FOREST)
    
    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Fit the Random Forest model."""
        self.feature_names = feature_names
        X_scaled = self._preprocess_features(X, fit=True)
        y_encoded = self._encode_labels(y, fit=True)
        
        # Configure class balancing
        class_weight = 'balanced' if self.config.class_balancing == 'balanced' else None
        
        # Initialize model
        self.model = RandomForestClassifier(
            n_estimators=self.config.rf_n_estimators,
            max_depth=self.config.rf_max_depth,
            min_samples_split=self.config.rf_min_samples_split,
            min_samples_leaf=self.config.rf_min_samples_leaf,
            class_weight=class_weight,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs
        )
        
        # Hyperparameter tuning if enabled
        if self.config.enable_hyperparameter_tuning:
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [None, 10, 20, 30],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            }
            
            if self.config.tuning_method == "randomized":
                search = RandomizedSearchCV(
                    self.model, param_grid, 
                    n_iter=self.config.tuning_iterations,
                    cv=self.config.cv_folds,
                    scoring=self.config.cv_scoring,
                    random_state=self.config.random_state,
                    n_jobs=self.config.n_jobs
                )
            else:
                search = GridSearchCV(
                    self.model, param_grid,
                    cv=self.config.cv_folds,
                    scoring=self.config.cv_scoring,
                    n_jobs=self.config.n_jobs
                )
            
            search.fit(X_scaled, y_encoded)
            self.model = search.best_estimator_
            
            logger.info(f"Best parameters: {search.best_params_}")
            logger.info(f"Best CV score: {search.best_score_:.4f}")
        else:
            self.model.fit(X_scaled, y_encoded)
        
        self.is_fitted = True
        
        # Cross-validation score
        cv_scores = cross_val_score(
            self.model, X_scaled, y_encoded,
            cv=self.config.cv_folds,
            scoring=self.config.cv_scoring,
            n_jobs=self.config.n_jobs
        )
        
        training_results = {
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'n_features': len(feature_names),
            'n_classes': len(self.class_names),
            'training_samples': len(X_scaled)
        }
        
        logger.info(f"Trained Random Forest: CV Score = {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        return training_results
    
    def predict(self, X: np.ndarray) -> List[ThreatPrediction]:
        """Predict threat categories using Random Forest."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_scaled = self._preprocess_features(X, fit=False)
        
        # Get predictions and probabilities
        y_pred_encoded = self.model.predict(X_scaled)
        y_pred_proba = self.model.predict_proba(X_scaled)
        
        # Convert predictions to ThreatPrediction objects
        predictions = []
        feature_importance = self._get_feature_importance()
        
        for i, (pred_encoded, proba) in enumerate(zip(y_pred_encoded, y_pred_proba)):
            predicted_category = ThreatCategory(self.label_encoder.inverse_transform([pred_encoded])[0])
            confidence_score = float(np.max(proba))
            
            # Create probability scores dictionary
            prob_scores = {
                class_name: float(prob) 
                for class_name, prob in zip(self.class_names, proba)
            }
            
            predictions.append(ThreatPrediction(
                event_id=f"event_{i}",
                predicted_category=predicted_category,
                confidence_score=confidence_score,
                probability_scores=prob_scores,
                feature_importance=feature_importance,
                method=self.method,
                timestamp=datetime.utcnow()
            ))
        
        return predictions


class XGBoostThreatClassifier(BaseThreatClassifier):
    """XGBoost based threat classifier."""
    
    def __init__(self, config: ClassificationConfig):
        super().__init__(config, ClassificationMethod.XG_BOOST)
    
    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Fit the XGBoost model."""
        self.feature_names = feature_names
        X_scaled = self._preprocess_features(X, fit=True)
        y_encoded = self._encode_labels(y, fit=True)
        
        # Calculate class weights for imbalanced datasets
        class_weights = None
        if self.config.class_balancing == 'weighted':
            class_weights = compute_class_weight(
                'balanced', classes=np.unique(y_encoded), y=y_encoded
            )
            sample_weight = class_weights[y_encoded]
        else:
            sample_weight = None
        
        # Initialize XGBoost model
        self.model = xgb.XGBClassifier(
            n_estimators=self.config.xgb_n_estimators,
            learning_rate=self.config.xgb_learning_rate,
            max_depth=self.config.xgb_max_depth,
            subsample=self.config.xgb_subsample,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs,
            eval_metric='mlogloss' if len(self.class_names) > 2 else 'logloss'
        )
        
        # Hyperparameter tuning if enabled
        if self.config.enable_hyperparameter_tuning:
            param_grid = {
                'n_estimators': [100, 200, 300],
                'learning_rate': [0.01, 0.1, 0.2],
                'max_depth': [3, 6, 9],
                'subsample': [0.8, 0.9, 1.0]
            }
            
            search = RandomizedSearchCV(
                self.model, param_grid,
                n_iter=self.config.tuning_iterations,
                cv=self.config.cv_folds,
                scoring=self.config.cv_scoring,
                random_state=self.config.random_state,
                n_jobs=self.config.n_jobs
            )
            
            search.fit(X_scaled, y_encoded, sample_weight=sample_weight)
            self.model = search.best_estimator_
            
            logger.info(f"Best XGBoost parameters: {search.best_params_}")
        else:
            self.model.fit(X_scaled, y_encoded, sample_weight=sample_weight)
        
        self.is_fitted = True
        
        # Cross-validation score
        cv_scores = cross_val_score(
            self.model, X_scaled, y_encoded,
            cv=self.config.cv_folds,
            scoring=self.config.cv_scoring,
            n_jobs=self.config.n_jobs
        )
        
        training_results = {
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'n_features': len(feature_names),
            'n_classes': len(self.class_names),
            'training_samples': len(X_scaled)
        }
        
        logger.info(f"Trained XGBoost: CV Score = {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        return training_results
    
    def predict(self, X: np.ndarray) -> List[ThreatPrediction]:
        """Predict threat categories using XGBoost."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_scaled = self._preprocess_features(X, fit=False)
        
        # Get predictions and probabilities
        y_pred_encoded = self.model.predict(X_scaled)
        y_pred_proba = self.model.predict_proba(X_scaled)
        
        # Convert predictions to ThreatPrediction objects
        predictions = []
        feature_importance = self._get_feature_importance()
        
        for i, (pred_encoded, proba) in enumerate(zip(y_pred_encoded, y_pred_proba)):
            predicted_category = ThreatCategory(self.label_encoder.inverse_transform([pred_encoded])[0])
            confidence_score = float(np.max(proba))
            
            # Create probability scores dictionary
            prob_scores = {
                class_name: float(prob) 
                for class_name, prob in zip(self.class_names, proba)
            }
            
            predictions.append(ThreatPrediction(
                event_id=f"event_{i}",
                predicted_category=predicted_category,
                confidence_score=confidence_score,
                probability_scores=prob_scores,
                feature_importance=feature_importance,
                method=self.method,
                timestamp=datetime.utcnow()
            ))
        
        return predictions


class DeepNeuralNetworkClassifier(BaseThreatClassifier):
    """Deep Neural Network based threat classifier."""
    
    def __init__(self, config: ClassificationConfig):
        super().__init__(config, ClassificationMethod.DEEP_NEURAL_NETWORK)
        self.device = torch.device('cuda' if config.enable_gpu and torch.cuda.is_available() else 'cpu')
    
    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Fit the Deep Neural Network model."""
        self.feature_names = feature_names
        X_scaled = self._preprocess_features(X, fit=True)
        y_encoded = self._encode_labels(y, fit=True)
        
        # Prepare data for PyTorch
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        y_tensor = torch.LongTensor(y_encoded).to(self.device)
        
        # Split for training and validation
        X_train, X_val, y_train, y_val = train_test_split(
            X_tensor, y_tensor, 
            test_size=self.config.validation_size,
            random_state=self.config.random_state,
            stratify=y_encoded
        )
        
        # Create model
        input_dim = X_scaled.shape[1]
        num_classes = len(self.class_names)
        
        self.model = DeepThreatClassifier(
            input_dim=input_dim,
            num_classes=num_classes,
            hidden_dims=self.config.dnn_hidden_dims,
            dropout_rate=self.config.dnn_dropout_rate
        ).to(self.device)
        
        # Training setup
        criterion = nn.CrossEntropyLoss()
        optimizer = optim.Adam(self.model.parameters(), lr=self.config.dnn_learning_rate)
        
        # Create data loaders
        train_dataset = TensorDataset(X_train, y_train)
        train_loader = DataLoader(train_dataset, batch_size=self.config.dnn_batch_size, shuffle=True)
        
        # Training loop with early stopping
        best_val_loss = float('inf')
        patience_counter = 0
        training_history = {'train_loss': [], 'val_loss': [], 'val_accuracy': []}
        
        for epoch in range(self.config.dnn_epochs):
            # Training phase
            self.model.train()
            train_loss = 0.0
            
            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()
            
            # Validation phase
            self.model.eval()
            with torch.no_grad():
                val_outputs = self.model(X_val)
                val_loss = criterion(val_outputs, y_val).item()
                
                _, val_predicted = torch.max(val_outputs, 1)
                val_accuracy = (val_predicted == y_val).float().mean().item()
            
            training_history['train_loss'].append(train_loss / len(train_loader))
            training_history['val_loss'].append(val_loss)
            training_history['val_accuracy'].append(val_accuracy)
            
            # Early stopping
            if self.config.early_stopping:
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                else:
                    patience_counter += 1
                    if patience_counter >= self.config.dnn_patience:
                        logger.info(f"Early stopping at epoch {epoch}")
                        break
            
            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: Train Loss = {train_loss/len(train_loader):.4f}, "
                           f"Val Loss = {val_loss:.4f}, Val Acc = {val_accuracy:.4f}")
        
        self.is_fitted = True
        
        training_results = {
            'final_train_loss': training_history['train_loss'][-1],
            'final_val_loss': training_history['val_loss'][-1],
            'final_val_accuracy': training_history['val_accuracy'][-1],
            'training_epochs': len(training_history['train_loss']),
            'n_features': len(feature_names),
            'n_classes': len(self.class_names),
            'training_samples': len(X_scaled)
        }
        
        logger.info(f"Trained Deep NN: Final Val Accuracy = {training_results['final_val_accuracy']:.4f}")
        return training_results
    
    def predict(self, X: np.ndarray) -> List[ThreatPrediction]:
        """Predict threat categories using Deep Neural Network."""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_scaled = self._preprocess_features(X, fit=False)
        X_tensor = torch.FloatTensor(X_scaled).to(self.device)
        
        self.model.eval()
        predictions = []
        
        with torch.no_grad():
            outputs = self.model(X_tensor)
            probabilities = self.model.predict_proba(X_tensor)
            _, predicted = torch.max(outputs, 1)
            
            for i, (pred_tensor, proba_tensor) in enumerate(zip(predicted, probabilities)):
                pred_encoded = pred_tensor.cpu().numpy()
                proba = proba_tensor.cpu().numpy()
                
                predicted_category = ThreatCategory(self.label_encoder.inverse_transform([pred_encoded])[0])
                confidence_score = float(np.max(proba))
                
                # Create probability scores dictionary
                prob_scores = {
                    class_name: float(prob) 
                    for class_name, prob in zip(self.class_names, proba)
                }
                
                predictions.append(ThreatPrediction(
                    event_id=f"event_{i}",
                    predicted_category=predicted_category,
                    confidence_score=confidence_score,
                    probability_scores=prob_scores,
                    feature_importance={},  # DNN feature importance requires additional computation
                    method=self.method,
                    timestamp=datetime.utcnow()
                ))
        
        return predictions


class EnsembleThreatClassifier:
    """Ensemble of multiple threat classification models."""
    
    def __init__(self, config: ClassificationConfig, methods: List[ClassificationMethod]):
        self.config = config
        self.methods = methods
        self.classifiers: Dict[ClassificationMethod, BaseThreatClassifier] = {}
        self.is_fitted = False
        self.ensemble_weights: Dict[ClassificationMethod, float] = {}
        
        # Initialize individual classifiers
        for method in methods:
            if method == ClassificationMethod.RANDOM_FOREST:
                self.classifiers[method] = RandomForestThreatClassifier(config)
            elif method == ClassificationMethod.XG_BOOST:
                self.classifiers[method] = XGBoostThreatClassifier(config)
            elif method == ClassificationMethod.DEEP_NEURAL_NETWORK:
                self.classifiers[method] = DeepNeuralNetworkClassifier(config)
            # Add other classifiers as needed
    
    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Fit all ensemble classifiers."""
        logger.info(f"Fitting ensemble with {len(self.classifiers)} classifiers")
        
        training_results = {}
        successful_classifiers = {}
        
        for method, classifier in self.classifiers.items():
            try:
                logger.info(f"Training {method.value} classifier...")
                results = classifier.fit(X, y, feature_names)
                training_results[method.value] = results
                successful_classifiers[method] = classifier
            except Exception as e:
                logger.error(f"Failed to train {method.value} classifier: {e}")
                continue
        
        # Update classifiers with only successful ones
        self.classifiers = successful_classifiers
        self.is_fitted = True
        
        # Calculate ensemble weights based on cross-validation performance
        if len(self.classifiers) > 1:
            self._calculate_ensemble_weights(X, y)
        
        ensemble_results = {
            'successful_classifiers': len(self.classifiers),
            'classifier_results': training_results,
            'ensemble_weights': {k.value: v for k, v in self.ensemble_weights.items()}
        }
        
        logger.info(f"Ensemble fitted with {len(self.classifiers)} successful classifiers")
        return ensemble_results
    
    def _calculate_ensemble_weights(self, X: np.ndarray, y: np.ndarray) -> None:
        """Calculate ensemble weights based on cross-validation performance."""
        weights = {}
        
        for method, classifier in self.classifiers.items():
            try:
                # Use the fitted classifier's cross-validation score
                if hasattr(classifier, 'metrics') and 'cv_mean' in classifier.metrics:
                    weights[method] = classifier.metrics['cv_mean']
                else:
                    weights[method] = 0.5  # Default weight
            except Exception as e:
                logger.warning(f"Could not calculate weight for {method.value}: {e}")
                weights[method] = 0.1  # Minimum weight
        
        # Normalize weights
        total_weight = sum(weights.values())
        if total_weight > 0:
            self.ensemble_weights = {k: v / total_weight for k, v in weights.items()}
        else:
            # Equal weights fallback
            n_classifiers = len(self.classifiers)
            self.ensemble_weights = {method: 1.0 / n_classifiers for method in self.classifiers.keys()}
    
    def predict(self, X: np.ndarray) -> List[ThreatPrediction]:
        """Predict threat categories using ensemble voting."""
        if not self.is_fitted:
            raise ValueError("Ensemble must be fitted before prediction")
        
        # Collect predictions from all classifiers
        all_predictions: Dict[ClassificationMethod, List[ThreatPrediction]] = {}
        
        for method, classifier in self.classifiers.items():
            try:
                predictions = classifier.predict(X)
                all_predictions[method] = predictions
            except Exception as e:
                logger.error(f"Failed to get predictions from {method.value}: {e}")
                continue
        
        if not all_predictions:
            raise ValueError("No classifiers produced valid predictions")
        
        # Ensemble voting
        n_samples = len(X)
        ensemble_predictions = []
        
        for i in range(n_samples):
            # Collect predictions from all classifiers for this sample
            classifier_predictions = []
            weighted_probabilities = defaultdict(float)
            
            for method, predictions in all_predictions.items():
                if i < len(predictions):
                    pred = predictions[i]
                    classifier_predictions.append(pred)
                    
                    # Weight the probability scores
                    weight = self.ensemble_weights.get(method, 0.0)
                    for category, prob in pred.probability_scores.items():
                        weighted_probabilities[category] += prob * weight
            
            if not classifier_predictions:
                continue
            
            # Determine ensemble prediction
            if self.config.ensemble_voting == "soft":
                # Use weighted probabilities
                best_category = max(weighted_probabilities, key=weighted_probabilities.get)
                confidence = weighted_probabilities[best_category]
                prob_scores = dict(weighted_probabilities)
            else:
                # Hard voting - majority wins
                votes = defaultdict(int)
                for pred in classifier_predictions:
                    votes[pred.predicted_category.value] += 1
                
                best_category = max(votes, key=votes.get)
                confidence = votes[best_category] / len(classifier_predictions)
                
                # Average probability scores
                prob_scores = defaultdict(float)
                for pred in classifier_predictions:
                    for category, prob in pred.probability_scores.items():
                        prob_scores[category] += prob
                
                prob_scores = {k: v / len(classifier_predictions) for k, v in prob_scores.items()}
            
            # Combine feature importance
            combined_importance = defaultdict(float)
            for pred in classifier_predictions:
                weight = self.ensemble_weights.get(pred.method, 0.0)
                for feature, importance in pred.feature_importance.items():
                    combined_importance[feature] += importance * weight
            
            ensemble_predictions.append(ThreatPrediction(
                event_id=f"event_{i}",
                predicted_category=ThreatCategory(best_category),
                confidence_score=float(confidence),
                probability_scores=prob_scores,
                feature_importance=dict(combined_importance),
                method=ClassificationMethod.ENSEMBLE_VOTING,
                timestamp=datetime.utcnow()
            ))
        
        return ensemble_predictions


class SupervisedThreatClassificationManager:
    """Main manager for supervised threat classification."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("supervised_threat_classification")
        self.mlflow_manager = MLFlowManager(settings)
        
        # Default configuration
        self.config = ClassificationConfig()
        
        # Storage for trained models
        self.trained_models: Dict[str, Union[BaseThreatClassifier, EnsembleThreatClassifier]] = {}
        
    async def prepare_training_data(
        self, 
        events: List[SecurityEvent],
        threat_labels: Dict[str, str]  # event_id -> threat_category
    ) -> Tuple[pd.DataFrame, np.ndarray]:
        """Prepare training data from security events and labels."""
        
        # Convert events to features
        features_data = []
        labels = []
        
        for event in events:
            if event.event_id in threat_labels:
                features = self._extract_comprehensive_features(event)
                features_data.append(features)
                labels.append(threat_labels[event.event_id])
        
        # Create DataFrame and label array
        features_df = pd.DataFrame(features_data)
        labels_array = np.array(labels)
        
        logger.info(f"Prepared training data: {len(features_df)} samples, {len(features_df.columns)} features")
        logger.info(f"Label distribution: {dict(zip(*np.unique(labels_array, return_counts=True)))}")
        
        return features_df, labels_array
    
    def _extract_comprehensive_features(self, event: SecurityEvent) -> Dict[str, Any]:
        """Extract comprehensive features from security event for classification."""
        features = {
            # Temporal features
            'hour': event.timestamp.hour,
            'day_of_week': event.timestamp.weekday(),
            'is_weekend': int(event.timestamp.weekday() >= 5),
            'is_business_hours': int(9 <= event.timestamp.hour <= 17),
            'is_night': int(event.timestamp.hour < 6 or event.timestamp.hour > 22),
            
            # Event type features
            'event_type_auth': int('auth' in event.event_type.lower()),
            'event_type_network': int('network' in event.event_type.lower()),
            'event_type_process': int('process' in event.event_type.lower()),
            'event_type_file': int('file' in event.event_type.lower()),
            
            # Severity features
            'severity_high': int(event.severity == 'high'),
            'severity_medium': int(event.severity == 'medium'),
            'severity_low': int(event.severity == 'low'),
            
            # Network features
            'has_source_ip': int(bool(event.source_ip)),
            'has_dest_ip': int(bool(event.dest_ip)),
            'port': event.port or 0,
            'is_well_known_port': int((event.port or 0) <= 1023),
            'is_registered_port': int(1024 <= (event.port or 0) <= 49151),
            
            # User and host features
            'has_username': int(bool(event.username)),
            'has_hostname': int(bool(event.hostname)),
            'username_length': len(event.username) if event.username else 0,
            'hostname_length': len(event.hostname) if event.hostname else 0,
            
            # Process features
            'has_process': int(bool(event.process_name)),
            'has_command': int(bool(event.command_line)),
            'process_name_length': len(event.process_name) if event.process_name else 0,
            'command_length': len(event.command_line) if event.command_line else 0,
            'command_has_redirect': int('>' in (event.command_line or '')),
            'command_has_pipe': int('|' in (event.command_line or '')),
            'command_has_background': int('&' in (event.command_line or '')),
            
            # File features
            'has_file': int(bool(event.file_path)),
            'file_path_length': len(event.file_path) if event.file_path else 0,
            'file_path_depth': len(event.file_path.split('/')) if event.file_path else 0,
            'file_is_system': int('/system' in (event.file_path or '').lower()),
            'file_is_temp': int('/tmp' in (event.file_path or '').lower()),
            
            # Protocol features
            'protocol_tcp': int((event.network_protocol or '').lower() == 'tcp'),
            'protocol_udp': int((event.network_protocol or '').lower() == 'udp'),
            'protocol_icmp': int((event.network_protocol or '').lower() == 'icmp'),
            'protocol_http': int((event.network_protocol or '').lower() in ['http', 'https']),
            
            # Raw data features (if available)
            'raw_data_size': len(str(event.raw_data)),
            'has_enriched_data': int(bool(event.enriched_data)),
            'enriched_data_size': len(str(event.enriched_data))
        }
        
        # Add user agent features if available
        if event.user_agent:
            features.update({
                'has_user_agent': 1,
                'user_agent_length': len(event.user_agent),
                'ua_is_browser': int('mozilla' in event.user_agent.lower()),
                'ua_is_bot': int('bot' in event.user_agent.lower()),
                'ua_is_script': int('script' in event.user_agent.lower())
            })
        else:
            features.update({
                'has_user_agent': 0,
                'user_agent_length': 0,
                'ua_is_browser': 0,
                'ua_is_bot': 0,
                'ua_is_script': 0
            })
        
        return features
    
    async def train_classification_models(
        self,
        training_data: pd.DataFrame,
        training_labels: np.ndarray,
        model_name: str = "default",
        methods: Optional[List[ClassificationMethod]] = None,
        config: Optional[ClassificationConfig] = None
    ) -> Dict[str, Any]:
        """Train threat classification models on labeled data."""
        
        if config:
            self.config = config
        
        if methods is None:
            methods = [
                ClassificationMethod.RANDOM_FOREST,
                ClassificationMethod.XG_BOOST,
                ClassificationMethod.DEEP_NEURAL_NETWORK
            ]
        
        logger.info(f"Training threat classifiers: {[m.value for m in methods]}")
        
        # Prepare feature matrix
        feature_columns = [col for col in training_data.columns if col != 'event_id']
        X = training_data[feature_columns].fillna(0).values
        y = training_labels
        
        training_results = {}
        
        with mlflow.start_run(run_name=f"supervised_classification_training_{model_name}"):
            # Train ensemble if multiple methods
            if len(methods) > 1:
                ensemble = EnsembleThreatClassifier(self.config, methods)
                start_time = datetime.utcnow()
                
                results = ensemble.fit(X, y, feature_columns)
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.trained_models[model_name] = ensemble
                
                # Log ensemble metrics
                mlflow.log_param("model_type", "ensemble")
                mlflow.log_param("methods", [m.value for m in methods])
                mlflow.log_param("n_classifiers", len(ensemble.classifiers))
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("training_samples", len(X))
                mlflow.log_metric("n_features", len(feature_columns))
                
                training_results = {
                    'model_name': model_name,
                    'model_type': 'ensemble',
                    'methods': [m.value for m in methods],
                    'training_time': training_time,
                    'ensemble_results': results
                }
                
            else:
                # Train single classifier
                method = methods[0]
                start_time = datetime.utcnow()
                
                if method == ClassificationMethod.RANDOM_FOREST:
                    classifier = RandomForestThreatClassifier(self.config)
                elif method == ClassificationMethod.XG_BOOST:
                    classifier = XGBoostThreatClassifier(self.config)
                elif method == ClassificationMethod.DEEP_NEURAL_NETWORK:
                    classifier = DeepNeuralNetworkClassifier(self.config)
                else:
                    raise ValueError(f"Unsupported classification method: {method}")
                
                results = classifier.fit(X, y, feature_columns)
                training_time = (datetime.utcnow() - start_time).total_seconds()
                
                self.trained_models[model_name] = classifier
                
                # Log single classifier metrics
                mlflow.log_param("model_type", method.value)
                mlflow.log_metric("training_time_seconds", training_time)
                mlflow.log_metric("training_samples", len(X))
                mlflow.log_metric("n_features", len(feature_columns))
                
                training_results = {
                    'model_name': model_name,
                    'model_type': method.value,
                    'training_time': training_time,
                    'classifier_results': results
                }
        
        logger.info(f"Completed training classification models for '{model_name}'")
        return training_results
    
    async def classify_threats(
        self,
        events: List[SecurityEvent],
        model_name: str = "default"
    ) -> List[ThreatPrediction]:
        """Classify threats in new security events."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        classifier = self.trained_models[model_name]
        
        # Convert events to feature matrix
        features_data = [self._extract_comprehensive_features(event) for event in events]
        features_df = pd.DataFrame(features_data)
        
        # Ensure consistent feature columns
        feature_columns = [col for col in features_df.columns if col != 'event_id']
        X = features_df[feature_columns].fillna(0).values
        
        # Get predictions
        predictions = classifier.predict(X)
        
        # Update event IDs in predictions
        for i, (event, prediction) in enumerate(zip(events, predictions)):
            prediction.event_id = event.event_id
            
            # Log classification metrics
            self.metrics.increment_counter(
                "threats_classified",
                tags={
                    "predicted_category": prediction.predicted_category.value,
                    "model": model_name,
                    "confidence_level": "high" if prediction.confidence_score > 0.8 else "medium" if prediction.confidence_score > 0.5 else "low"
                }
            )
        
        logger.info(f"Classified {len(predictions)} events using model '{model_name}'")
        return predictions
    
    async def evaluate_model_performance(
        self,
        test_data: pd.DataFrame,
        test_labels: np.ndarray,
        model_name: str = "default"
    ) -> Dict[str, Any]:
        """Evaluate classification model performance."""
        
        if model_name not in self.trained_models:
            raise ValueError(f"No trained model found with name '{model_name}'")
        
        classifier = self.trained_models[model_name]
        
        # Prepare test data
        feature_columns = [col for col in test_data.columns if col != 'event_id']
        X_test = test_data[feature_columns].fillna(0).values
        
        # Evaluate model
        if hasattr(classifier, 'evaluate_model'):
            evaluation_results = classifier.evaluate_model(X_test, test_labels)
        else:
            # For ensemble models, evaluate separately
            predictions = classifier.predict(X_test)
            y_pred = [pred.predicted_category.value for pred in predictions]
            
            # Convert to encoded labels for metrics calculation
            unique_labels = list(set(test_labels) | set(y_pred))
            label_encoder = LabelEncoder()
            label_encoder.fit(unique_labels)
            
            y_test_encoded = label_encoder.transform(test_labels)
            y_pred_encoded = label_encoder.transform(y_pred)
            
            evaluation_results = {
                'accuracy': accuracy_score(y_test_encoded, y_pred_encoded),
                'precision': precision_score(y_test_encoded, y_pred_encoded, average='macro', zero_division=0),
                'recall': recall_score(y_test_encoded, y_pred_encoded, average='macro', zero_division=0),
                'f1_score': f1_score(y_test_encoded, y_pred_encoded, average='macro', zero_division=0)
            }
        
        evaluation_results['model_name'] = model_name
        evaluation_results['test_samples'] = len(X_test)
        
        # Log evaluation metrics
        with mlflow.start_run(run_name=f"supervised_evaluation_{model_name}"):
            for metric, value in evaluation_results.items():
                if isinstance(value, (int, float)):
                    mlflow.log_metric(metric, value)
        
        logger.info(f"Model evaluation completed: {evaluation_results}")
        return evaluation_results
    
    async def get_classification_metrics(self) -> Dict[str, Any]:
        """Get classification performance metrics."""
        return {
            'trained_models': list(self.trained_models.keys()),
            'model_count': len(self.trained_models),
            'classification_metrics': await self.metrics.get_metrics() if hasattr(self.metrics, 'get_metrics') else {}
        }