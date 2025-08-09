#!/usr/bin/env python3
"""
iSECTECH SIEM ML Training Pipeline
Production-grade ML model training and validation pipeline
Automated training, evaluation, and deployment of anomaly detection models
"""

import asyncio
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import pickle
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
import psycopg2
from psycopg2.extras import RealDictCursor
import redis
import yaml
import mlflow
import mlflow.sklearn
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TrainingMetrics:
    """Training metrics for model evaluation"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    training_time: float
    prediction_time: float
    model_size_mb: float
    feature_importance: Dict[str, float]
    confusion_matrix: List[List[int]]
    cross_val_scores: List[float]
    hyperparameters: Dict[str, Any]

@dataclass
class ModelArtifact:
    """Model artifact for deployment"""
    model: Any
    scaler: Any
    encoder: Any
    metadata: Dict[str, Any]
    version: str
    created_at: datetime
    performance_metrics: TrainingMetrics

class MLTrainingPipeline:
    """
    Production ML training pipeline for SIEM anomaly detection
    Handles data preparation, model training, validation, and deployment
    """
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.db_connection = None
        self.redis_client = None
        self.mlflow_client = None
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.training_data = None
        self.validation_data = None
        self.test_data = None
        
        # Model configurations
        self.model_configs = {
            'isolation_forest': {
                'class': IsolationForest,
                'param_grid': {
                    'contamination': [0.05, 0.1, 0.15],
                    'n_estimators': [50, 100, 200],
                    'max_samples': ['auto', 0.5, 0.8]
                }
            },
            'one_class_svm': {
                'class': OneClassSVM,
                'param_grid': {
                    'nu': [0.05, 0.1, 0.2],
                    'gamma': ['scale', 'auto', 0.001, 0.01],
                    'kernel': ['rbf', 'linear', 'poly']
                }
            },
            'autoencoder_mlp': {
                'class': MLPClassifier,
                'param_grid': {
                    'hidden_layer_sizes': [(50,), (100,), (100, 50), (200, 100, 50)],
                    'activation': ['relu', 'tanh'],
                    'learning_rate': ['constant', 'adaptive'],
                    'alpha': [0.0001, 0.001, 0.01]
                }
            }
        }
        
    async def initialize(self):
        """Initialize the training pipeline"""
        try:
            await self._load_config()
            await self._setup_database_connection()
            await self._setup_redis_connection()
            await self._setup_mlflow()
            logger.info("ML Training Pipeline initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize training pipeline: {e}")
            raise
            
    async def _load_config(self):
        """Load training configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default configuration
            self.config = {
                'training': {
                    'batch_size': 1000,
                    'validation_split': 0.2,
                    'test_split': 0.1,
                    'cross_validation_folds': 5
                },
                'models': {
                    'isolation_forest': {'contamination': 0.1},
                    'one_class_svm': {'nu': 0.1},
                    'autoencoder_mlp': {'hidden_layer_sizes': (100, 50)}
                }
            }
            
    async def _setup_database_connection(self):
        """Setup database connection for training data"""
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
        """Setup Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 3),
                decode_responses=True
            )
            await asyncio.get_event_loop().run_in_executor(
                None, self.redis_client.ping
            )
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
            
    async def _setup_mlflow(self):
        """Setup MLflow for experiment tracking"""
        try:
            mlflow_config = self.config.get('mlflow', {})
            mlflow_uri = mlflow_config.get('tracking_uri', 'http://localhost:5000')
            mlflow.set_tracking_uri(mlflow_uri)
            mlflow.set_experiment('SIEM_Anomaly_Detection')
            logger.info(f"MLflow tracking configured: {mlflow_uri}")
        except Exception as e:
            logger.warning(f"MLflow setup failed: {e}")
            
    async def prepare_training_data(self, start_date: datetime, end_date: datetime) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Prepare training data from historical events and known anomalies
        """
        try:
            # Load historical events
            historical_events = await self._load_historical_events(start_date, end_date)
            
            # Load labeled anomalies
            labeled_anomalies = await self._load_labeled_anomalies(start_date, end_date)
            
            # Extract features
            features_df = await self._extract_training_features(historical_events)
            
            # Create labels (0 = normal, 1 = anomaly)
            labels = await self._create_labels(features_df, labeled_anomalies)
            
            # Data quality checks
            features_df, labels = await self._perform_data_quality_checks(features_df, labels)
            
            # Split data
            self.training_data, self.validation_data, self.test_data = await self._split_data(
                features_df, labels
            )
            
            logger.info(f"Training data prepared: {len(self.training_data)} samples")
            logger.info(f"Validation data: {len(self.validation_data)} samples")
            logger.info(f"Test data: {len(self.test_data)} samples")
            
            return features_df, labels
            
        except Exception as e:
            logger.error(f"Data preparation failed: {e}")
            raise
            
    async def _load_historical_events(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Load historical events from database"""
        events = []
        
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT event_data, timestamp 
                    FROM siem_events 
                    WHERE timestamp BETWEEN %s AND %s
                    ORDER BY timestamp
                    LIMIT 100000
                """, (start_date, end_date))
                
                for row in cursor.fetchall():
                    event_data = json.loads(row['event_data'])
                    events.append(event_data)
                    
                cursor.close()
                
        except Exception as e:
            logger.error(f"Failed to load historical events: {e}")
            # Generate synthetic data for testing
            events = await self._generate_synthetic_events(1000)
            
        return events
        
    async def _load_labeled_anomalies(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Load labeled anomalies from database"""
        anomalies = []
        
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT event_id, anomaly_type, confidence_score, timestamp
                    FROM ml_anomaly_results 
                    WHERE timestamp BETWEEN %s AND %s
                    AND verified = true
                """, (start_date, end_date))
                
                for row in cursor.fetchall():
                    anomalies.append(dict(row))
                    
                cursor.close()
                
        except Exception as e:
            logger.warning(f"Failed to load labeled anomalies: {e}")
            
        return anomalies
        
    async def _extract_training_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """Extract features for training"""
        features_list = []
        
        for event in events:
            features = {}
            
            # Basic features
            features['event_id'] = event.get('@metadata', {}).get('_id', '')
            features['timestamp'] = event.get('@timestamp', '')
            
            # Numerical features
            features['bytes_transferred'] = self._safe_float(event.get('network', {}).get('bytes', 0))
            features['duration'] = self._safe_float(event.get('event', {}).get('duration', 0))
            features['source_port'] = self._safe_int(event.get('source', {}).get('port', 0))
            features['destination_port'] = self._safe_int(event.get('destination', {}).get('port', 0))
            features['user_risk_score'] = self._safe_float(event.get('user', {}).get('risk_score', 0))
            features['enrichment_score'] = self._safe_float(event.get('enrichment', {}).get('score', 0))
            
            # Categorical features
            features['event_action'] = event.get('event', {}).get('action', 'unknown')
            features['source_ip'] = event.get('source', {}).get('ip', '')
            features['user_name'] = event.get('user', {}).get('name', '')
            features['host_name'] = event.get('host', {}).get('name', '')
            
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
            
            # Security features
            features['threat_detected'] = 1 if event.get('threat', {}).get('indicator', {}).get('matched') else 0
            features['asset_criticality'] = self._get_criticality_score(event.get('asset', {}).get('criticality', 'low'))
            features['network_security_level'] = self._get_security_level_score(
                event.get('source', {}).get('network', {}).get('security_level', 'low')
            )
            
            features_list.append(features)
            
        df = pd.DataFrame(features_list)
        
        # Handle missing values
        numerical_columns = ['bytes_transferred', 'duration', 'source_port', 'destination_port', 
                           'user_risk_score', 'enrichment_score']
        for col in numerical_columns:
            if col in df.columns:
                df[col] = df[col].fillna(df[col].median())
                
        categorical_columns = ['event_action', 'source_ip', 'user_name', 'host_name']
        for col in categorical_columns:
            if col in df.columns:
                df[col] = df[col].fillna('unknown')
                
        return df
        
    async def _create_labels(self, features_df: pd.DataFrame, labeled_anomalies: List[Dict[str, Any]]) -> np.ndarray:
        """Create binary labels for supervised learning"""
        labels = np.zeros(len(features_df))
        
        # Mark known anomalies
        anomaly_event_ids = {anomaly['event_id'] for anomaly in labeled_anomalies}
        
        for i, event_id in enumerate(features_df['event_id']):
            if event_id in anomaly_event_ids:
                labels[i] = 1
                
        # If we have very few labeled anomalies, create synthetic ones based on extreme values
        if np.sum(labels) < len(labels) * 0.01:  # Less than 1% anomalies
            labels = await self._create_synthetic_labels(features_df, labels)
            
        logger.info(f"Created labels: {np.sum(labels)} anomalies out of {len(labels)} samples")
        return labels
        
    async def _create_synthetic_labels(self, features_df: pd.DataFrame, labels: np.ndarray) -> np.ndarray:
        """Create synthetic anomaly labels based on extreme values"""
        numerical_features = ['bytes_transferred', 'duration', 'user_risk_score', 'enrichment_score']
        
        for feature in numerical_features:
            if feature in features_df.columns:
                values = features_df[feature].values
                # Mark top 1% as anomalies
                threshold = np.percentile(values, 99)
                extreme_indices = np.where(values >= threshold)[0]
                labels[extreme_indices] = 1
                
        return labels
        
    async def _perform_data_quality_checks(self, features_df: pd.DataFrame, 
                                         labels: np.ndarray) -> Tuple[pd.DataFrame, np.ndarray]:
        """Perform data quality checks and cleaning"""
        # Remove duplicates
        initial_size = len(features_df)
        features_df = features_df.drop_duplicates(subset=['event_id'])
        labels = labels[:len(features_df)]
        
        # Remove rows with too many missing values
        missing_threshold = 0.5
        missing_percentage = features_df.isnull().sum(axis=1) / len(features_df.columns)
        valid_rows = missing_percentage <= missing_threshold
        features_df = features_df[valid_rows]
        labels = labels[valid_rows]
        
        # Remove outliers using IQR method for numerical features
        numerical_features = ['bytes_transferred', 'duration', 'user_risk_score', 'enrichment_score']
        for feature in numerical_features:
            if feature in features_df.columns:
                Q1 = features_df[feature].quantile(0.25)
                Q3 = features_df[feature].quantile(0.75)
                IQR = Q3 - Q1
                lower_bound = Q1 - 3 * IQR
                upper_bound = Q3 + 3 * IQR
                
                # Keep anomalies even if they're outliers
                valid_indices = (
                    (features_df[feature] >= lower_bound) & 
                    (features_df[feature] <= upper_bound)
                ) | (labels == 1)
                
                features_df = features_df[valid_indices]
                labels = labels[valid_indices]
        
        logger.info(f"Data quality check: {initial_size} -> {len(features_df)} samples")
        return features_df, labels
        
    async def _split_data(self, features_df: pd.DataFrame, 
                         labels: np.ndarray) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Split data into train, validation, and test sets"""
        training_config = self.config.get('training', {})
        test_size = training_config.get('test_split', 0.1)
        val_size = training_config.get('validation_split', 0.2)
        
        # First split: train+val vs test
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            features_df, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        # Second split: train vs val
        val_size_adjusted = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val, y_train_val, test_size=val_size_adjusted, random_state=42, stratify=y_train_val
        )
        
        # Create datasets with labels
        train_data = X_train.copy()
        train_data['label'] = y_train
        
        val_data = X_val.copy()
        val_data['label'] = y_val
        
        test_data = X_test.copy()
        test_data['label'] = y_test
        
        return train_data, val_data, test_data
        
    async def train_models(self) -> Dict[str, ModelArtifact]:
        """Train multiple ML models"""
        if self.training_data is None:
            raise ValueError("Training data not prepared. Call prepare_training_data first.")
            
        trained_models = {}
        
        # Prepare features and labels
        feature_columns = [col for col in self.training_data.columns if col not in ['event_id', 'timestamp', 'label']]
        X_train = self.training_data[feature_columns]
        y_train = self.training_data['label']
        
        X_val = self.validation_data[feature_columns]
        y_val = self.validation_data['label']
        
        # Encode categorical features
        X_train_encoded, X_val_encoded = await self._encode_features(X_train, X_val)
        
        # Scale numerical features
        X_train_scaled, X_val_scaled = await self._scale_features(X_train_encoded, X_val_encoded)
        
        # Train each model type
        for model_name, model_config in self.model_configs.items():
            try:
                with mlflow.start_run(run_name=f"{model_name}_training"):
                    logger.info(f"Training {model_name}...")
                    
                    # Train model
                    model_artifact = await self._train_single_model(
                        model_name, model_config, X_train_scaled, y_train, X_val_scaled, y_val
                    )
                    
                    if model_artifact:
                        trained_models[model_name] = model_artifact
                        
                        # Log to MLflow
                        mlflow.log_params(model_artifact.performance_metrics.hyperparameters)
                        mlflow.log_metrics({
                            'accuracy': model_artifact.performance_metrics.accuracy,
                            'precision': model_artifact.performance_metrics.precision,
                            'recall': model_artifact.performance_metrics.recall,
                            'f1_score': model_artifact.performance_metrics.f1_score,
                            'roc_auc': model_artifact.performance_metrics.roc_auc
                        })
                        
                        # Save model
                        mlflow.sklearn.log_model(model_artifact.model, model_name)
                        
                        logger.info(f"{model_name} training completed")
                        
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {e}")
                
        return trained_models
        
    async def _encode_features(self, X_train: pd.DataFrame, X_val: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Encode categorical features"""
        categorical_features = ['event_action', 'source_ip', 'user_name', 'host_name']
        
        X_train_encoded = X_train.copy()
        X_val_encoded = X_val.copy()
        
        for feature in categorical_features:
            if feature in X_train.columns:
                # Use label encoding for high cardinality features
                if feature not in self.encoders:
                    self.encoders[feature] = LabelEncoder()
                    
                # Fit on training data
                X_train_encoded[feature] = self.encoders[feature].fit_transform(X_train[feature].astype(str))
                
                # Transform validation data, handling unseen labels
                val_labels = X_val[feature].astype(str)
                encoded_vals = []
                for label in val_labels:
                    if label in self.encoders[feature].classes_:
                        encoded_vals.append(self.encoders[feature].transform([label])[0])
                    else:
                        encoded_vals.append(-1)  # Unknown label
                        
                X_val_encoded[feature] = encoded_vals
                
        return X_train_encoded, X_val_encoded
        
    async def _scale_features(self, X_train: pd.DataFrame, X_val: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Scale numerical features"""
        numerical_features = ['bytes_transferred', 'duration', 'source_port', 'destination_port',
                            'user_risk_score', 'enrichment_score', 'hour_of_day', 'day_of_week']
        
        scaler = RobustScaler()  # More robust to outliers
        
        # Scale training data
        X_train_scaled = X_train.copy()
        if any(col in X_train.columns for col in numerical_features):
            available_features = [col for col in numerical_features if col in X_train.columns]
            X_train_scaled[available_features] = scaler.fit_transform(X_train[available_features])
            
            # Scale validation data
            X_val_scaled = X_val.copy()
            X_val_scaled[available_features] = scaler.transform(X_val[available_features])
            
            # Store scaler
            self.scalers['numerical'] = scaler
        else:
            X_val_scaled = X_val.copy()
            
        return X_train_scaled, X_val_scaled
        
    async def _train_single_model(self, model_name: str, model_config: Dict[str, Any],
                                X_train: pd.DataFrame, y_train: np.ndarray,
                                X_val: pd.DataFrame, y_val: np.ndarray) -> Optional[ModelArtifact]:
        """Train a single ML model"""
        try:
            start_time = datetime.now()
            
            # Get model class and parameters
            model_class = model_config['class']
            param_grid = model_config.get('param_grid', {})
            
            # Handle unsupervised models (like Isolation Forest)
            if model_name in ['isolation_forest', 'one_class_svm']:
                # For unsupervised models, use only normal data for training
                normal_indices = y_train == 0
                X_train_normal = X_train[normal_indices]
                
                if len(param_grid) > 1:
                    # Hyperparameter tuning for unsupervised models is tricky
                    # Use a simple approach with validation on mixed data
                    best_model = None
                    best_score = -float('inf')
                    best_params = {}
                    
                    for contamination in param_grid.get('contamination', [0.1]):
                        for n_estimators in param_grid.get('n_estimators', [100]):
                            params = {'contamination': contamination, 'n_estimators': n_estimators, 'random_state': 42}
                            model = model_class(**params)
                            model.fit(X_train_normal)
                            
                            # Evaluate on validation set
                            predictions = model.predict(X_val)
                            # Convert to binary classification (1 = normal, -1 = anomaly)
                            predictions_binary = (predictions == 1).astype(int)
                            y_val_inverted = 1 - y_val  # Invert labels for comparison
                            
                            score = np.mean(predictions_binary == y_val_inverted)
                            
                            if score > best_score:
                                best_score = score
                                best_model = model
                                best_params = params
                else:
                    # Use default parameters
                    best_params = {'contamination': 0.1, 'n_estimators': 100, 'random_state': 42}
                    best_model = model_class(**best_params)
                    best_model.fit(X_train_normal)
                    
            else:
                # Supervised models
                if len(param_grid) > 1:
                    # Hyperparameter tuning
                    model = model_class(random_state=42)
                    grid_search = GridSearchCV(
                        model, param_grid, cv=3, scoring='f1', n_jobs=-1
                    )
                    grid_search.fit(X_train, y_train)
                    best_model = grid_search.best_estimator_
                    best_params = grid_search.best_params_
                else:
                    # Use default parameters
                    best_params = {'random_state': 42}
                    best_model = model_class(**best_params)
                    best_model.fit(X_train, y_train)
            
            training_time = (datetime.now() - start_time).total_seconds()
            
            # Evaluate model
            metrics = await self._evaluate_model(best_model, model_name, X_val, y_val)
            metrics.hyperparameters = best_params
            metrics.training_time = training_time
            
            # Create model artifact
            artifact = ModelArtifact(
                model=best_model,
                scaler=self.scalers.get('numerical'),
                encoder=self.encoders,
                metadata={
                    'model_type': model_name,
                    'training_samples': len(X_train),
                    'features': list(X_train.columns),
                    'anomaly_rate': np.mean(y_train)
                },
                version=f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                created_at=datetime.now(timezone.utc),
                performance_metrics=metrics
            )
            
            return artifact
            
        except Exception as e:
            logger.error(f"Model training failed for {model_name}: {e}")
            return None
            
    async def _evaluate_model(self, model: Any, model_name: str, 
                            X_val: pd.DataFrame, y_val: np.ndarray) -> TrainingMetrics:
        """Evaluate trained model"""
        try:
            start_time = datetime.now()
            
            # Make predictions
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(X_val)
                if probabilities.shape[1] > 1:
                    predictions_proba = probabilities[:, 1]
                else:
                    predictions_proba = probabilities[:, 0]
                predictions = (predictions_proba > 0.5).astype(int)
            elif hasattr(model, 'decision_function'):
                decision_scores = model.decision_function(X_val)
                if model_name in ['isolation_forest', 'one_class_svm']:
                    # For unsupervised models, -1 indicates anomaly
                    predictions = (decision_scores < 0).astype(int)
                    predictions_proba = 1 / (1 + np.exp(-decision_scores))  # Sigmoid transformation
                else:
                    predictions = (decision_scores > 0).astype(int)
                    predictions_proba = 1 / (1 + np.exp(-decision_scores))
            else:
                predictions = model.predict(X_val)
                if model_name in ['isolation_forest', 'one_class_svm']:
                    predictions = (predictions == -1).astype(int)
                predictions_proba = predictions.astype(float)
            
            prediction_time = (datetime.now() - start_time).total_seconds()
            
            # Calculate metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            accuracy = accuracy_score(y_val, predictions)
            precision = precision_score(y_val, predictions, zero_division=0)
            recall = recall_score(y_val, predictions, zero_division=0)
            f1 = f1_score(y_val, predictions, zero_division=0)
            
            # ROC AUC
            try:
                roc_auc = roc_auc_score(y_val, predictions_proba)
            except:
                roc_auc = 0.5
            
            # Confusion matrix
            cm = confusion_matrix(y_val, predictions).tolist()
            
            # Cross-validation scores
            try:
                cv_scores = cross_val_score(model, X_val, y_val, cv=3, scoring='f1').tolist()
            except:
                cv_scores = [f1]
            
            # Feature importance (if available)
            feature_importance = {}
            if hasattr(model, 'feature_importances_'):
                for i, importance in enumerate(model.feature_importances_):
                    if i < len(X_val.columns):
                        feature_importance[X_val.columns[i]] = float(importance)
            
            # Model size
            model_size_mb = len(pickle.dumps(model)) / (1024 * 1024)
            
            return TrainingMetrics(
                model_name=model_name,
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                roc_auc=roc_auc,
                training_time=0.0,  # Will be set by caller
                prediction_time=prediction_time,
                model_size_mb=model_size_mb,
                feature_importance=feature_importance,
                confusion_matrix=cm,
                cross_val_scores=cv_scores,
                hyperparameters={}  # Will be set by caller
            )
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return TrainingMetrics(
                model_name=model_name,
                accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0, roc_auc=0.5,
                training_time=0.0, prediction_time=0.0, model_size_mb=0.0,
                feature_importance={}, confusion_matrix=[[0, 0], [0, 0]], 
                cross_val_scores=[0.0], hyperparameters={}
            )
            
    async def deploy_best_model(self, trained_models: Dict[str, ModelArtifact]) -> Optional[ModelArtifact]:
        """Select and deploy the best performing model"""
        if not trained_models:
            logger.error("No trained models available for deployment")
            return None
            
        # Select best model based on F1 score
        best_model = None
        best_f1_score = 0.0
        
        for model_name, artifact in trained_models.items():
            f1_score = artifact.performance_metrics.f1_score
            if f1_score > best_f1_score:
                best_f1_score = f1_score
                best_model = artifact
                
        if best_model:
            # Save model to filesystem
            model_path = await self._save_model_artifact(best_model)
            
            # Update model registry
            await self._update_model_registry(best_model, model_path)
            
            # Deploy to production (cache in Redis)
            await self._deploy_to_production(best_model)
            
            logger.info(f"Best model deployed: {best_model.metadata['model_type']} "
                       f"with F1 score: {best_f1_score:.4f}")
            
            return best_model
        else:
            logger.error("No suitable model found for deployment")
            return None
            
    async def _save_model_artifact(self, artifact: ModelArtifact) -> str:
        """Save model artifact to filesystem"""
        try:
            model_dir = Path("/opt/siem/models") / artifact.metadata['model_type']
            model_dir.mkdir(parents=True, exist_ok=True)
            
            model_path = model_dir / f"{artifact.version}.pkl"
            
            # Save complete artifact
            with open(model_path, 'wb') as f:
                pickle.dump(artifact, f)
                
            logger.info(f"Model saved to: {model_path}")
            return str(model_path)
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return ""
            
    async def _update_model_registry(self, artifact: ModelArtifact, model_path: str):
        """Update model registry in database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO ml_model_registry 
                    (model_name, version, model_path, performance_metrics, metadata, created_at, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    artifact.metadata['model_type'],
                    artifact.version,
                    model_path,
                    json.dumps(asdict(artifact.performance_metrics)),
                    json.dumps(artifact.metadata),
                    artifact.created_at,
                    True
                ))
                
                # Deactivate previous models
                cursor.execute("""
                    UPDATE ml_model_registry 
                    SET is_active = false 
                    WHERE model_name = %s AND version != %s
                """, (artifact.metadata['model_type'], artifact.version))
                
                cursor.close()
                logger.info("Model registry updated")
                
        except Exception as e:
            logger.error(f"Failed to update model registry: {e}")
            
    async def _deploy_to_production(self, artifact: ModelArtifact):
        """Deploy model to production environment"""
        try:
            if self.redis_client:
                # Cache model for fast access
                model_data = {
                    'model_type': artifact.metadata['model_type'],
                    'version': artifact.version,
                    'performance': asdict(artifact.performance_metrics),
                    'deployment_time': datetime.now(timezone.utc).isoformat()
                }
                
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.setex, 
                    f"production_model:{artifact.metadata['model_type']}", 
                    86400,  # 24 hours
                    json.dumps(model_data)
                )
                
                logger.info("Model deployed to production cache")
                
        except Exception as e:
            logger.error(f"Failed to deploy to production: {e}")
            
    async def _generate_synthetic_events(self, count: int) -> List[Dict[str, Any]]:
        """Generate synthetic events for testing"""
        events = []
        
        for i in range(count):
            event = {
                "@timestamp": (datetime.now() - timedelta(hours=i)).isoformat() + "Z",
                "@metadata": {"_id": f"synthetic-{i}"},
                "event": {"action": np.random.choice(["login", "logout", "file_access", "network_connection"])},
                "user": {"name": f"user_{i % 10}", "risk_score": np.random.randint(0, 100)},
                "source": {"ip": f"192.168.1.{i % 254 + 1}", "port": np.random.randint(1024, 65535)},
                "destination": {"ip": f"10.0.0.{i % 254 + 1}", "port": np.random.randint(1, 1024)},
                "network": {"bytes": np.random.randint(100, 1000000)},
                "enrichment": {"score": np.random.randint(0, 100)}
            }
            events.append(event)
            
        return events
        
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
        
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.db_connection:
                self.db_connection.close()
            if self.redis_client:
                await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.close
                )
            logger.info("Training pipeline cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

if __name__ == "__main__":
    # Example usage
    async def main():
        pipeline = MLTrainingPipeline("/path/to/ml_config.yaml")
        await pipeline.initialize()
        
        # Prepare training data
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        features_df, labels = await pipeline.prepare_training_data(start_date, end_date)
        
        # Train models
        trained_models = await pipeline.train_models()
        
        # Deploy best model
        best_model = await pipeline.deploy_best_model(trained_models)
        
        if best_model:
            print(f"Best model: {best_model.metadata['model_type']}")
            print(f"F1 Score: {best_model.performance_metrics.f1_score:.4f}")
            print(f"Accuracy: {best_model.performance_metrics.accuracy:.4f}")
            
        await pipeline.cleanup()
        
    # Run example
    # asyncio.run(main())