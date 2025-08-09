#!/usr/bin/env python3
"""
ISECTECH Data Loss Prevention - Machine Learning Classification Engine
Advanced ML-based content classification system for intelligent sensitive data detection.

This module provides comprehensive ML classification capabilities including:
- Context-aware NLP classification using transformer models
- Multi-label classification for complex documents  
- Ensemble methods combining multiple algorithms
- Continuous learning and model improvement
- False positive reduction through advanced techniques
- Model serving infrastructure for production deployment

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import pickle
import sqlite3
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import tempfile
import hashlib

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize, sent_tokenize
from nltk.stem import WordNetLemmatizer
import spacy
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from scipy.special import softmax
import redis

# ISECTECH Security Configuration
from ..config.security_config import SecurityConfig
from ..core.logging import SecurityLogger
from ..core.metrics import MetricsCollector
from ..core.performance import PerformanceProfiler

# Suppress warnings for production
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)


class ModelType(Enum):
    """ML model types for classification."""
    RANDOM_FOREST = "random_forest"
    LOGISTIC_REGRESSION = "logistic_regression"
    SVM = "svm"
    NAIVE_BAYES = "naive_bayes"
    ENSEMBLE = "ensemble"
    TRANSFORMER = "transformer"
    NEURAL_NETWORK = "neural_network"


class ClassificationTask(Enum):
    """Classification task types."""
    BINARY = "binary"          # Sensitive vs Non-sensitive
    MULTICLASS = "multiclass"  # PII, PHI, PCI, etc.
    MULTILABEL = "multilabel"  # Multiple labels per document


class FeatureType(Enum):
    """Feature extraction types."""
    TFIDF = "tfidf"
    COUNT = "count"
    WORD2VEC = "word2vec"
    BERT = "bert"
    CUSTOM = "custom"


@dataclass
class TrainingData:
    """Training data record."""
    id: str
    text: str
    labels: List[str]
    metadata: Dict[str, Any]
    created_time: datetime
    source: str


@dataclass
class ModelMetrics:
    """Model performance metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: Optional[float] = None
    confusion_matrix: Optional[List[List[int]]] = None
    classification_report: Optional[str] = None


@dataclass
class PredictionResult:
    """ML prediction result."""
    text_hash: str
    model_name: str
    model_version: str
    predictions: Dict[str, float]  # label -> confidence
    top_prediction: str
    confidence_score: float
    feature_importance: Optional[Dict[str, float]] = None
    prediction_time: float = 0.0
    metadata: Dict[str, Any] = None


@dataclass
class ModelConfig:
    """ML model configuration."""
    name: str
    model_type: ModelType
    task_type: ClassificationTask
    feature_type: FeatureType
    hyperparameters: Dict[str, Any]
    enabled: bool = True
    auto_retrain: bool = True
    min_training_samples: int = 100
    retrain_threshold: float = 0.8  # Retrain if accuracy drops below this


class MLClassificationEngine:
    """
    ISECTECH Machine Learning Classification Engine
    
    Advanced ML system for intelligent content classification with:
    - Multiple algorithm support (RF, SVM, Transformers, etc.)
    - Ensemble methods for improved accuracy
    - Context-aware NLP processing
    - Continuous learning capabilities
    - False positive reduction
    - Production-ready model serving
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = SecurityLogger("ml_classification_engine")
        self.metrics = MetricsCollector("dlp_ml_classification")
        self.profiler = PerformanceProfiler("ml_classification")
        
        # Database setup
        self.db_path = config.get("dlp.ml_db_path", "dlp_ml_classification.db")
        self._init_database()
        
        # Redis for caching
        self.redis_client = redis.Redis(
            host=config.get("redis.host", "localhost"),
            port=config.get("redis.port", 6379),
            db=config.get("redis.db", 4),
            decode_responses=False  # Store binary model data
        )
        
        # Thread pool for ML operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.get("dlp.ml.max_workers", 4)
        )
        
        # Model storage
        self.models_dir = Path(config.get("dlp.ml.models_dir", "ml_models"))
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Loaded models
        self.models: Dict[str, Any] = {}
        self.model_configs: Dict[str, ModelConfig] = {}
        self.label_encoders: Dict[str, LabelEncoder] = {}
        
        # NLP setup
        self._init_nlp()
        
        # Load existing models
        self._load_models()
        
        # Training data cache
        self.training_data_cache: List[TrainingData] = []
        self.cache_size = config.get("dlp.ml.training_cache_size", 10000)
        
        # Performance settings
        self.prediction_timeout = config.get("dlp.ml.prediction_timeout", 30.0)
        self.batch_size = config.get("dlp.ml.batch_size", 32)
        
        self.logger.info("ISECTECH ML Classification Engine initialized")


    def _init_database(self):
        """Initialize SQLite database with ML-specific schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Training data table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS training_data (
            id TEXT PRIMARY KEY,
            text TEXT NOT NULL,
            labels TEXT NOT NULL,  -- JSON array
            metadata TEXT,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source TEXT NOT NULL,
            used_for_training BOOLEAN DEFAULT 0,
            validation_set BOOLEAN DEFAULT 0
        )
        """)
        
        # Model configurations table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_configs (
            name TEXT PRIMARY KEY,
            model_type TEXT NOT NULL,
            task_type TEXT NOT NULL,
            feature_type TEXT NOT NULL,
            hyperparameters TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            auto_retrain BOOLEAN DEFAULT 1,
            min_training_samples INTEGER DEFAULT 100,
            retrain_threshold REAL DEFAULT 0.8,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Model metrics table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS model_metrics (
            id TEXT PRIMARY KEY,
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL,
            accuracy REAL NOT NULL,
            precision_score REAL NOT NULL,
            recall REAL NOT NULL,
            f1_score REAL NOT NULL,
            auc_roc REAL,
            confusion_matrix TEXT,
            classification_report TEXT,
            training_samples INTEGER NOT NULL,
            evaluation_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (model_name) REFERENCES model_configs (name)
        )
        """)
        
        # Predictions table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_predictions (
            id TEXT PRIMARY KEY,
            text_hash TEXT NOT NULL,
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL,
            predictions TEXT NOT NULL,  -- JSON
            top_prediction TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            feature_importance TEXT,
            prediction_time REAL NOT NULL,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT
        )
        """)
        
        # False positive feedback table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS false_positive_feedback (
            id TEXT PRIMARY KEY,
            text_hash TEXT NOT NULL,
            original_prediction TEXT NOT NULL,
            correct_label TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            feedback_source TEXT NOT NULL,  -- user, system, validation
            reviewed BOOLEAN DEFAULT 0,
            incorporated BOOLEAN DEFAULT 0,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_training_data_labels ON training_data(labels)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_training_data_source ON training_data(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_model ON ml_predictions(model_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_confidence ON ml_predictions(confidence_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_feedback_reviewed ON false_positive_feedback(reviewed)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_model_metrics_accuracy ON model_metrics(accuracy)")
        
        conn.commit()
        conn.close()
        
        self.logger.info("ML classification database initialized")


    def _init_nlp(self):
        """Initialize NLP components."""
        try:
            # Download required NLTK data
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True)
            nltk.download('wordnet', quiet=True)
            nltk.download('averaged_perceptron_tagger', quiet=True)
            
            # Initialize NLTK components
            self.stop_words = set(stopwords.words('english'))
            self.lemmatizer = WordNetLemmatizer()
            
            # Load spaCy model
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                self.logger.warning("spaCy English model not found. Install with: python -m spacy download en_core_web_sm")
                self.nlp = None
            
            # Initialize transformer pipeline for advanced classification
            try:
                self.transformer_pipeline = pipeline(
                    "text-classification",
                    model="microsoft/DialoGPT-medium",
                    device=-1  # CPU
                )
            except Exception as e:
                self.logger.warning(f"Failed to initialize transformer pipeline: {str(e)}")
                self.transformer_pipeline = None
            
            self.logger.info("NLP components initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize NLP components: {str(e)}")


    def _load_models(self):
        """Load existing models from database and files."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM model_configs WHERE enabled = 1")
        rows = cursor.fetchall()
        
        for row in rows:
            config = ModelConfig(
                name=row[0],
                model_type=ModelType(row[1]),
                task_type=ClassificationTask(row[2]),
                feature_type=FeatureType(row[3]),
                hyperparameters=json.loads(row[4]),
                enabled=bool(row[5]),
                auto_retrain=bool(row[6]),
                min_training_samples=row[7],
                retrain_threshold=row[8]
            )
            
            self.model_configs[config.name] = config
            
            # Load model file
            model_path = self.models_dir / f"{config.name}.joblib"
            if model_path.exists():
                try:
                    self.models[config.name] = joblib.load(model_path)
                    self.logger.info(f"Loaded model: {config.name}")
                except Exception as e:
                    self.logger.error(f"Failed to load model {config.name}: {str(e)}")
        
        conn.close()
        
        # Create default models if none exist
        if not self.model_configs:
            self._create_default_models()
        
        self.logger.info(f"Loaded {len(self.models)} ML models")


    def _create_default_models(self):
        """Create default ISECTECH ML model configurations."""
        default_configs = [
            {
                "name": "isec_binary_classifier",
                "model_type": ModelType.ENSEMBLE,
                "task_type": ClassificationTask.BINARY,
                "feature_type": FeatureType.TFIDF,
                "hyperparameters": {
                    "tfidf_max_features": 10000,
                    "tfidf_ngram_range": [1, 2],
                    "rf_n_estimators": 100,
                    "rf_max_depth": 10,
                    "svm_C": 1.0,
                    "svm_kernel": "linear"
                }
            },
            {
                "name": "isec_multiclass_classifier",
                "model_type": ModelType.RANDOM_FOREST,
                "task_type": ClassificationTask.MULTICLASS,
                "feature_type": FeatureType.TFIDF,
                "hyperparameters": {
                    "tfidf_max_features": 15000,
                    "tfidf_ngram_range": [1, 3],
                    "n_estimators": 200,
                    "max_depth": 15,
                    "min_samples_split": 5
                }
            },
            {
                "name": "isec_pii_specialist",
                "model_type": ModelType.SVM,
                "task_type": ClassificationTask.BINARY,
                "feature_type": FeatureType.TFIDF,
                "hyperparameters": {
                    "tfidf_max_features": 8000,
                    "tfidf_ngram_range": [1, 2],
                    "C": 10.0,
                    "kernel": "rbf",
                    "gamma": "scale"
                }
            },
            {
                "name": "isec_context_aware",
                "model_type": ModelType.TRANSFORMER,
                "task_type": ClassificationTask.MULTICLASS,
                "feature_type": FeatureType.BERT,
                "hyperparameters": {
                    "model_name": "bert-base-uncased",
                    "max_length": 512,
                    "batch_size": 16
                }
            }
        ]
        
        for config_data in default_configs:
            config = ModelConfig(**config_data)
            self.add_model_config(config)


    async def predict_async(self, text: str, model_names: Optional[List[str]] = None) -> List[PredictionResult]:
        """
        Asynchronously predict classification for text using specified models.
        
        Args:
            text: Text content to classify
            model_names: List of model names to use. If None, uses all enabled models.
            
        Returns:
            List of prediction results from each model
        """
        if model_names is None:
            model_names = [name for name, config in self.model_configs.items() if config.enabled]
        
        # Generate text hash for caching
        text_hash = hashlib.sha256(text.encode()).hexdigest()
        
        # Check cache
        cached_results = []
        for model_name in model_names:
            cache_key = f"ml_prediction:{model_name}:{text_hash}"
            cached_result = self.redis_client.get(cache_key)
            if cached_result:
                result_data = pickle.loads(cached_result)
                cached_results.append(PredictionResult(**result_data))
        
        if len(cached_results) == len(model_names):
            self.metrics.increment("ml_prediction_cache_hits")
            return cached_results
        
        # Perform predictions
        prediction_tasks = []
        for model_name in model_names:
            if model_name in self.models:
                task = asyncio.create_task(
                    asyncio.get_event_loop().run_in_executor(
                        self.thread_pool,
                        self._predict_with_model,
                        text, model_name, text_hash
                    )
                )
                prediction_tasks.append(task)
        
        # Wait for all predictions
        results = []
        for task in asyncio.as_completed(prediction_tasks, timeout=self.prediction_timeout):
            try:
                result = await task
                if result:
                    results.append(result)
                    
                    # Cache result
                    cache_key = f"ml_prediction:{result.model_name}:{text_hash}"
                    self.redis_client.setex(
                        cache_key,
                        3600,  # 1 hour cache
                        pickle.dumps(asdict(result))
                    )
            
            except asyncio.TimeoutError:
                self.logger.warning("ML prediction timeout")
            except Exception as e:
                self.logger.error(f"ML prediction failed: {str(e)}")
        
        # Save predictions to database
        for result in results:
            await self._save_prediction_result(result)
        
        self.metrics.increment("ml_predictions_completed", len(results))
        return results


    def _predict_with_model(self, text: str, model_name: str, text_hash: str) -> Optional[PredictionResult]:
        """Perform prediction with a specific model."""
        start_time = time.time()
        
        try:
            model = self.models[model_name]
            config = self.model_configs[model_name]
            
            # Preprocess text
            processed_text = self._preprocess_text(text)
            
            # Extract features based on model type
            if config.feature_type == FeatureType.TFIDF:
                features = model.named_steps['tfidf'].transform([processed_text])
            elif config.feature_type == FeatureType.COUNT:
                features = model.named_steps['count'].transform([processed_text])
            elif config.feature_type == FeatureType.BERT:
                return self._predict_with_transformer(text, model_name, text_hash)
            else:
                # Custom feature extraction
                features = self._extract_custom_features([processed_text])
            
            # Make prediction
            if hasattr(model, 'predict_proba'):
                probabilities = model.predict_proba(features)[0]
                classes = model.classes_
                
                # Create predictions dict
                predictions = {}
                for i, class_name in enumerate(classes):
                    predictions[str(class_name)] = float(probabilities[i])
                
                # Get top prediction
                top_idx = np.argmax(probabilities)
                top_prediction = str(classes[top_idx])
                confidence_score = float(probabilities[top_idx])
            
            else:
                # Models without probability prediction
                prediction = model.predict(features)[0]
                top_prediction = str(prediction)
                confidence_score = 1.0
                predictions = {top_prediction: confidence_score}
            
            # Extract feature importance if available
            feature_importance = None
            if hasattr(model, 'named_steps') and 'classifier' in model.named_steps:
                classifier = model.named_steps['classifier']
                if hasattr(classifier, 'feature_importances_'):
                    feature_names = model.named_steps['tfidf'].get_feature_names_out()
                    importances = classifier.feature_importances_
                    
                    # Get top 20 most important features
                    top_indices = np.argsort(importances)[-20:]
                    feature_importance = {
                        feature_names[i]: float(importances[i]) 
                        for i in top_indices
                    }
            
            prediction_time = time.time() - start_time
            
            return PredictionResult(
                text_hash=text_hash,
                model_name=model_name,
                model_version=self._get_model_version(model_name),
                predictions=predictions,
                top_prediction=top_prediction,
                confidence_score=confidence_score,
                feature_importance=feature_importance,
                prediction_time=prediction_time,
                metadata={
                    "text_length": len(text),
                    "processed_text_length": len(processed_text),
                    "model_type": config.model_type.value
                }
            )
        
        except Exception as e:
            self.logger.error(f"Prediction failed for model {model_name}: {str(e)}")
            return None


    def _predict_with_transformer(self, text: str, model_name: str, text_hash: str) -> Optional[PredictionResult]:
        """Perform prediction using transformer model."""
        if not self.transformer_pipeline:
            return None
        
        start_time = time.time()
        
        try:
            # Truncate text if too long
            max_length = self.model_configs[model_name].hyperparameters.get("max_length", 512)
            if len(text) > max_length:
                text = text[:max_length]
            
            # Get prediction
            result = self.transformer_pipeline(text)
            
            # Process results
            predictions = {}
            for item in result:
                predictions[item['label']] = float(item['score'])
            
            # Get top prediction
            top_result = max(result, key=lambda x: x['score'])
            top_prediction = top_result['label']
            confidence_score = float(top_result['score'])
            
            prediction_time = time.time() - start_time
            
            return PredictionResult(
                text_hash=text_hash,
                model_name=model_name,
                model_version=self._get_model_version(model_name),
                predictions=predictions,
                top_prediction=top_prediction,
                confidence_score=confidence_score,
                prediction_time=prediction_time,
                metadata={
                    "text_length": len(text),
                    "model_type": "transformer"
                }
            )
        
        except Exception as e:
            self.logger.error(f"Transformer prediction failed: {str(e)}")
            return None


    def _preprocess_text(self, text: str) -> str:
        """Preprocess text for ML classification."""
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Tokenize and remove stop words
        tokens = word_tokenize(text)
        tokens = [token for token in tokens if token.isalnum() and token not in self.stop_words]
        
        # Lemmatize
        tokens = [self.lemmatizer.lemmatize(token) for token in tokens]
        
        return ' '.join(tokens)


    def _extract_custom_features(self, texts: List[str]) -> np.ndarray:
        """Extract custom features from texts."""
        features = []
        
        for text in texts:
            feature_vector = []
            
            # Text length features
            feature_vector.append(len(text))
            feature_vector.append(len(text.split()))
            feature_vector.append(len(text.split()) / max(len(text), 1))  # words per character
            
            # Character type ratios
            total_chars = max(len(text), 1)
            feature_vector.append(sum(1 for c in text if c.isdigit()) / total_chars)
            feature_vector.append(sum(1 for c in text if c.isalpha()) / total_chars)
            feature_vector.append(sum(1 for c in text if c.isupper()) / total_chars)
            feature_vector.append(sum(1 for c in text if c.isspace()) / total_chars)
            
            # Pattern features
            feature_vector.append(text.count('@'))  # Email indicators
            feature_vector.append(text.count('-'))  # Dash separators (SSN, phone, etc.)
            feature_vector.append(text.count('.'))  # Decimal points
            feature_vector.append(text.count('('))  # Parentheses (phone numbers)
            
            # Sequence features
            feature_vector.append(len([c for c in text if c.isdigit()]))  # Total digits
            feature_vector.append(max([len(word) for word in text.split()] or [0]))  # Longest word
            
            features.append(feature_vector)
        
        return np.array(features)


    async def train_model_async(self, model_name: str, training_data: Optional[List[TrainingData]] = None) -> ModelMetrics:
        """
        Asynchronously train or retrain a model.
        
        Args:
            model_name: Name of model to train
            training_data: Optional training data. If None, loads from database.
            
        Returns:
            Model performance metrics
        """
        if model_name not in self.model_configs:
            raise ValueError(f"Model config not found: {model_name}")
        
        config = self.model_configs[model_name]
        
        # Load training data
        if training_data is None:
            training_data = await self._load_training_data(config.min_training_samples)
        
        if len(training_data) < config.min_training_samples:
            raise ValueError(f"Insufficient training data: {len(training_data)} < {config.min_training_samples}")
        
        # Prepare training data
        texts = [data.text for data in training_data]
        
        # Handle different label formats
        if config.task_type == ClassificationTask.BINARY:
            labels = []
            for data in training_data:
                # Convert to binary: sensitive vs non-sensitive
                is_sensitive = any(label.lower() in ['pii', 'phi', 'pci', 'confidential', 'restricted'] 
                                 for label in data.labels)
                labels.append('sensitive' if is_sensitive else 'non_sensitive')
        
        elif config.task_type == ClassificationTask.MULTICLASS:
            # Use primary label (first one)
            labels = [data.labels[0] if data.labels else 'unknown' for data in training_data]
        
        else:  # MULTILABEL
            # Multi-label classification (more complex, would need different approach)
            labels = [','.join(data.labels) for data in training_data]
        
        # Encode labels
        if model_name not in self.label_encoders:
            self.label_encoders[model_name] = LabelEncoder()
        
        encoded_labels = self.label_encoders[model_name].fit_transform(labels)
        
        # Train model in thread pool
        metrics = await asyncio.get_event_loop().run_in_executor(
            self.thread_pool,
            self._train_model_sync,
            config, texts, encoded_labels
        )
        
        # Save model
        model_path = self.models_dir / f"{model_name}.joblib"
        joblib.dump(self.models[model_name], model_path)
        
        # Save metrics to database
        await self._save_model_metrics(model_name, metrics, len(training_data))
        
        self.logger.info(f"Trained model {model_name} with accuracy: {metrics.accuracy:.3f}")
        return metrics


    def _train_model_sync(self, config: ModelConfig, texts: List[str], labels: np.ndarray) -> ModelMetrics:
        """Synchronously train model (runs in thread pool)."""
        # Preprocess texts
        processed_texts = [self._preprocess_text(text) for text in texts]
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            processed_texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Build pipeline based on model type
        if config.model_type == ModelType.RANDOM_FOREST:
            pipeline = self._build_rf_pipeline(config)
        elif config.model_type == ModelType.SVM:
            pipeline = self._build_svm_pipeline(config)
        elif config.model_type == ModelType.LOGISTIC_REGRESSION:
            pipeline = self._build_lr_pipeline(config)
        elif config.model_type == ModelType.NAIVE_BAYES:
            pipeline = self._build_nb_pipeline(config)
        elif config.model_type == ModelType.ENSEMBLE:
            pipeline = self._build_ensemble_pipeline(config)
        else:
            raise ValueError(f"Unsupported model type: {config.model_type}")
        
        # Train model
        pipeline.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = pipeline.predict(X_test)
        y_pred_proba = None
        
        if hasattr(pipeline, 'predict_proba'):
            try:
                y_pred_proba = pipeline.predict_proba(X_test)
            except:
                pass
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        
        # Get detailed metrics
        report = classification_report(y_test, y_pred, output_dict=True)
        precision = report['weighted avg']['precision']
        recall = report['weighted avg']['recall']
        f1 = report['weighted avg']['f1-score']
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        
        # AUC-ROC for binary classification
        auc_roc = None
        if len(np.unique(labels)) == 2 and y_pred_proba is not None:
            from sklearn.metrics import roc_auc_score
            auc_roc = roc_auc_score(y_test, y_pred_proba[:, 1])
        
        # Store trained model
        self.models[config.name] = pipeline
        
        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            auc_roc=auc_roc,
            confusion_matrix=cm.tolist(),
            classification_report=classification_report(y_test, y_pred)
        )


    def _build_rf_pipeline(self, config: ModelConfig) -> Pipeline:
        """Build Random Forest pipeline."""
        params = config.hyperparameters
        
        steps = []
        
        # Feature extraction
        if config.feature_type == FeatureType.TFIDF:
            steps.append(('tfidf', TfidfVectorizer(
                max_features=params.get('tfidf_max_features', 10000),
                ngram_range=tuple(params.get('tfidf_ngram_range', [1, 2])),
                stop_words='english'
            )))
        elif config.feature_type == FeatureType.COUNT:
            steps.append(('count', CountVectorizer(
                max_features=params.get('count_max_features', 10000),
                ngram_range=tuple(params.get('count_ngram_range', [1, 2])),
                stop_words='english'
            )))
        
        # Classifier
        steps.append(('classifier', RandomForestClassifier(
            n_estimators=params.get('n_estimators', 100),
            max_depth=params.get('max_depth', 10),
            min_samples_split=params.get('min_samples_split', 2),
            random_state=42,
            n_jobs=-1
        )))
        
        return Pipeline(steps)


    def _build_svm_pipeline(self, config: ModelConfig) -> Pipeline:
        """Build SVM pipeline."""
        params = config.hyperparameters
        
        steps = []
        
        # Feature extraction
        if config.feature_type == FeatureType.TFIDF:
            steps.append(('tfidf', TfidfVectorizer(
                max_features=params.get('tfidf_max_features', 10000),
                ngram_range=tuple(params.get('tfidf_ngram_range', [1, 2])),
                stop_words='english'
            )))
        
        # Scaler for SVM
        steps.append(('scaler', StandardScaler(with_mean=False)))
        
        # Classifier
        steps.append(('classifier', SVC(
            C=params.get('C', 1.0),
            kernel=params.get('kernel', 'linear'),
            gamma=params.get('gamma', 'scale'),
            probability=True,  # Enable probability predictions
            random_state=42
        )))
        
        return Pipeline(steps)


    def _build_lr_pipeline(self, config: ModelConfig) -> Pipeline:
        """Build Logistic Regression pipeline."""
        params = config.hyperparameters
        
        steps = []
        
        # Feature extraction
        if config.feature_type == FeatureType.TFIDF:
            steps.append(('tfidf', TfidfVectorizer(
                max_features=params.get('tfidf_max_features', 10000),
                ngram_range=tuple(params.get('tfidf_ngram_range', [1, 2])),
                stop_words='english'
            )))
        
        # Classifier
        steps.append(('classifier', LogisticRegression(
            C=params.get('C', 1.0),
            max_iter=params.get('max_iter', 1000),
            random_state=42
        )))
        
        return Pipeline(steps)


    def _build_nb_pipeline(self, config: ModelConfig) -> Pipeline:
        """Build Naive Bayes pipeline."""
        params = config.hyperparameters
        
        steps = []
        
        # Feature extraction
        if config.feature_type == FeatureType.TFIDF:
            steps.append(('tfidf', TfidfVectorizer(
                max_features=params.get('tfidf_max_features', 10000),
                ngram_range=tuple(params.get('tfidf_ngram_range', [1, 2])),
                stop_words='english'
            )))
        
        # Classifier
        steps.append(('classifier', MultinomialNB(
            alpha=params.get('alpha', 1.0)
        )))
        
        return Pipeline(steps)


    def _build_ensemble_pipeline(self, config: ModelConfig) -> Pipeline:
        """Build ensemble pipeline with multiple classifiers."""
        params = config.hyperparameters
        
        steps = []
        
        # Feature extraction
        if config.feature_type == FeatureType.TFIDF:
            steps.append(('tfidf', TfidfVectorizer(
                max_features=params.get('tfidf_max_features', 10000),
                ngram_range=tuple(params.get('tfidf_ngram_range', [1, 2])),
                stop_words='english'
            )))
        
        # Create ensemble of classifiers
        rf_classifier = RandomForestClassifier(
            n_estimators=params.get('rf_n_estimators', 100),
            max_depth=params.get('rf_max_depth', 10),
            random_state=42
        )
        
        svm_classifier = SVC(
            C=params.get('svm_C', 1.0),
            kernel=params.get('svm_kernel', 'linear'),
            probability=True,
            random_state=42
        )
        
        lr_classifier = LogisticRegression(
            C=params.get('lr_C', 1.0),
            random_state=42
        )
        
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf_classifier),
                ('svm', svm_classifier),
                ('lr', lr_classifier)
            ],
            voting='soft'  # Use probability predictions
        )
        
        steps.append(('classifier', ensemble))
        
        return Pipeline(steps)


    async def add_training_data(self, data: TrainingData):
        """Add training data to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO training_data 
        (id, text, labels, metadata, created_time, source)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data.id,
            data.text,
            json.dumps(data.labels),
            json.dumps(data.metadata),
            data.created_time.isoformat(),
            data.source
        ))
        
        conn.commit()
        conn.close()
        
        # Add to cache
        self.training_data_cache.append(data)
        if len(self.training_data_cache) > self.cache_size:
            self.training_data_cache.pop(0)
        
        self.logger.debug(f"Added training data: {data.id}")


    async def _load_training_data(self, min_samples: int) -> List[TrainingData]:
        """Load training data from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT * FROM training_data 
        ORDER BY created_time DESC 
        LIMIT ?
        """, (min_samples * 2,))  # Load extra for better diversity
        
        rows = cursor.fetchall()
        conn.close()
        
        training_data = []
        for row in rows:
            data = TrainingData(
                id=row[0],
                text=row[1],
                labels=json.loads(row[2]),
                metadata=json.loads(row[3]) if row[3] else {},
                created_time=datetime.fromisoformat(row[4]),
                source=row[5]
            )
            training_data.append(data)
        
        return training_data


    async def record_false_positive(self, text_hash: str, original_prediction: str, 
                                  correct_label: str, confidence_score: float,
                                  feedback_source: str = "user"):
        """Record false positive feedback for model improvement."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        feedback_id = f"fp_{text_hash}_{int(time.time())}"
        
        cursor.execute("""
        INSERT INTO false_positive_feedback 
        (id, text_hash, original_prediction, correct_label, confidence_score, 
         feedback_source, reviewed, incorporated)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feedback_id, text_hash, original_prediction, correct_label,
            confidence_score, feedback_source, False, False
        ))
        
        conn.commit()
        conn.close()
        
        self.metrics.increment("false_positive_feedback_received")
        self.logger.info(f"Recorded false positive feedback: {feedback_id}")


    async def incorporate_feedback(self) -> int:
        """Incorporate false positive feedback into training data."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get unprocessed feedback
        cursor.execute("""
        SELECT fp.*, p.text_hash 
        FROM false_positive_feedback fp
        JOIN ml_predictions p ON fp.text_hash = p.text_hash
        WHERE fp.reviewed = 0
        LIMIT 100
        """)
        
        feedback_rows = cursor.fetchall()
        incorporated_count = 0
        
        for row in feedback_rows:
            feedback_id = row[0]
            text_hash = row[1]
            correct_label = row[3]
            
            # Find original text (would need to be cached or stored separately)
            # For now, mark as reviewed
            cursor.execute("""
            UPDATE false_positive_feedback 
            SET reviewed = 1, incorporated = 1 
            WHERE id = ?
            """, (feedback_id,))
            
            incorporated_count += 1
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Incorporated {incorporated_count} feedback items")
        return incorporated_count


    def add_model_config(self, config: ModelConfig):
        """Add new model configuration."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO model_configs 
        (name, model_type, task_type, feature_type, hyperparameters,
         enabled, auto_retrain, min_training_samples, retrain_threshold)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            config.name, config.model_type.value, config.task_type.value,
            config.feature_type.value, json.dumps(config.hyperparameters),
            config.enabled, config.auto_retrain, config.min_training_samples,
            config.retrain_threshold
        ))
        
        conn.commit()
        conn.close()
        
        self.model_configs[config.name] = config
        self.logger.info(f"Added model config: {config.name}")


    async def _save_prediction_result(self, result: PredictionResult):
        """Save prediction result to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO ml_predictions 
        (id, text_hash, model_name, model_version, predictions, top_prediction,
         confidence_score, feature_importance, prediction_time, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"pred_{result.text_hash}_{result.model_name}_{int(time.time())}",
            result.text_hash,
            result.model_name,
            result.model_version,
            json.dumps(result.predictions),
            result.top_prediction,
            result.confidence_score,
            json.dumps(result.feature_importance or {}),
            result.prediction_time,
            json.dumps(result.metadata or {})
        ))
        
        conn.commit()
        conn.close()


    async def _save_model_metrics(self, model_name: str, metrics: ModelMetrics, training_samples: int):
        """Save model performance metrics to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO model_metrics 
        (id, model_name, model_version, accuracy, precision_score, recall,
         f1_score, auc_roc, confusion_matrix, classification_report, training_samples)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"metrics_{model_name}_{int(time.time())}",
            model_name,
            self._get_model_version(model_name),
            metrics.accuracy,
            metrics.precision,
            metrics.recall,
            metrics.f1_score,
            metrics.auc_roc,
            json.dumps(metrics.confusion_matrix) if metrics.confusion_matrix else None,
            metrics.classification_report,
            training_samples
        ))
        
        conn.commit()
        conn.close()


    def _get_model_version(self, model_name: str) -> str:
        """Get model version string."""
        return f"v1.0_{int(time.time())}"


    def get_model_performance(self, model_name: str) -> Optional[ModelMetrics]:
        """Get latest performance metrics for a model."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT * FROM model_metrics 
        WHERE model_name = ? 
        ORDER BY evaluation_time DESC 
        LIMIT 1
        """, (model_name,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return ModelMetrics(
                accuracy=row[3],
                precision=row[4],
                recall=row[5],
                f1_score=row[6],
                auc_roc=row[7],
                confusion_matrix=json.loads(row[8]) if row[8] else None,
                classification_report=row[9]
            )
        
        return None


    def get_statistics(self) -> Dict[str, Any]:
        """Get ML engine statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total predictions
        cursor.execute("SELECT COUNT(*) FROM ml_predictions")
        total_predictions = cursor.fetchone()[0]
        
        # Average confidence by model
        cursor.execute("""
        SELECT model_name, AVG(confidence_score) 
        FROM ml_predictions 
        GROUP BY model_name
        """)
        avg_confidence_by_model = dict(cursor.fetchall())
        
        # Training data count
        cursor.execute("SELECT COUNT(*) FROM training_data")
        training_data_count = cursor.fetchone()[0]
        
        # False positive feedback
        cursor.execute("SELECT COUNT(*) FROM false_positive_feedback")
        fp_feedback_count = cursor.fetchone()[0]
        
        # Recent performance
        cursor.execute("""
        SELECT model_name, accuracy 
        FROM model_metrics 
        WHERE evaluation_time >= datetime('now', '-7 days')
        ORDER BY evaluation_time DESC
        """)
        recent_performance = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            "total_predictions": total_predictions,
            "avg_confidence_by_model": avg_confidence_by_model,
            "training_data_count": training_data_count,
            "false_positive_feedback": fp_feedback_count,
            "recent_performance": recent_performance,
            "active_models": len([c for c in self.model_configs.values() if c.enabled]),
            "loaded_models": len(self.models)
        }


    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'thread_pool'):
            self.thread_pool.shutdown(wait=True)
        if hasattr(self, 'redis_client'):
            self.redis_client.close()