"""
Model Trainer - Continuous training and improvement for ML triage models

Implements automated model training, evaluation, and deployment pipeline
for the ML-based alert triage system. Supports both batch and incremental
learning approaches with comprehensive model validation and A/B testing.
"""

import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import joblib
import json
import structlog

# ML libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, average_precision_score, f1_score
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

# Storage and database
from elasticsearch import AsyncElasticsearch
import redis.asyncio as redis

logger = structlog.get_logger(__name__)

@dataclass
class ModelPerformance:
    """Model performance metrics"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    avg_precision: float
    confusion_matrix: List[List[int]]
    classification_report: Dict[str, Any]
    training_size: int
    validation_size: int
    training_time: float

@dataclass
class TrainingResults:
    """Complete training results"""
    model_id: str
    model_version: str
    model_type: str
    performance: ModelPerformance
    feature_importance: Dict[str, float]
    model_path: str
    training_metadata: Dict[str, Any]
    timestamp: str

class ModelTrainer:
    """
    Advanced model trainer for ML-based alert triage system.
    
    Features:
    - Continuous learning from new alert data
    - Automated model evaluation and validation
    - A/B testing for model deployment
    - Feature importance analysis
    - Model versioning and rollback capabilities
    - Performance monitoring and alerts
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Training configuration
        self.training_config = self.config.get('training', {
            'batch_size': 1000,
            'validation_split': 0.2,
            'min_training_samples': 500,
            'retrain_threshold_days': 7,
            'performance_threshold': 0.85,
            'feature_selection_threshold': 0.01
        })
        
        # Model configuration
        self.model_config = self.config.get('models', {
            'random_forest': {
                'n_estimators': 100,
                'max_depth': 10,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'random_state': 42
            },
            'gradient_boosting': {
                'n_estimators': 100,
                'learning_rate': 0.1,
                'max_depth': 6,
                'min_samples_split': 5,
                'random_state': 42
            },
            'logistic_regression': {
                'C': 1.0,
                'max_iter': 1000,
                'random_state': 42
            }
        })
        
        # Storage paths
        self.model_storage_path = Path(self.config.get('model_storage_path', './models'))
        self.model_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Database connections
        self.elasticsearch = None
        self.redis = None
        
        # Current models
        self.active_models = {}
        self.model_metadata = {}
        
        # Training history
        self.training_history = []
        
        logger.info("ModelTrainer initialized", 
                   training_config=self.training_config,
                   model_storage_path=str(self.model_storage_path))
    
    async def initialize(self, elasticsearch_config: Dict[str, Any], redis_config: Dict[str, Any]):
        """Initialize database connections"""
        try:
            # Initialize Elasticsearch
            self.elasticsearch = AsyncElasticsearch([elasticsearch_config])
            
            # Initialize Redis
            self.redis = redis.Redis(**redis_config)
            
            # Load existing models
            await self._load_existing_models()
            
            logger.info("ModelTrainer initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize ModelTrainer", error=str(e))
            raise
    
    async def train_models(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        force_retrain: bool = False
    ) -> Dict[str, TrainingResults]:
        """
        Train or retrain all models with latest data
        
        Args:
            start_date: Start date for training data
            end_date: End date for training data  
            force_retrain: Force retraining even if not needed
            
        Returns:
            Dictionary of training results by model type
        """
        try:
            training_start = datetime.now(timezone.utc)
            
            # Check if retraining is needed
            if not force_retrain and not await self._should_retrain():
                logger.info("Models are up-to-date, skipping training")
                return {}
            
            # Prepare training data
            logger.info("Preparing training data", 
                       start_date=start_date, end_date=end_date)
            
            X, y, metadata = await self._prepare_training_data(start_date, end_date)
            
            if len(X) < self.training_config['min_training_samples']:
                logger.warning("Insufficient training data", 
                             samples=len(X), 
                             required=self.training_config['min_training_samples'])
                return {}
            
            # Split data
            X_train, X_val, y_train, y_val = train_test_split(
                X, y, 
                test_size=self.training_config['validation_split'],
                stratify=y,
                random_state=42
            )
            
            logger.info("Training data prepared", 
                       total_samples=len(X),
                       training_samples=len(X_train),
                       validation_samples=len(X_val))
            
            # Train models
            results = {}
            
            for model_type in ['random_forest', 'gradient_boosting', 'logistic_regression']:
                logger.info(f"Training {model_type} model")
                
                result = await self._train_single_model(
                    model_type, X_train, y_train, X_val, y_val, metadata
                )
                
                if result:
                    results[model_type] = result
                    
                    # Store model performance
                    await self._store_model_performance(result)
            
            # Update training history
            self.training_history.append({
                'timestamp': training_start.isoformat(),
                'duration': (datetime.now(timezone.utc) - training_start).total_seconds(),
                'models_trained': list(results.keys()),
                'training_samples': len(X_train),
                'validation_samples': len(X_val)
            })
            
            logger.info("Model training completed", 
                       models_trained=len(results),
                       total_time=(datetime.now(timezone.utc) - training_start).total_seconds())
            
            return results
            
        except Exception as e:
            logger.error("Model training failed", error=str(e))
            raise
    
    async def evaluate_models(
        self,
        test_data: Optional[Tuple[np.ndarray, np.ndarray]] = None
    ) -> Dict[str, ModelPerformance]:
        """
        Evaluate all active models on test data
        
        Args:
            test_data: Optional test dataset (X, y)
            
        Returns:
            Performance metrics for each model
        """
        try:
            if test_data is None:
                # Prepare fresh test data
                X_test, y_test, _ = await self._prepare_training_data(
                    start_date=datetime.now(timezone.utc) - timedelta(days=1),
                    end_date=datetime.now(timezone.utc)
                )
            else:
                X_test, y_test = test_data
            
            if len(X_test) == 0:
                logger.warning("No test data available for evaluation")
                return {}
            
            results = {}
            
            for model_type, model_info in self.active_models.items():
                try:
                    model = model_info['model']
                    
                    # Make predictions
                    y_pred = model.predict(X_test)
                    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred
                    
                    # Calculate metrics
                    performance = ModelPerformance(
                        accuracy=float(np.mean(y_pred == y_test)),
                        precision=float(precision_score(y_test, y_pred, average='weighted', zero_division=0)),
                        recall=float(recall_score(y_test, y_pred, average='weighted', zero_division=0)),
                        f1_score=float(f1_score(y_test, y_pred, average='weighted', zero_division=0)),
                        roc_auc=float(roc_auc_score(y_test, y_prob)) if len(np.unique(y_test)) > 1 else 0.0,
                        avg_precision=float(average_precision_score(y_test, y_prob)) if len(np.unique(y_test)) > 1 else 0.0,
                        confusion_matrix=confusion_matrix(y_test, y_pred).tolist(),
                        classification_report=classification_report(y_test, y_pred, output_dict=True, zero_division=0),
                        training_size=0,  # Not applicable for evaluation
                        validation_size=len(X_test),
                        training_time=0.0  # Not applicable for evaluation
                    )
                    
                    results[model_type] = performance
                    
                    logger.info(f"Evaluated {model_type} model",
                               accuracy=performance.accuracy,
                               f1_score=performance.f1_score,
                               roc_auc=performance.roc_auc)
                    
                except Exception as e:
                    logger.error(f"Failed to evaluate {model_type} model", error=str(e))
                    continue
            
            return results
            
        except Exception as e:
            logger.error("Model evaluation failed", error=str(e))
            return {}
    
    async def deploy_best_model(
        self,
        evaluation_results: Dict[str, ModelPerformance],
        deployment_threshold: float = 0.85
    ) -> Optional[str]:
        """
        Deploy the best performing model based on evaluation results
        
        Args:
            evaluation_results: Model performance results
            deployment_threshold: Minimum performance threshold for deployment
            
        Returns:
            Name of deployed model or None if no model meets threshold
        """
        try:
            if not evaluation_results:
                logger.warning("No evaluation results provided for deployment")
                return None
            
            # Find best model based on F1 score
            best_model = None
            best_score = 0.0
            
            for model_type, performance in evaluation_results.items():
                # Combined score: F1 * 0.4 + ROC-AUC * 0.3 + Precision * 0.3
                combined_score = (
                    performance.f1_score * 0.4 +
                    performance.roc_auc * 0.3 +
                    performance.precision * 0.3
                )
                
                if combined_score > best_score:
                    best_score = combined_score
                    best_model = model_type
            
            if best_model is None or best_score < deployment_threshold:
                logger.warning("No model meets deployment threshold",
                             best_score=best_score,
                             threshold=deployment_threshold)
                return None
            
            # Deploy best model
            await self._deploy_model(best_model)
            
            logger.info("Model deployed successfully",
                       model=best_model,
                       score=best_score)
            
            return best_model
            
        except Exception as e:
            logger.error("Model deployment failed", error=str(e))
            return None
    
    async def _prepare_training_data(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
        """Prepare training data from Elasticsearch"""
        try:
            # Default date range
            if end_date is None:
                end_date = datetime.now(timezone.utc)
            if start_date is None:
                start_date = end_date - timedelta(days=30)
            
            # Query processed alerts with triage decisions
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "processed_timestamp": {
                                        "gte": start_date.isoformat(),
                                        "lt": end_date.isoformat()
                                    }
                                }
                            },
                            {
                                "exists": {
                                    "field": "ml_triage_result.decision"
                                }
                            },
                            {
                                "exists": {
                                    "field": "feature_vector"
                                }
                            }
                        ]
                    }
                },
                "size": 10000,
                "sort": [{"processed_timestamp": {"order": "desc"}}]
            }
            
            # Execute search
            response = await self.elasticsearch.search(
                index="alerts-*",
                body=query
            )
            
            alerts = response['hits']['hits']
            
            if not alerts:
                logger.warning("No training data found in date range",
                             start_date=start_date, end_date=end_date)
                return np.array([]), np.array([]), {}
            
            # Extract features and labels
            features = []
            labels = []
            
            for alert in alerts:
                source = alert['_source']
                
                # Extract feature vector
                feature_vector = source.get('feature_vector', {})
                if not feature_vector:
                    continue
                
                # Convert feature dict to array (sorted by key for consistency)
                feature_keys = sorted(feature_vector.keys())
                feature_array = [feature_vector.get(key, 0) for key in feature_keys]
                
                # Extract label from triage decision
                triage_result = source.get('ml_triage_result', {})
                decision = triage_result.get('decision', 'investigate').lower()
                
                # Map decision to binary label (1 = escalate, 0 = no action)
                label = 1 if decision in ['escalate', 'investigate', 'critical'] else 0
                
                features.append(feature_array)
                labels.append(label)
            
            # Convert to numpy arrays
            X = np.array(features)
            y = np.array(labels)
            
            # Metadata
            metadata = {
                'feature_names': sorted(feature_vector.keys()) if feature_vector else [],
                'data_range': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'total_alerts': len(alerts),
                'valid_samples': len(X),
                'label_distribution': {
                    'escalate': int(np.sum(y)),
                    'no_action': int(len(y) - np.sum(y))
                }
            }
            
            logger.info("Training data prepared",
                       samples=len(X),
                       features=X.shape[1] if len(X) > 0 else 0,
                       positive_samples=int(np.sum(y)) if len(y) > 0 else 0)
            
            return X, y, metadata
            
        except Exception as e:
            logger.error("Failed to prepare training data", error=str(e))
            return np.array([]), np.array([]), {}
    
    async def _train_single_model(
        self,
        model_type: str,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        metadata: Dict[str, Any]
    ) -> Optional[TrainingResults]:
        """Train a single model"""
        try:
            training_start = datetime.now(timezone.utc)
            
            # Create model based on type
            if model_type == 'random_forest':
                base_model = RandomForestClassifier(**self.model_config['random_forest'])
            elif model_type == 'gradient_boosting':
                base_model = GradientBoostingClassifier(**self.model_config['gradient_boosting'])
            elif model_type == 'logistic_regression':
                base_model = LogisticRegression(**self.model_config['logistic_regression'])
            else:
                logger.error(f"Unknown model type: {model_type}")
                return None
            
            # Create pipeline with scaling for logistic regression
            if model_type == 'logistic_regression':
                model = Pipeline([
                    ('scaler', StandardScaler()),
                    ('classifier', base_model)
                ])
            else:
                model = Pipeline([
                    ('classifier', base_model)
                ])
            
            # Calibrate probabilities
            calibrated_model = CalibratedClassifierCV(model, method='sigmoid', cv=3)
            
            # Train model
            calibrated_model.fit(X_train, y_train)
            
            training_time = (datetime.now(timezone.utc) - training_start).total_seconds()
            
            # Evaluate on validation set
            y_pred = calibrated_model.predict(X_val)
            y_prob = calibrated_model.predict_proba(X_val)[:, 1]
            
            # Calculate performance metrics
            performance = ModelPerformance(
                accuracy=float(np.mean(y_pred == y_val)),
                precision=float(precision_score(y_val, y_pred, average='weighted', zero_division=0)),
                recall=float(recall_score(y_val, y_pred, average='weighted', zero_division=0)),
                f1_score=float(f1_score(y_val, y_pred, average='weighted', zero_division=0)),
                roc_auc=float(roc_auc_score(y_val, y_prob)) if len(np.unique(y_val)) > 1 else 0.0,
                avg_precision=float(average_precision_score(y_val, y_prob)) if len(np.unique(y_val)) > 1 else 0.0,
                confusion_matrix=confusion_matrix(y_val, y_pred).tolist(),
                classification_report=classification_report(y_val, y_pred, output_dict=True, zero_division=0),
                training_size=len(X_train),
                validation_size=len(X_val),
                training_time=training_time
            )
            
            # Extract feature importance
            feature_importance = {}
            if hasattr(model.named_steps['classifier'], 'feature_importances_'):
                importances = model.named_steps['classifier'].feature_importances_
                feature_names = metadata.get('feature_names', [f'feature_{i}' for i in range(len(importances))])
                
                for name, importance in zip(feature_names, importances):
                    feature_importance[name] = float(importance)
            
            # Generate model version and save
            model_version = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            model_id = f"{model_type}_{model_version}"
            
            model_path = self.model_storage_path / f"{model_id}.joblib"
            joblib.dump(calibrated_model, model_path)
            
            # Create training results
            results = TrainingResults(
                model_id=model_id,
                model_version=model_version,
                model_type=model_type,
                performance=performance,
                feature_importance=feature_importance,
                model_path=str(model_path),
                training_metadata={
                    'training_config': self.model_config[model_type],
                    'data_metadata': metadata,
                    'cross_validation_scores': await self._cross_validate_model(calibrated_model, X_train, y_train)
                },
                timestamp=training_start.isoformat()
            )
            
            # Update active models
            self.active_models[model_type] = {
                'model': calibrated_model,
                'metadata': results
            }
            
            logger.info(f"Successfully trained {model_type} model",
                       model_id=model_id,
                       accuracy=performance.accuracy,
                       f1_score=performance.f1_score,
                       training_time=training_time)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to train {model_type} model", error=str(e))
            return None
    
    async def _cross_validate_model(
        self,
        model: Pipeline,
        X: np.ndarray,
        y: np.ndarray,
        cv_folds: int = 5
    ) -> Dict[str, float]:
        """Perform cross-validation on model"""
        try:
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            
            # Calculate multiple metrics
            scoring_metrics = ['accuracy', 'f1_weighted', 'precision_weighted', 'recall_weighted']
            cv_results = {}
            
            for metric in scoring_metrics:
                scores = cross_val_score(model, X, y, cv=cv, scoring=metric, n_jobs=-1)
                cv_results[f'{metric}_mean'] = float(np.mean(scores))
                cv_results[f'{metric}_std'] = float(np.std(scores))
            
            return cv_results
            
        except Exception as e:
            logger.error("Cross-validation failed", error=str(e))
            return {}
    
    async def _should_retrain(self) -> bool:
        """Check if models should be retrained"""
        try:
            # Check if we have any models
            if not self.active_models:
                return True
            
            # Check age of models
            retrain_threshold = timedelta(days=self.training_config['retrain_threshold_days'])
            current_time = datetime.now(timezone.utc)
            
            for model_type, model_info in self.active_models.items():
                model_timestamp = datetime.fromisoformat(model_info['metadata'].timestamp)
                
                if current_time - model_timestamp > retrain_threshold:
                    logger.info("Model needs retraining due to age",
                               model_type=model_type,
                               age_days=(current_time - model_timestamp).days)
                    return True
            
            # Check performance degradation (simplified - would use more sophisticated monitoring)
            recent_performance = await self._get_recent_performance()
            if recent_performance and recent_performance < self.training_config['performance_threshold']:
                logger.info("Model needs retraining due to performance degradation",
                           recent_performance=recent_performance,
                           threshold=self.training_config['performance_threshold'])
                return True
            
            return False
            
        except Exception as e:
            logger.error("Failed to check retrain requirements", error=str(e))
            return True  # Err on the side of retraining
    
    async def _get_recent_performance(self) -> Optional[float]:
        """Get recent model performance from monitoring data"""
        try:
            # Query recent triage results and outcomes
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=1)
            
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "processed_timestamp": {
                                        "gte": start_time.isoformat(),
                                        "lt": end_time.isoformat()
                                    }
                                }
                            },
                            {
                                "exists": {
                                    "field": "ml_triage_result.decision"
                                }
                            },
                            {
                                "exists": {
                                    "field": "outcome.analyst_feedback"
                                }
                            }
                        ]
                    }
                },
                "size": 1000
            }
            
            response = await self.elasticsearch.search(
                index="alerts-*",
                body=query
            )
            
            alerts = response['hits']['hits']
            
            if len(alerts) < 10:  # Need minimum samples for reliable metrics
                return None
            
            # Calculate accuracy based on analyst feedback
            correct_predictions = 0
            total_predictions = len(alerts)
            
            for alert in alerts:
                source = alert['_source']
                ml_decision = source.get('ml_triage_result', {}).get('decision', '').lower()
                analyst_feedback = source.get('outcome', {}).get('analyst_feedback', '').lower()
                
                # Simplified mapping - would be more sophisticated in practice
                if ((ml_decision in ['escalate', 'investigate'] and analyst_feedback in ['true_positive', 'escalated']) or
                    (ml_decision in ['ignore', 'low_priority'] and analyst_feedback in ['false_positive', 'closed'])):
                    correct_predictions += 1
            
            accuracy = correct_predictions / total_predictions
            return accuracy
            
        except Exception as e:
            logger.error("Failed to get recent performance", error=str(e))
            return None
    
    async def _load_existing_models(self):
        """Load existing models from storage"""
        try:
            model_files = list(self.model_storage_path.glob("*.joblib"))
            
            for model_file in model_files:
                try:
                    # Extract model type from filename
                    model_id = model_file.stem
                    model_type = model_id.split('_')[0]
                    
                    # Load model
                    model = joblib.load(model_file)
                    
                    # Load metadata if exists
                    metadata_file = model_file.with_suffix('.json')
                    if metadata_file.exists():
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                    else:
                        metadata = {'timestamp': datetime.now(timezone.utc).isoformat()}
                    
                    self.active_models[model_type] = {
                        'model': model,
                        'metadata': metadata
                    }
                    
                    logger.info("Loaded existing model", 
                               model_type=model_type,
                               model_id=model_id)
                    
                except Exception as e:
                    logger.error("Failed to load model", 
                               model_file=str(model_file),
                               error=str(e))
            
        except Exception as e:
            logger.error("Failed to load existing models", error=str(e))
    
    async def _store_model_performance(self, result: TrainingResults):
        """Store model performance in Elasticsearch for monitoring"""
        try:
            performance_doc = {
                'model_id': result.model_id,
                'model_type': result.model_type,
                'model_version': result.model_version,
                'performance': {
                    'accuracy': result.performance.accuracy,
                    'precision': result.performance.precision,
                    'recall': result.performance.recall,
                    'f1_score': result.performance.f1_score,
                    'roc_auc': result.performance.roc_auc,
                    'avg_precision': result.performance.avg_precision
                },
                'training_metadata': result.training_metadata,
                'timestamp': result.timestamp
            }
            
            await self.elasticsearch.index(
                index='ml-triage-models',
                body=performance_doc
            )
            
            # Save metadata to file
            metadata_file = Path(result.model_path).with_suffix('.json')
            with open(metadata_file, 'w') as f:
                json.dump(performance_doc, f, indent=2, default=str)
            
            logger.info("Stored model performance", 
                       model_id=result.model_id,
                       f1_score=result.performance.f1_score)
            
        except Exception as e:
            logger.error("Failed to store model performance", error=str(e))
    
    async def _deploy_model(self, model_type: str):
        """Deploy model to production (update Redis cache)"""
        try:
            if model_type not in self.active_models:
                raise ValueError(f"Model {model_type} not found in active models")
            
            model_info = self.active_models[model_type]
            
            # Serialize model for Redis storage
            model_bytes = joblib.dumps(model_info['model'])
            metadata_json = json.dumps(model_info['metadata'], default=str)
            
            # Store in Redis with deployment flag
            deployment_key = f"ml_triage:deployed_model:{model_type}"
            metadata_key = f"ml_triage:deployed_metadata:{model_type}"
            
            await self.redis.set(deployment_key, model_bytes)
            await self.redis.set(metadata_key, metadata_json)
            
            # Set deployment timestamp
            await self.redis.set(
                f"ml_triage:deployment_time:{model_type}",
                datetime.now(timezone.utc).isoformat()
            )
            
            logger.info("Model deployed to production", model_type=model_type)
            
        except Exception as e:
            logger.error("Model deployment failed", error=str(e))
            raise
    
    def get_training_statistics(self) -> Dict[str, Any]:
        """Get training statistics and history"""
        return {
            'active_models': list(self.active_models.keys()),
            'model_storage_path': str(self.model_storage_path),
            'training_history': self.training_history[-10:],  # Last 10 training runs
            'training_config': self.training_config,
            'model_config': self.model_config
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.elasticsearch:
                await self.elasticsearch.close()
            
            if self.redis:
                await self.redis.close()
                
            logger.info("ModelTrainer cleanup completed")
            
        except Exception as e:
            logger.error("Cleanup failed", error=str(e))


# Example usage and testing
if __name__ == "__main__":
    async def main():
        # Configuration
        config = {
            'training': {
                'batch_size': 1000,
                'validation_split': 0.2,
                'min_training_samples': 100,  # Lower for testing
                'retrain_threshold_days': 7,
                'performance_threshold': 0.75,  # Lower for testing
            },
            'model_storage_path': './models'
        }
        
        # Initialize trainer
        trainer = ModelTrainer(config)
        
        # Mock database configs
        es_config = {'host': 'localhost', 'port': 9200}
        redis_config = {'host': 'localhost', 'port': 6379, 'decode_responses': True}
        
        try:
            await trainer.initialize(es_config, redis_config)
            
            # Train models (will use mock data in production environment)
            results = await trainer.train_models(force_retrain=True)
            
            if results:
                print("Training completed successfully!")
                for model_type, result in results.items():
                    print(f"{model_type}: F1={result.performance.f1_score:.3f}, "
                          f"Accuracy={result.performance.accuracy:.3f}")
            else:
                print("No training performed - insufficient data")
            
        except Exception as e:
            print(f"Training failed: {e}")
        
        finally:
            await trainer.cleanup()
    
    # Run example
    asyncio.run(main())