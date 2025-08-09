"""
ML-Based Alert Triage Engine - Intelligent alert prioritization and risk scoring

Uses advanced machine learning models to automatically triage security alerts,
providing risk scores, priority classifications, and automated response recommendations.
"""

import asyncio
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import structlog

from .feature_extractor import AlertFeatureExtractor
from .risk_scorer import RiskScorer
from .model_trainer import ModelTrainer

logger = structlog.get_logger(__name__)

class TriageDecision(Enum):
    """Triage decision types"""
    ESCALATE = "escalate"
    INVESTIGATE = "investigate"
    MONITOR = "monitor"
    SUPPRESS = "suppress"
    AUTO_RESOLVE = "auto_resolve"

class ConfidenceLevel(Enum):
    """Confidence levels for triage decisions"""
    VERY_HIGH = "very_high"  # >95%
    HIGH = "high"           # 85-95%
    MEDIUM = "medium"       # 70-85%
    LOW = "low"            # 50-70%
    VERY_LOW = "very_low"  # <50%

@dataclass
class TriageResult:
    """Result of ML-based alert triage"""
    alert_id: str
    risk_score: float
    confidence_score: float
    confidence_level: ConfidenceLevel
    priority: str
    decision: TriageDecision
    recommended_actions: List[str]
    reasoning: List[str]
    model_predictions: Dict[str, Any]
    feature_importance: Dict[str, float]
    processing_time_ms: float
    timestamp: str

class MLTriageEngine:
    """
    Advanced ML-powered alert triage engine that uses multiple models
    and sophisticated feature engineering to intelligently prioritize
    security alerts and recommend appropriate responses.
    
    Features:
    - Multi-model ensemble approach
    - Real-time feature extraction
    - Contextual risk scoring
    - Automated response recommendations
    - Explainable AI with feature importance
    - Continuous learning and model updates
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Model configuration
        self.model_path = Path(config.get('model_path', '/app/models'))
        self.model_version = config.get('model_version', '1.0.0')
        self.ensemble_weights = config.get('ensemble_weights', {
            'random_forest': 0.4,
            'gradient_boosting': 0.3,
            'logistic_regression': 0.3
        })
        
        # Processing configuration
        self.confidence_threshold = config.get('confidence_threshold', 0.8)
        self.feature_cache_ttl = config.get('feature_cache_ttl', 3600)  # 1 hour
        self.batch_size = config.get('batch_size', 100)
        self.max_processing_time = config.get('max_processing_time', 1.0)  # 1 second
        
        # Initialize components
        self.feature_extractor = AlertFeatureExtractor(config.get('feature_extraction', {}))
        self.risk_scorer = RiskScorer(config.get('risk_scoring', {}))
        self.model_trainer = ModelTrainer(config.get('model_training', {}))
        
        # ML models
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.feature_names = []
        
        # Performance tracking
        self.performance_metrics = {
            'total_processed': 0,
            'average_processing_time': 0.0,
            'accuracy_score': 0.0,
            'false_positive_rate': 0.0,
            'model_confidence_distribution': {},
            'decision_distribution': {}
        }
        
        # Feature cache for performance
        self.feature_cache = {}
        self.cache_timestamps = {}
        
        logger.info("MLTriageEngine initialized",
                   model_version=self.model_version,
                   ensemble_weights=self.ensemble_weights,
                   confidence_threshold=self.confidence_threshold)
    
    async def initialize(self):
        """Initialize ML models and components"""
        try:
            # Create model directory if it doesn't exist
            self.model_path.mkdir(parents=True, exist_ok=True)
            
            # Initialize components
            await self.feature_extractor.initialize()
            await self.risk_scorer.initialize()
            
            # Load or train models
            await self._load_models()
            
            # Validate model performance
            await self._validate_models()
            
            logger.info("ML Triage Engine initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize ML Triage Engine", error=str(e))
            raise
    
    async def triage_alert(self, enriched_alert: Dict[str, Any]) -> TriageResult:
        """
        Perform ML-based triage on an enriched alert
        
        Args:
            enriched_alert: Alert with enrichment data
            
        Returns:
            TriageResult with risk score and recommendations
        """
        start_time = datetime.now(timezone.utc)
        alert_id = enriched_alert.get('alert_id', 'unknown')
        
        try:
            # Extract features
            features = await self.feature_extractor.extract_features(enriched_alert)
            
            # Calculate risk score
            risk_assessment = await self.risk_scorer.calculate_risk_score(
                enriched_alert, features
            )
            
            # Prepare feature vector for ML models
            feature_vector = self._prepare_feature_vector(features)
            
            # Get predictions from ensemble
            model_predictions = await self._predict_ensemble(feature_vector)
            
            # Calculate final risk score and confidence
            final_risk_score = self._calculate_final_risk_score(
                risk_assessment, model_predictions
            )
            
            confidence_score = self._calculate_confidence_score(model_predictions)
            confidence_level = self._determine_confidence_level(confidence_score)
            
            # Make triage decision
            priority = self._determine_priority(final_risk_score, confidence_score)
            decision = self._make_triage_decision(
                final_risk_score, confidence_score, enriched_alert
            )
            
            # Generate recommendations
            recommended_actions = self._generate_recommendations(
                decision, final_risk_score, enriched_alert
            )
            
            # Generate reasoning
            reasoning = self._generate_reasoning(
                final_risk_score, model_predictions, features, enriched_alert
            )
            
            # Calculate feature importance
            feature_importance = self._calculate_feature_importance(
                features, model_predictions
            )
            
            # Calculate processing time
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            # Create triage result
            triage_result = TriageResult(
                alert_id=alert_id,
                risk_score=final_risk_score,
                confidence_score=confidence_score,
                confidence_level=confidence_level,
                priority=priority,
                decision=decision,
                recommended_actions=recommended_actions,
                reasoning=reasoning,
                model_predictions=model_predictions,
                feature_importance=feature_importance,
                processing_time_ms=processing_time,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            
            # Update performance metrics
            self._update_performance_metrics(triage_result)
            
            logger.debug("Alert triage completed",
                        alert_id=alert_id,
                        risk_score=final_risk_score,
                        confidence=confidence_score,
                        decision=decision.value,
                        processing_time_ms=processing_time)
            
            return triage_result
            
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            logger.error("Alert triage failed",
                        alert_id=alert_id,
                        processing_time_ms=processing_time,
                        error=str(e))
            
            # Return default triage result on failure
            return TriageResult(
                alert_id=alert_id,
                risk_score=0.5,  # Default medium risk
                confidence_score=0.0,
                confidence_level=ConfidenceLevel.VERY_LOW,
                priority="medium",
                decision=TriageDecision.INVESTIGATE,
                recommended_actions=["manual_review"],
                reasoning=["Triage system error - manual review required"],
                model_predictions={},
                feature_importance={},
                processing_time_ms=processing_time,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
    
    async def batch_triage_alerts(self, enriched_alerts: List[Dict[str, Any]]) -> List[TriageResult]:
        """Triage multiple alerts in batch for improved performance"""
        try:
            # Process alerts in parallel batches
            batch_size = min(self.batch_size, len(enriched_alerts))
            results = []
            
            for i in range(0, len(enriched_alerts), batch_size):
                batch = enriched_alerts[i:i + batch_size]
                
                # Process batch in parallel
                batch_tasks = [
                    self.triage_alert(alert) for alert in batch
                ]
                
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                # Handle any exceptions
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error("Batch triage error", error=str(result))
                        # Create default result for failed alerts
                        result = TriageResult(
                            alert_id="unknown",
                            risk_score=0.5,
                            confidence_score=0.0,
                            confidence_level=ConfidenceLevel.VERY_LOW,
                            priority="medium",
                            decision=TriageDecision.INVESTIGATE,
                            recommended_actions=["manual_review"],
                            reasoning=["Batch processing error"],
                            model_predictions={},
                            feature_importance={},
                            processing_time_ms=0.0,
                            timestamp=datetime.now(timezone.utc).isoformat()
                        )
                    results.append(result)
            
            logger.info("Batch alert triage completed",
                       total_alerts=len(enriched_alerts),
                       successful=len([r for r in results if r.confidence_score > 0]))
            
            return results
            
        except Exception as e:
            logger.error("Batch alert triage failed", error=str(e))
            raise
    
    async def _load_models(self):
        """Load ML models from disk or train new ones"""
        model_files = {
            'random_forest': self.model_path / 'random_forest_model.pkl',
            'gradient_boosting': self.model_path / 'gradient_boosting_model.pkl',
            'logistic_regression': self.model_path / 'logistic_regression_model.pkl'
        }
        
        scaler_file = self.model_path / 'feature_scaler.pkl'
        encoder_file = self.model_path / 'label_encoder.pkl'
        features_file = self.model_path / 'feature_names.pkl'
        
        try:
            # Load existing models
            if all(path.exists() for path in model_files.values()):
                for name, path in model_files.items():
                    self.models[name] = joblib.load(path)
                    logger.info(f"Loaded {name} model", path=str(path))
                
                # Load scalers and encoders
                if scaler_file.exists():
                    self.scalers['standard'] = joblib.load(scaler_file)
                if encoder_file.exists():
                    self.label_encoders['priority'] = joblib.load(encoder_file)
                if features_file.exists():
                    self.feature_names = joblib.load(features_file)
                
                logger.info("All models loaded successfully")
            else:
                # Train new models
                logger.info("Training new ML models")
                await self._train_initial_models()
                
        except Exception as e:
            logger.error("Failed to load models", error=str(e))
            # Train new models as fallback
            await self._train_initial_models()
    
    async def _train_initial_models(self):
        """Train initial ML models with synthetic data"""
        try:
            # Generate synthetic training data for initial models
            training_data = await self._generate_synthetic_training_data()
            
            # Prepare features and labels
            X, y = self._prepare_training_data(training_data)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train feature scaler
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Train models
            models_config = {
                'random_forest': RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                ),
                'gradient_boosting': GradientBoostingClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    random_state=42
                ),
                'logistic_regression': LogisticRegression(
                    random_state=42,
                    max_iter=1000,
                    n_jobs=-1
                )
            }
            
            for name, model in models_config.items():
                logger.info(f"Training {name} model")
                model.fit(X_train_scaled, y_train)
                
                # Evaluate model
                y_pred = model.predict(X_test_scaled)
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, average='weighted')
                recall = recall_score(y_test, y_pred, average='weighted')
                f1 = f1_score(y_test, y_pred, average='weighted')
                
                logger.info(f"{name} model performance",
                           accuracy=accuracy,
                           precision=precision,
                           recall=recall,
                           f1=f1)
                
                # Store model
                self.models[name] = model
                
                # Save model to disk
                model_path = self.model_path / f'{name}_model.pkl'
                joblib.dump(model, model_path)
            
            # Store scaler and other components
            self.scalers['standard'] = scaler
            joblib.dump(scaler, self.model_path / 'feature_scaler.pkl')
            
            # Save feature names
            joblib.dump(self.feature_names, self.model_path / 'feature_names.pkl')
            
            logger.info("Initial model training completed")
            
        except Exception as e:
            logger.error("Failed to train initial models", error=str(e))
            raise
    
    async def _generate_synthetic_training_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data for initial model training"""
        # This is a simplified version - in production you would use real historical data
        synthetic_data = []
        
        # Generate diverse alert scenarios
        scenarios = [
            {'severity': 'critical', 'category': 'malware', 'priority': 'critical'},
            {'severity': 'high', 'category': 'intrusion', 'priority': 'high'},
            {'severity': 'medium', 'category': 'policy_violation', 'priority': 'medium'},
            {'severity': 'low', 'category': 'system_anomaly', 'priority': 'low'},
            {'severity': 'high', 'category': 'data_exfiltration', 'priority': 'critical'},
            {'severity': 'medium', 'category': 'brute_force', 'priority': 'high'}
        ]
        
        import random
        np.random.seed(42)
        random.seed(42)
        
        for _ in range(10000):  # Generate 10,000 synthetic alerts
            scenario = random.choice(scenarios)
            
            # Create synthetic alert data
            alert_data = {
                'alert_id': f"synthetic_{_}",
                'severity': scenario['severity'],
                'category': scenario['category'],
                'priority': scenario['priority'],
                
                # Synthetic features
                'threat_score': np.random.uniform(0, 1),
                'asset_criticality': np.random.uniform(0, 1),
                'user_risk_score': np.random.uniform(0, 1),
                'network_anomaly_score': np.random.uniform(0, 1),
                'time_since_last_alert': np.random.exponential(3600),
                'alert_frequency': np.random.poisson(5),
                'is_external_source': random.choice([True, False]),
                'is_after_hours': random.choice([True, False]),
                'has_mitre_mapping': random.choice([True, False]),
                
                # Enrichment indicators
                'has_threat_intel': random.choice([True, False]),
                'has_geolocation': random.choice([True, False]),
                'has_asset_context': random.choice([True, False]),
                'has_user_context': random.choice([True, False])
            }
            
            synthetic_data.append(alert_data)
        
        return synthetic_data
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models"""
        # Extract features
        features_list = []
        labels = []
        
        for alert in training_data:
            # Create feature vector
            feature_vector = [
                alert.get('threat_score', 0),
                alert.get('asset_criticality', 0),
                alert.get('user_risk_score', 0),
                alert.get('network_anomaly_score', 0),
                alert.get('time_since_last_alert', 0) / 3600,  # Normalize to hours
                alert.get('alert_frequency', 0),
                1 if alert.get('is_external_source') else 0,
                1 if alert.get('is_after_hours') else 0,
                1 if alert.get('has_mitre_mapping') else 0,
                1 if alert.get('has_threat_intel') else 0,
                1 if alert.get('has_geolocation') else 0,
                1 if alert.get('has_asset_context') else 0,
                1 if alert.get('has_user_context') else 0,
                
                # Severity encoding
                {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}.get(alert.get('severity', 'medium'), 2)
            ]
            
            features_list.append(feature_vector)
            
            # Extract label (priority)
            priority_mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
            labels.append(priority_mapping.get(alert.get('priority', 'medium'), 2))
        
        # Store feature names for later use
        self.feature_names = [
            'threat_score', 'asset_criticality', 'user_risk_score',
            'network_anomaly_score', 'time_since_last_alert', 'alert_frequency',
            'is_external_source', 'is_after_hours', 'has_mitre_mapping',
            'has_threat_intel', 'has_geolocation', 'has_asset_context',
            'has_user_context', 'severity_encoded'
        ]
        
        return np.array(features_list), np.array(labels)
    
    def _prepare_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Prepare feature vector for ML prediction"""
        # Create feature vector matching training data structure
        feature_vector = [
            features.get('threat_score', 0),
            features.get('asset_criticality', 0),
            features.get('user_risk_score', 0),
            features.get('network_anomaly_score', 0),
            features.get('time_since_last_alert', 0) / 3600,
            features.get('alert_frequency', 0),
            1 if features.get('is_external_source') else 0,
            1 if features.get('is_after_hours') else 0,
            1 if features.get('has_mitre_mapping') else 0,
            1 if features.get('has_threat_intel') else 0,
            1 if features.get('has_geolocation') else 0,
            1 if features.get('has_asset_context') else 0,
            1 if features.get('has_user_context') else 0,
            features.get('severity_encoded', 2)
        ]
        
        return np.array(feature_vector).reshape(1, -1)
    
    async def _predict_ensemble(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """Get predictions from ensemble of models"""
        try:
            # Scale features
            if 'standard' in self.scalers:
                feature_vector_scaled = self.scalers['standard'].transform(feature_vector)
            else:
                feature_vector_scaled = feature_vector
            
            predictions = {}
            
            # Get predictions from each model
            for name, model in self.models.items():
                try:
                    # Get prediction and probability
                    pred_class = model.predict(feature_vector_scaled)[0]
                    pred_proba = model.predict_proba(feature_vector_scaled)[0]
                    
                    predictions[name] = {
                        'class': pred_class,
                        'probability': pred_proba.tolist(),
                        'confidence': max(pred_proba)
                    }
                    
                    # Add feature importance for tree-based models
                    if hasattr(model, 'feature_importances_'):
                        predictions[name]['feature_importance'] = model.feature_importances_.tolist()
                    
                except Exception as e:
                    logger.warning(f"Prediction failed for {name}", error=str(e))
                    predictions[name] = {
                        'class': 2,  # Default to medium priority
                        'probability': [0.0, 0.0, 1.0, 0.0, 0.0],
                        'confidence': 0.0
                    }
            
            return predictions
            
        except Exception as e:
            logger.error("Ensemble prediction failed", error=str(e))
            return {}
    
    def _calculate_final_risk_score(
        self, 
        risk_assessment: Dict[str, Any], 
        model_predictions: Dict[str, Any]
    ) -> float:
        """Calculate final risk score combining risk assessment and ML predictions"""
        try:
            # Base risk score from risk assessment
            base_risk = risk_assessment.get('composite_score', 0.5)
            
            # ML ensemble score
            ml_scores = []
            total_weight = 0
            
            for model_name, prediction in model_predictions.items():
                if model_name in self.ensemble_weights:
                    weight = self.ensemble_weights[model_name]
                    # Convert class prediction to risk score (0-1 scale)
                    class_prediction = prediction.get('class', 2)
                    risk_score = class_prediction / 4.0  # Normalize 0-4 to 0-1
                    
                    ml_scores.append(risk_score * weight)
                    total_weight += weight
            
            # Calculate weighted ML score
            ml_risk = sum(ml_scores) / max(total_weight, 1)
            
            # Combine base risk and ML risk (70% ML, 30% base risk)
            final_risk = (ml_risk * 0.7) + (base_risk * 0.3)
            
            return min(1.0, max(0.0, final_risk))
            
        except Exception as e:
            logger.error("Risk score calculation failed", error=str(e))
            return 0.5  # Default medium risk
    
    def _calculate_confidence_score(self, model_predictions: Dict[str, Any]) -> float:
        """Calculate confidence score from model predictions"""
        try:
            confidences = []
            weights = []
            
            for model_name, prediction in model_predictions.items():
                if model_name in self.ensemble_weights:
                    confidence = prediction.get('confidence', 0.0)
                    weight = self.ensemble_weights[model_name]
                    
                    confidences.append(confidence * weight)
                    weights.append(weight)
            
            if not confidences:
                return 0.0
            
            # Calculate weighted average confidence
            weighted_confidence = sum(confidences) / max(sum(weights), 1)
            
            return min(1.0, max(0.0, weighted_confidence))
            
        except Exception as e:
            logger.error("Confidence calculation failed", error=str(e))
            return 0.0
    
    def _determine_confidence_level(self, confidence_score: float) -> ConfidenceLevel:
        """Determine confidence level from confidence score"""
        if confidence_score >= 0.95:
            return ConfidenceLevel.VERY_HIGH
        elif confidence_score >= 0.85:
            return ConfidenceLevel.HIGH
        elif confidence_score >= 0.70:
            return ConfidenceLevel.MEDIUM
        elif confidence_score >= 0.50:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _determine_priority(self, risk_score: float, confidence_score: float) -> str:
        """Determine alert priority based on risk score and confidence"""
        # Adjust priority based on confidence
        adjusted_risk = risk_score * confidence_score
        
        if adjusted_risk >= 0.8:
            return "critical"
        elif adjusted_risk >= 0.6:
            return "high"
        elif adjusted_risk >= 0.4:
            return "medium"
        elif adjusted_risk >= 0.2:
            return "low"
        else:
            return "informational"
    
    def _make_triage_decision(
        self, 
        risk_score: float, 
        confidence_score: float,
        enriched_alert: Dict[str, Any]
    ) -> TriageDecision:
        """Make triage decision based on risk score and context"""
        # High confidence decisions
        if confidence_score >= self.confidence_threshold:
            if risk_score >= 0.8:
                return TriageDecision.ESCALATE
            elif risk_score >= 0.5:
                return TriageDecision.INVESTIGATE
            elif risk_score >= 0.2:
                return TriageDecision.MONITOR
            else:
                return TriageDecision.AUTO_RESOLVE
        
        # Low confidence decisions - default to investigation
        else:
            if risk_score >= 0.7:
                return TriageDecision.ESCALATE
            else:
                return TriageDecision.INVESTIGATE
    
    def _generate_recommendations(
        self, 
        decision: TriageDecision,
        risk_score: float,
        enriched_alert: Dict[str, Any]
    ) -> List[str]:
        """Generate automated response recommendations"""
        recommendations = []
        
        if decision == TriageDecision.ESCALATE:
            recommendations.extend([
                "immediate_analyst_review",
                "create_high_priority_ticket", 
                "notify_security_team",
                "isolate_affected_systems",
                "collect_additional_evidence"
            ])
        
        elif decision == TriageDecision.INVESTIGATE:
            recommendations.extend([
                "assign_to_analyst",
                "create_investigation_ticket",
                "gather_context_data",
                "check_related_alerts",
                "review_asset_information"
            ])
        
        elif decision == TriageDecision.MONITOR:
            recommendations.extend([
                "add_to_watch_list",
                "schedule_follow_up",
                "track_patterns",
                "set_monitoring_rules"
            ])
        
        elif decision == TriageDecision.SUPPRESS:
            recommendations.extend([
                "add_to_suppression_rules",
                "document_false_positive",
                "update_detection_logic"
            ])
        
        elif decision == TriageDecision.AUTO_RESOLVE:
            recommendations.extend([
                "automatic_resolution",
                "update_knowledge_base",
                "apply_automated_remediation"
            ])
        
        # Add contextual recommendations
        if enriched_alert.get('severity') == 'critical':
            recommendations.append("executive_notification")
        
        if 'malware' in enriched_alert.get('category', '').lower():
            recommendations.append("malware_analysis")
        
        if enriched_alert.get('source_ip') and enriched_alert.get('enrichments', {}).get('threat_intelligence', {}).get('is_malicious'):
            recommendations.append("block_ip_address")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _generate_reasoning(
        self,
        risk_score: float,
        model_predictions: Dict[str, Any],
        features: Dict[str, Any],
        enriched_alert: Dict[str, Any]
    ) -> List[str]:
        """Generate human-readable reasoning for the triage decision"""
        reasoning = []
        
        # Risk score reasoning
        if risk_score >= 0.8:
            reasoning.append(f"High risk score ({risk_score:.2f}) indicates critical threat")
        elif risk_score >= 0.5:
            reasoning.append(f"Moderate risk score ({risk_score:.2f}) requires investigation")
        else:
            reasoning.append(f"Low risk score ({risk_score:.2f}) suggests limited threat")
        
        # Model consensus reasoning
        high_confidence_models = sum(1 for pred in model_predictions.values() 
                                   if pred.get('confidence', 0) > 0.8)
        if high_confidence_models >= 2:
            reasoning.append(f"{high_confidence_models} models show high confidence")
        
        # Feature-based reasoning
        if features.get('threat_score', 0) > 0.7:
            reasoning.append("Strong threat intelligence indicators")
        
        if features.get('asset_criticality', 0) > 0.8:
            reasoning.append("Alert affects critical business assets")
        
        if features.get('user_risk_score', 0) > 0.7:
            reasoning.append("High-risk user involved in alert")
        
        if features.get('is_external_source'):
            reasoning.append("External source increases risk profile")
        
        if features.get('is_after_hours'):
            reasoning.append("After-hours activity is suspicious")
        
        # Alert context reasoning
        severity = enriched_alert.get('severity', '').lower()
        if severity in ['critical', 'high']:
            reasoning.append(f"Original severity ({severity}) supports escalation")
        
        category = enriched_alert.get('category', '').lower()
        if 'malware' in category or 'ransomware' in category:
            reasoning.append("Malware category requires immediate attention")
        
        return reasoning
    
    def _calculate_feature_importance(
        self,
        features: Dict[str, Any],
        model_predictions: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate feature importance for explainability"""
        try:
            importance_scores = {}
            
            # Get feature importance from tree-based models
            for model_name, prediction in model_predictions.items():
                if 'feature_importance' in prediction:
                    importances = prediction['feature_importance']
                    weight = self.ensemble_weights.get(model_name, 0)
                    
                    for i, importance in enumerate(importances):
                        if i < len(self.feature_names):
                            feature_name = self.feature_names[i]
                            importance_scores[feature_name] = importance_scores.get(feature_name, 0) + (importance * weight)
            
            # Normalize importance scores
            if importance_scores:
                max_importance = max(importance_scores.values())
                if max_importance > 0:
                    importance_scores = {k: v / max_importance for k, v in importance_scores.items()}
            
            return importance_scores
            
        except Exception as e:
            logger.error("Feature importance calculation failed", error=str(e))
            return {}
    
    def _update_performance_metrics(self, triage_result: TriageResult):
        """Update performance tracking metrics"""
        try:
            self.performance_metrics['total_processed'] += 1
            
            # Update average processing time
            current_avg = self.performance_metrics['average_processing_time']
            total_processed = self.performance_metrics['total_processed']
            new_avg = ((current_avg * (total_processed - 1)) + triage_result.processing_time_ms) / total_processed
            self.performance_metrics['average_processing_time'] = new_avg
            
            # Update confidence distribution
            confidence_level = triage_result.confidence_level.value
            confidence_dist = self.performance_metrics['confidence_distribution']
            confidence_dist[confidence_level] = confidence_dist.get(confidence_level, 0) + 1
            
            # Update decision distribution
            decision = triage_result.decision.value
            decision_dist = self.performance_metrics['decision_distribution']
            decision_dist[decision] = decision_dist.get(decision, 0) + 1
            
        except Exception as e:
            logger.error("Performance metrics update failed", error=str(e))
    
    async def _validate_models(self):
        """Validate loaded models with test data"""
        try:
            # Generate small validation dataset
            validation_data = await self._generate_synthetic_training_data()
            validation_data = validation_data[:100]  # Small sample
            
            X_val, y_val = self._prepare_training_data(validation_data)
            
            if 'standard' in self.scalers:
                X_val_scaled = self.scalers['standard'].transform(X_val)
            else:
                X_val_scaled = X_val
            
            # Validate each model
            total_accuracy = 0
            valid_models = 0
            
            for name, model in self.models.items():
                try:
                    y_pred = model.predict(X_val_scaled)
                    accuracy = accuracy_score(y_val, y_pred)
                    total_accuracy += accuracy
                    valid_models += 1
                    
                    logger.info(f"Model validation: {name}",
                               accuracy=accuracy)
                    
                except Exception as e:
                    logger.warning(f"Model validation failed: {name}", error=str(e))
            
            if valid_models > 0:
                avg_accuracy = total_accuracy / valid_models
                self.performance_metrics['accuracy_score'] = avg_accuracy
                logger.info("Model validation completed",
                           average_accuracy=avg_accuracy,
                           valid_models=valid_models)
            else:
                logger.warning("No models passed validation")
                
        except Exception as e:
            logger.error("Model validation failed", error=str(e))
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return self.performance_metrics.copy()
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models"""
        return {
            'model_version': self.model_version,
            'loaded_models': list(self.models.keys()),
            'ensemble_weights': self.ensemble_weights,
            'feature_count': len(self.feature_names),
            'confidence_threshold': self.confidence_threshold
        }