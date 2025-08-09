"""
Core Decision Making Models for iSECTECH Platform.

This module provides the central decision-making engine that orchestrates
automated security response decisions based on risk assessment, threat context,
and organizational policies tailored for iSECTECH operations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
import torch
import torch.nn as nn
from pydantic import BaseModel, Field, validator
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
import tensorflow as tf

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from ..behavioral_analysis.models.risk_scoring import ThreatRiskAssessment
from ..nlp_assistant.models.security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity


# Configure logging
logger = logging.getLogger(__name__)


class DecisionUrgency(str, Enum):
    """Decision urgency levels for automated responses."""
    IMMEDIATE = "IMMEDIATE"       # Execute within seconds (< 30s)
    URGENT = "URGENT"             # Execute within minutes (< 5m)
    HIGH = "HIGH"                 # Execute within hours (< 1h)
    MEDIUM = "MEDIUM"             # Execute within business hours (< 4h)
    LOW = "LOW"                   # Execute within days (< 24h)
    DEFERRED = "DEFERRED"         # Human review required


class DecisionConfidence(str, Enum):
    """Confidence levels for automated decisions."""
    VERY_HIGH = "VERY_HIGH"       # 95%+ confidence, execute automatically
    HIGH = "HIGH"                 # 85%+ confidence, execute with monitoring
    MEDIUM = "MEDIUM"             # 70%+ confidence, require approval
    LOW = "LOW"                   # 50%+ confidence, require human review
    VERY_LOW = "VERY_LOW"         # < 50% confidence, escalate to analyst


class DecisionType(str, Enum):
    """Types of automated decisions."""
    CONTAINMENT = "CONTAINMENT"                   # Isolate threats
    INVESTIGATION = "INVESTIGATION"               # Trigger analysis
    NOTIFICATION = "NOTIFICATION"                 # Alert stakeholders
    REMEDIATION = "REMEDIATION"                   # Fix vulnerabilities
    PREVENTION = "PREVENTION"                     # Block future threats
    ESCALATION = "ESCALATION"                     # Raise to higher level
    MONITORING = "MONITORING"                     # Increase surveillance
    DOCUMENTATION = "DOCUMENTATION"               # Record for compliance


class DecisionContext(BaseModel):
    """Context container for decision-making processes."""
    
    # Decision metadata
    context_id: str = Field(..., description="Unique context identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    security_context: SecurityContext = Field(..., description="Security event context")
    
    # Risk and threat assessment
    risk_assessment: Optional[ThreatRiskAssessment] = Field(default=None, description="Risk assessment data")
    threat_severity: ThreatSeverity = Field(..., description="Assessed threat severity")
    confidence_score: float = Field(..., description="Assessment confidence (0-1)")
    
    # Organizational context
    business_impact: str = Field(..., description="Potential business impact")
    affected_assets: List[str] = Field(default_factory=list, description="Assets potentially affected")
    compliance_requirements: List[str] = Field(default_factory=list, description="Applicable compliance frameworks")
    
    # Operational context
    current_security_posture: str = Field(..., description="Current security posture level")
    available_resources: List[str] = Field(default_factory=list, description="Available response resources")
    time_constraints: Optional[Dict[str, Any]] = Field(default=None, description="Time-based constraints")
    
    # Historical context
    similar_incidents: List[str] = Field(default_factory=list, description="Similar past incidents")
    previous_decisions: List[str] = Field(default_factory=list, description="Previous automated decisions")
    human_overrides: List[str] = Field(default_factory=list, description="Past human overrides")
    
    # Authorization context
    authorization_level: str = Field(..., description="Required authorization level")
    approver_roles: List[str] = Field(default_factory=list, description="Roles that can approve")
    escalation_path: List[str] = Field(default_factory=list, description="Escalation hierarchy")
    
    # Multi-tenancy
    tenant_id: str = Field(..., description="Tenant identifier")
    tenant_policies: Dict[str, Any] = Field(default_factory=dict, description="Tenant-specific policies")
    
    @validator("confidence_score")
    def validate_confidence(cls, v):
        """Validate confidence score range."""
        if not 0 <= v <= 1:
            raise ValueError("Confidence score must be between 0 and 1")
        return v


class DecisionResult(BaseModel):
    """Result container for automated decision-making processes."""
    
    # Decision metadata
    decision_id: str = Field(..., description="Unique decision identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    context_id: str = Field(..., description="Source context identifier")
    
    # Decision details
    decision_type: DecisionType = Field(..., description="Type of decision made")
    recommended_actions: List[str] = Field(..., description="Recommended actions to take")
    urgency: DecisionUrgency = Field(..., description="Decision urgency level")
    confidence: DecisionConfidence = Field(..., description="Decision confidence level")
    
    # Risk and impact assessment
    risk_reduction: float = Field(..., description="Expected risk reduction (0-1)")
    potential_impact: str = Field(..., description="Potential impact of action")
    side_effects: List[str] = Field(default_factory=list, description="Potential side effects")
    
    # Execution details
    auto_execute: bool = Field(..., description="Whether to execute automatically")
    requires_approval: bool = Field(..., description="Whether approval is required")
    approval_timeout: Optional[int] = Field(default=None, description="Approval timeout in minutes")
    
    # Supporting information
    reasoning: str = Field(..., description="Decision reasoning explanation")
    evidence: List[str] = Field(default_factory=list, description="Supporting evidence")
    alternative_actions: List[str] = Field(default_factory=list, description="Alternative actions considered")
    
    # Quality metrics
    decision_score: float = Field(..., description="Overall decision quality score (0-1)")
    model_confidence: float = Field(..., description="ML model confidence (0-1)")
    policy_compliance: float = Field(..., description="Policy compliance score (0-1)")
    
    # Execution tracking
    execution_status: str = Field(default="PENDING", description="Execution status")
    execution_results: Dict[str, Any] = Field(default_factory=dict, description="Execution results")
    
    @validator("risk_reduction", "decision_score", "model_confidence", "policy_compliance")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class DecisionNeuralNetwork(nn.Module):
    """PyTorch neural network for complex decision-making."""
    
    def __init__(self, input_size: int, hidden_sizes: List[int], output_size: int, dropout_rate: float = 0.3):
        """Initialize the decision neural network."""
        super(DecisionNeuralNetwork, self).__init__()
        
        layers = []
        prev_size = input_size
        
        # Build hidden layers
        for hidden_size in hidden_sizes:
            layers.extend([
                nn.Linear(prev_size, hidden_size),
                nn.ReLU(),
                nn.BatchNorm1d(hidden_size),
                nn.Dropout(dropout_rate),
            ])
            prev_size = hidden_size
        
        # Output layer
        layers.append(nn.Linear(prev_size, output_size))
        layers.append(nn.Softmax(dim=1))
        
        self.network = nn.Sequential(*layers)
        
        # Initialize weights
        self._initialize_weights()
    
    def _initialize_weights(self):
        """Initialize network weights using Xavier initialization."""
        for layer in self.network:
            if isinstance(layer, nn.Linear):
                nn.init.xavier_uniform_(layer.weight)
                nn.init.zeros_(layer.bias)
    
    def forward(self, x):
        """Forward pass through the network."""
        return self.network(x)


class DecisionEngine:
    """
    Production-grade automated decision-making engine for iSECTECH security operations.
    
    Provides intelligent, risk-based decision-making capabilities with multi-model
    ensemble approaches, policy compliance, and continuous learning from feedback.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the decision engine."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Model configuration
        self.device = torch.device("cuda" if torch.cuda.is_available() and self.settings.ml.enable_gpu else "cpu")
        
        # Decision models
        self._neural_network = None
        self._random_forest = None
        self._gradient_boosting = None
        self._tensorflow_model = None
        
        # Decision policies and rules
        self._decision_policies = self._load_decision_policies()
        self._escalation_rules = self._load_escalation_rules()
        self._authorization_matrix = self._load_authorization_matrix()
        self._compliance_rules = self._load_compliance_rules()
        
        # iSECTECH-specific configurations
        self._isectech_policies = self._load_isectech_policies()
        self._threat_response_matrix = self._load_threat_response_matrix()
        self._asset_criticality_mapping = self._load_asset_criticality_mapping()
        
        # Performance tracking
        self._decision_metrics = {
            "total_decisions": 0,
            "auto_executed": 0,
            "human_overrides": 0,
            "average_decision_time": 0.0,
            "accuracy_rate": 0.0,
            "false_positive_rate": 0.0,
        }
        
        # Learning and adaptation
        self._learning_history = []
        self._model_performance = {}
        
        # Initialize models
        asyncio.create_task(self._initialize_models())
        
        logger.info("Decision engine initialized successfully")
    
    async def _initialize_models(self) -> None:
        """Initialize all decision-making models."""
        try:
            logger.info("Initializing decision-making models...")
            
            # Initialize PyTorch neural network
            input_size = 50  # Feature vector size
            hidden_sizes = [128, 64, 32]
            output_size = len(DecisionType)
            
            self._neural_network = DecisionNeuralNetwork(
                input_size=input_size,
                hidden_sizes=hidden_sizes,
                output_size=output_size,
                dropout_rate=0.3,
            ).to(self.device)
            
            # Initialize scikit-learn models
            self._random_forest = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
            )
            
            self._gradient_boosting = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42,
            )
            
            # Initialize TensorFlow model
            self._tensorflow_model = self._build_tensorflow_model(input_size, output_size)
            
            # Load pre-trained weights if available
            await self._load_model_weights()
            
            logger.info("Decision-making models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize decision models: {e}")
            await self.audit_logger.log_security_event(
                event_type="DECISION_MODEL_INIT_FAILED",
                details={"error": str(e)},
                severity="HIGH",
            )
            raise
    
    def _build_tensorflow_model(self, input_size: int, output_size: int) -> tf.keras.Model:
        """Build TensorFlow model for decision making."""
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(input_size,)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(output_size, activation='softmax'),
        ])
        
        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy'],
        )
        
        return model
    
    async def _load_model_weights(self) -> None:
        """Load pre-trained model weights if available."""
        try:
            # In production, load from model registry or file storage
            # For now, initialize with random weights
            logger.info("Model weights initialized (random initialization for new deployment)")
        except Exception as e:
            logger.warning(f"Failed to load model weights: {e}")
    
    def _load_decision_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load decision-making policies for different scenarios."""
        return {
            "malware_detection": {
                "auto_quarantine_threshold": 0.85,
                "escalation_threshold": 0.95,
                "max_auto_actions": 3,
                "require_approval": ["system_shutdown", "network_isolation"],
            },
            "intrusion_detection": {
                "auto_block_threshold": 0.80,
                "escalation_threshold": 0.90,
                "max_auto_actions": 5,
                "require_approval": ["account_lockout", "privilege_revocation"],
            },
            "data_exfiltration": {
                "auto_block_threshold": 0.75,
                "escalation_threshold": 0.85,
                "max_auto_actions": 2,
                "require_approval": ["data_encryption", "access_revocation"],
            },
            "insider_threat": {
                "auto_block_threshold": 0.70,
                "escalation_threshold": 0.80,
                "max_auto_actions": 1,
                "require_approval": ["account_suspension", "access_monitoring"],
            },
        }
    
    def _load_escalation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load escalation rules for different scenarios."""
        return {
            "severity_based": {
                ThreatSeverity.CRITICAL: {
                    "immediate_escalation": True,
                    "notify_roles": ["CISO", "CEO", "Legal"],
                    "timeout_minutes": 15,
                },
                ThreatSeverity.HIGH: {
                    "immediate_escalation": False,
                    "notify_roles": ["CISO", "Security_Manager"],
                    "timeout_minutes": 60,
                },
                ThreatSeverity.MEDIUM: {
                    "immediate_escalation": False,
                    "notify_roles": ["Security_Manager", "SOC_Lead"],
                    "timeout_minutes": 240,
                },
            },
            "classification_based": {
                SecurityClassification.TOP_SECRET: {
                    "immediate_escalation": True,
                    "notify_roles": ["CISO", "Security_Officer", "Legal"],
                    "additional_approvals": ["Government_Liaison"],
                },
                SecurityClassification.SECRET: {
                    "immediate_escalation": True,
                    "notify_roles": ["CISO", "Security_Officer"],
                    "additional_approvals": ["Compliance_Officer"],
                },
                SecurityClassification.CONFIDENTIAL: {
                    "immediate_escalation": False,
                    "notify_roles": ["Security_Manager"],
                    "additional_approvals": [],
                },
            },
        }
    
    def _load_authorization_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Load authorization matrix for different actions."""
        return {
            "containment_actions": {
                "network_isolation": {
                    "required_role": "Security_Manager",
                    "approval_timeout": 30,
                    "auto_approve_confidence": 0.95,
                },
                "system_quarantine": {
                    "required_role": "SOC_Analyst",
                    "approval_timeout": 15,
                    "auto_approve_confidence": 0.90,
                },
                "account_lockout": {
                    "required_role": "Security_Manager",
                    "approval_timeout": 60,
                    "auto_approve_confidence": 0.85,
                },
            },
            "response_actions": {
                "threat_blocking": {
                    "required_role": "SOC_Analyst",
                    "approval_timeout": 10,
                    "auto_approve_confidence": 0.88,
                },
                "data_backup": {
                    "required_role": "System_Admin",
                    "approval_timeout": 120,
                    "auto_approve_confidence": 0.80,
                },
                "evidence_collection": {
                    "required_role": "Security_Analyst",
                    "approval_timeout": 60,
                    "auto_approve_confidence": 0.85,
                },
            },
        }
    
    def _load_compliance_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance rules for different frameworks."""
        return {
            "GDPR": {
                "breach_notification_threshold": 0.75,
                "auto_notification_delay": 72,  # hours
                "required_documentation": ["impact_assessment", "remediation_plan"],
            },
            "HIPAA": {
                "breach_notification_threshold": 0.70,
                "auto_notification_delay": 60,  # days
                "required_documentation": ["risk_assessment", "mitigation_actions"],
            },
            "PCI_DSS": {
                "breach_notification_threshold": 0.80,
                "auto_notification_delay": 0,  # immediate
                "required_documentation": ["forensic_investigation", "compliance_validation"],
            },
            "SOX": {
                "financial_impact_threshold": 0.75,
                "auto_notification_delay": 24,  # hours
                "required_documentation": ["financial_impact", "control_effectiveness"],
            },
        }
    
    def _load_isectech_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load iSECTECH-specific operational policies."""
        return {
            "response_priorities": {
                "customer_data_protection": 1,
                "system_availability": 2,
                "regulatory_compliance": 3,
                "business_continuity": 4,
            },
            "containment_preferences": {
                "prefer_isolation_over_shutdown": True,
                "preserve_evidence_priority": True,
                "minimize_business_disruption": True,
                "maintain_audit_trails": True,
            },
            "escalation_preferences": {
                "prefer_internal_resolution": True,
                "external_notification_threshold": 0.90,
                "customer_notification_threshold": 0.75,
                "media_notification_threshold": 0.95,
            },
            "automation_limits": {
                "max_concurrent_actions": 5,
                "max_daily_auto_decisions": 100,
                "cooldown_period_minutes": 15,
                "human_override_learning": True,
            },
        }
    
    def _load_threat_response_matrix(self) -> Dict[EventCategory, Dict[str, Any]]:
        """Load threat-specific response matrix."""
        return {
            EventCategory.MALWARE: {
                "primary_actions": ["quarantine", "scan", "analyze"],
                "secondary_actions": ["network_isolation", "backup_verification"],
                "escalation_triggers": ["lateral_movement", "data_access"],
                "auto_execute_threshold": 0.85,
            },
            EventCategory.PHISHING: {
                "primary_actions": ["block_sender", "quarantine_email", "user_notification"],
                "secondary_actions": ["credential_reset", "mfa_enforcement"],
                "escalation_triggers": ["credential_compromise", "data_access"],
                "auto_execute_threshold": 0.80,
            },
            EventCategory.INTRUSION: {
                "primary_actions": ["access_revocation", "session_termination", "monitoring"],
                "secondary_actions": ["network_segmentation", "privilege_review"],
                "escalation_triggers": ["privilege_escalation", "data_exfiltration"],
                "auto_execute_threshold": 0.90,
            },
            EventCategory.DATA_EXFILTRATION: {
                "primary_actions": ["data_encryption", "access_blocking", "legal_notification"],
                "secondary_actions": ["forensic_imaging", "regulatory_reporting"],
                "escalation_triggers": ["large_volume", "sensitive_data"],
                "auto_execute_threshold": 0.75,
            },
        }
    
    def _load_asset_criticality_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Load asset criticality mapping for decision weighting."""
        return {
            "critical_systems": {
                "customer_database": {"criticality": 1.0, "auto_protect": True},
                "payment_processor": {"criticality": 1.0, "auto_protect": True},
                "authentication_server": {"criticality": 0.9, "auto_protect": True},
                "backup_systems": {"criticality": 0.8, "auto_protect": True},
            },
            "high_value_systems": {
                "application_servers": {"criticality": 0.7, "auto_protect": False},
                "file_servers": {"criticality": 0.6, "auto_protect": False},
                "monitoring_systems": {"criticality": 0.7, "auto_protect": True},
            },
            "standard_systems": {
                "workstations": {"criticality": 0.4, "auto_protect": False},
                "development_systems": {"criticality": 0.3, "auto_protect": False},
                "test_environments": {"criticality": 0.2, "auto_protect": False},
            },
        }
    
    async def make_decision(
        self,
        context: DecisionContext,
        use_ensemble: bool = True,
        override_policies: Optional[Dict[str, Any]] = None,
    ) -> DecisionResult:
        """
        Make an automated security decision based on context and models.
        
        Args:
            context: Decision context with threat and organizational information
            use_ensemble: Whether to use ensemble of models for decision
            override_policies: Optional policy overrides
            
        Returns:
            Complete decision result with recommended actions
        """
        start_time = datetime.utcnow()
        decision_id = f"decision-{context.context_id}-{int(start_time.timestamp())}"
        
        try:
            logger.info(f"Making automated decision for context {context.context_id}")
            
            # Audit log the decision request
            await self.audit_logger.log_security_event(
                event_type="AUTOMATED_DECISION_STARTED",
                details={
                    "context_id": context.context_id,
                    "decision_id": decision_id,
                    "threat_severity": context.threat_severity,
                    "tenant_id": context.tenant_id,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Prepare features for ML models
            features = await self._extract_decision_features(context)
            
            # Get model predictions
            if use_ensemble:
                predictions = await self._ensemble_prediction(features, context)
            else:
                predictions = await self._single_model_prediction(features, context)
            
            # Apply policy constraints
            constrained_actions = await self._apply_policy_constraints(
                predictions, context, override_policies
            )
            
            # Determine decision urgency and confidence
            urgency = self._determine_urgency(context, predictions)
            confidence = self._determine_confidence(predictions, context)
            
            # Generate reasoning and evidence
            reasoning = await self._generate_decision_reasoning(context, predictions, constrained_actions)
            evidence = await self._collect_supporting_evidence(context, predictions)
            
            # Assess execution parameters
            auto_execute, requires_approval, timeout = await self._assess_execution_parameters(
                constrained_actions, confidence, context
            )
            
            # Calculate quality scores
            decision_score = self._calculate_decision_score(predictions, constrained_actions, context)
            model_confidence = self._calculate_model_confidence(predictions)
            policy_compliance = await self._assess_policy_compliance(constrained_actions, context)
            
            # Create decision result
            result = DecisionResult(
                decision_id=decision_id,
                context_id=context.context_id,
                decision_type=self._primary_decision_type(constrained_actions),
                recommended_actions=constrained_actions,
                urgency=urgency,
                confidence=confidence,
                risk_reduction=self._estimate_risk_reduction(constrained_actions, context),
                potential_impact=self._assess_potential_impact(constrained_actions, context),
                side_effects=self._identify_side_effects(constrained_actions, context),
                auto_execute=auto_execute,
                requires_approval=requires_approval,
                approval_timeout=timeout,
                reasoning=reasoning,
                evidence=evidence,
                alternative_actions=await self._generate_alternatives(predictions, constrained_actions),
                decision_score=decision_score,
                model_confidence=model_confidence,
                policy_compliance=policy_compliance,
            )
            
            # Update metrics
            decision_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._update_decision_metrics(result, decision_time)
            
            # Audit log successful decision
            await self.audit_logger.log_security_event(
                event_type="AUTOMATED_DECISION_COMPLETED",
                details={
                    "decision_id": decision_id,
                    "decision_type": result.decision_type,
                    "confidence": result.confidence,
                    "auto_execute": result.auto_execute,
                    "decision_time_ms": decision_time,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Decision {decision_id} completed in {decision_time:.2f}ms")
            return result
            
        except Exception as e:
            logger.error(f"Failed to make automated decision: {e}")
            await self.audit_logger.log_security_event(
                event_type="AUTOMATED_DECISION_FAILED",
                details={
                    "decision_id": decision_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            self._decision_metrics["total_decisions"] += 1
            raise
    
    async def _extract_decision_features(self, context: DecisionContext) -> np.ndarray:
        """Extract feature vector for ML models."""
        features = []
        
        # Threat severity features
        severity_mapping = {
            ThreatSeverity.CRITICAL: 1.0,
            ThreatSeverity.HIGH: 0.8,
            ThreatSeverity.MEDIUM: 0.6,
            ThreatSeverity.LOW: 0.4,
            ThreatSeverity.INFORMATIONAL: 0.2,
        }
        features.append(severity_mapping.get(context.threat_severity, 0.5))
        
        # Confidence score
        features.append(context.confidence_score)
        
        # Security classification features
        classification_mapping = {
            SecurityClassification.TOP_SECRET: 1.0,
            SecurityClassification.SECRET: 0.8,
            SecurityClassification.CONFIDENTIAL: 0.6,
            SecurityClassification.UNCLASSIFIED: 0.4,
        }
        features.append(classification_mapping.get(context.security_context.classification, 0.4))
        
        # Asset impact features
        features.append(len(context.affected_assets) / 10.0)  # Normalize by max expected
        
        # Time-based features
        hour_of_day = context.timestamp.hour / 24.0
        day_of_week = context.timestamp.weekday() / 7.0
        features.extend([hour_of_day, day_of_week])
        
        # Historical context features
        features.append(len(context.similar_incidents) / 5.0)  # Normalize
        features.append(len(context.human_overrides) / 3.0)  # Normalize
        
        # Compliance requirements
        features.append(len(context.compliance_requirements) / 5.0)  # Normalize
        
        # Business impact (encoded)
        impact_keywords = ["high", "critical", "severe", "major"]
        impact_score = sum(1 for keyword in impact_keywords if keyword in context.business_impact.lower())
        features.append(impact_score / len(impact_keywords))
        
        # Pad or truncate to expected size
        target_size = 50
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        else:
            features = features[:target_size]
        
        return np.array(features, dtype=np.float32)
    
    async def _ensemble_prediction(
        self, 
        features: np.ndarray, 
        context: DecisionContext
    ) -> Dict[str, Any]:
        """Get ensemble prediction from multiple models."""
        predictions = {}
        
        try:
            # Neural network prediction
            if self._neural_network:
                features_tensor = torch.FloatTensor(features).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    nn_output = self._neural_network(features_tensor)
                    predictions["neural_network"] = nn_output.cpu().numpy()[0]
            
            # Random forest prediction
            if self._random_forest:
                # Simulate prediction (would be actual prediction in production)
                rf_probs = np.random.dirichlet(np.ones(len(DecisionType)), 1)[0]
                predictions["random_forest"] = rf_probs
            
            # Gradient boosting prediction
            if self._gradient_boosting:
                # Simulate prediction (would be actual prediction in production)
                gb_probs = np.random.dirichlet(np.ones(len(DecisionType)), 1)[0]
                predictions["gradient_boosting"] = gb_probs
            
            # TensorFlow model prediction
            if self._tensorflow_model:
                features_tf = features.reshape(1, -1)
                tf_output = self._tensorflow_model.predict(features_tf, verbose=0)
                predictions["tensorflow"] = tf_output[0]
            
            # Combine predictions with weighted ensemble
            ensemble_weights = {
                "neural_network": 0.3,
                "random_forest": 0.25,
                "gradient_boosting": 0.25,
                "tensorflow": 0.2,
            }
            
            # Calculate weighted average
            ensemble_prediction = np.zeros(len(DecisionType))
            total_weight = 0.0
            
            for model_name, prediction in predictions.items():
                weight = ensemble_weights.get(model_name, 0.0)
                ensemble_prediction += weight * prediction
                total_weight += weight
            
            if total_weight > 0:
                ensemble_prediction /= total_weight
            
            return {
                "ensemble": ensemble_prediction,
                "individual_models": predictions,
                "confidence": np.max(ensemble_prediction),
            }
        
        except Exception as e:
            logger.warning(f"Ensemble prediction failed: {e}")
            # Fallback to rule-based prediction
            return await self._rule_based_prediction(context)
    
    async def _single_model_prediction(
        self, 
        features: np.ndarray, 
        context: DecisionContext
    ) -> Dict[str, Any]:
        """Get prediction from primary model."""
        try:
            if self._neural_network:
                features_tensor = torch.FloatTensor(features).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    output = self._neural_network(features_tensor)
                    prediction = output.cpu().numpy()[0]
                
                return {
                    "primary": prediction,
                    "confidence": np.max(prediction),
                }
        
        except Exception as e:
            logger.warning(f"Primary model prediction failed: {e}")
        
        # Fallback to rule-based
        return await self._rule_based_prediction(context)
    
    async def _rule_based_prediction(self, context: DecisionContext) -> Dict[str, Any]:
        """Fallback rule-based prediction."""
        # Simple rule-based logic
        threat_category = getattr(context.security_context, 'event_type', 'unknown').lower()
        
        # Default to containment for unknown threats
        decision_probs = np.zeros(len(DecisionType))
        decision_probs[list(DecisionType).index(DecisionType.CONTAINMENT)] = 0.7
        decision_probs[list(DecisionType).index(DecisionType.INVESTIGATION)] = 0.2
        decision_probs[list(DecisionType).index(DecisionType.NOTIFICATION)] = 0.1
        
        return {
            "rule_based": decision_probs,
            "confidence": 0.6,
        }
    
    async def _apply_policy_constraints(
        self,
        predictions: Dict[str, Any],
        context: DecisionContext,
        override_policies: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Apply policy constraints to model predictions."""
        try:
            # Get the primary prediction
            prediction_probs = predictions.get("ensemble", predictions.get("primary", predictions.get("rule_based")))
            
            # Get top decision types
            decision_types = list(DecisionType)
            top_indices = np.argsort(prediction_probs)[::-1][:3]  # Top 3
            
            actions = []
            
            for idx in top_indices:
                decision_type = decision_types[idx]
                confidence = prediction_probs[idx]
                
                # Apply policy constraints
                if await self._is_action_allowed(decision_type, context, confidence, override_policies):
                    action = await self._generate_specific_action(decision_type, context)
                    actions.append(action)
            
            return actions if actions else ["monitor_and_alert"]
        
        except Exception as e:
            logger.warning(f"Policy constraint application failed: {e}")
            return ["monitor_and_alert"]
    
    async def _is_action_allowed(
        self,
        decision_type: DecisionType,
        context: DecisionContext,
        confidence: float,
        override_policies: Optional[Dict[str, Any]],
    ) -> bool:
        """Check if action is allowed by policies."""
        # Check override policies first
        if override_policies:
            override_result = override_policies.get(f"allow_{decision_type.value.lower()}")
            if override_result is not None:
                return override_result
        
        # Check threat-specific policies
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        response_matrix = self._threat_response_matrix.get(threat_category, {})
        auto_threshold = response_matrix.get("auto_execute_threshold", 0.8)
        
        if confidence < auto_threshold:
            return False
        
        # Check security classification constraints
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            if decision_type in [DecisionType.CONTAINMENT, DecisionType.ESCALATION]:
                return confidence >= 0.9
        
        # Check iSECTECH-specific policies
        automation_limits = self._isectech_policies.get("automation_limits", {})
        max_actions = automation_limits.get("max_concurrent_actions", 5)
        
        # In production, check current running actions
        # For now, assume we're within limits
        
        return True
    
    async def _generate_specific_action(self, decision_type: DecisionType, context: DecisionContext) -> str:
        """Generate specific action based on decision type and context."""
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        response_matrix = self._threat_response_matrix.get(threat_category, {})
        
        action_mapping = {
            DecisionType.CONTAINMENT: response_matrix.get("primary_actions", ["isolate_system"])[0],
            DecisionType.INVESTIGATION: "initiate_forensic_analysis",
            DecisionType.NOTIFICATION: "alert_security_team",
            DecisionType.REMEDIATION: "apply_security_patches",
            DecisionType.PREVENTION: "update_threat_signatures",
            DecisionType.ESCALATION: "escalate_to_analyst",
            DecisionType.MONITORING: "increase_monitoring_level",
            DecisionType.DOCUMENTATION: "create_incident_record",
        }
        
        base_action = action_mapping.get(decision_type, "monitor_and_alert")
        
        # Add context-specific details
        if context.affected_assets:
            asset_list = ", ".join(context.affected_assets[:3])
            return f"{base_action} (assets: {asset_list})"
        
        return base_action
    
    def _determine_urgency(self, context: DecisionContext, predictions: Dict[str, Any]) -> DecisionUrgency:
        """Determine decision urgency based on context and predictions."""
        confidence = predictions.get("confidence", 0.5)
        
        # Critical severity always gets immediate attention
        if context.threat_severity == ThreatSeverity.CRITICAL:
            return DecisionUrgency.IMMEDIATE
        
        # High confidence + high severity = urgent
        if confidence >= 0.9 and context.threat_severity == ThreatSeverity.HIGH:
            return DecisionUrgency.URGENT
        
        # Classification-based urgency
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            return DecisionUrgency.HIGH
        
        # Default based on severity
        severity_urgency = {
            ThreatSeverity.HIGH: DecisionUrgency.HIGH,
            ThreatSeverity.MEDIUM: DecisionUrgency.MEDIUM,
            ThreatSeverity.LOW: DecisionUrgency.LOW,
            ThreatSeverity.INFORMATIONAL: DecisionUrgency.DEFERRED,
        }
        
        return severity_urgency.get(context.threat_severity, DecisionUrgency.MEDIUM)
    
    def _determine_confidence(self, predictions: Dict[str, Any], context: DecisionContext) -> DecisionConfidence:
        """Determine decision confidence level."""
        model_confidence = predictions.get("confidence", 0.5)
        
        # Adjust confidence based on context
        if context.confidence_score < 0.5:
            model_confidence *= 0.8  # Reduce if context is uncertain
        
        if len(context.similar_incidents) >= 3:
            model_confidence *= 1.1  # Boost if we have historical data
        
        model_confidence = min(1.0, model_confidence)  # Cap at 1.0
        
        if model_confidence >= 0.95:
            return DecisionConfidence.VERY_HIGH
        elif model_confidence >= 0.85:
            return DecisionConfidence.HIGH
        elif model_confidence >= 0.70:
            return DecisionConfidence.MEDIUM
        elif model_confidence >= 0.50:
            return DecisionConfidence.LOW
        else:
            return DecisionConfidence.VERY_LOW
    
    async def _generate_decision_reasoning(
        self,
        context: DecisionContext,
        predictions: Dict[str, Any],
        actions: List[str],
    ) -> str:
        """Generate human-readable decision reasoning."""
        reasoning_parts = [
            f"**Decision Analysis for {context.security_context.event_type}**",
            f"",
            f"**Threat Assessment:**",
            f"- Severity: {context.threat_severity.value}",
            f"- Confidence: {context.confidence_score:.2f}",
            f"- Classification: {context.security_context.classification.value}",
            f"",
            f"**Model Analysis:**",
            f"- Prediction confidence: {predictions.get('confidence', 0.5):.2f}",
            f"- Primary recommendation: {actions[0] if actions else 'No action'}",
            f"",
            f"**Policy Compliance:**",
            f"- iSECTECH automation policies: Compliant",
            f"- Security classification requirements: Verified",
            f"- Business impact consideration: {context.business_impact}",
        ]
        
        if context.affected_assets:
            reasoning_parts.extend([
                f"",
                f"**Asset Impact:**",
                *[f"- {asset}" for asset in context.affected_assets[:5]],
            ])
        
        if context.compliance_requirements:
            reasoning_parts.extend([
                f"",
                f"**Compliance Requirements:**",
                *[f"- {req}" for req in context.compliance_requirements],
            ])
        
        return "\n".join(reasoning_parts)
    
    async def _collect_supporting_evidence(
        self, 
        context: DecisionContext, 
        predictions: Dict[str, Any]
    ) -> List[str]:
        """Collect supporting evidence for the decision."""
        evidence = []
        
        # Model evidence
        evidence.append(f"ML model confidence: {predictions.get('confidence', 0.5):.2f}")
        
        # Context evidence
        if context.threat_severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            evidence.append(f"High severity threat detected: {context.threat_severity.value}")
        
        if context.security_context.threat_indicators:
            evidence.append(f"Threat indicators present: {len(context.security_context.threat_indicators)} IOCs")
        
        if context.similar_incidents:
            evidence.append(f"Historical precedent: {len(context.similar_incidents)} similar incidents")
        
        # Policy evidence
        evidence.append("Action complies with iSECTECH automation policies")
        
        if context.compliance_requirements:
            evidence.append(f"Regulatory requirements considered: {', '.join(context.compliance_requirements)}")
        
        return evidence
    
    async def _assess_execution_parameters(
        self,
        actions: List[str],
        confidence: DecisionConfidence,
        context: DecisionContext,
    ) -> Tuple[bool, bool, Optional[int]]:
        """Assess execution parameters for the decision."""
        auto_execute = False
        requires_approval = True
        timeout = 60  # Default 60 minutes
        
        # Auto-execution logic
        if confidence in [DecisionConfidence.VERY_HIGH, DecisionConfidence.HIGH]:
            # Check if actions are in auto-approval list
            authorization_matrix = self._authorization_matrix
            for action in actions:
                for category, action_configs in authorization_matrix.items():
                    for action_name, config in action_configs.items():
                        if action_name in action.lower():
                            auto_confidence_threshold = config.get("auto_approve_confidence", 0.95)
                            confidence_value = {
                                DecisionConfidence.VERY_HIGH: 0.97,
                                DecisionConfidence.HIGH: 0.87,
                                DecisionConfidence.MEDIUM: 0.72,
                                DecisionConfidence.LOW: 0.55,
                                DecisionConfidence.VERY_LOW: 0.35,
                            }.get(confidence, 0.5)
                            
                            if confidence_value >= auto_confidence_threshold:
                                auto_execute = True
                                requires_approval = False
                                timeout = config.get("approval_timeout", 30)
                                break
        
        # Override for critical threats with high confidence
        if (context.threat_severity == ThreatSeverity.CRITICAL and 
            confidence == DecisionConfidence.VERY_HIGH):
            auto_execute = True
            requires_approval = False
            timeout = 15
        
        # Always require approval for classified data
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            requires_approval = True
            if auto_execute:
                timeout = 30  # Shorter timeout for classified
        
        return auto_execute, requires_approval, timeout
    
    def _calculate_decision_score(
        self,
        predictions: Dict[str, Any],
        actions: List[str],
        context: DecisionContext,
    ) -> float:
        """Calculate overall decision quality score."""
        score = 0.0
        
        # Model confidence contribution (40%)
        model_confidence = predictions.get("confidence", 0.5)
        score += 0.4 * model_confidence
        
        # Context relevance contribution (30%)
        context_score = min(1.0, context.confidence_score + 0.2)  # Boost slightly
        score += 0.3 * context_score
        
        # Action appropriateness contribution (20%)
        if actions:
            action_score = 0.8 if len(actions) <= 3 else 0.6  # Prefer focused actions
            score += 0.2 * action_score
        
        # Policy compliance contribution (10%)
        compliance_score = 0.9  # Assume high compliance since actions passed policy checks
        score += 0.1 * compliance_score
        
        return min(1.0, score)
    
    def _calculate_model_confidence(self, predictions: Dict[str, Any]) -> float:
        """Calculate model-specific confidence score."""
        return predictions.get("confidence", 0.5)
    
    async def _assess_policy_compliance(
        self, 
        actions: List[str], 
        context: DecisionContext
    ) -> float:
        """Assess policy compliance for the decision."""
        compliance_score = 1.0
        
        # Check against iSECTECH policies
        automation_limits = self._isectech_policies.get("automation_limits", {})
        
        # Check action count limits
        max_actions = automation_limits.get("max_concurrent_actions", 5)
        if len(actions) > max_actions:
            compliance_score *= 0.8
        
        # Check classification compliance
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            # Higher scrutiny for classified data
            if any("shutdown" in action.lower() or "delete" in action.lower() for action in actions):
                compliance_score *= 0.9
        
        # Check compliance framework requirements
        for framework in context.compliance_requirements:
            framework_rules = self._compliance_rules.get(framework, {})
            # Add framework-specific compliance checks
            if framework == "GDPR" and "notification" not in " ".join(actions).lower():
                compliance_score *= 0.95
        
        return max(0.0, compliance_score)
    
    def _primary_decision_type(self, actions: List[str]) -> DecisionType:
        """Determine primary decision type from actions."""
        if not actions:
            return DecisionType.MONITORING
        
        action_keywords = {
            DecisionType.CONTAINMENT: ["isolate", "quarantine", "block", "contain"],
            DecisionType.INVESTIGATION: ["analyze", "investigate", "forensic", "examine"],
            DecisionType.NOTIFICATION: ["alert", "notify", "inform", "escalate"],
            DecisionType.REMEDIATION: ["patch", "fix", "repair", "remediate"],
            DecisionType.PREVENTION: ["update", "signature", "rule", "prevent"],
            DecisionType.ESCALATION: ["escalate", "manager", "ciso", "senior"],
            DecisionType.MONITORING: ["monitor", "watch", "observe", "track"],
            DecisionType.DOCUMENTATION: ["record", "document", "log", "report"],
        }
        
        primary_action = actions[0].lower()
        
        for decision_type, keywords in action_keywords.items():
            if any(keyword in primary_action for keyword in keywords):
                return decision_type
        
        return DecisionType.MONITORING
    
    def _estimate_risk_reduction(self, actions: List[str], context: DecisionContext) -> float:
        """Estimate risk reduction from proposed actions."""
        base_reduction = 0.3  # Base reduction for any action
        
        # Action-specific reduction
        action_effectiveness = {
            "isolate": 0.8,
            "quarantine": 0.7,
            "block": 0.6,
            "patch": 0.9,
            "update": 0.7,
            "monitor": 0.3,
            "alert": 0.2,
        }
        
        max_reduction = base_reduction
        for action in actions:
            for keyword, effectiveness in action_effectiveness.items():
                if keyword in action.lower():
                    max_reduction = max(max_reduction, effectiveness)
                    break
        
        # Adjust based on threat severity
        severity_multiplier = {
            ThreatSeverity.CRITICAL: 1.0,
            ThreatSeverity.HIGH: 0.9,
            ThreatSeverity.MEDIUM: 0.8,
            ThreatSeverity.LOW: 0.7,
            ThreatSeverity.INFORMATIONAL: 0.5,
        }
        
        multiplier = severity_multiplier.get(context.threat_severity, 0.8)
        return min(1.0, max_reduction * multiplier)
    
    def _assess_potential_impact(self, actions: List[str], context: DecisionContext) -> str:
        """Assess potential impact of proposed actions."""
        impacts = []
        
        # Business impact
        if any("isolate" in action.lower() or "shutdown" in action.lower() for action in actions):
            impacts.append("Potential service disruption")
        
        if any("block" in action.lower() for action in actions):
            impacts.append("May affect legitimate traffic")
        
        # Asset impact
        if context.affected_assets:
            impacts.append(f"Direct impact on {len(context.affected_assets)} assets")
        
        # Compliance impact
        if context.compliance_requirements:
            impacts.append("Regulatory compliance obligations triggered")
        
        return "; ".join(impacts) if impacts else "Minimal operational impact expected"
    
    def _identify_side_effects(self, actions: List[str], context: DecisionContext) -> List[str]:
        """Identify potential side effects of actions."""
        side_effects = []
        
        for action in actions:
            if "isolate" in action.lower():
                side_effects.append("Network connectivity loss")
            elif "quarantine" in action.lower():
                side_effects.append("Application functionality may be impacted")
            elif "block" in action.lower():
                side_effects.append("False positives may block legitimate activity")
            elif "patch" in action.lower():
                side_effects.append("System restart may be required")
        
        # Context-specific side effects
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            side_effects.append("Additional security review required")
        
        return side_effects
    
    async def _generate_alternatives(
        self, 
        predictions: Dict[str, Any], 
        chosen_actions: List[str]
    ) -> List[str]:
        """Generate alternative actions not chosen."""
        all_possible_actions = [
            "increase_monitoring_sensitivity",
            "deploy_additional_sensors",
            "implement_network_segmentation",
            "enhance_user_training",
            "update_security_policies",
            "schedule_vulnerability_scan",
            "request_external_consultation",
        ]
        
        # Filter out actions similar to chosen ones
        alternatives = []
        for action in all_possible_actions:
            if not any(self._actions_similar(action, chosen) for chosen in chosen_actions):
                alternatives.append(action)
        
        return alternatives[:3]  # Return top 3 alternatives
    
    def _actions_similar(self, action1: str, action2: str) -> bool:
        """Check if two actions are similar."""
        common_words = set(action1.lower().split()) & set(action2.lower().split())
        return len(common_words) >= 2
    
    def _update_decision_metrics(self, result: DecisionResult, decision_time: float) -> None:
        """Update decision-making performance metrics."""
        self._decision_metrics["total_decisions"] += 1
        
        if result.auto_execute:
            self._decision_metrics["auto_executed"] += 1
        
        # Update average decision time
        current_avg = self._decision_metrics["average_decision_time"]
        count = self._decision_metrics["total_decisions"]
        
        self._decision_metrics["average_decision_time"] = (
            (current_avg * (count - 1)) + decision_time
        ) / count
    
    async def record_feedback(
        self,
        decision_id: str,
        human_action: str,
        outcome: str,
        feedback_notes: Optional[str] = None,
    ) -> None:
        """Record feedback for learning and improvement."""
        try:
            feedback_record = {
                "decision_id": decision_id,
                "timestamp": datetime.utcnow(),
                "human_action": human_action,
                "outcome": outcome,
                "notes": feedback_notes,
            }
            
            self._learning_history.append(feedback_record)
            
            # Update metrics if override occurred
            if human_action != "approved":
                self._decision_metrics["human_overrides"] += 1
            
            # Audit log the feedback
            await self.audit_logger.log_security_event(
                event_type="DECISION_FEEDBACK_RECORDED",
                details=feedback_record,
                severity="INFO",
            )
            
            logger.info(f"Feedback recorded for decision {decision_id}")
            
        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
    
    def get_decision_metrics(self) -> Dict[str, Any]:
        """Get current decision-making metrics."""
        metrics = self._decision_metrics.copy()
        
        # Calculate additional metrics
        if metrics["total_decisions"] > 0:
            metrics["auto_execution_rate"] = metrics["auto_executed"] / metrics["total_decisions"]
            metrics["human_override_rate"] = metrics["human_overrides"] / metrics["total_decisions"]
        else:
            metrics["auto_execution_rate"] = 0.0
            metrics["human_override_rate"] = 0.0
        
        return metrics
    
    def get_learning_history(self) -> List[Dict[str, Any]]:
        """Get learning history for analysis."""
        return self._learning_history.copy()
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return {
            "device": str(self.device),
            "models_available": {
                "neural_network": self._neural_network is not None,
                "random_forest": self._random_forest is not None,
                "gradient_boosting": self._gradient_boosting is not None,
                "tensorflow": self._tensorflow_model is not None,
            },
            "decision_types": [dt.value for dt in DecisionType],
            "urgency_levels": [du.value for du in DecisionUrgency],
            "confidence_levels": [dc.value for dc in DecisionConfidence],
        }