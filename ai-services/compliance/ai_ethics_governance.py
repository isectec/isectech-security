"""
AI Ethics Governance Framework
Production-grade ethical AI governance system for threat detection models
Ensures fairness, accountability, and transparency in AI/ML decision-making
"""

import logging
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
import uuid
import hashlib
import aioredis
from sqlalchemy import create_engine, Column, String, DateTime, Float, Integer, JSON, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats

logger = logging.getLogger(__name__)

class EthicsViolationType(Enum):
    """Types of AI ethics violations"""
    ALGORITHMIC_BIAS = "algorithmic_bias"
    DISCRIMINATION = "discrimination"
    UNFAIR_TREATMENT = "unfair_treatment"
    LACK_OF_TRANSPARENCY = "lack_of_transparency"
    PRIVACY_VIOLATION = "privacy_violation"
    SECURITY_CONCERN = "security_concern"
    ACCOUNTABILITY_ISSUE = "accountability_issue"

class FairnessMetric(Enum):
    """Types of fairness metrics for AI evaluation"""
    DEMOGRAPHIC_PARITY = "demographic_parity"
    EQUALIZED_ODDS = "equalized_odds"
    EQUAL_OPPORTUNITY = "equal_opportunity"
    CALIBRATION = "calibration"
    INDIVIDUAL_FAIRNESS = "individual_fairness"
    COUNTERFACTUAL_FAIRNESS = "counterfactual_fairness"

class BiasType(Enum):
    """Types of bias that can occur in AI models"""
    SELECTION_BIAS = "selection_bias"
    CONFIRMATION_BIAS = "confirmation_bias"
    REPRESENTATION_BIAS = "representation_bias"
    MEASUREMENT_BIAS = "measurement_bias"
    EVALUATION_BIAS = "evaluation_bias"
    DEPLOYMENT_BIAS = "deployment_bias"
    HISTORICAL_BIAS = "historical_bias"

@dataclass
class EthicsAssessment:
    """Ethics assessment result for AI model"""
    assessment_id: str
    model_id: str
    model_version: str
    assessment_timestamp: datetime
    fairness_scores: Dict[str, float]
    bias_detection_results: Dict[str, Any]
    transparency_score: float
    accountability_score: float
    privacy_score: float
    overall_ethics_score: float
    violations_detected: List[str]
    recommendations: List[str]
    approved_for_production: bool
    assessor_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['assessment_timestamp'] = self.assessment_timestamp.isoformat()
        return data

@dataclass 
class BiasAssessmentResult:
    """Result of bias assessment for a protected group"""
    protected_attribute: str
    group_name: str
    sample_size: int
    bias_metrics: Dict[str, float]
    statistical_significance: float
    bias_severity: str  # "low", "medium", "high", "critical"
    mitigation_required: bool
    
class EthicsGovernanceDB:
    """Database models for ethics governance"""
    Base = declarative_base()
    
    class EthicsAssessmentRecord(Base):
        __tablename__ = 'ethics_assessments'
        
        assessment_id = Column(String, primary_key=True)
        model_id = Column(String, nullable=False, index=True)
        model_version = Column(String, nullable=False)
        assessment_timestamp = Column(DateTime, nullable=False)
        fairness_scores = Column(JSON, nullable=False)
        bias_detection_results = Column(JSON, nullable=False)
        transparency_score = Column(Float, nullable=False)
        accountability_score = Column(Float, nullable=False)
        privacy_score = Column(Float, nullable=False)
        overall_ethics_score = Column(Float, nullable=False)
        violations_detected = Column(JSON, nullable=False)
        recommendations = Column(JSON, nullable=False)
        approved_for_production = Column(Boolean, nullable=False)
        assessor_id = Column(String, nullable=False)
        created_at = Column(DateTime, default=datetime.utcnow)
    
    class BiasIncidentRecord(Base):
        __tablename__ = 'bias_incidents'
        
        incident_id = Column(String, primary_key=True)
        model_id = Column(String, nullable=False, index=True)
        incident_timestamp = Column(DateTime, nullable=False)
        bias_type = Column(String, nullable=False)
        protected_attribute = Column(String, nullable=False)
        severity = Column(String, nullable=False)
        detection_method = Column(String, nullable=False)
        impact_assessment = Column(JSON, nullable=False)
        mitigation_actions = Column(JSON, nullable=False)
        status = Column(String, default="open")  # open, investigating, resolved, false_positive
        resolved_at = Column(DateTime, nullable=True)
    
    class EthicsPolicy(Base):
        __tablename__ = 'ethics_policies'
        
        policy_id = Column(String, primary_key=True)
        policy_name = Column(String, nullable=False)
        policy_version = Column(String, nullable=False)
        effective_date = Column(DateTime, nullable=False)
        policy_content = Column(JSON, nullable=False)
        applies_to_models = Column(JSON, nullable=False)
        compliance_requirements = Column(JSON, nullable=False)
        created_by = Column(String, nullable=False)
        approved_by = Column(String, nullable=True)
        status = Column(String, default="draft")  # draft, approved, deprecated

class AIEthicsGovernance:
    """
    Comprehensive AI Ethics Governance system for threat detection models
    Ensures ethical AI deployment with continuous monitoring and assessment
    """
    
    def __init__(
        self,
        database_url: str = "postgresql://localhost/isectech_ethics",
        redis_url: str = "redis://localhost:6379/2",
        fairness_threshold: float = 0.8,
        bias_threshold: float = 0.1
    ):
        """Initialize AI Ethics Governance system"""
        self.database_url = database_url
        self.redis_url = redis_url
        self.fairness_threshold = fairness_threshold
        self.bias_threshold = bias_threshold
        
        # Database setup
        self.engine = create_engine(database_url)
        EthicsGovernanceDB.Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Protected attributes for bias detection
        self.protected_attributes = [
            'gender', 'race', 'age_group', 'ethnicity', 'location', 
            'socioeconomic_status', 'disability_status'
        ]
        
        # Redis for caching
        self.redis_pool = None
        
        logger.info("AI Ethics Governance system initialized")

    async def initialize_redis(self) -> None:
        """Initialize Redis connection"""
        if not self.redis_pool:
            self.redis_pool = aioredis.from_url(
                self.redis_url,
                encoding="utf-8", 
                decode_responses=True,
                max_connections=10
            )

    async def assess_model_ethics(
        self,
        model_id: str,
        model_version: str,
        training_data: pd.DataFrame,
        test_data: pd.DataFrame,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        assessor_id: str,
        protected_attributes: Optional[List[str]] = None
    ) -> EthicsAssessment:
        """
        Comprehensive ethics assessment of AI/ML model
        
        Args:
            model_id: Unique model identifier
            model_version: Model version
            training_data: Training dataset
            test_data: Test dataset with predictions
            predictions: Model predictions
            ground_truth: True labels
            assessor_id: ID of person conducting assessment
            protected_attributes: Attributes to check for bias
            
        Returns:
            EthicsAssessment object with comprehensive results
        """
        assessment_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        logger.info(f"Starting ethics assessment for model {model_id} v{model_version}")
        
        # 1. Fairness Assessment
        fairness_scores = await self._assess_fairness(
            test_data, predictions, ground_truth, protected_attributes
        )
        
        # 2. Bias Detection
        bias_results = await self._detect_bias(
            training_data, test_data, predictions, ground_truth, protected_attributes
        )
        
        # 3. Transparency Assessment
        transparency_score = await self._assess_transparency(
            model_id, training_data, test_data
        )
        
        # 4. Accountability Assessment
        accountability_score = await self._assess_accountability(model_id)
        
        # 5. Privacy Assessment
        privacy_score = await self._assess_privacy(training_data, test_data)
        
        # 6. Overall Ethics Score Calculation
        overall_score = self._calculate_overall_ethics_score(
            fairness_scores, bias_results, transparency_score, 
            accountability_score, privacy_score
        )
        
        # 7. Violation Detection
        violations = self._detect_ethics_violations(
            fairness_scores, bias_results, transparency_score,
            accountability_score, privacy_score
        )
        
        # 8. Generate Recommendations
        recommendations = await self._generate_recommendations(
            violations, fairness_scores, bias_results
        )
        
        # 9. Production Approval Decision
        approved_for_production = self._evaluate_production_readiness(
            overall_score, violations
        )
        
        # Create assessment record
        assessment = EthicsAssessment(
            assessment_id=assessment_id,
            model_id=model_id,
            model_version=model_version,
            assessment_timestamp=timestamp,
            fairness_scores=fairness_scores,
            bias_detection_results=bias_results,
            transparency_score=transparency_score,
            accountability_score=accountability_score,
            privacy_score=privacy_score,
            overall_ethics_score=overall_score,
            violations_detected=violations,
            recommendations=recommendations,
            approved_for_production=approved_for_production,
            assessor_id=assessor_id
        )
        
        # Store in database
        await self._store_ethics_assessment(assessment)
        
        logger.info(
            f"Ethics assessment completed: {assessment_id}, "
            f"Score: {overall_score:.2f}, Approved: {approved_for_production}"
        )
        
        return assessment

    async def _assess_fairness(
        self,
        test_data: pd.DataFrame,
        predictions: np.ndarray, 
        ground_truth: np.ndarray,
        protected_attributes: Optional[List[str]] = None
    ) -> Dict[str, float]:
        """Assess fairness across different demographic groups"""
        fairness_scores = {}
        
        if protected_attributes is None:
            protected_attributes = [attr for attr in self.protected_attributes 
                                   if attr in test_data.columns]
        
        for attr in protected_attributes:
            if attr not in test_data.columns:
                continue
                
            # Demographic Parity
            demo_parity = self._calculate_demographic_parity(
                test_data[attr], predictions
            )
            fairness_scores[f'{attr}_demographic_parity'] = demo_parity
            
            # Equalized Odds
            eq_odds = self._calculate_equalized_odds(
                test_data[attr], predictions, ground_truth
            )
            fairness_scores[f'{attr}_equalized_odds'] = eq_odds
            
            # Equal Opportunity 
            eq_opp = self._calculate_equal_opportunity(
                test_data[attr], predictions, ground_truth
            )
            fairness_scores[f'{attr}_equal_opportunity'] = eq_opp
            
            # Calibration
            calibration = self._calculate_calibration(
                test_data[attr], predictions, ground_truth
            )
            fairness_scores[f'{attr}_calibration'] = calibration
        
        # Overall fairness score
        fairness_scores['overall_fairness'] = np.mean(list(fairness_scores.values()))
        
        return fairness_scores

    def _calculate_demographic_parity(
        self, 
        protected_attr: pd.Series, 
        predictions: np.ndarray
    ) -> float:
        """Calculate demographic parity fairness metric"""
        groups = protected_attr.unique()
        positive_rates = []
        
        for group in groups:
            group_mask = protected_attr == group
            group_predictions = predictions[group_mask]
            positive_rate = np.mean(group_predictions)
            positive_rates.append(positive_rate)
        
        # Demographic parity is achieved when positive rates are similar
        # Score is 1 - max difference in positive rates
        max_diff = max(positive_rates) - min(positive_rates)
        return max(0.0, 1.0 - max_diff)

    def _calculate_equalized_odds(
        self,
        protected_attr: pd.Series,
        predictions: np.ndarray,
        ground_truth: np.ndarray
    ) -> float:
        """Calculate equalized odds fairness metric"""
        groups = protected_attr.unique()
        tpr_scores = []  # True Positive Rates
        fpr_scores = []  # False Positive Rates
        
        for group in groups:
            group_mask = protected_attr == group
            group_pred = predictions[group_mask]
            group_truth = ground_truth[group_mask]
            
            # Calculate TPR and FPR
            cm = confusion_matrix(group_truth, group_pred)
            if cm.shape == (2, 2):
                tn, fp, fn, tp = cm.ravel()
                tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
                
                tpr_scores.append(tpr)
                fpr_scores.append(fpr)
        
        if len(tpr_scores) < 2:
            return 1.0
        
        # Equalized odds achieved when TPR and FPR are similar across groups
        tpr_diff = max(tpr_scores) - min(tpr_scores)
        fpr_diff = max(fpr_scores) - min(fpr_scores)
        max_diff = max(tpr_diff, fpr_diff)
        
        return max(0.0, 1.0 - max_diff)

    def _calculate_equal_opportunity(
        self,
        protected_attr: pd.Series,
        predictions: np.ndarray,
        ground_truth: np.ndarray
    ) -> float:
        """Calculate equal opportunity fairness metric"""
        groups = protected_attr.unique()
        tpr_scores = []
        
        for group in groups:
            group_mask = protected_attr == group
            group_pred = predictions[group_mask]
            group_truth = ground_truth[group_mask]
            
            # Calculate TPR for positive class
            true_positives = np.sum((group_pred == 1) & (group_truth == 1))
            actual_positives = np.sum(group_truth == 1)
            tpr = true_positives / actual_positives if actual_positives > 0 else 0
            
            tpr_scores.append(tpr)
        
        if len(tpr_scores) < 2:
            return 1.0
        
        # Equal opportunity achieved when TPR is similar across groups
        max_diff = max(tpr_scores) - min(tpr_scores)
        return max(0.0, 1.0 - max_diff)

    def _calculate_calibration(
        self,
        protected_attr: pd.Series,
        predictions: np.ndarray,
        ground_truth: np.ndarray
    ) -> float:
        """Calculate calibration fairness metric"""
        groups = protected_attr.unique()
        calibration_scores = []
        
        for group in groups:
            group_mask = protected_attr == group
            group_pred = predictions[group_mask]
            group_truth = ground_truth[group_mask]
            
            if len(group_pred) == 0:
                continue
            
            # For binary predictions, check if positive prediction rate matches actual positive rate
            pred_positive_rate = np.mean(group_pred)
            actual_positive_rate = np.mean(group_truth)
            
            calibration_error = abs(pred_positive_rate - actual_positive_rate)
            calibration_score = max(0.0, 1.0 - calibration_error)
            calibration_scores.append(calibration_score)
        
        return np.mean(calibration_scores) if calibration_scores else 1.0

    async def _detect_bias(
        self,
        training_data: pd.DataFrame,
        test_data: pd.DataFrame,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        protected_attributes: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Comprehensive bias detection across multiple dimensions"""
        bias_results = {
            'bias_detected': False,
            'bias_assessments': [],
            'statistical_tests': {},
            'bias_severity': 'low'
        }
        
        if protected_attributes is None:
            protected_attributes = [attr for attr in self.protected_attributes 
                                   if attr in test_data.columns]
        
        for attr in protected_attributes:
            if attr not in test_data.columns:
                continue
            
            # Assess bias for each group within the protected attribute
            attr_groups = test_data[attr].unique()
            
            for group in attr_groups:
                bias_assessment = await self._assess_group_bias(
                    attr, group, test_data, predictions, ground_truth
                )
                
                bias_results['bias_assessments'].append(bias_assessment)
                
                if bias_assessment.mitigation_required:
                    bias_results['bias_detected'] = True
                    if bias_assessment.bias_severity in ['high', 'critical']:
                        bias_results['bias_severity'] = bias_assessment.bias_severity
        
        # Statistical significance tests
        bias_results['statistical_tests'] = await self._run_statistical_bias_tests(
            test_data, predictions, ground_truth, protected_attributes
        )
        
        return bias_results

    async def _assess_group_bias(
        self,
        protected_attribute: str,
        group_name: str,
        test_data: pd.DataFrame,
        predictions: np.ndarray,
        ground_truth: np.ndarray
    ) -> BiasAssessmentResult:
        """Assess bias for a specific demographic group"""
        group_mask = test_data[protected_attribute] == group_name
        sample_size = np.sum(group_mask)
        
        if sample_size == 0:
            return BiasAssessmentResult(
                protected_attribute=protected_attribute,
                group_name=str(group_name),
                sample_size=0,
                bias_metrics={},
                statistical_significance=1.0,
                bias_severity="low",
                mitigation_required=False
            )
        
        # Calculate bias metrics for this group vs others
        group_predictions = predictions[group_mask]
        group_ground_truth = ground_truth[group_mask]
        other_predictions = predictions[~group_mask]
        other_ground_truth = ground_truth[~group_mask]
        
        # Metrics calculation
        bias_metrics = {}
        
        # Selection rate difference
        group_positive_rate = np.mean(group_predictions)
        other_positive_rate = np.mean(other_predictions)
        bias_metrics['selection_rate_difference'] = abs(group_positive_rate - other_positive_rate)
        
        # Accuracy difference
        group_accuracy = np.mean(group_predictions == group_ground_truth)
        other_accuracy = np.mean(other_predictions == other_ground_truth)
        bias_metrics['accuracy_difference'] = abs(group_accuracy - other_accuracy)
        
        # Precision/Recall differences
        if len(np.unique(group_predictions)) > 1 and len(np.unique(other_predictions)) > 1:
            group_report = classification_report(group_ground_truth, group_predictions, output_dict=True, zero_division=0)
            other_report = classification_report(other_ground_truth, other_predictions, output_dict=True, zero_division=0)
            
            bias_metrics['precision_difference'] = abs(
                group_report.get('weighted avg', {}).get('precision', 0) - 
                other_report.get('weighted avg', {}).get('precision', 0)
            )
            bias_metrics['recall_difference'] = abs(
                group_report.get('weighted avg', {}).get('recall', 0) - 
                other_report.get('weighted avg', {}).get('recall', 0)
            )
        
        # Statistical significance test
        stat_significance = self._calculate_statistical_significance(
            group_predictions, other_predictions
        )
        
        # Determine bias severity
        max_bias = max(bias_metrics.values()) if bias_metrics else 0
        if max_bias > 0.2 and stat_significance < 0.01:
            bias_severity = "critical"
        elif max_bias > 0.15 and stat_significance < 0.05:
            bias_severity = "high"
        elif max_bias > 0.1 and stat_significance < 0.1:
            bias_severity = "medium"
        else:
            bias_severity = "low"
        
        mitigation_required = bias_severity in ["high", "critical"]
        
        return BiasAssessmentResult(
            protected_attribute=protected_attribute,
            group_name=str(group_name),
            sample_size=sample_size,
            bias_metrics=bias_metrics,
            statistical_significance=stat_significance,
            bias_severity=bias_severity,
            mitigation_required=mitigation_required
        )

    def _calculate_statistical_significance(
        self, 
        group1_predictions: np.ndarray, 
        group2_predictions: np.ndarray
    ) -> float:
        """Calculate statistical significance of difference between groups"""
        if len(group1_predictions) == 0 or len(group2_predictions) == 0:
            return 1.0
        
        # Use appropriate statistical test
        if len(np.unique(group1_predictions)) == 2:  # Binary predictions
            # Chi-square test for independence
            from scipy.stats import chi2_contingency
            
            # Create contingency table
            group1_pos = np.sum(group1_predictions == 1)
            group1_neg = np.sum(group1_predictions == 0)
            group2_pos = np.sum(group2_predictions == 1)
            group2_neg = np.sum(group2_predictions == 0)
            
            contingency_table = np.array([[group1_pos, group1_neg], 
                                         [group2_pos, group2_neg]])
            
            if np.all(contingency_table.sum(axis=0) > 0) and np.all(contingency_table.sum(axis=1) > 0):
                chi2, p_value, _, _ = chi2_contingency(contingency_table)
                return p_value
        
        # Default to t-test for continuous predictions
        try:
            _, p_value = stats.ttest_ind(group1_predictions, group2_predictions)
            return p_value
        except:
            return 1.0

    async def _run_statistical_bias_tests(
        self,
        test_data: pd.DataFrame,
        predictions: np.ndarray,
        ground_truth: np.ndarray,
        protected_attributes: List[str]
    ) -> Dict[str, Any]:
        """Run comprehensive statistical tests for bias detection"""
        statistical_tests = {}
        
        for attr in protected_attributes:
            if attr not in test_data.columns:
                continue
            
            # ANOVA test for differences across all groups
            groups = test_data[attr].unique()
            group_predictions = [predictions[test_data[attr] == group] for group in groups]
            
            try:
                from scipy.stats import f_oneway
                f_stat, p_value = f_oneway(*group_predictions)
                
                statistical_tests[f'{attr}_anova'] = {
                    'f_statistic': float(f_stat),
                    'p_value': float(p_value),
                    'significant': p_value < 0.05
                }
            except Exception as e:
                logger.warning(f"ANOVA test failed for {attr}: {str(e)}")
        
        return statistical_tests

    async def _assess_transparency(
        self, 
        model_id: str, 
        training_data: pd.DataFrame, 
        test_data: pd.DataFrame
    ) -> float:
        """Assess model transparency and explainability"""
        transparency_score = 0.0
        
        # Check for model documentation
        doc_score = await self._check_model_documentation(model_id)
        transparency_score += doc_score * 0.3
        
        # Check for feature importance availability
        feature_importance_score = await self._check_feature_importance(model_id)
        transparency_score += feature_importance_score * 0.3
        
        # Check for prediction explainability
        explainability_score = await self._check_explainability(model_id)
        transparency_score += explainability_score * 0.4
        
        return min(1.0, transparency_score)

    async def _check_model_documentation(self, model_id: str) -> float:
        """Check if model has adequate documentation"""
        # In a real implementation, this would check for:
        # - Model card existence
        # - Training data documentation
        # - Performance metrics documentation
        # - Bias assessment documentation
        
        # For now, return a placeholder score
        return 0.8  # Assuming most models have basic documentation

    async def _check_feature_importance(self, model_id: str) -> float:
        """Check if feature importance information is available"""
        # In real implementation, check if model provides:
        # - Feature importance scores
        # - SHAP values
        # - Other interpretability measures
        
        return 0.7  # Placeholder score

    async def _check_explainability(self, model_id: str) -> float:
        """Check if model predictions are explainable"""
        # In real implementation, check for:
        # - LIME/SHAP integration
        # - Local explanation availability
        # - Global explanation availability
        
        return 0.6  # Placeholder score

    async def _assess_accountability(self, model_id: str) -> float:
        """Assess model accountability measures"""
        accountability_score = 0.0
        
        # Check for audit trail
        audit_trail_score = await self._check_audit_trail(model_id)
        accountability_score += audit_trail_score * 0.4
        
        # Check for governance processes
        governance_score = await self._check_governance_processes(model_id)
        accountability_score += governance_score * 0.3
        
        # Check for responsibility assignment
        responsibility_score = await self._check_responsibility_assignment(model_id)
        accountability_score += responsibility_score * 0.3
        
        return min(1.0, accountability_score)

    async def _check_audit_trail(self, model_id: str) -> float:
        """Check if adequate audit trail exists"""
        # Check for decision logging, version control, etc.
        return 0.8

    async def _check_governance_processes(self, model_id: str) -> float:
        """Check if governance processes are in place"""
        # Check for ethics review board, approval processes, etc.
        return 0.7

    async def _check_responsibility_assignment(self, model_id: str) -> float:
        """Check if responsibility is clearly assigned"""
        # Check for clear ownership, escalation paths, etc.
        return 0.8

    async def _assess_privacy(
        self, 
        training_data: pd.DataFrame, 
        test_data: pd.DataFrame
    ) -> float:
        """Assess privacy protection measures"""
        privacy_score = 0.0
        
        # Check for PII protection
        pii_protection_score = await self._check_pii_protection(training_data, test_data)
        privacy_score += pii_protection_score * 0.4
        
        # Check for data anonymization
        anonymization_score = await self._check_anonymization(training_data, test_data)
        privacy_score += anonymization_score * 0.3
        
        # Check for differential privacy
        diff_privacy_score = await self._check_differential_privacy()
        privacy_score += diff_privacy_score * 0.3
        
        return min(1.0, privacy_score)

    async def _check_pii_protection(
        self, 
        training_data: pd.DataFrame, 
        test_data: pd.DataFrame
    ) -> float:
        """Check for personally identifiable information protection"""
        # Look for potential PII columns
        pii_indicators = ['email', 'phone', 'ssn', 'id', 'name', 'address']
        
        potential_pii_columns = []
        for col in training_data.columns:
            if any(indicator in col.lower() for indicator in pii_indicators):
                potential_pii_columns.append(col)
        
        if potential_pii_columns:
            # Check if PII columns are properly handled
            # For now, assume they need to be protected
            return 0.5
        else:
            return 1.0

    async def _check_anonymization(
        self, 
        training_data: pd.DataFrame, 
        test_data: pd.DataFrame
    ) -> float:
        """Check for data anonymization measures"""
        # This would check for k-anonymity, l-diversity, t-closeness
        return 0.8  # Placeholder

    async def _check_differential_privacy(self) -> float:
        """Check for differential privacy implementation"""
        # This would check if differential privacy is implemented
        return 0.6  # Placeholder

    def _calculate_overall_ethics_score(
        self,
        fairness_scores: Dict[str, float],
        bias_results: Dict[str, Any],
        transparency_score: float,
        accountability_score: float,
        privacy_score: float
    ) -> float:
        """Calculate overall ethics score"""
        # Weighted average of all ethics dimensions
        weights = {
            'fairness': 0.3,
            'bias': 0.25,
            'transparency': 0.2,
            'accountability': 0.15,
            'privacy': 0.1
        }
        
        overall_fairness = fairness_scores.get('overall_fairness', 0.0)
        
        # Bias score (inverse of bias severity)
        bias_severity_scores = {
            'low': 1.0,
            'medium': 0.7,
            'high': 0.4,
            'critical': 0.0
        }
        bias_score = bias_severity_scores.get(bias_results.get('bias_severity', 'low'), 1.0)
        
        overall_score = (
            weights['fairness'] * overall_fairness +
            weights['bias'] * bias_score +
            weights['transparency'] * transparency_score +
            weights['accountability'] * accountability_score +
            weights['privacy'] * privacy_score
        )
        
        return min(1.0, max(0.0, overall_score))

    def _detect_ethics_violations(
        self,
        fairness_scores: Dict[str, float],
        bias_results: Dict[str, Any],
        transparency_score: float,
        accountability_score: float,
        privacy_score: float
    ) -> List[str]:
        """Detect specific ethics violations"""
        violations = []
        
        # Fairness violations
        for metric, score in fairness_scores.items():
            if score < self.fairness_threshold:
                violations.append(f"Fairness violation: {metric} score {score:.2f} below threshold {self.fairness_threshold}")
        
        # Bias violations
        if bias_results.get('bias_detected', False):
            severity = bias_results.get('bias_severity', 'low')
            if severity in ['high', 'critical']:
                violations.append(f"Bias violation: {severity} bias detected")
        
        # Transparency violations
        if transparency_score < 0.6:
            violations.append(f"Transparency violation: score {transparency_score:.2f} below minimum requirement")
        
        # Accountability violations
        if accountability_score < 0.7:
            violations.append(f"Accountability violation: score {accountability_score:.2f} below requirement")
        
        # Privacy violations
        if privacy_score < 0.8:
            violations.append(f"Privacy violation: score {privacy_score:.2f} below requirement")
        
        return violations

    async def _generate_recommendations(
        self,
        violations: List[str],
        fairness_scores: Dict[str, float],
        bias_results: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable recommendations for ethics improvements"""
        recommendations = []
        
        if not violations:
            recommendations.append("Model passes all ethics checks. Continue monitoring.")
            return recommendations
        
        # Fairness recommendations
        for violation in violations:
            if "fairness violation" in violation.lower():
                recommendations.append("Implement fairness-aware training techniques")
                recommendations.append("Consider data augmentation for underrepresented groups")
                recommendations.append("Apply post-processing fairness correction")
        
        # Bias recommendations
        if bias_results.get('bias_detected', False):
            recommendations.append("Implement bias mitigation strategies")
            recommendations.append("Collect more representative training data")
            recommendations.append("Apply algorithmic bias correction techniques")
            recommendations.append("Implement continuous bias monitoring")
        
        # Transparency recommendations
        if any("transparency" in v.lower() for v in violations):
            recommendations.append("Implement SHAP or LIME explainability")
            recommendations.append("Create comprehensive model documentation")
            recommendations.append("Develop model cards with fairness assessments")
        
        # Accountability recommendations
        if any("accountability" in v.lower() for v in violations):
            recommendations.append("Establish clear model governance processes")
            recommendations.append("Implement audit trail for all decisions")
            recommendations.append("Assign clear responsibility for model outcomes")
        
        # Privacy recommendations
        if any("privacy" in v.lower() for v in violations):
            recommendations.append("Implement differential privacy")
            recommendations.append("Enhance data anonymization procedures")
            recommendations.append("Conduct privacy impact assessment")
        
        return recommendations

    def _evaluate_production_readiness(
        self, 
        overall_score: float, 
        violations: List[str]
    ) -> bool:
        """Determine if model is ready for production deployment"""
        # Minimum ethics score threshold
        min_score_threshold = 0.7
        
        # Critical violations that block production
        critical_violations = [
            "critical bias detected",
            "privacy violation", 
            "accountability violation"
        ]
        
        # Check overall score
        if overall_score < min_score_threshold:
            return False
        
        # Check for critical violations
        for violation in violations:
            if any(critical in violation.lower() for critical in critical_violations):
                return False
        
        return True

    async def _store_ethics_assessment(self, assessment: EthicsAssessment) -> None:
        """Store ethics assessment in database"""
        db = self.SessionLocal()
        try:
            db_record = EthicsGovernanceDB.EthicsAssessmentRecord(
                assessment_id=assessment.assessment_id,
                model_id=assessment.model_id,
                model_version=assessment.model_version,
                assessment_timestamp=assessment.assessment_timestamp,
                fairness_scores=assessment.fairness_scores,
                bias_detection_results=assessment.bias_detection_results,
                transparency_score=assessment.transparency_score,
                accountability_score=assessment.accountability_score,
                privacy_score=assessment.privacy_score,
                overall_ethics_score=assessment.overall_ethics_score,
                violations_detected=assessment.violations_detected,
                recommendations=assessment.recommendations,
                approved_for_production=assessment.approved_for_production,
                assessor_id=assessment.assessor_id
            )
            
            db.add(db_record)
            db.commit()
            
            # Cache the assessment
            await self.initialize_redis()
            cache_key = f"ethics_assessment:{assessment.assessment_id}"
            await self.redis_pool.setex(
                cache_key,
                3600,  # 1 hour
                json.dumps(assessment.to_dict(), default=str)
            )
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error storing ethics assessment: {str(e)}")
            raise
        finally:
            db.close()

    async def generate_ethics_report(
        self, 
        model_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive ethics report for a model"""
        db = self.SessionLocal()
        try:
            query = db.query(EthicsGovernanceDB.EthicsAssessmentRecord).filter(
                EthicsGovernanceDB.EthicsAssessmentRecord.model_id == model_id
            )
            
            if start_date:
                query = query.filter(
                    EthicsGovernanceDB.EthicsAssessmentRecord.assessment_timestamp >= start_date
                )
            if end_date:
                query = query.filter(
                    EthicsGovernanceDB.EthicsAssessmentRecord.assessment_timestamp <= end_date
                )
            
            assessments = query.order_by(
                EthicsGovernanceDB.EthicsAssessmentRecord.assessment_timestamp.desc()
            ).all()
            
            if not assessments:
                return {'error': f'No ethics assessments found for model {model_id}'}
            
            # Generate comprehensive report
            latest_assessment = assessments[0]
            
            report = {
                'model_id': model_id,
                'report_generated_at': datetime.utcnow().isoformat(),
                'assessment_count': len(assessments),
                'latest_assessment': {
                    'assessment_id': latest_assessment.assessment_id,
                    'assessment_date': latest_assessment.assessment_timestamp.isoformat(),
                    'overall_ethics_score': latest_assessment.overall_ethics_score,
                    'production_approved': latest_assessment.approved_for_production,
                    'violations_count': len(latest_assessment.violations_detected),
                    'recommendations_count': len(latest_assessment.recommendations)
                },
                'ethics_trends': self._analyze_ethics_trends(assessments),
                'compliance_status': {
                    'fairness_compliant': latest_assessment.overall_ethics_score >= self.fairness_threshold,
                    'bias_free': len(latest_assessment.violations_detected) == 0,
                    'production_ready': latest_assessment.approved_for_production
                },
                'recommendations': latest_assessment.recommendations[:5],  # Top 5 recommendations
                'assessment_history': [
                    {
                        'date': a.assessment_timestamp.isoformat(),
                        'score': a.overall_ethics_score,
                        'approved': a.approved_for_production
                    } for a in assessments[-10:]  # Last 10 assessments
                ]
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating ethics report: {str(e)}")
            raise
        finally:
            db.close()

    def _analyze_ethics_trends(
        self, 
        assessments: List[EthicsGovernanceDB.EthicsAssessmentRecord]
    ) -> Dict[str, Any]:
        """Analyze trends in ethics scores over time"""
        if len(assessments) < 2:
            return {'trend': 'insufficient_data'}
        
        # Sort by timestamp
        assessments = sorted(assessments, key=lambda x: x.assessment_timestamp)
        
        scores = [a.overall_ethics_score for a in assessments]
        dates = [a.assessment_timestamp for a in assessments]
        
        # Calculate trend
        if len(scores) >= 2:
            recent_avg = np.mean(scores[-3:]) if len(scores) >= 3 else scores[-1]
            earlier_avg = np.mean(scores[:3]) if len(scores) >= 3 else scores[0]
            
            if recent_avg > earlier_avg + 0.05:
                trend = 'improving'
            elif recent_avg < earlier_avg - 0.05:
                trend = 'declining'
            else:
                trend = 'stable'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'score_range': {'min': min(scores), 'max': max(scores)},
            'average_score': np.mean(scores),
            'latest_score': scores[-1],
            'score_change': scores[-1] - scores[0] if len(scores) > 1 else 0
        }

# Utility functions for integration
async def assess_threat_detection_model_ethics(
    governance: AIEthicsGovernance,
    model_name: str,
    training_data: pd.DataFrame,
    test_predictions: Dict[str, Any],
    assessor_id: str = "system"
) -> EthicsAssessment:
    """Convenience function for assessing threat detection model ethics"""
    
    # Convert predictions to required format
    predictions = np.array(test_predictions.get('predictions', []))
    ground_truth = np.array(test_predictions.get('ground_truth', []))
    test_data = test_predictions.get('test_data', pd.DataFrame())
    
    return await governance.assess_model_ethics(
        model_id=model_name,
        model_version="1.0",
        training_data=training_data,
        test_data=test_data,
        predictions=predictions,
        ground_truth=ground_truth,
        assessor_id=assessor_id
    )

if __name__ == "__main__":
    # Example usage
    async def test_ethics_governance():
        governance = AIEthicsGovernance()
        
        # Create sample data
        np.random.seed(42)
        n_samples = 1000
        
        training_data = pd.DataFrame({
            'feature1': np.random.randn(n_samples),
            'feature2': np.random.randn(n_samples),
            'gender': np.random.choice(['M', 'F'], n_samples),
            'age_group': np.random.choice(['young', 'middle', 'senior'], n_samples),
            'target': np.random.randint(0, 2, n_samples)
        })
        
        test_data = training_data.sample(200).copy()
        predictions = np.random.randint(0, 2, 200)
        ground_truth = test_data['target'].values
        
        # Assess model ethics
        assessment = await governance.assess_model_ethics(
            model_id="threat_detection_v1",
            model_version="1.0",
            training_data=training_data,
            test_data=test_data,
            predictions=predictions,
            ground_truth=ground_truth,
            assessor_id="test_assessor"
        )
        
        print(f"Ethics Assessment Results:")
        print(f"Overall Score: {assessment.overall_ethics_score:.2f}")
        print(f"Production Approved: {assessment.approved_for_production}")
        print(f"Violations: {len(assessment.violations_detected)}")
        print(f"Recommendations: {len(assessment.recommendations)}")
        
        # Generate report
        report = await governance.generate_ethics_report("threat_detection_v1")
        print(f"\nEthics Report Generated: {len(report)} sections")
    
    # Run test
    asyncio.run(test_ethics_governance())