"""
Tests for Zero-Day and Unknown Threat Detection Models

This module contains comprehensive tests for the zero-day detection system,
including unit tests for individual components and integration tests for
the complete detection pipeline.
"""

import pytest
import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict
from unittest.mock import Mock, patch, AsyncMock

from ..models.zero_day_detection import (
    ZeroDayDetectionManager,
    ZeroDayDetectionConfig,
    ZeroDayDetectionMethod,
    NoveltyType,
    ZeroDayThreat,
    SemiSupervisedZeroDayDetector,
    ClusteringOutlierDetector,
    VariationalAENoveltyDetector,
    PatternDeviationDetector,
    AdversarialThreatDetector,
    EnsembleZeroDayDetector
)
from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings


@pytest.fixture
def settings():
    """Mock settings for testing."""
    settings = Mock(spec=Settings)
    settings.ai_ml_threat_detection = Mock()
    settings.ai_ml_threat_detection.model_storage_path = "/tmp/test_models"
    settings.ai_ml_threat_detection.enable_mlflow = False
    return settings


@pytest.fixture
def zero_day_config():
    """Default configuration for zero-day detection."""
    return ZeroDayDetectionConfig(
        contamination_rate=0.1,
        confidence_threshold=0.6,
        novelty_threshold=2.0,
        random_state=42,
        enable_gpu=False,
        batch_processing=True
    )


@pytest.fixture
def sample_security_events():
    """Generate sample security events for testing."""
    events = []
    
    # Normal events
    for i in range(50):
        events.append(SecurityEvent(
            event_id=f"normal_{i}",
            timestamp=datetime.utcnow() - timedelta(hours=i),
            event_type="login",
            source_ip=f"192.168.1.{100 + i % 20}",
            dest_ip="10.0.0.1",
            port=22,
            username=f"user_{i % 10}",
            hostname=f"host_{i % 5}",
            severity="low",
            network_protocol="ssh",
            command_line="ssh user@host",
            process_name="/usr/bin/ssh",
            file_path="/var/log/auth.log",
            raw_data={"session_id": f"sess_{i}"}
        ))
    
    # Suspicious events (potential zero-day)
    for i in range(20):
        events.append(SecurityEvent(
            event_id=f"suspicious_{i}",
            timestamp=datetime.utcnow() - timedelta(hours=i, minutes=30),
            event_type="process_execution",
            source_ip=f"10.0.{i}.{200 + i}",
            dest_ip="192.168.1.1",
            port=4444 + i,
            username="admin",
            hostname="target_host",
            severity="high",
            network_protocol="tcp",
            command_line=f"powershell -enc SGVsbG8gV29ybGQ= && certutil -decode {i}",
            process_name="/windows/system32/powershell.exe",
            file_path=f"/tmp/malicious_{i}.exe",
            raw_data={"process_id": 1000 + i, "parent_pid": 500}
        ))
    
    return events


@pytest.fixture
def zero_day_manager(settings):
    """Zero-day detection manager for testing."""
    return ZeroDayDetectionManager(settings)


class TestZeroDayDetectionConfig:
    """Test zero-day detection configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ZeroDayDetectionConfig()
        
        assert config.contamination_rate == 0.05
        assert config.confidence_threshold == 0.7
        assert config.novelty_threshold == 2.0
        assert config.random_state == 42
        
        # SSL settings
        assert config.ssl_kernel == "rbf"
        assert config.ssl_gamma == 20
        assert config.ssl_max_iter == 1000
        
        # Clustering settings
        assert config.dbscan_eps == 0.5
        assert config.dbscan_min_samples == 5
        assert config.kmeans_clusters == 8
        
        # VAE settings
        assert config.vae_latent_dim == 16
        assert len(config.vae_hidden_dims) == 3
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = ZeroDayDetectionConfig(
            contamination_rate=0.1,
            confidence_threshold=0.8,
            novelty_threshold=3.0
        )
        
        assert config.contamination_rate == 0.1
        assert config.confidence_threshold == 0.8
        assert config.novelty_threshold == 3.0


class TestSemiSupervisedZeroDayDetector:
    """Test semi-supervised zero-day detector."""
    
    def test_initialization(self, zero_day_config):
        """Test detector initialization."""
        detector = SemiSupervisedZeroDayDetector(zero_day_config)
        
        assert detector.method == ZeroDayDetectionMethod.SEMI_SUPERVISED
        assert detector.config == zero_day_config
        assert not detector.is_fitted
    
    def test_fit_with_unlabeled_data(self, zero_day_config):
        """Test fitting with only unlabeled data."""
        detector = SemiSupervisedZeroDayDetector(zero_day_config)
        
        # Generate synthetic normal data
        X_normal = np.random.normal(0, 1, (100, 10))
        feature_names = [f"feature_{i}" for i in range(10)]
        
        detector.fit(X_normal, feature_names=feature_names)
        
        assert detector.is_fitted
        assert detector.feature_names == feature_names
        assert detector.normal_patterns is not None
        assert detector.model is not None
    
    def test_fit_with_labeled_data(self, zero_day_config):
        """Test fitting with labeled data."""
        detector = SemiSupervisedZeroDayDetector(zero_day_config)
        
        # Generate synthetic data
        X_normal = np.random.normal(0, 1, (100, 10))
        X_labeled = np.random.normal(2, 1, (20, 10))  # Different distribution
        y_labeled = np.ones(20)  # All labeled as threats
        
        detector.fit(X_normal, X_labeled, y_labeled)
        
        assert detector.is_fitted
        assert hasattr(detector.model, 'predict')
    
    def test_detect_threats(self, zero_day_config):
        """Test threat detection."""
        detector = SemiSupervisedZeroDayDetector(zero_day_config)
        
        # Train detector
        X_normal = np.random.normal(0, 1, (100, 10))
        detector.fit(X_normal)
        
        # Test detection
        X_test = np.random.normal(3, 1, (10, 10))  # Anomalous data
        threats = detector.detect_zero_day_threats(X_test)
        
        assert isinstance(threats, list)
        # Should detect some threats due to different distribution
        assert len([t for t in threats if t is not None]) > 0


class TestClusteringOutlierDetector:
    """Test clustering-based outlier detector."""
    
    def test_initialization(self, zero_day_config):
        """Test detector initialization."""
        detector = ClusteringOutlierDetector(zero_day_config)
        
        assert detector.method == ZeroDayDetectionMethod.CLUSTERING_OUTLIER
        assert detector.cluster_models == {}
        assert not detector.is_fitted
    
    def test_fit_clustering_models(self, zero_day_config):
        """Test fitting clustering models."""
        detector = ClusteringOutlierDetector(zero_day_config)
        
        X_normal = np.random.normal(0, 1, (100, 10))
        detector.fit(X_normal)
        
        assert detector.is_fitted
        assert 'dbscan' in detector.cluster_models
        assert 'kmeans' in detector.cluster_models
        assert 'gmm' in detector.cluster_models
        assert 'kmeans_centers' in detector.cluster_info
    
    def test_outlier_detection(self, zero_day_config):
        """Test outlier detection using clustering."""
        detector = ClusteringOutlierDetector(zero_day_config)
        
        # Train with normal data
        X_normal = np.random.normal(0, 1, (100, 10))
        detector.fit(X_normal)
        
        # Test with outliers
        X_outliers = np.random.normal(5, 1, (5, 10))  # Far from normal
        threats = detector.detect_zero_day_threats(X_outliers)
        
        assert isinstance(threats, list)
        # Should detect outliers
        assert len([t for t in threats if t is not None]) > 0


class TestPatternDeviationDetector:
    """Test pattern deviation detector."""
    
    def test_initialization(self, zero_day_config):
        """Test detector initialization."""
        detector = PatternDeviationDetector(zero_day_config)
        
        assert detector.method == ZeroDayDetectionMethod.PATTERN_DEVIATION
        assert detector.temporal_patterns == {}
        assert detector.sequence_models == {}
        assert not detector.is_fitted
    
    def test_temporal_pattern_building(self, zero_day_config):
        """Test temporal pattern building."""
        detector = PatternDeviationDetector(zero_day_config)
        
        # Create sequential data with patterns
        X_normal = np.array([[i, i*2, i%3] for i in range(50)])
        detector.fit(X_normal)
        
        assert detector.is_fitted
        assert len(detector.temporal_patterns) > 0
        assert 'statistical' in detector.deviation_thresholds
        
        # Check if temporal patterns were built
        first_pattern = next(iter(detector.temporal_patterns.values()))
        assert 'mean' in first_pattern
        assert 'trend' in first_pattern
        assert 'autocorr' in first_pattern
    
    def test_sequence_model_building(self, zero_day_config):
        """Test sequence model building."""
        detector = PatternDeviationDetector(zero_day_config)
        
        X_normal = np.random.normal(0, 1, (50, 10))
        detector.fit(X_normal)
        
        if 'kmeans' in detector.sequence_models:
            assert 'cluster_frequencies' in detector.sequence_models
            assert 'cluster_distance_stats' in detector.sequence_models


class TestAdversarialThreatDetector:
    """Test adversarial threat detector."""
    
    def test_initialization(self, zero_day_config):
        """Test detector initialization."""
        detector = AdversarialThreatDetector(zero_day_config)
        
        assert detector.method == ZeroDayDetectionMethod.ADVERSARIAL_DETECTION
        assert detector.adversarial_examples == []
        assert detector.boundary_models == {}
        assert not detector.is_fitted
    
    def test_adversarial_example_generation(self, zero_day_config):
        """Test generation of adversarial examples."""
        detector = AdversarialThreatDetector(zero_day_config)
        
        X_normal = np.random.normal(0, 1, (50, 10))
        detector.fit(X_normal)
        
        assert detector.is_fitted
        # Should generate some adversarial examples
        assert len(detector.adversarial_examples) > 0
        
        # Check adversarial example structure
        adv_example = detector.adversarial_examples[0]
        assert 'original' in adv_example
        assert 'adversarial' in adv_example
        assert 'perturbation' in adv_example
        assert 'method' in adv_example
    
    def test_boundary_model_training(self, zero_day_config):
        """Test boundary detection model training."""
        detector = AdversarialThreatDetector(zero_day_config)
        
        X_normal = np.random.normal(0, 1, (50, 10))
        detector.fit(X_normal)
        
        assert 'nearest_neighbors' in detector.boundary_models
        assert 'isolation_forest' in detector.boundary_models
        assert 'distance_threshold' in detector.boundary_models


class TestEnsembleZeroDayDetector:
    """Test ensemble zero-day detector."""
    
    def test_initialization(self, zero_day_config):
        """Test ensemble initialization."""
        methods = [
            ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
            ZeroDayDetectionMethod.SEMI_SUPERVISED
        ]
        ensemble = EnsembleZeroDayDetector(zero_day_config, methods)
        
        assert len(ensemble.detectors) == 2
        assert not ensemble.is_fitted
    
    def test_ensemble_fitting(self, zero_day_config):
        """Test ensemble fitting."""
        methods = [
            ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
            ZeroDayDetectionMethod.SEMI_SUPERVISED
        ]
        ensemble = EnsembleZeroDayDetector(zero_day_config, methods)
        
        X_normal = np.random.normal(0, 1, (100, 10))
        ensemble.fit(X_normal)
        
        assert ensemble.is_fitted
        # Should have successfully fitted detectors
        assert len(ensemble.detectors) >= 1
    
    def test_ensemble_detection(self, zero_day_config):
        """Test ensemble detection with voting."""
        methods = [
            ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
            ZeroDayDetectionMethod.SEMI_SUPERVISED
        ]
        ensemble = EnsembleZeroDayDetector(zero_day_config, methods)
        
        X_normal = np.random.normal(0, 1, (100, 10))
        ensemble.fit(X_normal)
        
        X_test = np.random.normal(3, 1, (10, 10))  # Anomalous data
        threats = ensemble.detect_zero_day_threats(X_test)
        
        assert isinstance(threats, list)


class TestZeroDayDetectionManager:
    """Test zero-day detection manager."""
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self, settings):
        """Test manager initialization."""
        manager = ZeroDayDetectionManager(settings)
        
        assert manager.settings == settings
        assert isinstance(manager.config, ZeroDayDetectionConfig)
        assert manager.trained_models == {}
        assert len(manager.known_signatures) == 0
    
    @pytest.mark.asyncio
    async def test_feature_extraction(self, zero_day_manager, sample_security_events):
        """Test zero-day feature extraction."""
        event = sample_security_events[0]
        features = zero_day_manager._extract_zero_day_features(event)
        
        assert isinstance(features, dict)
        assert 'hour' in features
        assert 'severity_numeric' in features
        assert 'port_category' in features
        assert 'command_complexity' in features
        assert 'file_path_depth' in features
    
    @pytest.mark.asyncio
    async def test_entropy_calculation(self, zero_day_manager):
        """Test entropy calculation for strings."""
        # Test normal string
        entropy1 = zero_day_manager._calculate_entropy("hello world")
        assert entropy1 > 0
        
        # Test highly random string (should have higher entropy)
        entropy2 = zero_day_manager._calculate_entropy("a1b2c3d4e5f6g7h8i9")
        assert entropy2 > entropy1
        
        # Test empty string
        entropy3 = zero_day_manager._calculate_entropy("")
        assert entropy3 == 0.0
    
    @pytest.mark.asyncio
    async def test_port_categorization(self, zero_day_manager):
        """Test port categorization."""
        assert zero_day_manager._categorize_port(22) == 1    # Well-known
        assert zero_day_manager._categorize_port(8080) == 2  # Registered
        assert zero_day_manager._categorize_port(50000) == 3  # Dynamic
        assert zero_day_manager._categorize_port(None) == 0  # Unknown
    
    @pytest.mark.asyncio
    async def test_command_complexity(self, zero_day_manager):
        """Test command complexity calculation."""
        simple_cmd = zero_day_manager._calculate_command_complexity("ls -la")
        complex_cmd = zero_day_manager._calculate_command_complexity(
            "powershell -enc SGVsbG8gV29ybGQ= && certutil -decode malware.exe"
        )
        
        assert complex_cmd > simple_cmd
        assert zero_day_manager._calculate_command_complexity("") == 0.0
    
    @pytest.mark.asyncio
    async def test_suspicious_keywords(self, zero_day_manager):
        """Test suspicious keyword detection."""
        suspicious = zero_day_manager._check_suspicious_keywords(
            "powershell -ExecutionPolicy Bypass"
        )
        normal = zero_day_manager._check_suspicious_keywords("ls -la /home/user")
        
        assert suspicious > normal
        assert zero_day_manager._check_suspicious_keywords("") == 0
    
    @pytest.mark.asyncio 
    async def test_model_training(self, zero_day_manager, sample_security_events):
        """Test zero-day model training."""
        normal_events = [e for e in sample_security_events if e.event_id.startswith("normal")]
        
        with patch('mlflow.start_run'):
            result = await zero_day_manager.train_zero_day_detectors(
                normal_events=normal_events[:20],  # Use smaller dataset for testing
                model_name="test_model",
                methods=[ZeroDayDetectionMethod.CLUSTERING_OUTLIER]
            )
        
        assert result['model_name'] == "test_model"
        assert 'training_time' in result
        assert "test_model" in zero_day_manager.trained_models
    
    @pytest.mark.asyncio
    async def test_zero_day_detection(self, zero_day_manager, sample_security_events):
        """Test zero-day threat detection."""
        normal_events = [e for e in sample_security_events if e.event_id.startswith("normal")]
        suspicious_events = [e for e in sample_security_events if e.event_id.startswith("suspicious")]
        
        # Train model first
        with patch('mlflow.start_run'):
            await zero_day_manager.train_zero_day_detectors(
                normal_events=normal_events[:20],
                model_name="test_model",
                methods=[ZeroDayDetectionMethod.CLUSTERING_OUTLIER]
            )
        
        # Test detection
        threats = await zero_day_manager.detect_zero_day_threats(
            events=suspicious_events[:5],
            model_name="test_model"
        )
        
        assert isinstance(threats, list)
        # Should detect some suspicious events as threats
        for threat in threats:
            if threat:
                assert isinstance(threat, ZeroDayThreat)
                assert threat.detection_method == ZeroDayDetectionMethod.CLUSTERING_OUTLIER
                assert 0 <= threat.threat_score <= 1
                assert 0 <= threat.confidence_score <= 1
    
    @pytest.mark.asyncio
    async def test_synthetic_data_generation(self, zero_day_manager, sample_security_events):
        """Test synthetic zero-day data generation."""
        base_events = sample_security_events[:10]
        
        synthetic_events, labels = await zero_day_manager.generate_synthetic_zero_day_data(
            base_events=base_events,
            n_synthetic=20,
            mutation_strategies=['feature_drift', 'temporal_shift']
        )
        
        assert len(synthetic_events) > 20  # Includes normal events too
        assert len(labels) == len(synthetic_events)
        
        # Check that some events are labeled as zero-day
        zero_day_count = sum(labels.values())
        assert zero_day_count > 0
        
        # Check that synthetic events have expected modifications
        synthetic_zd_events = [e for e in synthetic_events if e.event_id.startswith("synthetic_zd")]
        assert len(synthetic_zd_events) == 20
    
    @pytest.mark.asyncio
    async def test_model_validation(self, zero_day_manager, sample_security_events):
        """Test zero-day model validation."""
        normal_events = [e for e in sample_security_events if e.event_id.startswith("normal")]
        test_events = sample_security_events[:20]
        
        # Create ground truth labels
        ground_truth = {}
        for event in test_events:
            ground_truth[event.event_id] = event.event_id.startswith("suspicious")
        
        # Train model
        with patch('mlflow.start_run'):
            await zero_day_manager.train_zero_day_detectors(
                normal_events=normal_events[:15],
                model_name="validation_test",
                methods=[ZeroDayDetectionMethod.CLUSTERING_OUTLIER]
            )
        
        # Validate model
        with patch('mlflow.start_run'):
            validation_results = await zero_day_manager.validate_zero_day_models(
                test_events=test_events,
                ground_truth_labels=ground_truth,
                model_name="validation_test"
            )
        
        assert 'accuracy' in validation_results
        assert 'precision' in validation_results
        assert 'recall' in validation_results
        assert 'f1_score' in validation_results
        assert 'confusion_matrix' in validation_results
        assert 0 <= validation_results['accuracy'] <= 1
    
    @pytest.mark.asyncio
    async def test_continuous_learning(self, zero_day_manager, sample_security_events):
        """Test continuous learning functionality."""
        normal_events = [e for e in sample_security_events if e.event_id.startswith("normal")]
        
        # Train initial model
        with patch('mlflow.start_run'):
            await zero_day_manager.train_zero_day_detectors(
                normal_events=normal_events[:15],
                model_name="continuous_test",
                methods=[ZeroDayDetectionMethod.CLUSTERING_OUTLIER]
            )
        
        # Prepare feedback data
        new_events = sample_security_events[20:25]
        feedback = {event.event_id: event.event_id.startswith("suspicious") for event in new_events}
        
        # Test continuous learning update
        update_results = await zero_day_manager.continuous_learning_update(
            new_events=new_events,
            feedback=feedback,
            model_name="continuous_test",
            retrain_threshold=5  # Low threshold for testing
        )
        
        assert 'model_name' in update_results
        assert 'new_normal_events' in update_results
        assert 'new_zero_day_events' in update_results
        assert 'retrained' in update_results
    
    @pytest.mark.asyncio
    async def test_threat_intelligence_summary(self, zero_day_manager):
        """Test threat intelligence summary generation."""
        # Add some mock signatures
        zero_day_manager.known_signatures = {"sig1", "sig2", "sig3"}
        zero_day_manager.signature_history.extend([
            {
                'signature': 'sig1',
                'timestamp': datetime.utcnow() - timedelta(hours=1),
                'novelty_type': NoveltyType.ZERO_DAY_EXPLOIT.value
            },
            {
                'signature': 'sig2',
                'timestamp': datetime.utcnow() - timedelta(days=2),
                'novelty_type': NoveltyType.ADVANCED_EVASION.value
            }
        ])
        
        summary = await zero_day_manager.get_threat_intelligence_summary()
        
        assert summary['total_signatures'] == 3
        assert summary['recent_signatures'] == 1  # Only one in last 7 days
        assert 'novelty_type_distribution' in summary
        assert 'trained_models' in summary


class TestZeroDayThreatModel:
    """Test ZeroDayThreat data model."""
    
    def test_threat_creation(self):
        """Test zero-day threat object creation."""
        threat = ZeroDayThreat(
            event_id="test_event_123",
            detection_method=ZeroDayDetectionMethod.SEMI_SUPERVISED,
            novelty_type=NoveltyType.ZERO_DAY_EXPLOIT,
            threat_score=0.85,
            confidence_score=0.92,
            timestamp=datetime.utcnow(),
            anomaly_features={"suspicious_port": 4444, "unusual_time": 3.2},
            recommended_actions=["Isolate system", "Collect forensics"]
        )
        
        assert threat.event_id == "test_event_123"
        assert threat.detection_method == ZeroDayDetectionMethod.SEMI_SUPERVISED
        assert threat.novelty_type == NoveltyType.ZERO_DAY_EXPLOIT
        assert threat.threat_score == 0.85
        assert threat.confidence_score == 0.92
        assert len(threat.recommended_actions) == 2
    
    def test_threat_serialization(self):
        """Test zero-day threat JSON serialization."""
        threat = ZeroDayThreat(
            event_id="test_event_456",
            detection_method=ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
            novelty_type=NoveltyType.NOVEL_BEHAVIOR_PATTERN,
            threat_score=0.75,
            confidence_score=0.80,
            timestamp=datetime.utcnow()
        )
        
        # Should be able to serialize to dict
        threat_dict = threat.dict()
        assert threat_dict['event_id'] == "test_event_456"
        assert threat_dict['detection_method'] == ZeroDayDetectionMethod.CLUSTERING_OUTLIER.value
        assert threat_dict['novelty_type'] == NoveltyType.NOVEL_BEHAVIOR_PATTERN.value
        
        # Should be able to serialize to JSON
        threat_json = threat.json()
        assert isinstance(threat_json, str)
        assert "test_event_456" in threat_json


@pytest.mark.integration
class TestZeroDayDetectionIntegration:
    """Integration tests for complete zero-day detection pipeline."""
    
    @pytest.mark.asyncio
    async def test_full_detection_pipeline(self, zero_day_manager, sample_security_events):
        """Test complete zero-day detection pipeline."""
        normal_events = [e for e in sample_security_events if e.event_id.startswith("normal")]
        suspicious_events = [e for e in sample_security_events if e.event_id.startswith("suspicious")]
        
        # 1. Train ensemble model
        with patch('mlflow.start_run'):
            training_result = await zero_day_manager.train_zero_day_detectors(
                normal_events=normal_events[:30],
                model_name="integration_test",
                methods=[
                    ZeroDayDetectionMethod.CLUSTERING_OUTLIER,
                    ZeroDayDetectionMethod.SEMI_SUPERVISED
                ]
            )
        
        assert training_result['model_type'] == 'ensemble'
        assert 'training_time' in training_result
        
        # 2. Detect threats
        threats = await zero_day_manager.detect_zero_day_threats(
            events=suspicious_events[:10],
            model_name="integration_test"
        )
        
        assert isinstance(threats, list)
        
        # 3. Generate synthetic data for validation
        synthetic_events, synthetic_labels = await zero_day_manager.generate_synthetic_zero_day_data(
            base_events=normal_events[:10],
            n_synthetic=20
        )
        
        # 4. Validate model performance
        all_test_events = suspicious_events[:5] + synthetic_events[:10]
        combined_labels = {
            **{e.event_id: True for e in suspicious_events[:5]},
            **{k: v for k, v in list(synthetic_labels.items())[:10]}
        }
        
        with patch('mlflow.start_run'):
            validation_result = await zero_day_manager.validate_zero_day_models(
                test_events=all_test_events,
                ground_truth_labels=combined_labels,
                model_name="integration_test"
            )
        
        # Should have reasonable performance metrics
        assert 0 <= validation_result['accuracy'] <= 1
        assert 0 <= validation_result['precision'] <= 1
        assert 0 <= validation_result['recall'] <= 1
        
        # 5. Test continuous learning
        feedback = {e.event_id: True for e in suspicious_events[5:8]}  # Mark as zero-day
        
        update_result = await zero_day_manager.continuous_learning_update(
            new_events=suspicious_events[5:8],
            feedback=feedback,
            model_name="integration_test",
            retrain_threshold=3
        )
        
        assert 'retrained' in update_result
        
        # 6. Get final metrics
        metrics = await zero_day_manager.get_detection_metrics()
        assert 'trained_models' in metrics
        assert 'model_count' in metrics
        assert metrics['model_count'] > 0


if __name__ == "__main__":
    # Run specific test functions for quick validation
    import sys
    import os
    
    # Add the project root to Python path
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../.."))
    
    # Run a simple validation test
    from ai_services.services.threat_detection_ml.models.zero_day_detection import ZeroDayDetectionConfig
    
    print("Testing Zero-Day Detection Implementation...")
    
    # Test configuration
    config = ZeroDayDetectionConfig()
    print(f"✓ Configuration created: contamination_rate={config.contamination_rate}")
    
    # Test detector initialization
    from ai_services.services.threat_detection_ml.models.zero_day_detection import SemiSupervisedZeroDayDetector
    detector = SemiSupervisedZeroDayDetector(config)
    print(f"✓ Semi-supervised detector initialized: method={detector.method.value}")
    
    print("✓ All basic tests passed!")