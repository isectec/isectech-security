#!/usr/bin/env python3
# iSECTECH Advanced Signature Detection Engine
# Production-grade signature-based threat detection with ML enhancement

import json
import yaml
import asyncio
import aioredis
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import re
import hashlib
import pickle
import sqlite3
from collections import defaultdict, Counter
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess
import psutil
import socket
import struct

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/signature-detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SignatureMatch:
    """Represents a signature detection match"""
    timestamp: datetime
    signature_id: int
    signature_name: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    severity: str
    classification: str
    confidence_score: float
    payload: Optional[str] = None
    metadata: Dict[str, Any] = None
    mitre_tactics: List[str] = None
    mitre_techniques: List[str] = None
    threat_score: float = 0.0
    false_positive_likelihood: float = 0.0

@dataclass
class ThreatPattern:
    """Advanced threat pattern for detection"""
    pattern_id: str
    name: str
    pattern_type: str  # 'sequence', 'frequency', 'behavioral'
    signatures: List[int]
    time_window: int  # seconds
    threshold: int
    mitre_mapping: Dict[str, List[str]]
    description: str
    confidence_baseline: float = 0.7

@dataclass
class AttackChain:
    """Represents a detected attack chain"""
    chain_id: str
    start_time: datetime
    end_time: datetime
    source_ip: str
    target_ips: Set[str]
    attack_stages: List[Dict[str, Any]]
    total_confidence: float
    mitre_tactics: Set[str]
    risk_score: float

class AdvancedSignatureAnalyzer:
    """Advanced signature analysis with machine learning enhancement"""
    
    def __init__(self, config_path: str = "/etc/nsm/signature-config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.redis_client = None
        self.db_path = "/var/lib/nsm/signature_detection.db"
        self._init_database()
        
        # ML Models for enhancement
        self.anomaly_detector = None
        self.false_positive_classifier = None
        self.threat_scorer = None
        self._load_ml_models()
        
        # Pattern detection
        self.threat_patterns: Dict[str, ThreatPattern] = {}
        self.active_chains: Dict[str, AttackChain] = {}
        self._load_threat_patterns()
        
        # Performance tracking
        self.performance_metrics = {
            'total_matches': 0,
            'false_positives': 0,
            'true_positives': 0,
            'avg_processing_time': 0.0,
            'memory_usage': 0,
            'cpu_usage': 0.0
        }
        
        # Real-time processing
        self.processing_queue = asyncio.Queue(maxsize=10000)
        self.is_running = False
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {self.config_path} not found, using defaults")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'password': None
            },
            'detection': {
                'confidence_threshold': 0.7,
                'false_positive_threshold': 0.3,
                'max_attack_chain_duration': 3600,
                'min_chain_confidence': 0.8
            },
            'ml_models': {
                'enable_anomaly_detection': True,
                'enable_false_positive_reduction': True,
                'enable_threat_scoring': True,
                'model_update_frequency': 86400
            },
            'performance': {
                'max_memory_usage_mb': 2048,
                'max_cpu_usage_percent': 80,
                'processing_timeout': 30
            }
        }
    
    def _init_database(self):
        """Initialize SQLite database for signature data"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signature_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    signature_id INTEGER,
                    signature_name TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    severity TEXT,
                    classification TEXT,
                    confidence_score REAL,
                    threat_score REAL,
                    false_positive_likelihood REAL,
                    payload TEXT,
                    metadata TEXT,
                    mitre_tactics TEXT,
                    mitre_techniques TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_chains (
                    chain_id TEXT PRIMARY KEY,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    source_ip TEXT,
                    target_ips TEXT,
                    attack_stages TEXT,
                    total_confidence REAL,
                    mitre_tactics TEXT,
                    risk_score REAL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    name TEXT,
                    pattern_type TEXT,
                    signatures TEXT,
                    time_window INTEGER,
                    threshold INTEGER,
                    mitre_mapping TEXT,
                    description TEXT,
                    confidence_baseline REAL,
                    last_updated TIMESTAMP
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_signature_matches_timestamp ON signature_matches(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_signature_matches_source_ip ON signature_matches(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_chains_start_time ON attack_chains(start_time)")
    
    def _load_ml_models(self):
        """Load or initialize machine learning models"""
        models_dir = Path("/var/lib/nsm/models")
        models_dir.mkdir(exist_ok=True)
        
        # Anomaly Detection Model
        anomaly_model_path = models_dir / "anomaly_detector.pkl"
        if anomaly_model_path.exists():
            self.anomaly_detector = joblib.load(anomaly_model_path)
        else:
            # Initialize new model
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
        
        # False Positive Classifier
        fp_model_path = models_dir / "false_positive_classifier.pkl"
        if fp_model_path.exists():
            self.false_positive_classifier = joblib.load(fp_model_path)
        else:
            # Initialize new model (would be trained with labeled data)
            from sklearn.ensemble import RandomForestClassifier
            self.false_positive_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
        
        # Threat Scoring Model
        threat_model_path = models_dir / "threat_scorer.pkl"
        if threat_model_path.exists():
            self.threat_scorer = joblib.load(threat_model_path)
        else:
            # Initialize new model
            from sklearn.ensemble import GradientBoostingRegressor
            self.threat_scorer = GradientBoostingRegressor(
                n_estimators=100,
                random_state=42
            )
    
    def _load_threat_patterns(self):
        """Load threat patterns from database and configuration"""
        # Load from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM threat_patterns")
            for row in cursor.fetchall():
                pattern = ThreatPattern(
                    pattern_id=row[0],
                    name=row[1],
                    pattern_type=row[2],
                    signatures=json.loads(row[3]),
                    time_window=row[4],
                    threshold=row[5],
                    mitre_mapping=json.loads(row[6]),
                    description=row[7],
                    confidence_baseline=row[8]
                )
                self.threat_patterns[pattern.pattern_id] = pattern
        
        # Load default patterns if none exist
        if not self.threat_patterns:
            self._create_default_patterns()
    
    def _create_default_patterns(self):
        """Create default threat detection patterns"""
        default_patterns = [
            ThreatPattern(
                pattern_id="lateral_movement_sequence",
                name="Lateral Movement Attack Sequence",
                pattern_type="sequence",
                signatures=[10001004, 10001005, 10001001],  # RDP, SSH, PsExec
                time_window=1800,  # 30 minutes
                threshold=2,
                mitre_mapping={
                    "tactics": ["TA0008"],  # Lateral Movement
                    "techniques": ["T1021", "T1570"]
                },
                description="Detects lateral movement using multiple protocols",
                confidence_baseline=0.8
            ),
            ThreatPattern(
                pattern_id="data_exfiltration_pattern",
                name="Data Exfiltration Pattern",
                pattern_type="behavioral",
                signatures=[10002001, 10002002, 10002003],  # Large uploads
                time_window=3600,  # 1 hour
                threshold=3,
                mitre_mapping={
                    "tactics": ["TA0010"],  # Exfiltration
                    "techniques": ["T1041", "T1567"]
                },
                description="Detects potential data exfiltration activities",
                confidence_baseline=0.75
            ),
            ThreatPattern(
                pattern_id="c2_beaconing_frequency",
                name="C2 Beaconing Frequency Pattern",
                pattern_type="frequency",
                signatures=[10003001, 10003002, 10003003],  # Beaconing patterns
                time_window=900,  # 15 minutes
                threshold=10,
                mitre_mapping={
                    "tactics": ["TA0011"],  # Command and Control
                    "techniques": ["T1071", "T1568"]
                },
                description="Detects command and control beaconing behavior",
                confidence_baseline=0.85
            ),
            ThreatPattern(
                pattern_id="apt_toolset_usage",
                name="APT Toolset Usage Pattern",
                pattern_type="sequence",
                signatures=[10007001, 10007002, 10007003],  # APT techniques
                time_window=7200,  # 2 hours
                threshold=2,
                mitre_mapping={
                    "tactics": ["TA0003", "TA0004", "TA0005"],  # Persistence, Privilege Escalation, Defense Evasion
                    "techniques": ["T1053", "T1546", "T1562"]
                },
                description="Detects advanced persistent threat techniques",
                confidence_baseline=0.9
            )
        ]
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            for pattern in default_patterns:
                conn.execute("""
                    INSERT OR REPLACE INTO threat_patterns 
                    (pattern_id, name, pattern_type, signatures, time_window, threshold, 
                     mitre_mapping, description, confidence_baseline, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern.pattern_id,
                    pattern.name,
                    pattern.pattern_type,
                    json.dumps(pattern.signatures),
                    pattern.time_window,
                    pattern.threshold,
                    json.dumps(pattern.mitre_mapping),
                    pattern.description,
                    pattern.confidence_baseline,
                    datetime.now()
                ))
                
                self.threat_patterns[pattern.pattern_id] = pattern
    
    async def initialize_redis(self):
        """Initialize Redis connection"""
        redis_config = self.config.get('redis', {})
        self.redis_client = await aioredis.create_redis_pool(
            f"redis://{redis_config.get('host', 'localhost')}:{redis_config.get('port', 6379)}",
            password=redis_config.get('password'),
            db=redis_config.get('db', 0)
        )
    
    def extract_features_from_match(self, match: SignatureMatch) -> np.ndarray:
        """Extract features from signature match for ML analysis"""
        features = [
            match.signature_id,
            hash(match.source_ip) % 10000,  # Hash IP to numeric
            hash(match.destination_ip) % 10000,
            match.source_port,
            match.destination_port,
            len(match.payload) if match.payload else 0,
            match.timestamp.hour,
            match.timestamp.weekday(),
            1 if match.protocol == 'tcp' else 0,
            1 if match.protocol == 'udp' else 0,
            1 if match.severity == 'high' else 0,
            len(match.mitre_tactics) if match.mitre_tactics else 0,
            len(match.mitre_techniques) if match.mitre_techniques else 0
        ]
        
        return np.array(features).reshape(1, -1)
    
    def calculate_anomaly_score(self, match: SignatureMatch) -> float:
        """Calculate anomaly score using machine learning"""
        if not self.config.get('ml_models', {}).get('enable_anomaly_detection', True):
            return 0.5
        
        try:
            features = self.extract_features_from_match(match)
            
            # Use isolation forest to detect anomalies
            anomaly_score = self.anomaly_detector.decision_function(features)[0]
            
            # Normalize to 0-1 range (higher = more anomalous)
            normalized_score = max(0, min(1, (anomaly_score + 0.5) / 1.0))
            
            return normalized_score
            
        except Exception as e:
            logger.error(f"Error calculating anomaly score: {e}")
            return 0.5
    
    def calculate_false_positive_likelihood(self, match: SignatureMatch) -> float:
        """Calculate likelihood that this is a false positive"""
        if not self.config.get('ml_models', {}).get('enable_false_positive_reduction', True):
            return 0.3
        
        try:
            features = self.extract_features_from_match(match)
            
            # Use trained classifier to predict false positive likelihood
            if hasattr(self.false_positive_classifier, 'predict_proba'):
                fp_likelihood = self.false_positive_classifier.predict_proba(features)[0][1]
            else:
                # Fallback calculation based on heuristics
                fp_likelihood = self._heuristic_false_positive_score(match)
            
            return fp_likelihood
            
        except Exception as e:
            logger.error(f"Error calculating false positive likelihood: {e}")
            return 0.3
    
    def _heuristic_false_positive_score(self, match: SignatureMatch) -> float:
        """Heuristic-based false positive scoring"""
        score = 0.3  # Base score
        
        # Internal to internal traffic is more suspicious
        if self._is_internal_ip(match.source_ip) and self._is_internal_ip(match.destination_ip):
            score -= 0.1
        
        # High severity rules are typically more accurate
        if match.severity in ['high', 'critical']:
            score -= 0.15
        
        # Business hours activity might be more legitimate
        if 9 <= match.timestamp.hour <= 17:
            score += 0.1
        
        # Multiple MITRE techniques suggest complex attack
        if match.mitre_techniques and len(match.mitre_techniques) > 2:
            score -= 0.1
        
        return max(0.0, min(1.0, score))
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal"""
        try:
            addr = struct.unpack("!I", socket.inet_aton(ip))[0]
            
            # RFC 1918 private ranges
            return (
                (addr & 0xFF000000) == 0x0A000000 or  # 10.0.0.0/8
                (addr & 0xFFF00000) == 0xAC100000 or  # 172.16.0.0/12
                (addr & 0xFFFF0000) == 0xC0A80000     # 192.168.0.0/16
            )
        except:
            return False
    
    def calculate_threat_score(self, match: SignatureMatch) -> float:
        """Calculate comprehensive threat score"""
        try:
            features = self.extract_features_from_match(match)
            
            if self.config.get('ml_models', {}).get('enable_threat_scoring', True):
                # Use ML model for scoring
                threat_score = self.threat_scorer.predict(features)[0]
            else:
                # Fallback heuristic scoring
                threat_score = self._heuristic_threat_score(match)
            
            # Combine with anomaly score
            anomaly_weight = 0.3
            threat_weight = 0.7
            
            anomaly_score = self.calculate_anomaly_score(match)
            combined_score = (threat_weight * threat_score + 
                            anomaly_weight * anomaly_score)
            
            return max(0.0, min(1.0, combined_score))
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return match.confidence_score
    
    def _heuristic_threat_score(self, match: SignatureMatch) -> float:
        """Heuristic-based threat scoring"""
        score = match.confidence_score
        
        # Severity multiplier
        severity_multipliers = {
            'low': 0.5,
            'medium': 0.75,
            'high': 1.0,
            'critical': 1.25
        }
        score *= severity_multipliers.get(match.severity, 1.0)
        
        # Classification multiplier
        if 'trojan' in match.classification.lower():
            score *= 1.2
        elif 'exploit' in match.classification.lower():
            score *= 1.15
        elif 'policy' in match.classification.lower():
            score *= 0.8
        
        # MITRE tactics bonus
        if match.mitre_tactics:
            critical_tactics = {'TA0001', 'TA0008', 'TA0010', 'TA0011'}  # Initial Access, Lateral Movement, Exfiltration, C2
            if any(tactic in critical_tactics for tactic in match.mitre_tactics):
                score *= 1.1
        
        return max(0.0, min(1.0, score))
    
    async def process_signature_match(self, match_data: Dict[str, Any]) -> SignatureMatch:
        """Process a signature match and enhance with ML analysis"""
        start_time = time.time()
        
        try:
            # Create SignatureMatch object
            match = SignatureMatch(
                timestamp=datetime.fromisoformat(match_data.get('timestamp', datetime.now().isoformat())),
                signature_id=match_data.get('signature_id', 0),
                signature_name=match_data.get('signature_name', ''),
                source_ip=match_data.get('source_ip', ''),
                destination_ip=match_data.get('destination_ip', ''),
                source_port=match_data.get('source_port', 0),
                destination_port=match_data.get('destination_port', 0),
                protocol=match_data.get('protocol', ''),
                severity=match_data.get('severity', 'medium'),
                classification=match_data.get('classification', ''),
                confidence_score=match_data.get('confidence_score', 0.5),
                payload=match_data.get('payload'),
                metadata=match_data.get('metadata', {}),
                mitre_tactics=match_data.get('mitre_tactics', []),
                mitre_techniques=match_data.get('mitre_techniques', [])
            )
            
            # Enhanced analysis
            match.false_positive_likelihood = self.calculate_false_positive_likelihood(match)
            match.threat_score = self.calculate_threat_score(match)
            
            # Store in database
            await self._store_signature_match(match)
            
            # Check for attack chain patterns
            await self._check_attack_patterns(match)
            
            # Update performance metrics
            processing_time = time.time() - start_time
            self.performance_metrics['total_matches'] += 1
            self.performance_metrics['avg_processing_time'] = (
                (self.performance_metrics['avg_processing_time'] * (self.performance_metrics['total_matches'] - 1) +
                 processing_time) / self.performance_metrics['total_matches']
            )
            
            # Send to Redis for real-time access
            if self.redis_client:
                await self.redis_client.lpush(
                    'signature_matches',
                    json.dumps(asdict(match), default=str)
                )
                await self.redis_client.ltrim('signature_matches', 0, 9999)  # Keep last 10k matches
            
            return match
            
        except Exception as e:
            logger.error(f"Error processing signature match: {e}")
            raise
    
    async def _store_signature_match(self, match: SignatureMatch):
        """Store signature match in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO signature_matches 
                (timestamp, signature_id, signature_name, source_ip, destination_ip,
                 source_port, destination_port, protocol, severity, classification,
                 confidence_score, threat_score, false_positive_likelihood,
                 payload, metadata, mitre_tactics, mitre_techniques)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                match.timestamp,
                match.signature_id,
                match.signature_name,
                match.source_ip,
                match.destination_ip,
                match.source_port,
                match.destination_port,
                match.protocol,
                match.severity,
                match.classification,
                match.confidence_score,
                match.threat_score,
                match.false_positive_likelihood,
                match.payload,
                json.dumps(match.metadata) if match.metadata else None,
                json.dumps(match.mitre_tactics) if match.mitre_tactics else None,
                json.dumps(match.mitre_techniques) if match.mitre_techniques else None
            ))
    
    async def _check_attack_patterns(self, match: SignatureMatch):
        """Check if signature match fits attack chain patterns"""
        current_time = datetime.now()
        
        for pattern_id, pattern in self.threat_patterns.items():
            if match.signature_id in pattern.signatures:
                # Check for existing or create new attack chain
                chain_key = f"{match.source_ip}_{pattern_id}"
                
                if chain_key not in self.active_chains:
                    # Create new attack chain
                    self.active_chains[chain_key] = AttackChain(
                        chain_id=chain_key,
                        start_time=current_time,
                        end_time=current_time,
                        source_ip=match.source_ip,
                        target_ips=set([match.destination_ip]),
                        attack_stages=[],
                        total_confidence=0.0,
                        mitre_tactics=set(),
                        risk_score=0.0
                    )
                
                chain = self.active_chains[chain_key]
                
                # Update attack chain
                chain.end_time = current_time
                chain.target_ips.add(match.destination_ip)
                chain.attack_stages.append({
                    'timestamp': current_time,
                    'signature_id': match.signature_id,
                    'signature_name': match.signature_name,
                    'target_ip': match.destination_ip,
                    'confidence': match.confidence_score,
                    'threat_score': match.threat_score
                })
                
                if match.mitre_tactics:
                    chain.mitre_tactics.update(match.mitre_tactics)
                
                # Check if pattern threshold is met
                relevant_stages = [
                    stage for stage in chain.attack_stages
                    if stage['signature_id'] in pattern.signatures and
                    (current_time - stage['timestamp']).total_seconds() <= pattern.time_window
                ]
                
                if len(relevant_stages) >= pattern.threshold:
                    # Pattern detected!
                    chain.total_confidence = sum(stage['confidence'] for stage in relevant_stages) / len(relevant_stages)
                    chain.risk_score = self._calculate_chain_risk_score(chain, pattern)
                    
                    if chain.total_confidence >= self.config.get('detection', {}).get('min_chain_confidence', 0.8):
                        await self._alert_attack_chain(chain, pattern)
        
        # Clean up old chains
        await self._cleanup_old_chains()
    
    def _calculate_chain_risk_score(self, chain: AttackChain, pattern: ThreatPattern) -> float:
        """Calculate risk score for attack chain"""
        base_score = chain.total_confidence
        
        # Factor in number of targets
        target_multiplier = min(2.0, 1.0 + len(chain.target_ips) * 0.2)
        
        # Factor in attack duration
        duration = (chain.end_time - chain.start_time).total_seconds()
        duration_factor = min(1.5, duration / 3600)  # Longer attacks are more concerning
        
        # Factor in MITRE tactic diversity
        tactic_diversity = len(chain.mitre_tactics) / 14  # 14 MITRE tactics total
        
        risk_score = base_score * target_multiplier * (1 + duration_factor * 0.3) * (1 + tactic_diversity * 0.2)
        
        return min(1.0, risk_score)
    
    async def _alert_attack_chain(self, chain: AttackChain, pattern: ThreatPattern):
        """Generate alert for detected attack chain"""
        alert = {
            'alert_type': 'attack_chain_detected',
            'chain_id': chain.chain_id,
            'pattern_name': pattern.name,
            'source_ip': chain.source_ip,
            'target_ips': list(chain.target_ips),
            'start_time': chain.start_time.isoformat(),
            'end_time': chain.end_time.isoformat(),
            'total_confidence': chain.total_confidence,
            'risk_score': chain.risk_score,
            'mitre_tactics': list(chain.mitre_tactics),
            'attack_stages': chain.attack_stages,
            'severity': 'critical' if chain.risk_score > 0.8 else 'high'
        }
        
        # Store attack chain
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO attack_chains 
                (chain_id, start_time, end_time, source_ip, target_ips, 
                 attack_stages, total_confidence, mitre_tactics, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                chain.chain_id,
                chain.start_time,
                chain.end_time,
                chain.source_ip,
                json.dumps(list(chain.target_ips)),
                json.dumps(chain.attack_stages, default=str),
                chain.total_confidence,
                json.dumps(list(chain.mitre_tactics)),
                chain.risk_score
            ))
        
        # Send to Redis for real-time alerts
        if self.redis_client:
            await self.redis_client.lpush('attack_chain_alerts', json.dumps(alert, default=str))
            await self.redis_client.ltrim('attack_chain_alerts', 0, 999)  # Keep last 1k alerts
        
        logger.critical(f"Attack chain detected: {pattern.name} from {chain.source_ip} (Risk: {chain.risk_score:.2f})")
    
    async def _cleanup_old_chains(self):
        """Clean up old attack chains"""
        current_time = datetime.now()
        max_duration = self.config.get('detection', {}).get('max_attack_chain_duration', 3600)
        
        chains_to_remove = []
        for chain_key, chain in self.active_chains.items():
            if (current_time - chain.start_time).total_seconds() > max_duration:
                chains_to_remove.append(chain_key)
        
        for chain_key in chains_to_remove:
            del self.active_chains[chain_key]
    
    async def start_processing(self):
        """Start the signature detection engine"""
        logger.info("Starting signature detection engine")
        
        await self.initialize_redis()
        self.is_running = True
        
        # Start monitoring tasks
        asyncio.create_task(self._performance_monitor())
        asyncio.create_task(self._model_updater())
        
        # Process signature matches
        while self.is_running:
            try:
                # Get match data from queue (would be populated by Suricata EVE output)
                match_data = await asyncio.wait_for(
                    self.processing_queue.get(),
                    timeout=1.0
                )
                
                # Process the match
                enhanced_match = await self.process_signature_match(match_data)
                
                # Mark task as done
                self.processing_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _performance_monitor(self):
        """Monitor system performance"""
        while self.is_running:
            try:
                # Update performance metrics
                process = psutil.Process()
                self.performance_metrics['memory_usage'] = process.memory_info().rss // 1024 // 1024  # MB
                self.performance_metrics['cpu_usage'] = process.cpu_percent()
                
                # Check thresholds
                max_memory = self.config.get('performance', {}).get('max_memory_usage_mb', 2048)
                max_cpu = self.config.get('performance', {}).get('max_cpu_usage_percent', 80)
                
                if self.performance_metrics['memory_usage'] > max_memory:
                    logger.warning(f"High memory usage: {self.performance_metrics['memory_usage']}MB")
                
                if self.performance_metrics['cpu_usage'] > max_cpu:
                    logger.warning(f"High CPU usage: {self.performance_metrics['cpu_usage']}%")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in performance monitor: {e}")
                await asyncio.sleep(60)
    
    async def _model_updater(self):
        """Periodically update ML models"""
        update_frequency = self.config.get('ml_models', {}).get('model_update_frequency', 86400)
        
        while self.is_running:
            try:
                await asyncio.sleep(update_frequency)
                
                logger.info("Updating ML models with recent data")
                await self._retrain_models()
                
            except Exception as e:
                logger.error(f"Error updating models: {e}")
    
    async def _retrain_models(self):
        """Retrain ML models with recent data"""
        try:
            # Get recent training data
            training_data = self._get_training_data()
            
            if len(training_data) < 100:  # Need minimum samples
                logger.info("Insufficient training data for model update")
                return
            
            # Retrain anomaly detector
            features = np.array([self.extract_features_from_match(match).flatten() for match in training_data])
            self.anomaly_detector.fit(features)
            
            # Save updated models
            models_dir = Path("/var/lib/nsm/models")
            joblib.dump(self.anomaly_detector, models_dir / "anomaly_detector.pkl")
            
            logger.info("ML models updated successfully")
            
        except Exception as e:
            logger.error(f"Error retraining models: {e}")
    
    def _get_training_data(self) -> List[SignatureMatch]:
        """Get recent signature matches for training"""
        matches = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM signature_matches 
                WHERE timestamp > datetime('now', '-7 days')
                ORDER BY timestamp DESC
                LIMIT 10000
            """)
            
            for row in cursor.fetchall():
                match = SignatureMatch(
                    timestamp=datetime.fromisoformat(row[1]),
                    signature_id=row[2],
                    signature_name=row[3],
                    source_ip=row[4],
                    destination_ip=row[5],
                    source_port=row[6],
                    destination_port=row[7],
                    protocol=row[8],
                    severity=row[9],
                    classification=row[10],
                    confidence_score=row[11],
                    threat_score=row[12],
                    false_positive_likelihood=row[13],
                    payload=row[14],
                    metadata=json.loads(row[15]) if row[15] else {},
                    mitre_tactics=json.loads(row[16]) if row[16] else [],
                    mitre_techniques=json.loads(row[17]) if row[17] else []
                )
                matches.append(match)
        
        return matches
    
    def stop_processing(self):
        """Stop the signature detection engine"""
        logger.info("Stopping signature detection engine")
        self.is_running = False
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        return self.performance_metrics.copy()
    
    def get_active_chains(self) -> List[Dict[str, Any]]:
        """Get currently active attack chains"""
        return [asdict(chain) for chain in self.active_chains.values()]

async def main():
    """Main function for signature detection engine"""
    engine = AdvancedSignatureAnalyzer()
    
    try:
        # Start the detection engine
        await engine.start_processing()
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        engine.stop_processing()

if __name__ == "__main__":
    asyncio.run(main())