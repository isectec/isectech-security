#!/usr/bin/env python3
"""
iSECTECH SIEM Log Integrity Verifier
Advanced log integrity verification and tamper detection system
"""

import asyncio
import json
import logging
import hashlib
import hmac
import time
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

# Third-party imports
from kafka import KafkaProducer, KafkaConsumer
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import redis
import structlog

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class IntegrityRecord:
    """Log integrity record"""
    log_id: str
    timestamp: datetime
    source_system: str
    original_hash: str
    signature: str
    signature_algorithm: str
    chain_hash: Optional[str] = None
    previous_record_hash: Optional[str] = None
    verification_status: str = "pending"
    verification_timestamp: Optional[datetime] = None
    verification_errors: List[str] = None
    
    def __post_init__(self):
        if self.verification_errors is None:
            self.verification_errors = []

@dataclass
class TamperDetection:
    """Tamper detection result"""
    log_id: str
    tamper_detected: bool
    tamper_type: str
    detection_timestamp: datetime
    original_hash: str
    current_hash: str
    confidence_score: float
    evidence: List[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []

@dataclass
class ChainVerificationResult:
    """Chain verification result"""
    chain_id: str
    start_timestamp: datetime
    end_timestamp: datetime
    total_records: int
    verified_records: int
    failed_records: int
    missing_records: int
    chain_integrity: bool
    verification_errors: List[str] = None
    
    def __post_init__(self):
        if self.verification_errors is None:
            self.verification_errors = []

class LogIntegrityConfig:
    """Configuration management for log integrity verifier"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/integrity-verifier.yaml"):
        self.config_file = Path(config_file)
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            "verifier": {
                "worker_threads": 10,
                "batch_size": 100,
                "verification_interval": 300,  # 5 minutes
                "metrics_port": 9168,
                "enable_real_time": True,
                "enable_batch_verification": True,
                "enable_chain_verification": True
            },
            "kafka": {
                "bootstrap_servers": ["kafka-1.isectech.local:9092"],
                "input_topic": "parsed-logs",
                "integrity_topic": "log-integrity",
                "alert_topic": "integrity-alerts",
                "batch_size": 1000,
                "linger_ms": 1000,
                "compression_type": "gzip"
            },
            "redis": {
                "host": "redis.isectech.local",
                "port": 6379,
                "db": 8,
                "password": None
            },
            "integrity": {
                "hash_algorithm": "sha256",
                "signature_algorithm": "rsa_pss",
                "key_size": 2048,
                "enable_hmac": True,
                "hmac_key": "isectech_siem_integrity_key_2024",
                "enable_digital_signatures": True,
                "private_key_path": "/etc/isectech-siem/keys/integrity-private.pem",
                "public_key_path": "/etc/isectech-siem/keys/integrity-public.pem",
                "chain_verification_depth": 1000,
                "tamper_detection_threshold": 0.8
            },
            "storage": {
                "backend": "redis",  # redis, postgresql, elasticsearch
                "retention_days": 90,
                "compression": True,
                "encryption": True
            },
            "logging": {
                "level": "INFO",
                "format": "json"
            }
        }

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Prometheus metrics
integrity_checks_total = Counter('log_integrity_checks_total', 'Total integrity checks performed', ['status', 'source'])
integrity_verification_duration = Histogram('log_integrity_verification_duration_seconds', 'Integrity verification duration', ['type'])
tamper_detections_total = Counter('log_tamper_detections_total', 'Total tamper detections', ['type', 'source'])
chain_verifications_total = Counter('log_chain_verifications_total', 'Total chain verifications', ['status'])
integrity_records_stored = Gauge('log_integrity_records_stored', 'Number of integrity records stored')

# ═══════════════════════════════════════════════════════════════════════════════
# LOG INTEGRITY VERIFIER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class LogIntegrityVerifier:
    """Advanced log integrity verification and tamper detection system"""
    
    def __init__(self, config_file: str = "/etc/isectech-siem/integrity-verifier.yaml"):
        self.config = LogIntegrityConfig(config_file)
        self.logger = self._setup_logging()
        self.running = False
        self.tasks = []
        
        # Initialize components
        self.kafka_producer = None
        self.kafka_consumer = None
        self.redis_client = None
        self.executor = ThreadPoolExecutor(max_workers=self.config.config["verifier"]["worker_threads"])
        
        # Cryptographic components
        self.private_key = None
        self.public_key = None
        self.hmac_key = None
        
        # Verification state
        self.last_chain_verification = {}
        self.integrity_records_cache = {}
        
    def _setup_logging(self) -> structlog.BoundLogger:
        """Setup structured logging"""
        logging.basicConfig(
            level=getattr(logging, self.config.config["logging"]["level"]),
            format="%(message)s"
        )
        
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger("integrity_verifier")
    
    async def initialize(self):
        """Initialize verifier components"""
        self.logger.info("Initializing Log Integrity Verifier")
        
        # Initialize Kafka producer
        self.kafka_producer = KafkaProducer(
            bootstrap_servers=self.config.config["kafka"]["bootstrap_servers"],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            batch_size=self.config.config["kafka"]["batch_size"],
            linger_ms=self.config.config["kafka"]["linger_ms"],
            compression_type=self.config.config["kafka"]["compression_type"]
        )
        
        # Initialize Redis client
        redis_config = self.config.config["redis"]
        self.redis_client = redis.Redis(
            host=redis_config["host"],
            port=redis_config["port"],
            db=redis_config["db"],
            password=redis_config.get("password"),
            decode_responses=False  # Keep binary for crypto operations
        )
        
        # Load cryptographic keys
        await self._load_crypto_keys()
        
        # Start Prometheus metrics server
        start_http_server(self.config.config["verifier"]["metrics_port"])
        
        self.logger.info("Log Integrity Verifier initialized")
    
    async def _load_crypto_keys(self):
        """Load cryptographic keys for signing and verification"""
        integrity_config = self.config.config["integrity"]
        
        # Load HMAC key
        if integrity_config.get("enable_hmac"):
            self.hmac_key = integrity_config.get("hmac_key", "").encode('utf-8')
        
        # Load RSA keys for digital signatures
        if integrity_config.get("enable_digital_signatures"):
            try:
                # Load private key
                private_key_path = Path(integrity_config.get("private_key_path", ""))
                if private_key_path.exists():
                    with open(private_key_path, 'rb') as f:
                        self.private_key = load_pem_private_key(f.read(), password=None)
                else:
                    # Generate new key pair
                    await self._generate_key_pair()
                
                # Load public key
                public_key_path = Path(integrity_config.get("public_key_path", ""))
                if public_key_path.exists():
                    with open(public_key_path, 'rb') as f:
                        self.public_key = load_pem_public_key(f.read())
                else:
                    # Extract public key from private key
                    if self.private_key:
                        self.public_key = self.private_key.public_key()
                        await self._save_public_key(public_key_path)
                
            except Exception as e:
                self.logger.error("Failed to load cryptographic keys", error=str(e))
                # Fall back to HMAC only
                self.private_key = None
                self.public_key = None
    
    async def _generate_key_pair(self):
        """Generate new RSA key pair for integrity signing"""
        key_size = self.config.config["integrity"].get("key_size", 2048)
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Save private key
        private_key_path = Path(self.config.config["integrity"].get("private_key_path", "/tmp/integrity-private.pem"))
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(private_key_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Set secure permissions
        private_key_path.chmod(0o600)
        
        self.logger.info("Generated new RSA key pair", key_size=key_size)
    
    async def _save_public_key(self, public_key_path: Path):
        """Save public key to file"""
        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(public_key_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        public_key_path.chmod(0o644)
    
    async def start(self):
        """Start the integrity verifier"""
        self.logger.info("Starting Log Integrity Verifier")
        self.running = True
        
        # Start real-time verification if enabled
        if self.config.config["verifier"]["enable_real_time"]:
            task = asyncio.create_task(self._real_time_verification_loop())
            self.tasks.append(task)
        
        # Start batch verification if enabled
        if self.config.config["verifier"]["enable_batch_verification"]:
            task = asyncio.create_task(self._batch_verification_loop())
            self.tasks.append(task)
        
        # Start chain verification if enabled
        if self.config.config["verifier"]["enable_chain_verification"]:
            task = asyncio.create_task(self._chain_verification_loop())
            self.tasks.append(task)
        
        # Start monitoring task
        self.tasks.append(asyncio.create_task(self._monitoring_loop()))
        
        # Wait for all tasks
        await asyncio.gather(*self.tasks, return_exceptions=True)
    
    async def stop(self):
        """Stop the integrity verifier"""
        self.logger.info("Stopping Log Integrity Verifier")
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Close connections
        if self.kafka_producer:
            self.kafka_producer.close()
        if self.kafka_consumer:
            self.kafka_consumer.close()
        if self.redis_client:
            self.redis_client.close()
        
        self.executor.shutdown(wait=True)
    
    async def _real_time_verification_loop(self):
        """Real-time log integrity verification loop"""
        self.logger.info("Starting real-time verification loop")
        
        # Initialize Kafka consumer
        self.kafka_consumer = KafkaConsumer(
            self.config.config["kafka"]["input_topic"],
            bootstrap_servers=self.config.config["kafka"]["bootstrap_servers"],
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            group_id='integrity-verifier'
        )
        
        while self.running:
            try:
                # Poll for new messages
                messages = self.kafka_consumer.poll(timeout_ms=1000)
                
                for topic_partition, records in messages.items():
                    for record in records:
                        await self._verify_log_integrity(record.value)
                
            except Exception as e:
                self.logger.error("Real-time verification loop error", error=str(e))
                await asyncio.sleep(5)
    
    async def _verify_log_integrity(self, log_event: Dict[str, Any]):
        """Verify integrity of a single log event"""
        start_time = time.time()
        
        try:
            log_id = log_event.get("log_hash", "")
            source_system = log_event.get("source_system", "unknown")
            
            if not log_id:
                self.logger.warning("Log event missing hash", source=source_system)
                return
            
            # Create integrity record
            integrity_record = await self._create_integrity_record(log_event)
            
            # Perform verification
            verification_result = await self._perform_verification(log_event, integrity_record)
            
            # Update integrity record with results
            integrity_record.verification_status = "verified" if verification_result else "failed"
            integrity_record.verification_timestamp = datetime.now(timezone.utc)
            
            # Store integrity record
            await self._store_integrity_record(integrity_record)
            
            # Check for tampering
            if not verification_result:
                tamper_detection = await self._detect_tampering(log_event, integrity_record)
                if tamper_detection.tamper_detected:
                    await self._handle_tamper_detection(tamper_detection)
            
            # Update metrics
            status = "verified" if verification_result else "failed"
            integrity_checks_total.labels(status=status, source=source_system).inc()
            integrity_verification_duration.labels(type="real_time").observe(time.time() - start_time)
            
        except Exception as e:
            self.logger.error("Failed to verify log integrity", error=str(e), log_id=log_id)
            integrity_checks_total.labels(status="error", source=source_system).inc()
    
    async def _create_integrity_record(self, log_event: Dict[str, Any]) -> IntegrityRecord:
        """Create integrity record for a log event"""
        log_id = log_event.get("log_hash", "")
        timestamp = datetime.fromisoformat(log_event.get("timestamp", datetime.now(timezone.utc).isoformat()))
        source_system = log_event.get("source_system", "unknown")
        raw_message = log_event.get("raw_message", "")
        
        # Calculate hash
        original_hash = self._calculate_hash(raw_message)
        
        # Generate signature
        signature = await self._generate_signature(raw_message, original_hash)
        
        # Get previous record hash for chaining
        previous_record_hash = await self._get_previous_record_hash(source_system)
        
        # Calculate chain hash
        chain_hash = None
        if previous_record_hash:
            chain_data = f"{original_hash}:{previous_record_hash}"
            chain_hash = self._calculate_hash(chain_data)
        
        return IntegrityRecord(
            log_id=log_id,
            timestamp=timestamp,
            source_system=source_system,
            original_hash=original_hash,
            signature=signature,
            signature_algorithm=self.config.config["integrity"]["signature_algorithm"],
            chain_hash=chain_hash,
            previous_record_hash=previous_record_hash
        )
    
    def _calculate_hash(self, data: str) -> str:
        """Calculate hash of data"""
        hash_algorithm = self.config.config["integrity"]["hash_algorithm"]
        hash_func = getattr(hashlib, hash_algorithm)
        return hash_func(data.encode('utf-8')).hexdigest()
    
    async def _generate_signature(self, data: str, data_hash: str) -> str:
        """Generate signature for data"""
        signature_data = f"{data_hash}:{int(time.time())}"
        
        # HMAC signature
        if self.hmac_key:
            hmac_signature = hmac.new(
                self.hmac_key,
                signature_data.encode('utf-8'),
                getattr(hashlib, self.config.config["integrity"]["hash_algorithm"])
            ).hexdigest()
            
            # If RSA is also available, combine signatures
            if self.private_key:
                try:
                    rsa_signature = self.private_key.sign(
                        signature_data.encode('utf-8'),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    
                    combined_signature = {
                        "hmac": hmac_signature,
                        "rsa": base64.b64encode(rsa_signature).decode('utf-8'),
                        "timestamp": int(time.time())
                    }
                    
                    return base64.b64encode(json.dumps(combined_signature).encode('utf-8')).decode('utf-8')
                
                except Exception as e:
                    self.logger.warning("RSA signature failed, using HMAC only", error=str(e))
            
            return hmac_signature
        
        # RSA signature only
        elif self.private_key:
            try:
                rsa_signature = self.private_key.sign(
                    signature_data.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                return base64.b64encode(rsa_signature).decode('utf-8')
            
            except Exception as e:
                self.logger.error("Failed to generate RSA signature", error=str(e))
        
        # Fallback: simple hash-based signature
        return self._calculate_hash(signature_data)
    
    async def _get_previous_record_hash(self, source_system: str) -> Optional[str]:
        """Get hash of previous integrity record for chaining"""
        try:
            key = f"integrity:last:{source_system}"
            return self.redis_client.get(key)
        except Exception as e:
            self.logger.error("Failed to get previous record hash", error=str(e))
            return None
    
    async def _perform_verification(self, log_event: Dict[str, Any], integrity_record: IntegrityRecord) -> bool:
        """Perform integrity verification"""
        try:
            raw_message = log_event.get("raw_message", "")
            
            # Verify hash
            calculated_hash = self._calculate_hash(raw_message)
            if calculated_hash != integrity_record.original_hash:
                integrity_record.verification_errors.append("Hash mismatch")
                return False
            
            # Verify signature
            if not await self._verify_signature(raw_message, integrity_record.original_hash, integrity_record.signature):
                integrity_record.verification_errors.append("Signature verification failed")
                return False
            
            # Verify timestamp (within acceptable drift)
            timestamp_diff = abs((datetime.now(timezone.utc) - integrity_record.timestamp).total_seconds())
            max_drift = self.config.config["integrity"].get("max_timestamp_drift", 300)
            if timestamp_diff > max_drift:
                integrity_record.verification_errors.append(f"Timestamp drift too large: {timestamp_diff}s")
                return False
            
            return True
            
        except Exception as e:
            integrity_record.verification_errors.append(f"Verification error: {str(e)}")
            return False
    
    async def _verify_signature(self, data: str, data_hash: str, signature: str) -> bool:
        """Verify signature"""
        try:
            signature_data = f"{data_hash}:{int(time.time())}"
            
            # Try to decode as combined signature
            try:
                decoded_sig = json.loads(base64.b64decode(signature).decode('utf-8'))
                if isinstance(decoded_sig, dict) and "hmac" in decoded_sig:
                    # Combined HMAC + RSA signature
                    hmac_valid = False
                    rsa_valid = False
                    
                    # Verify HMAC
                    if self.hmac_key and "hmac" in decoded_sig:
                        expected_hmac = hmac.new(
                            self.hmac_key,
                            signature_data.encode('utf-8'),
                            getattr(hashlib, self.config.config["integrity"]["hash_algorithm"])
                        ).hexdigest()
                        hmac_valid = hmac.compare_digest(expected_hmac, decoded_sig["hmac"])
                    
                    # Verify RSA
                    if self.public_key and "rsa" in decoded_sig:
                        try:
                            rsa_signature = base64.b64decode(decoded_sig["rsa"])
                            self.public_key.verify(
                                rsa_signature,
                                signature_data.encode('utf-8'),
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                            )
                            rsa_valid = True
                        except InvalidSignature:
                            rsa_valid = False
                    
                    return hmac_valid or rsa_valid
            except:
                pass
            
            # Try HMAC verification
            if self.hmac_key:
                expected_hmac = hmac.new(
                    self.hmac_key,
                    signature_data.encode('utf-8'),
                    getattr(hashlib, self.config.config["integrity"]["hash_algorithm"])
                ).hexdigest()
                if hmac.compare_digest(expected_hmac, signature):
                    return True
            
            # Try RSA verification
            if self.public_key:
                try:
                    rsa_signature = base64.b64decode(signature)
                    self.public_key.verify(
                        rsa_signature,
                        signature_data.encode('utf-8'),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    return True
                except (InvalidSignature, Exception):
                    pass
            
            # Fallback: hash-based verification
            expected_hash = self._calculate_hash(signature_data)
            return expected_hash == signature
            
        except Exception as e:
            self.logger.error("Signature verification error", error=str(e))
            return False
    
    async def _store_integrity_record(self, integrity_record: IntegrityRecord):
        """Store integrity record"""
        try:
            # Store in Redis
            key = f"integrity:record:{integrity_record.log_id}"
            value = json.dumps(asdict(integrity_record), default=str)
            
            # Set TTL based on retention policy
            retention_days = self.config.config["storage"].get("retention_days", 90)
            ttl = retention_days * 24 * 60 * 60
            
            self.redis_client.setex(key, ttl, value)
            
            # Update last record for chaining
            last_key = f"integrity:last:{integrity_record.source_system}"
            self.redis_client.set(last_key, integrity_record.original_hash)
            
            # Update metrics
            integrity_records_stored.inc()
            
        except Exception as e:
            self.logger.error("Failed to store integrity record", error=str(e))
    
    async def _detect_tampering(self, log_event: Dict[str, Any], integrity_record: IntegrityRecord) -> TamperDetection:
        """Detect tampering in log event"""
        log_id = log_event.get("log_hash", "")
        raw_message = log_event.get("raw_message", "")
        current_hash = self._calculate_hash(raw_message)
        
        tamper_detected = False
        tamper_type = "none"
        confidence_score = 0.0
        evidence = []
        
        # Hash comparison
        if current_hash != integrity_record.original_hash:
            tamper_detected = True
            tamper_type = "content_modification"
            confidence_score += 0.5
            evidence.append("Hash mismatch detected")
        
        # Signature verification failure
        if integrity_record.verification_status == "failed":
            tamper_detected = True
            if tamper_type == "none":
                tamper_type = "signature_tampering"
            confidence_score += 0.3
            evidence.append("Signature verification failed")
        
        # Timestamp anomalies
        if integrity_record.verification_errors:
            for error in integrity_record.verification_errors:
                if "timestamp" in error.lower():
                    tamper_detected = True
                    tamper_type = "timestamp_manipulation"
                    confidence_score += 0.2
                    evidence.append(f"Timestamp anomaly: {error}")
        
        # Chain verification (if applicable)
        chain_integrity = await self._verify_chain_integrity(integrity_record)
        if not chain_integrity:
            tamper_detected = True
            tamper_type = "chain_tampering"
            confidence_score += 0.4
            evidence.append("Chain integrity violation")
        
        # Apply detection threshold
        threshold = self.config.config["integrity"].get("tamper_detection_threshold", 0.8)
        if confidence_score < threshold:
            tamper_detected = False
        
        return TamperDetection(
            log_id=log_id,
            tamper_detected=tamper_detected,
            tamper_type=tamper_type,
            detection_timestamp=datetime.now(timezone.utc),
            original_hash=integrity_record.original_hash,
            current_hash=current_hash,
            confidence_score=confidence_score,
            evidence=evidence
        )
    
    async def _verify_chain_integrity(self, integrity_record: IntegrityRecord) -> bool:
        """Verify chain integrity for the record"""
        if not integrity_record.chain_hash or not integrity_record.previous_record_hash:
            return True  # No chain to verify
        
        try:
            # Reconstruct chain hash
            chain_data = f"{integrity_record.original_hash}:{integrity_record.previous_record_hash}"
            expected_chain_hash = self._calculate_hash(chain_data)
            
            return expected_chain_hash == integrity_record.chain_hash
            
        except Exception as e:
            self.logger.error("Chain verification error", error=str(e))
            return False
    
    async def _handle_tamper_detection(self, tamper_detection: TamperDetection):
        """Handle detected tampering"""
        # Update metrics
        tamper_detections_total.labels(
            type=tamper_detection.tamper_type,
            source="unknown"  # Would extract from log context
        ).inc()
        
        # Create alert
        alert = {
            "alert_id": f"tamper_{tamper_detection.log_id}_{int(time.time())}",
            "timestamp": tamper_detection.detection_timestamp.isoformat(),
            "type": "log_tampering",
            "severity": "high",
            "log_id": tamper_detection.log_id,
            "tamper_type": tamper_detection.tamper_type,
            "confidence_score": tamper_detection.confidence_score,
            "evidence": tamper_detection.evidence,
            "original_hash": tamper_detection.original_hash,
            "current_hash": tamper_detection.current_hash
        }
        
        # Send alert to Kafka
        self.kafka_producer.send(
            self.config.config["kafka"]["alert_topic"],
            value=alert
        )
        
        self.logger.warning(
            "Tamper detection alert",
            log_id=tamper_detection.log_id,
            tamper_type=tamper_detection.tamper_type,
            confidence=tamper_detection.confidence_score
        )
    
    async def _batch_verification_loop(self):
        """Batch verification loop for periodic integrity checks"""
        while self.running:
            try:
                await asyncio.sleep(self.config.config["verifier"]["verification_interval"])
                
                if not self.running:
                    break
                
                # Perform batch verification
                await self._perform_batch_verification()
                
            except Exception as e:
                self.logger.error("Batch verification loop error", error=str(e))
                await asyncio.sleep(60)
    
    async def _perform_batch_verification(self):
        """Perform batch verification of stored logs"""
        start_time = time.time()
        
        try:
            # Get batch of integrity records to verify
            records = await self._get_integrity_records_batch()
            
            verified_count = 0
            failed_count = 0
            
            for record in records:
                # Re-verify each record
                verification_result = await self._reverify_integrity_record(record)
                
                if verification_result:
                    verified_count += 1
                else:
                    failed_count += 1
                    # Handle verification failure
                    await self._handle_verification_failure(record)
            
            # Update metrics
            integrity_verification_duration.labels(type="batch").observe(time.time() - start_time)
            
            self.logger.info(
                "Batch verification completed",
                verified=verified_count,
                failed=failed_count,
                duration=time.time() - start_time
            )
            
        except Exception as e:
            self.logger.error("Batch verification failed", error=str(e))
    
    async def _get_integrity_records_batch(self) -> List[IntegrityRecord]:
        """Get batch of integrity records for verification"""
        # This is a simplified implementation
        # In production, would implement proper pagination and filtering
        records = []
        
        try:
            # Get record keys from Redis
            pattern = "integrity:record:*"
            keys = self.redis_client.keys(pattern)
            
            batch_size = self.config.config["verifier"]["batch_size"]
            for key in keys[:batch_size]:
                record_data = self.redis_client.get(key)
                if record_data:
                    record_dict = json.loads(record_data)
                    # Convert timestamp strings back to datetime
                    record_dict["timestamp"] = datetime.fromisoformat(record_dict["timestamp"])
                    if record_dict.get("verification_timestamp"):
                        record_dict["verification_timestamp"] = datetime.fromisoformat(record_dict["verification_timestamp"])
                    
                    records.append(IntegrityRecord(**record_dict))
        
        except Exception as e:
            self.logger.error("Failed to get integrity records batch", error=str(e))
        
        return records
    
    async def _reverify_integrity_record(self, record: IntegrityRecord) -> bool:
        """Re-verify an integrity record"""
        try:
            # This would involve re-fetching the original log and verifying
            # For now, we'll check signature and chain integrity
            
            # Verify signature (simplified)
            signature_valid = True  # Would implement actual re-verification
            
            # Verify chain integrity
            chain_valid = await self._verify_chain_integrity(record)
            
            return signature_valid and chain_valid
            
        except Exception as e:
            self.logger.error("Re-verification failed", record_id=record.log_id, error=str(e))
            return False
    
    async def _handle_verification_failure(self, record: IntegrityRecord):
        """Handle verification failure"""
        self.logger.warning(
            "Verification failure detected",
            record_id=record.log_id,
            source=record.source_system,
            errors=record.verification_errors
        )
        
        # Create alert for verification failure
        alert = {
            "alert_id": f"verification_failure_{record.log_id}_{int(time.time())}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "verification_failure",
            "severity": "medium",
            "record_id": record.log_id,
            "source_system": record.source_system,
            "verification_errors": record.verification_errors
        }
        
        self.kafka_producer.send(
            self.config.config["kafka"]["alert_topic"],
            value=alert
        )
    
    async def _chain_verification_loop(self):
        """Chain verification loop for verifying log chains"""
        while self.running:
            try:
                await asyncio.sleep(self.config.config["verifier"]["verification_interval"] * 2)
                
                if not self.running:
                    break
                
                # Perform chain verification for each source system
                source_systems = await self._get_source_systems()
                
                for source_system in source_systems:
                    await self._verify_log_chain(source_system)
                
            except Exception as e:
                self.logger.error("Chain verification loop error", error=str(e))
                await asyncio.sleep(120)
    
    async def _get_source_systems(self) -> List[str]:
        """Get list of source systems with integrity records"""
        try:
            keys = self.redis_client.keys("integrity:last:*")
            return [key.decode('utf-8').split(':', 2)[2] for key in keys]
        except Exception as e:
            self.logger.error("Failed to get source systems", error=str(e))
            return []
    
    async def _verify_log_chain(self, source_system: str):
        """Verify integrity chain for a source system"""
        start_time = time.time()
        
        try:
            # Get chain records
            chain_records = await self._get_chain_records(source_system)
            
            if not chain_records:
                return
            
            verification_result = ChainVerificationResult(
                chain_id=source_system,
                start_timestamp=min(r.timestamp for r in chain_records),
                end_timestamp=max(r.timestamp for r in chain_records),
                total_records=len(chain_records),
                verified_records=0,
                failed_records=0,
                missing_records=0,
                chain_integrity=True
            )
            
            # Verify chain continuity
            for i, record in enumerate(chain_records):
                if i > 0:
                    previous_record = chain_records[i-1]
                    
                    # Verify chain link
                    if record.previous_record_hash != previous_record.original_hash:
                        verification_result.chain_integrity = False
                        verification_result.failed_records += 1
                        verification_result.verification_errors.append(
                            f"Chain break at record {record.log_id}"
                        )
                    else:
                        verification_result.verified_records += 1
                else:
                    verification_result.verified_records += 1
            
            # Update metrics
            status = "verified" if verification_result.chain_integrity else "failed"
            chain_verifications_total.labels(status=status).inc()
            
            # Log result
            self.logger.info(
                "Chain verification completed",
                source_system=source_system,
                total_records=verification_result.total_records,
                verified_records=verification_result.verified_records,
                failed_records=verification_result.failed_records,
                chain_integrity=verification_result.chain_integrity,
                duration=time.time() - start_time
            )
            
        except Exception as e:
            self.logger.error("Chain verification failed", source_system=source_system, error=str(e))
    
    async def _get_chain_records(self, source_system: str) -> List[IntegrityRecord]:
        """Get chain records for a source system"""
        # This is a simplified implementation
        # In production, would implement proper ordering and pagination
        records = []
        
        try:
            # Get all records for source system
            pattern = f"integrity:record:*"
            keys = self.redis_client.keys(pattern)
            
            for key in keys:
                record_data = self.redis_client.get(key)
                if record_data:
                    record_dict = json.loads(record_data)
                    if record_dict.get("source_system") == source_system:
                        # Convert timestamps
                        record_dict["timestamp"] = datetime.fromisoformat(record_dict["timestamp"])
                        if record_dict.get("verification_timestamp"):
                            record_dict["verification_timestamp"] = datetime.fromisoformat(record_dict["verification_timestamp"])
                        
                        records.append(IntegrityRecord(**record_dict))
            
            # Sort by timestamp
            records.sort(key=lambda r: r.timestamp)
            
        except Exception as e:
            self.logger.error("Failed to get chain records", source_system=source_system, error=str(e))
        
        return records
    
    async def _monitoring_loop(self):
        """Monitoring and health check loop"""
        while self.running:
            try:
                # Perform health checks
                await self._health_check()
                
                # Update metrics
                record_count = len(self.redis_client.keys("integrity:record:*"))
                integrity_records_stored.set(record_count)
                
                self.logger.info("Health check completed", integrity_records=record_count)
                
            except Exception as e:
                self.logger.error("Monitoring loop error", error=str(e))
            
            await asyncio.sleep(60)  # Health check every minute
    
    async def _health_check(self):
        """Perform health checks on verifier components"""
        # Check Kafka connectivity
        try:
            self.kafka_producer.bootstrap_connected()
        except Exception as e:
            self.logger.error("Kafka health check failed", error=str(e))
        
        # Check Redis connectivity
        try:
            self.redis_client.ping()
        except Exception as e:
            self.logger.error("Redis health check failed", error=str(e))
        
        # Check cryptographic keys
        if self.config.config["integrity"].get("enable_digital_signatures"):
            if not self.private_key or not self.public_key:
                self.logger.warning("Digital signature keys not available")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main execution function"""
    verifier = LogIntegrityVerifier()
    
    # Setup signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(verifier.stop())
    
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await verifier.initialize()
        await verifier.start()
    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        print(f"Verifier error: {e}")
    finally:
        await verifier.stop()

if __name__ == "__main__":
    asyncio.run(main())