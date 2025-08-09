#!/usr/bin/env python3
# iSECTECH Encrypted Traffic Analyzer
# Production-grade encrypted traffic analysis without payload decryption

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
import socket
import struct
import base64
import binascii

# Cryptographic analysis imports
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import ssl
import OpenSSL.crypto

# Network analysis imports
import dpkt
import pcap
from scapy.all import *
import pyshark

# Machine learning imports
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/encrypted-analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TLSHandshake:
    """TLS handshake information"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    
    # TLS information
    tls_version: str
    cipher_suites: List[str]
    extensions: List[str]
    supported_groups: List[str]
    signature_algorithms: List[str]
    server_name: Optional[str] = None
    
    # Certificates
    certificates: List[Dict[str, Any]] = None
    certificate_chain_length: int = 0
    
    # JA3 fingerprints
    ja3_client: Optional[str] = None
    ja3s_server: Optional[str] = None
    
    # Timing information
    handshake_duration: Optional[float] = None
    certificate_chain_time: Optional[float] = None

@dataclass
class EncryptedFlow:
    """Encrypted network flow analysis"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    
    # Flow characteristics
    total_bytes: int
    total_packets: int
    duration: float
    bytes_ratio: float  # client to server ratio
    
    # Encrypted traffic patterns
    packet_sizes: List[int]
    inter_arrival_times: List[float]
    burst_patterns: List[Dict[str, Any]]
    
    # Statistical features
    entropy_score: float
    periodicity_score: float
    randomness_score: float
    
    # TLS information
    tls_handshake: Optional[TLSHandshake] = None
    application_protocol: Optional[str] = None
    
    # Threat indicators
    threat_score: float = 0.0
    anomaly_indicators: List[str] = None
    
@dataclass
class EncryptedThreatAlert:
    """Threat alert for encrypted traffic"""
    alert_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    threat_type: str
    severity: str
    confidence: float
    
    description: str
    indicators: Dict[str, Any]
    context: Dict[str, Any]
    
    # Supporting evidence
    tls_fingerprints: Dict[str, str] = None
    certificate_anomalies: List[str] = None
    traffic_patterns: Dict[str, Any] = None
    
    # Recommended actions
    recommendations: List[str] = None

class JA3FingerprintAnalyzer:
    """JA3/JA3S TLS fingerprinting implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.known_ja3_db = {}
        self.threat_ja3_db = {}
        self._load_ja3_databases()
    
    def _load_ja3_databases(self):
        """Load known and threat JA3 fingerprint databases"""
        try:
            # Load known good JA3 fingerprints
            known_ja3_path = "/var/lib/nsm/ja3/known_ja3.json"
            if Path(known_ja3_path).exists():
                with open(known_ja3_path, 'r') as f:
                    self.known_ja3_db = json.load(f)
            
            # Load threat JA3 fingerprints
            threat_ja3_path = "/var/lib/nsm/ja3/threat_ja3.json"
            if Path(threat_ja3_path).exists():
                with open(threat_ja3_path, 'r') as f:
                    self.threat_ja3_db = json.load(f)
                    
        except Exception as e:
            logger.warning(f"Error loading JA3 databases: {e}")
    
    def calculate_ja3_client(self, tls_version: str, cipher_suites: List[str], 
                           extensions: List[str], supported_groups: List[str],
                           signature_algorithms: List[str]) -> str:
        """Calculate JA3 client fingerprint"""
        try:
            # JA3 format: TLSVersion,Ciphers,Extensions,SupportedGroups,SignatureAlgorithms
            version_map = {
                'TLSv1.0': '769',
                'TLSv1.1': '770', 
                'TLSv1.2': '771',
                'TLSv1.3': '772'
            }
            
            version_code = version_map.get(tls_version, '0')
            
            # Convert lists to comma-separated strings
            ciphers_str = '-'.join(sorted(cipher_suites))
            extensions_str = '-'.join(sorted(extensions))
            groups_str = '-'.join(sorted(supported_groups))
            signatures_str = '-'.join(sorted(signature_algorithms))
            
            # Create JA3 string
            ja3_string = f"{version_code},{ciphers_str},{extensions_str},{groups_str},{signatures_str}"
            
            # Calculate MD5 hash
            ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
            
            return ja3_hash
            
        except Exception as e:
            logger.error(f"Error calculating JA3 fingerprint: {e}")
            return ""
    
    def calculate_ja3s_server(self, tls_version: str, cipher_suite: str,
                            extensions: List[str]) -> str:
        """Calculate JA3S server fingerprint"""
        try:
            # JA3S format: TLSVersion,Cipher,Extensions
            version_map = {
                'TLSv1.0': '769',
                'TLSv1.1': '770',
                'TLSv1.2': '771', 
                'TLSv1.3': '772'
            }
            
            version_code = version_map.get(tls_version, '0')
            extensions_str = '-'.join(sorted(extensions))
            
            # Create JA3S string
            ja3s_string = f"{version_code},{cipher_suite},{extensions_str}"
            
            # Calculate MD5 hash
            ja3s_hash = hashlib.md5(ja3s_string.encode()).hexdigest()
            
            return ja3s_hash
            
        except Exception as e:
            logger.error(f"Error calculating JA3S fingerprint: {e}")
            return ""
    
    def analyze_ja3_fingerprint(self, ja3_hash: str) -> Dict[str, Any]:
        """Analyze JA3 fingerprint for threats and identification"""
        analysis = {
            'hash': ja3_hash,
            'is_known': False,
            'is_threat': False,
            'application': 'Unknown',
            'description': '',
            'threat_level': 'low',
            'last_seen': None
        }
        
        # Check against known fingerprints
        if ja3_hash in self.known_ja3_db:
            fingerprint_info = self.known_ja3_db[ja3_hash]
            analysis.update({
                'is_known': True,
                'application': fingerprint_info.get('application', 'Unknown'),
                'description': fingerprint_info.get('description', ''),
                'last_seen': fingerprint_info.get('last_seen')
            })
        
        # Check against threat fingerprints
        if ja3_hash in self.threat_ja3_db:
            threat_info = self.threat_ja3_db[ja3_hash]
            analysis.update({
                'is_threat': True,
                'threat_level': threat_info.get('threat_level', 'medium'),
                'description': threat_info.get('description', 'Known malicious fingerprint'),
                'malware_family': threat_info.get('malware_family'),
                'first_seen': threat_info.get('first_seen')
            })
        
        # Analyze fingerprint characteristics
        analysis['characteristics'] = self._analyze_fingerprint_characteristics(ja3_hash)
        
        return analysis
    
    def _analyze_fingerprint_characteristics(self, ja3_hash: str) -> Dict[str, Any]:
        """Analyze characteristics of JA3 fingerprint"""
        # This would analyze the actual TLS parameters behind the hash
        # For now, return basic characteristics
        return {
            'uniqueness': 'medium',  # Would calculate based on frequency
            'complexity': 'medium',  # Would analyze cipher suite complexity
            'age': 'unknown'         # Would track first/last seen
        }
    
    def update_ja3_database(self, ja3_hash: str, info: Dict[str, Any], db_type: str = 'known'):
        """Update JA3 database with new fingerprint"""
        try:
            if db_type == 'known':
                self.known_ja3_db[ja3_hash] = info
                db_path = "/var/lib/nsm/ja3/known_ja3.json"
            else:
                self.threat_ja3_db[ja3_hash] = info
                db_path = "/var/lib/nsm/ja3/threat_ja3.json"
            
            # Ensure directory exists
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save updated database
            with open(db_path, 'w') as f:
                if db_type == 'known':
                    json.dump(self.known_ja3_db, f, indent=2)
                else:
                    json.dump(self.threat_ja3_db, f, indent=2)
                    
        except Exception as e:
            logger.error(f"Error updating JA3 database: {e}")

class CertificateAnalyzer:
    """X.509 certificate analysis for threat detection"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.suspicious_patterns = self._load_suspicious_patterns()
        
    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load suspicious certificate patterns"""
        return {
            'suspicious_subjects': [
                r'.*\.onion$',
                r'.*\.(tk|ml|ga|cf)$',
                r'localhost',
                r'test\..*',
                r'example\..*',
                r'.*[0-9]{10,}.*'  # Long numeric sequences
            ],
            'suspicious_issuers': [
                r'.*test.*',
                r'.*localhost.*',
                r'.*self.*signed.*',
                r'.*temp.*'
            ],
            'suspicious_extensions': [
                'critical',
                'unknown'
            ]
        }
    
    def analyze_certificate_chain(self, certificates: List[bytes]) -> Dict[str, Any]:
        """Analyze certificate chain for suspicious indicators"""
        analysis = {
            'chain_length': len(certificates),
            'certificates': [],
            'trust_issues': [],
            'suspicious_indicators': [],
            'validity_issues': [],
            'overall_score': 0.0
        }
        
        try:
            for i, cert_der in enumerate(certificates):
                cert_analysis = self.analyze_single_certificate(cert_der, i == 0)
                analysis['certificates'].append(cert_analysis)
                
                # Aggregate issues
                analysis['trust_issues'].extend(cert_analysis.get('trust_issues', []))
                analysis['suspicious_indicators'].extend(cert_analysis.get('suspicious_indicators', []))
                analysis['validity_issues'].extend(cert_analysis.get('validity_issues', []))
            
            # Calculate overall score
            analysis['overall_score'] = self._calculate_certificate_score(analysis)
            
        except Exception as e:
            logger.error(f"Error analyzing certificate chain: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def analyze_single_certificate(self, cert_der: bytes, is_leaf: bool = False) -> Dict[str, Any]:
        """Analyze a single X.509 certificate"""
        analysis = {
            'is_leaf': is_leaf,
            'subject': {},
            'issuer': {},
            'validity': {},
            'extensions': {},
            'public_key': {},
            'trust_issues': [],
            'suspicious_indicators': [],
            'validity_issues': []
        }
        
        try:
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der)
            
            # Extract subject information
            analysis['subject'] = self._extract_name_info(cert.subject)
            analysis['issuer'] = self._extract_name_info(cert.issuer)
            
            # Extract validity information
            analysis['validity'] = {
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'is_expired': cert.not_valid_after < datetime.now(),
                'is_not_yet_valid': cert.not_valid_before > datetime.now(),
                'validity_period_days': (cert.not_valid_after - cert.not_valid_before).days
            }
            
            # Analyze public key
            analysis['public_key'] = self._analyze_public_key(cert.public_key())
            
            # Analyze extensions
            analysis['extensions'] = self._analyze_extensions(cert)
            
            # Check for suspicious patterns
            self._check_suspicious_patterns(analysis)
            
            # Check certificate validity
            self._check_certificate_validity(analysis)
            
        except Exception as e:
            logger.error(f"Error analyzing certificate: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _extract_name_info(self, name: x509.Name) -> Dict[str, str]:
        """Extract information from X.509 Name object"""
        name_info = {}
        
        try:
            name_info['common_name'] = name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            pass
        
        try:
            name_info['organization'] = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        except IndexError:
            pass
        
        try:
            name_info['country'] = name.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        except IndexError:
            pass
        
        try:
            name_info['organizational_unit'] = name.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
        except IndexError:
            pass
        
        return name_info
    
    def _analyze_public_key(self, public_key) -> Dict[str, Any]:
        """Analyze certificate public key"""
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
        
        key_info = {
            'algorithm': '',
            'key_size': 0,
            'is_weak': False
        }
        
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info['algorithm'] = 'RSA'
                key_info['key_size'] = public_key.key_size
                key_info['is_weak'] = public_key.key_size < 2048
                
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_info['algorithm'] = 'EC'
                key_info['curve'] = public_key.curve.name
                key_info['key_size'] = public_key.curve.key_size
                key_info['is_weak'] = public_key.curve.key_size < 256
                
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_info['algorithm'] = 'DSA'
                key_info['key_size'] = public_key.key_size
                key_info['is_weak'] = public_key.key_size < 2048
                
        except Exception as e:
            logger.warning(f"Error analyzing public key: {e}")
        
        return key_info
    
    def _analyze_extensions(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Analyze certificate extensions"""
        extensions_info = {
            'subject_alternative_names': [],
            'key_usage': [],
            'extended_key_usage': [],
            'basic_constraints': {},
            'critical_extensions': [],
            'unknown_extensions': []
        }
        
        try:
            for extension in cert.extensions:
                if extension.critical:
                    extensions_info['critical_extensions'].append(extension.oid._name)
                
                # Subject Alternative Names
                if extension.oid._name == 'subjectAltName':
                    try:
                        san_list = []
                        for name in extension.value:
                            san_list.append(name.value)
                        extensions_info['subject_alternative_names'] = san_list
                    except:
                        pass
                
                # Key Usage
                elif extension.oid._name == 'keyUsage':
                    try:
                        usage_list = []
                        usage = extension.value
                        if usage.digital_signature:
                            usage_list.append('digital_signature')
                        if usage.key_encipherment:
                            usage_list.append('key_encipherment')
                        if usage.key_agreement:
                            usage_list.append('key_agreement')
                        extensions_info['key_usage'] = usage_list
                    except:
                        pass
                
                # Extended Key Usage
                elif extension.oid._name == 'extendedKeyUsage':
                    try:
                        ext_usage_list = []
                        for usage in extension.value:
                            ext_usage_list.append(usage._name)
                        extensions_info['extended_key_usage'] = ext_usage_list
                    except:
                        pass
                
                # Basic Constraints
                elif extension.oid._name == 'basicConstraints':
                    try:
                        constraints = extension.value
                        extensions_info['basic_constraints'] = {
                            'ca': constraints.ca,
                            'path_length': constraints.path_length
                        }
                    except:
                        pass
                
                else:
                    # Unknown or unhandled extension
                    extensions_info['unknown_extensions'].append(extension.oid._name)
                    
        except Exception as e:
            logger.warning(f"Error analyzing extensions: {e}")
        
        return extensions_info
    
    def _check_suspicious_patterns(self, analysis: Dict[str, Any]):
        """Check certificate for suspicious patterns"""
        suspicious_indicators = analysis['suspicious_indicators']
        
        # Check subject patterns
        subject_cn = analysis['subject'].get('common_name', '')
        for pattern in self.suspicious_patterns['suspicious_subjects']:
            if re.search(pattern, subject_cn, re.IGNORECASE):
                suspicious_indicators.append(f"Suspicious subject pattern: {pattern}")
        
        # Check issuer patterns
        issuer_cn = analysis['issuer'].get('common_name', '')
        for pattern in self.suspicious_patterns['suspicious_issuers']:
            if re.search(pattern, issuer_cn, re.IGNORECASE):
                suspicious_indicators.append(f"Suspicious issuer pattern: {pattern}")
        
        # Check for self-signed certificates
        if analysis['subject'] == analysis['issuer']:
            suspicious_indicators.append("Self-signed certificate")
        
        # Check for weak public keys
        if analysis['public_key'].get('is_weak', False):
            suspicious_indicators.append(f"Weak public key: {analysis['public_key'].get('algorithm')} {analysis['public_key'].get('key_size')} bits")
        
        # Check for very short validity periods
        validity_days = analysis['validity'].get('validity_period_days', 0)
        if validity_days < 30:
            suspicious_indicators.append(f"Very short validity period: {validity_days} days")
        
        # Check for very long validity periods
        if validity_days > 3650:  # 10 years
            suspicious_indicators.append(f"Very long validity period: {validity_days} days")
    
    def _check_certificate_validity(self, analysis: Dict[str, Any]):
        """Check certificate validity issues"""
        validity_issues = analysis['validity_issues']
        
        # Check if expired
        if analysis['validity'].get('is_expired', False):
            validity_issues.append("Certificate is expired")
        
        # Check if not yet valid
        if analysis['validity'].get('is_not_yet_valid', False):
            validity_issues.append("Certificate is not yet valid")
        
        # Check for missing required extensions for leaf certificates
        if analysis['is_leaf']:
            if not analysis['extensions'].get('subject_alternative_names'):
                validity_issues.append("Leaf certificate missing Subject Alternative Names")
            
            if not analysis['extensions'].get('key_usage'):
                validity_issues.append("Leaf certificate missing Key Usage extension")
    
    def _calculate_certificate_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall certificate trust score (0-1, higher is more trustworthy)"""
        score = 1.0
        
        # Deduct for trust issues
        score -= len(analysis['trust_issues']) * 0.2
        
        # Deduct for suspicious indicators
        score -= len(analysis['suspicious_indicators']) * 0.15
        
        # Deduct for validity issues
        score -= len(analysis['validity_issues']) * 0.1
        
        return max(0.0, score)

class EncryptedFlowAnalyzer:
    """Analyze encrypted network flows for behavioral patterns"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.flow_cache = defaultdict(dict)
        self.ml_models = self._load_ml_models()
    
    def _load_ml_models(self) -> Dict[str, Any]:
        """Load machine learning models for flow analysis"""
        models = {}
        models_dir = Path("/var/lib/nsm/models/encrypted")
        models_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or create Isolation Forest for anomaly detection
        isolation_path = models_dir / "encrypted_isolation_forest.pkl"
        if isolation_path.exists():
            models['isolation_forest'] = joblib.load(isolation_path)
        else:
            models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=200
            )
        
        # Load or create classifier for C2 detection
        c2_classifier_path = models_dir / "c2_classifier.pkl"
        if c2_classifier_path.exists():
            models['c2_classifier'] = joblib.load(c2_classifier_path)
        else:
            models['c2_classifier'] = RandomForestClassifier(
                n_estimators=200,
                random_state=42
            )
        
        return models
    
    def analyze_encrypted_flow(self, flow_data: Dict[str, Any]) -> EncryptedFlow:
        """Analyze encrypted network flow"""
        timestamp = datetime.fromisoformat(flow_data['timestamp']) if isinstance(flow_data['timestamp'], str) else flow_data['timestamp']
        
        # Extract packet timing and size patterns
        packet_sizes = flow_data.get('packet_sizes', [])
        inter_arrival_times = flow_data.get('inter_arrival_times', [])
        
        # Calculate statistical features
        entropy_score = self._calculate_entropy_score(packet_sizes)
        periodicity_score = self._calculate_periodicity_score(inter_arrival_times)
        randomness_score = self._calculate_randomness_score(packet_sizes, inter_arrival_times)
        
        # Detect burst patterns
        burst_patterns = self._detect_burst_patterns(packet_sizes, inter_arrival_times)
        
        # Create EncryptedFlow object
        encrypted_flow = EncryptedFlow(
            timestamp=timestamp,
            source_ip=flow_data['source_ip'],
            destination_ip=flow_data['destination_ip'],
            source_port=flow_data['source_port'],
            destination_port=flow_data['destination_port'],
            protocol=flow_data.get('protocol', 'tcp'),
            total_bytes=flow_data.get('total_bytes', 0),
            total_packets=len(packet_sizes),
            duration=flow_data.get('duration', 0.0),
            bytes_ratio=flow_data.get('bytes_ratio', 1.0),
            packet_sizes=packet_sizes,
            inter_arrival_times=inter_arrival_times,
            burst_patterns=burst_patterns,
            entropy_score=entropy_score,
            periodicity_score=periodicity_score,
            randomness_score=randomness_score,
            application_protocol=flow_data.get('application_protocol'),
            anomaly_indicators=[]
        )
        
        # Analyze for threats
        encrypted_flow.threat_score = self._calculate_threat_score(encrypted_flow)
        encrypted_flow.anomaly_indicators = self._detect_anomaly_indicators(encrypted_flow)
        
        return encrypted_flow
    
    def _calculate_entropy_score(self, packet_sizes: List[int]) -> float:
        """Calculate entropy score for packet sizes"""
        if not packet_sizes:
            return 0.0
        
        try:
            # Calculate frequency distribution
            size_counts = Counter(packet_sizes)
            total_packets = len(packet_sizes)
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in size_counts.values():
                probability = count / total_packets
                if probability > 0:
                    entropy -= probability * np.log2(probability)
            
            # Normalize by maximum possible entropy
            max_entropy = np.log2(len(size_counts)) if len(size_counts) > 1 else 1
            
            return entropy / max_entropy if max_entropy > 0 else 0.0
            
        except Exception as e:
            logger.warning(f"Error calculating entropy score: {e}")
            return 0.0
    
    def _calculate_periodicity_score(self, inter_arrival_times: List[float]) -> float:
        """Calculate periodicity score for timing patterns"""
        if len(inter_arrival_times) < 10:
            return 0.0
        
        try:
            # Use autocorrelation to detect periodic patterns
            times_array = np.array(inter_arrival_times)
            
            # Calculate autocorrelation
            autocorr = np.correlate(times_array, times_array, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            
            # Normalize
            autocorr = autocorr / autocorr[0]
            
            # Find peaks in autocorrelation
            if len(autocorr) > 5:
                peak_threshold = 0.3
                peaks = np.where(autocorr[1:] > peak_threshold)[0]
                
                if len(peaks) > 0:
                    return np.max(autocorr[peaks + 1])
            
            return 0.0
            
        except Exception as e:
            logger.warning(f"Error calculating periodicity score: {e}")
            return 0.0
    
    def _calculate_randomness_score(self, packet_sizes: List[int], 
                                   inter_arrival_times: List[float]) -> float:
        """Calculate randomness score for flow patterns"""
        if not packet_sizes or not inter_arrival_times:
            return 0.0
        
        try:
            # Combine size and timing randomness
            size_variance = np.var(packet_sizes) if len(packet_sizes) > 1 else 0
            timing_variance = np.var(inter_arrival_times) if len(inter_arrival_times) > 1 else 0
            
            # Normalize variances
            size_cv = size_variance / max(np.mean(packet_sizes), 1) if packet_sizes else 0
            timing_cv = timing_variance / max(np.mean(inter_arrival_times), 0.001) if inter_arrival_times else 0
            
            # Combine scores
            randomness = (size_cv + timing_cv) / 2
            
            # Normalize to 0-1 range
            return min(1.0, randomness / 10.0)
            
        except Exception as e:
            logger.warning(f"Error calculating randomness score: {e}")
            return 0.0
    
    def _detect_burst_patterns(self, packet_sizes: List[int], 
                              inter_arrival_times: List[float]) -> List[Dict[str, Any]]:
        """Detect burst patterns in encrypted traffic"""
        burst_patterns = []
        
        try:
            if len(packet_sizes) < 5 or len(inter_arrival_times) < 4:
                return burst_patterns
            
            # Define burst criteria
            size_threshold = np.percentile(packet_sizes, 75)
            timing_threshold = np.percentile(inter_arrival_times, 25)  # Fast packets
            
            # Find burst sequences
            in_burst = False
            burst_start = 0
            burst_packets = []
            
            for i, (size, timing) in enumerate(zip(packet_sizes[:-1], inter_arrival_times)):
                if size > size_threshold and timing < timing_threshold:
                    if not in_burst:
                        in_burst = True
                        burst_start = i
                        burst_packets = [size]
                    else:
                        burst_packets.append(size)
                else:
                    if in_burst and len(burst_packets) >= 3:
                        # End of burst
                        burst_patterns.append({
                            'start_index': burst_start,
                            'end_index': i,
                            'packet_count': len(burst_packets),
                            'total_bytes': sum(burst_packets),
                            'avg_packet_size': np.mean(burst_packets),
                            'duration': sum(inter_arrival_times[burst_start:i])
                        })
                    
                    in_burst = False
                    burst_packets = []
            
            # Handle burst at end of flow
            if in_burst and len(burst_packets) >= 3:
                burst_patterns.append({
                    'start_index': burst_start,
                    'end_index': len(packet_sizes) - 1,
                    'packet_count': len(burst_packets),
                    'total_bytes': sum(burst_packets),
                    'avg_packet_size': np.mean(burst_packets),
                    'duration': sum(inter_arrival_times[burst_start:])
                })
            
        except Exception as e:
            logger.warning(f"Error detecting burst patterns: {e}")
        
        return burst_patterns
    
    def _calculate_threat_score(self, flow: EncryptedFlow) -> float:
        """Calculate threat score for encrypted flow"""
        threat_score = 0.0
        
        try:
            # Extract features for ML analysis
            features = self._extract_flow_features(flow)
            
            if len(features) > 0:
                features_array = np.array(features).reshape(1, -1)
                
                # Use isolation forest for anomaly detection
                anomaly_score = self.ml_models['isolation_forest'].decision_function(features_array)[0]
                
                # Normalize anomaly score to 0-1 range
                normalized_anomaly = max(0, min(1, (0.5 - anomaly_score) * 2))
                threat_score += normalized_anomaly * 0.4
                
                # Check for C2-like patterns
                c2_score = self._detect_c2_patterns(flow)
                threat_score += c2_score * 0.3
                
                # Check for data exfiltration patterns
                exfil_score = self._detect_exfiltration_patterns(flow)
                threat_score += exfil_score * 0.3
            
            return min(1.0, threat_score)
            
        except Exception as e:
            logger.warning(f"Error calculating threat score: {e}")
            return 0.0
    
    def _extract_flow_features(self, flow: EncryptedFlow) -> List[float]:
        """Extract numerical features from encrypted flow"""
        features = []
        
        try:
            # Basic flow features
            features.extend([
                flow.total_bytes,
                flow.total_packets,
                flow.duration,
                flow.bytes_ratio
            ])
            
            # Statistical features
            features.extend([
                flow.entropy_score,
                flow.periodicity_score,
                flow.randomness_score
            ])
            
            # Packet size statistics
            if flow.packet_sizes:
                features.extend([
                    np.mean(flow.packet_sizes),
                    np.std(flow.packet_sizes),
                    np.min(flow.packet_sizes),
                    np.max(flow.packet_sizes),
                    np.median(flow.packet_sizes)
                ])
            else:
                features.extend([0, 0, 0, 0, 0])
            
            # Timing statistics
            if flow.inter_arrival_times:
                features.extend([
                    np.mean(flow.inter_arrival_times),
                    np.std(flow.inter_arrival_times),
                    np.min(flow.inter_arrival_times),
                    np.max(flow.inter_arrival_times)
                ])
            else:
                features.extend([0, 0, 0, 0])
            
            # Burst pattern features
            features.extend([
                len(flow.burst_patterns),
                sum(bp['packet_count'] for bp in flow.burst_patterns),
                sum(bp['total_bytes'] for bp in flow.burst_patterns)
            ])
            
            # Port-based features
            features.extend([
                1 if flow.destination_port in [443, 80] else 0,  # Web traffic
                1 if flow.destination_port in [53, 853] else 0,  # DNS traffic
                1 if flow.destination_port > 1024 else 0          # High port
            ])
            
        except Exception as e:
            logger.warning(f"Error extracting flow features: {e}")
        
        return features
    
    def _detect_c2_patterns(self, flow: EncryptedFlow) -> float:
        """Detect command and control communication patterns"""
        c2_score = 0.0
        
        try:
            # Regular beaconing patterns
            if flow.periodicity_score > 0.7:
                c2_score += 0.4
            
            # Small, regular packet sizes (heartbeats)
            if flow.packet_sizes:
                size_variance = np.var(flow.packet_sizes)
                mean_size = np.mean(flow.packet_sizes)
                
                # Low variance in small packets suggests beaconing
                if size_variance < (mean_size * 0.1) and mean_size < 200:
                    c2_score += 0.3
            
            # Regular timing intervals
            if flow.inter_arrival_times and len(flow.inter_arrival_times) > 5:
                timing_cv = np.std(flow.inter_arrival_times) / max(np.mean(flow.inter_arrival_times), 0.001)
                if timing_cv < 0.2:  # Very regular timing
                    c2_score += 0.3
            
        except Exception as e:
            logger.warning(f"Error detecting C2 patterns: {e}")
        
        return min(1.0, c2_score)
    
    def _detect_exfiltration_patterns(self, flow: EncryptedFlow) -> float:
        """Detect data exfiltration patterns"""
        exfil_score = 0.0
        
        try:
            # Large data transfers
            if flow.total_bytes > 10 * 1024 * 1024:  # 10MB threshold
                exfil_score += 0.3
            
            # High upload ratio (more data sent than received)
            if flow.bytes_ratio > 5.0:
                exfil_score += 0.4
            
            # Long duration transfers
            if flow.duration > 300:  # 5 minutes
                exfil_score += 0.2
            
            # Many burst patterns (chunked transfer)
            if len(flow.burst_patterns) > 5:
                exfil_score += 0.1
            
        except Exception as e:
            logger.warning(f"Error detecting exfiltration patterns: {e}")
        
        return min(1.0, exfil_score)
    
    def _detect_anomaly_indicators(self, flow: EncryptedFlow) -> List[str]:
        """Detect specific anomaly indicators in encrypted flow"""
        indicators = []
        
        try:
            # High entropy (potentially compressed/encrypted data)
            if flow.entropy_score > 0.9:
                indicators.append("Very high entropy - possible compressed data")
            
            # Regular beaconing
            if flow.periodicity_score > 0.8:
                indicators.append("Regular periodic communication pattern")
            
            # Unusual packet size distribution
            if flow.packet_sizes:
                unique_sizes = len(set(flow.packet_sizes))
                if unique_sizes == 1 and len(flow.packet_sizes) > 10:
                    indicators.append("All packets same size - possible covert channel")
            
            # Suspicious port usage
            if flow.destination_port in [443, 80] and flow.entropy_score < 0.3:
                indicators.append("Low entropy on encrypted port - possible tunneling")
            
            # Long duration with small packets
            if flow.duration > 600 and flow.total_bytes < 10000:
                indicators.append("Long duration with minimal data transfer")
            
        except Exception as e:
            logger.warning(f"Error detecting anomaly indicators: {e}")
        
        return indicators

class EncryptedTrafficAnalyzer:
    """Main encrypted traffic analysis engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/encrypted-analysis.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize components
        self.ja3_analyzer = JA3FingerprintAnalyzer(self.config.get('ja3', {}))
        self.cert_analyzer = CertificateAnalyzer(self.config.get('certificates', {}))
        self.flow_analyzer = EncryptedFlowAnalyzer(self.config.get('flows', {}))
        
        # Database for storing results
        self.db_path = "/var/lib/nsm/encrypted_analysis.db"
        self._init_database()
        
        # Redis for real-time data
        self.redis_client = None
        
        # Processing state
        self.is_running = False
        self.processing_queue = asyncio.Queue(maxsize=10000)
    
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
                'db': 5
            },
            'ja3': {
                'update_databases': True,
                'threat_threshold': 0.7
            },
            'certificates': {
                'analyze_chain': True,
                'check_revocation': False
            },
            'flows': {
                'min_packets': 5,
                'max_duration': 3600
            },
            'alerting': {
                'min_threat_score': 0.6,
                'enable_ja3_alerts': True,
                'enable_cert_alerts': True,
                'enable_flow_alerts': True
            }
        }
    
    def _init_database(self):
        """Initialize database for encrypted traffic analysis"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tls_handshakes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    tls_version TEXT,
                    server_name TEXT,
                    ja3_client TEXT,
                    ja3s_server TEXT,
                    certificate_data TEXT,
                    handshake_duration REAL,
                    threat_indicators TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    total_bytes INTEGER,
                    total_packets INTEGER,
                    duration REAL,
                    entropy_score REAL,
                    periodicity_score REAL,
                    threat_score REAL,
                    anomaly_indicators TEXT,
                    flow_data TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_threats (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP,
                    source_ip TEXT,
                    destination_ip TEXT,
                    threat_type TEXT,
                    severity TEXT,
                    confidence REAL,
                    description TEXT,
                    indicators TEXT,
                    context TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tls_timestamp ON tls_handshakes(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON encrypted_flows(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON encrypted_threats(timestamp)")
    
    async def initialize_redis(self):
        """Initialize Redis connection"""
        redis_config = self.config.get('redis', {})
        self.redis_client = await aioredis.create_redis_pool(
            f"redis://{redis_config.get('host', 'localhost')}:{redis_config.get('port', 6379)}",
            db=redis_config.get('db', 5)
        )
    
    async def analyze_tls_handshake(self, handshake_data: Dict[str, Any]) -> TLSHandshake:
        """Analyze TLS handshake for threats"""
        # Create TLS handshake object
        tls_handshake = TLSHandshake(
            timestamp=datetime.fromisoformat(handshake_data['timestamp']) if isinstance(handshake_data['timestamp'], str) else handshake_data['timestamp'],
            source_ip=handshake_data['source_ip'],
            destination_ip=handshake_data['destination_ip'],
            source_port=handshake_data['source_port'],
            destination_port=handshake_data['destination_port'],
            tls_version=handshake_data.get('tls_version', ''),
            cipher_suites=handshake_data.get('cipher_suites', []),
            extensions=handshake_data.get('extensions', []),
            supported_groups=handshake_data.get('supported_groups', []),
            signature_algorithms=handshake_data.get('signature_algorithms', []),
            server_name=handshake_data.get('server_name'),
            certificates=handshake_data.get('certificates', []),
            handshake_duration=handshake_data.get('handshake_duration')
        )
        
        # Calculate JA3 fingerprints
        if tls_handshake.cipher_suites and tls_handshake.extensions:
            tls_handshake.ja3_client = self.ja3_analyzer.calculate_ja3_client(
                tls_handshake.tls_version,
                tls_handshake.cipher_suites,
                tls_handshake.extensions,
                tls_handshake.supported_groups,
                tls_handshake.signature_algorithms
            )
        
        # Analyze certificates if present
        cert_analysis = None
        if tls_handshake.certificates:
            cert_analysis = self.cert_analyzer.analyze_certificate_chain(tls_handshake.certificates)
            tls_handshake.certificate_chain_length = len(tls_handshake.certificates)
        
        # Store TLS handshake
        await self._store_tls_handshake(tls_handshake, cert_analysis)
        
        # Generate alerts if needed
        await self._check_tls_threats(tls_handshake, cert_analysis)
        
        return tls_handshake
    
    async def analyze_encrypted_flow(self, flow_data: Dict[str, Any]) -> EncryptedFlow:
        """Analyze encrypted network flow"""
        # Use flow analyzer
        encrypted_flow = self.flow_analyzer.analyze_encrypted_flow(flow_data)
        
        # Store encrypted flow
        await self._store_encrypted_flow(encrypted_flow)
        
        # Generate alerts if needed
        await self._check_flow_threats(encrypted_flow)
        
        return encrypted_flow
    
    async def _check_tls_threats(self, handshake: TLSHandshake, cert_analysis: Dict[str, Any]):
        """Check TLS handshake for threat indicators"""
        threats = []
        
        # Check JA3 fingerprint
        if handshake.ja3_client:
            ja3_analysis = self.ja3_analyzer.analyze_ja3_fingerprint(handshake.ja3_client)
            
            if ja3_analysis.get('is_threat', False):
                threat = EncryptedThreatAlert(
                    alert_id=f"ja3_threat_{handshake.source_ip}_{int(handshake.timestamp.timestamp())}",
                    timestamp=datetime.now(),
                    source_ip=handshake.source_ip,
                    destination_ip=handshake.destination_ip,
                    threat_type='malicious_ja3',
                    severity=ja3_analysis.get('threat_level', 'medium'),
                    confidence=0.9,
                    description=f"Malicious JA3 fingerprint detected: {ja3_analysis.get('description', '')}",
                    indicators={'ja3_hash': handshake.ja3_client, 'malware_family': ja3_analysis.get('malware_family')},
                    context={'handshake_data': asdict(handshake)},
                    tls_fingerprints={'ja3': handshake.ja3_client, 'ja3s': handshake.ja3s_server}
                )
                threats.append(threat)
        
        # Check certificate issues
        if cert_analysis and cert_analysis.get('overall_score', 1.0) < 0.5:
            threat = EncryptedThreatAlert(
                alert_id=f"cert_threat_{handshake.source_ip}_{int(handshake.timestamp.timestamp())}",
                timestamp=datetime.now(),
                source_ip=handshake.source_ip,
                destination_ip=handshake.destination_ip,
                threat_type='suspicious_certificate',
                severity='medium',
                confidence=0.7,
                description=f"Suspicious certificate detected with score {cert_analysis['overall_score']:.2f}",
                indicators={'certificate_issues': cert_analysis.get('suspicious_indicators', [])},
                context={'certificate_analysis': cert_analysis},
                certificate_anomalies=cert_analysis.get('suspicious_indicators', [])
            )
            threats.append(threat)
        
        # Store threats
        for threat in threats:
            await self._store_threat_alert(threat)
    
    async def _check_flow_threats(self, flow: EncryptedFlow):
        """Check encrypted flow for threat indicators"""
        threats = []
        
        # Check threat score
        if flow.threat_score > self.config.get('alerting', {}).get('min_threat_score', 0.6):
            threat = EncryptedThreatAlert(
                alert_id=f"flow_threat_{flow.source_ip}_{int(flow.timestamp.timestamp())}",
                timestamp=datetime.now(),
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                threat_type='suspicious_encrypted_flow',
                severity=self._determine_severity(flow.threat_score),
                confidence=flow.threat_score,
                description=f"Suspicious encrypted flow patterns detected (score: {flow.threat_score:.2f})",
                indicators={'anomaly_indicators': flow.anomaly_indicators},
                context={'flow_data': asdict(flow)},
                traffic_patterns={
                    'entropy_score': flow.entropy_score,
                    'periodicity_score': flow.periodicity_score,
                    'burst_patterns': len(flow.burst_patterns)
                }
            )
            threats.append(threat)
        
        # Store threats
        for threat in threats:
            await self._store_threat_alert(threat)
    
    def _determine_severity(self, threat_score: float) -> str:
        """Determine threat severity based on score"""
        if threat_score >= 0.9:
            return 'critical'
        elif threat_score >= 0.7:
            return 'high'
        elif threat_score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    async def _store_tls_handshake(self, handshake: TLSHandshake, cert_analysis: Dict[str, Any]):
        """Store TLS handshake in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO tls_handshakes 
                (timestamp, source_ip, destination_ip, source_port, destination_port,
                 tls_version, server_name, ja3_client, ja3s_server, certificate_data,
                 handshake_duration, threat_indicators)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                handshake.timestamp,
                handshake.source_ip,
                handshake.destination_ip,
                handshake.source_port,
                handshake.destination_port,
                handshake.tls_version,
                handshake.server_name,
                handshake.ja3_client,
                handshake.ja3s_server,
                json.dumps(cert_analysis, default=str) if cert_analysis else None,
                handshake.handshake_duration,
                json.dumps(asdict(handshake), default=str)
            ))
    
    async def _store_encrypted_flow(self, flow: EncryptedFlow):
        """Store encrypted flow in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO encrypted_flows 
                (timestamp, source_ip, destination_ip, source_port, destination_port,
                 protocol, total_bytes, total_packets, duration, entropy_score,
                 periodicity_score, threat_score, anomaly_indicators, flow_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow.timestamp,
                flow.source_ip,
                flow.destination_ip,
                flow.source_port,
                flow.destination_port,
                flow.protocol,
                flow.total_bytes,
                flow.total_packets,
                flow.duration,
                flow.entropy_score,
                flow.periodicity_score,
                flow.threat_score,
                json.dumps(flow.anomaly_indicators),
                json.dumps(asdict(flow), default=str)
            ))
    
    async def _store_threat_alert(self, threat: EncryptedThreatAlert):
        """Store threat alert in database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO encrypted_threats 
                (alert_id, timestamp, source_ip, destination_ip, threat_type,
                 severity, confidence, description, indicators, context)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat.alert_id,
                threat.timestamp,
                threat.source_ip,
                threat.destination_ip,
                threat.threat_type,
                threat.severity,
                threat.confidence,
                threat.description,
                json.dumps(threat.indicators, default=str),
                json.dumps(threat.context, default=str)
            ))
        
        # Send to Redis for real-time access
        if self.redis_client:
            await self.redis_client.lpush(
                'encrypted_threats',
                json.dumps(asdict(threat), default=str)
            )
            await self.redis_client.ltrim('encrypted_threats', 0, 9999)
    
    async def start_processing(self):
        """Start the encrypted traffic analyzer"""
        logger.info("Starting encrypted traffic analyzer")
        
        await self.initialize_redis()
        self.is_running = True
        
        # Main processing loop
        while self.is_running:
            try:
                # Get data from queue (would be populated by network capture)
                analysis_data = await asyncio.wait_for(
                    self.processing_queue.get(),
                    timeout=1.0
                )
                
                # Determine analysis type and process
                if analysis_data.get('type') == 'tls_handshake':
                    await self.analyze_tls_handshake(analysis_data['data'])
                elif analysis_data.get('type') == 'encrypted_flow':
                    await self.analyze_encrypted_flow(analysis_data['data'])
                
                # Mark task as done
                self.processing_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                await asyncio.sleep(1)
    
    def stop_processing(self):
        """Stop the encrypted traffic analyzer"""
        logger.info("Stopping encrypted traffic analyzer")
        self.is_running = False

async def main():
    """Main function for encrypted traffic analyzer"""
    analyzer = EncryptedTrafficAnalyzer()
    
    try:
        await analyzer.start_processing()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        analyzer.stop_processing()

if __name__ == "__main__":
    asyncio.run(main())