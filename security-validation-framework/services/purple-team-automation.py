"""
Purple Team Automation Framework
Automated coordination between red team (attack) and blue team (defense) activities
"""

import asyncio
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
import asyncpg
import aiohttp
import yaml
from pathlib import Path
import random
import time
import base64
from collections import defaultdict


class TeamRole(Enum):
    """Purple team participant roles"""
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    OBSERVER = "observer"


class ExerciseType(Enum):
    """Types of purple team exercises"""
    TABLETOP = "tabletop"
    TECHNICAL = "technical"
    FULL_SIMULATION = "full_simulation"
    THREAT_HUNT = "threat_hunt"
    DETECTION_ENGINEERING = "detection_engineering"
    INCIDENT_RESPONSE = "incident_response"


class AttackPhase(Enum):
    """Attack kill chain phases"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class DetectionCapability(Enum):
    """Detection capability levels"""
    NOT_DETECTED = "not_detected"
    PARTIALLY_DETECTED = "partially_detected"
    FULLY_DETECTED = "fully_detected"
    PREVENTED = "prevented"


@dataclass
class AttackScenario:
    """Purple team attack scenario"""
    scenario_id: str
    name: str
    description: str
    threat_actor: str
    ttps: List[str]  # MITRE ATT&CK TTPs
    kill_chain_phases: List[AttackPhase]
    objectives: List[str]
    difficulty: str
    estimated_duration: int  # minutes
    detection_opportunities: List[Dict[str, Any]]
    success_criteria: Dict[str, Any]


@dataclass
class ExerciseResult:
    """Purple team exercise result"""
    exercise_id: str
    scenario_id: str
    start_time: datetime
    end_time: Optional[datetime]
    red_team_actions: List[Dict[str, Any]]
    blue_team_detections: List[Dict[str, Any]]
    detection_rate: float
    prevention_rate: float
    mean_time_to_detect: Optional[float]
    gaps_identified: List[Dict[str, Any]]
    lessons_learned: List[str]
    recommendations: List[Dict[str, Any]]


class PurpleTeamOrchestrator:
    """Orchestrates purple team exercises"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scenarios = self._load_attack_scenarios()
        self.active_exercises = {}
        
    def _load_attack_scenarios(self) -> Dict[str, AttackScenario]:
        """Load predefined attack scenarios"""
        scenarios = {}
        
        # APT29 Scenario
        scenarios["APT29"] = AttackScenario(
            scenario_id="APT29",
            name="APT29 - Cozy Bear Simulation",
            description="Simulate APT29 threat actor tactics targeting cloud infrastructure",
            threat_actor="APT29",
            ttps=["T1595", "T1190", "T1055", "T1003", "T1071", "T1041", "T1486"],
            kill_chain_phases=[
                AttackPhase.RECONNAISSANCE,
                AttackPhase.EXPLOITATION,
                AttackPhase.INSTALLATION,
                AttackPhase.COMMAND_CONTROL,
                AttackPhase.ACTIONS_ON_OBJECTIVES
            ],
            objectives=[
                "Gain initial access through spear phishing",
                "Establish persistence",
                "Steal credentials",
                "Exfiltrate sensitive data"
            ],
            difficulty="high",
            estimated_duration=240,
            detection_opportunities=[
                {
                    "phase": "initial_access",
                    "indicators": ["suspicious_email", "macro_execution"],
                    "detection_sources": ["email_gateway", "endpoint_detection"]
                },
                {
                    "phase": "persistence",
                    "indicators": ["registry_modification", "scheduled_task"],
                    "detection_sources": ["edr", "sysmon"]
                },
                {
                    "phase": "credential_access",
                    "indicators": ["lsass_access", "mimikatz_patterns"],
                    "detection_sources": ["edr", "windows_event_logs"]
                }
            ],
            success_criteria={
                "red_team": {
                    "objectives_completed": 3,
                    "data_exfiltrated": True
                },
                "blue_team": {
                    "detection_rate": 70,
                    "mean_time_to_detect": 30
                }
            }
        )
        
        # Ransomware Scenario
        scenarios["RANSOMWARE"] = AttackScenario(
            scenario_id="RANSOMWARE",
            name="Ransomware Attack Simulation",
            description="Simulate modern ransomware attack with data exfiltration",
            threat_actor="Ransomware Operator",
            ttps=["T1566", "T1055", "T1490", "T1486", "T1041"],
            kill_chain_phases=[
                AttackPhase.DELIVERY,
                AttackPhase.EXPLOITATION,
                AttackPhase.INSTALLATION,
                AttackPhase.ACTIONS_ON_OBJECTIVES
            ],
            objectives=[
                "Deploy ransomware payload",
                "Encrypt critical systems",
                "Exfiltrate data for double extortion",
                "Delete backups"
            ],
            difficulty="medium",
            estimated_duration=120,
            detection_opportunities=[
                {
                    "phase": "delivery",
                    "indicators": ["suspicious_attachment", "download_cradle"],
                    "detection_sources": ["email_security", "proxy_logs"]
                },
                {
                    "phase": "encryption",
                    "indicators": ["mass_file_modification", "encryption_patterns"],
                    "detection_sources": ["file_integrity_monitoring", "edr"]
                }
            ],
            success_criteria={
                "red_team": {
                    "systems_encrypted": 5,
                    "backups_deleted": True
                },
                "blue_team": {
                    "detection_rate": 90,
                    "containment_time": 15
                }
            }
        )
        
        # Insider Threat Scenario
        scenarios["INSIDER"] = AttackScenario(
            scenario_id="INSIDER",
            name="Insider Threat Simulation",
            description="Simulate malicious insider stealing intellectual property",
            threat_actor="Malicious Insider",
            ttps=["T1078", "T1083", "T1005", "T1048", "T1070"],
            kill_chain_phases=[
                AttackPhase.RECONNAISSANCE,
                AttackPhase.ACTIONS_ON_OBJECTIVES
            ],
            objectives=[
                "Access sensitive repositories",
                "Download intellectual property",
                "Exfiltrate via personal cloud storage",
                "Cover tracks"
            ],
            difficulty="medium",
            estimated_duration=180,
            detection_opportunities=[
                {
                    "phase": "data_access",
                    "indicators": ["unusual_access_patterns", "bulk_downloads"],
                    "detection_sources": ["dlp", "ueba"]
                },
                {
                    "phase": "exfiltration",
                    "indicators": ["cloud_storage_upload", "large_data_transfer"],
                    "detection_sources": ["proxy", "casb"]
                }
            ],
            success_criteria={
                "red_team": {
                    "data_stolen_gb": 10,
                    "detection_avoided": False
                },
                "blue_team": {
                    "detection_rate": 80,
                    "data_loss_prevented": True
                }
            }
        )
        
        # Supply Chain Attack
        scenarios["SUPPLY_CHAIN"] = AttackScenario(
            scenario_id="SUPPLY_CHAIN",
            name="Supply Chain Attack Simulation",
            description="Simulate supply chain compromise through third-party software",
            threat_actor="Advanced Persistent Threat",
            ttps=["T1195", "T1199", "T1072", "T1053", "T1055"],
            kill_chain_phases=[
                AttackPhase.DELIVERY,
                AttackPhase.INSTALLATION,
                AttackPhase.COMMAND_CONTROL,
                AttackPhase.ACTIONS_ON_OBJECTIVES
            ],
            objectives=[
                "Compromise third-party software",
                "Deploy backdoor through update",
                "Establish C2 communication",
                "Move laterally to target systems"
            ],
            difficulty="high",
            estimated_duration=300,
            detection_opportunities=[
                {
                    "phase": "backdoor_deployment",
                    "indicators": ["unsigned_binary", "suspicious_update"],
                    "detection_sources": ["application_control", "edr"]
                },
                {
                    "phase": "c2_communication",
                    "indicators": ["beaconing", "dns_tunneling"],
                    "detection_sources": ["network_monitoring", "dns_logs"]
                }
            ],
            success_criteria={
                "red_team": {
                    "backdoor_deployed": True,
                    "lateral_movement_achieved": True
                },
                "blue_team": {
                    "detection_rate": 60,
                    "supply_chain_risk_identified": True
                }
            }
        )
        
        return scenarios
    
    async def execute_exercise(self, scenario_id: str, exercise_type: ExerciseType) -> ExerciseResult:
        """Execute a purple team exercise"""
        if scenario_id not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario_id}")
        
        scenario = self.scenarios[scenario_id]
        exercise_id = str(uuid.uuid4())
        
        # Initialize exercise result
        result = ExerciseResult(
            exercise_id=exercise_id,
            scenario_id=scenario_id,
            start_time=datetime.utcnow(),
            end_time=None,
            red_team_actions=[],
            blue_team_detections=[],
            detection_rate=0.0,
            prevention_rate=0.0,
            mean_time_to_detect=None,
            gaps_identified=[],
            lessons_learned=[],
            recommendations=[]
        )
        
        self.active_exercises[exercise_id] = result
        
        try:
            if exercise_type == ExerciseType.TECHNICAL:
                # Execute technical simulation
                await self._execute_technical_exercise(scenario, result)
            elif exercise_type == ExerciseType.TABLETOP:
                # Execute tabletop exercise
                await self._execute_tabletop_exercise(scenario, result)
            elif exercise_type == ExerciseType.FULL_SIMULATION:
                # Execute full simulation
                await self._execute_full_simulation(scenario, result)
            else:
                # Default to technical exercise
                await self._execute_technical_exercise(scenario, result)
            
            # Analyze results
            self._analyze_exercise_results(result)
            
            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)
            
        finally:
            result.end_time = datetime.utcnow()
            del self.active_exercises[exercise_id]
        
        return result
    
    async def _execute_technical_exercise(self, scenario: AttackScenario, result: ExerciseResult):
        """Execute technical purple team exercise"""
        detection_times = []
        
        for i, ttp in enumerate(scenario.ttps):
            # Simulate red team action
            red_action = {
                "action_id": str(uuid.uuid4()),
                "ttp": ttp,
                "phase": scenario.kill_chain_phases[min(i, len(scenario.kill_chain_phases)-1)].value,
                "timestamp": datetime.utcnow().isoformat(),
                "success": random.random() > 0.2  # 80% success rate
            }
            result.red_team_actions.append(red_action)
            
            # Simulate blue team detection
            detection_opportunity = scenario.detection_opportunities[
                min(i, len(scenario.detection_opportunities)-1)
            ]
            
            detection_probability = self._calculate_detection_probability(
                ttp, detection_opportunity
            )
            
            detected = random.random() < detection_probability
            
            if detected:
                detection_time = random.uniform(1, 30)  # 1-30 minutes
                detection_times.append(detection_time)
                
                blue_detection = {
                    "detection_id": str(uuid.uuid4()),
                    "ttp_detected": ttp,
                    "detection_source": random.choice(detection_opportunity["detection_sources"]),
                    "timestamp": datetime.utcnow().isoformat(),
                    "time_to_detect": detection_time,
                    "action_taken": self._determine_response_action(ttp)
                }
                result.blue_team_detections.append(blue_detection)
            else:
                # Gap identified
                result.gaps_identified.append({
                    "ttp": ttp,
                    "phase": red_action["phase"],
                    "detection_missed": True,
                    "reason": "No detection capability"
                })
            
            # Simulate delay between actions
            await asyncio.sleep(0.1)
        
        # Calculate metrics
        result.detection_rate = (
            len(result.blue_team_detections) / len(result.red_team_actions) * 100
        )
        
        prevented_count = sum(
            1 for d in result.blue_team_detections 
            if d["action_taken"] == "blocked"
        )
        result.prevention_rate = prevented_count / len(result.red_team_actions) * 100
        
        if detection_times:
            result.mean_time_to_detect = sum(detection_times) / len(detection_times)
    
    async def _execute_tabletop_exercise(self, scenario: AttackScenario, result: ExerciseResult):
        """Execute tabletop purple team exercise"""
        # Simulate discussion-based exercise
        for phase in scenario.kill_chain_phases:
            # Red team presents attack approach
            red_action = {
                "phase": phase.value,
                "approach": f"Simulated {phase.value} activities",
                "techniques": [ttp for ttp in scenario.ttps],
                "expected_outcome": "Success"
            }
            result.red_team_actions.append(red_action)
            
            # Blue team responds with detection capabilities
            blue_response = {
                "phase": phase.value,
                "detection_capabilities": self._assess_detection_capabilities(phase),
                "response_plan": self._get_response_plan(phase),
                "gaps": self._identify_phase_gaps(phase)
            }
            result.blue_team_detections.append(blue_response)
            
            # Document lessons learned
            result.lessons_learned.append(
                f"Phase {phase.value}: Detection capability assessed"
            )
    
    async def _execute_full_simulation(self, scenario: AttackScenario, result: ExerciseResult):
        """Execute full purple team simulation"""
        # Comprehensive simulation with real tools
        for i, ttp in enumerate(scenario.ttps):
            # Execute actual attack simulation
            attack_result = await self._simulate_attack_technique(ttp)
            result.red_team_actions.append(attack_result)
            
            # Monitor actual detection systems
            detection_result = await self._check_detection_systems(ttp)
            if detection_result["detected"]:
                result.blue_team_detections.append(detection_result)
            
            # Real-time adjustments
            if detection_result["detected"] and detection_result["blocked"]:
                # Adjust attack path
                result.lessons_learned.append(
                    f"TTP {ttp} blocked, red team adjusted tactics"
                )
    
    def _calculate_detection_probability(self, ttp: str, detection_opportunity: Dict[str, Any]) -> float:
        """Calculate probability of detecting a TTP"""
        base_probability = 0.5
        
        # Adjust based on detection sources
        if "edr" in detection_opportunity.get("detection_sources", []):
            base_probability += 0.2
        if "siem" in detection_opportunity.get("detection_sources", []):
            base_probability += 0.15
        if "network_monitoring" in detection_opportunity.get("detection_sources", []):
            base_probability += 0.1
        
        return min(base_probability, 0.95)
    
    def _determine_response_action(self, ttp: str) -> str:
        """Determine blue team response action"""
        critical_ttps = ["T1003", "T1055", "T1486"]  # Critical techniques
        
        if ttp in critical_ttps:
            return "blocked"
        elif random.random() > 0.5:
            return "alerted"
        else:
            return "logged"
    
    def _assess_detection_capabilities(self, phase: AttackPhase) -> Dict[str, Any]:
        """Assess detection capabilities for a phase"""
        capabilities = {
            AttackPhase.RECONNAISSANCE: {
                "tools": ["Network monitoring", "DNS logs"],
                "coverage": "partial"
            },
            AttackPhase.EXPLOITATION: {
                "tools": ["EDR", "IDS", "WAF"],
                "coverage": "good"
            },
            AttackPhase.COMMAND_CONTROL: {
                "tools": ["Network monitoring", "Proxy logs", "DNS filtering"],
                "coverage": "moderate"
            }
        }
        
        return capabilities.get(phase, {"tools": [], "coverage": "limited"})
    
    def _get_response_plan(self, phase: AttackPhase) -> str:
        """Get response plan for attack phase"""
        response_plans = {
            AttackPhase.RECONNAISSANCE: "Monitor and log suspicious scanning activity",
            AttackPhase.EXPLOITATION: "Block and isolate affected systems",
            AttackPhase.COMMAND_CONTROL: "Block C2 communications and hunt for backdoors",
            AttackPhase.ACTIONS_ON_OBJECTIVES: "Contain damage and preserve evidence"
        }
        
        return response_plans.get(phase, "Investigate and respond")
    
    def _identify_phase_gaps(self, phase: AttackPhase) -> List[str]:
        """Identify gaps in detection for a phase"""
        # Simulate gap identification
        common_gaps = {
            AttackPhase.RECONNAISSANCE: ["Limited external reconnaissance visibility"],
            AttackPhase.EXPLOITATION: ["Zero-day detection capability"],
            AttackPhase.COMMAND_CONTROL: ["Encrypted C2 channel detection"],
            AttackPhase.ACTIONS_ON_OBJECTIVES: ["Data exfiltration via legitimate channels"]
        }
        
        return common_gaps.get(phase, [])
    
    async def _simulate_attack_technique(self, ttp: str) -> Dict[str, Any]:
        """Simulate actual attack technique execution"""
        # In production, this would execute real attack simulations
        return {
            "ttp": ttp,
            "execution_time": datetime.utcnow().isoformat(),
            "success": random.random() > 0.3,
            "artifacts": ["process_created", "file_modified", "registry_changed"],
            "iocs": ["suspicious_process.exe", "c2_domain.com"]
        }
    
    async def _check_detection_systems(self, ttp: str) -> Dict[str, Any]:
        """Check actual detection systems for alerts"""
        # In production, this would query real security tools
        detected = random.random() > 0.4
        
        return {
            "detected": detected,
            "ttp": ttp,
            "detection_time": datetime.utcnow().isoformat(),
            "alert_id": str(uuid.uuid4()) if detected else None,
            "blocked": detected and random.random() > 0.5,
            "detection_source": "EDR" if detected else None
        }
    
    def _analyze_exercise_results(self, result: ExerciseResult):
        """Analyze exercise results and identify improvements"""
        # Identify detection gaps
        detected_ttps = {d.get("ttp_detected") for d in result.blue_team_detections}
        all_ttps = {a.get("ttp") for a in result.red_team_actions}
        missed_ttps = all_ttps - detected_ttps
        
        for ttp in missed_ttps:
            if ttp:  # Check if ttp is not None
                result.gaps_identified.append({
                    "type": "detection_gap",
                    "ttp": ttp,
                    "impact": "high",
                    "remediation": f"Implement detection for {ttp}"
                })
        
        # Analyze response times
        if result.mean_time_to_detect and result.mean_time_to_detect > 15:
            result.gaps_identified.append({
                "type": "response_time",
                "current": result.mean_time_to_detect,
                "target": 15,
                "impact": "medium",
                "remediation": "Improve detection automation"
            })
        
        # Document lessons learned
        result.lessons_learned.append(
            f"Detection rate: {result.detection_rate:.1f}%"
        )
        result.lessons_learned.append(
            f"Prevention rate: {result.prevention_rate:.1f}%"
        )
        
        if result.mean_time_to_detect:
            result.lessons_learned.append(
                f"Average detection time: {result.mean_time_to_detect:.1f} minutes"
            )
    
    def _generate_recommendations(self, result: ExerciseResult) -> List[Dict[str, Any]]:
        """Generate recommendations based on exercise results"""
        recommendations = []
        
        # Detection improvement recommendations
        if result.detection_rate < 70:
            recommendations.append({
                "category": "detection",
                "priority": "high",
                "recommendation": "Enhance detection capabilities",
                "actions": [
                    "Deploy additional detection tools",
                    "Tune existing detection rules",
                    "Implement behavioral analytics"
                ]
            })
        
        # Response time recommendations
        if result.mean_time_to_detect and result.mean_time_to_detect > 20:
            recommendations.append({
                "category": "response_time",
                "priority": "medium",
                "recommendation": "Reduce mean time to detect",
                "actions": [
                    "Automate detection workflows",
                    "Implement SOAR playbooks",
                    "Enhance alert correlation"
                ]
            })
        
        # Gap remediation recommendations
        for gap in result.gaps_identified:
            if gap.get("impact") in ["high", "critical"]:
                recommendations.append({
                    "category": "gap_remediation",
                    "priority": gap.get("impact"),
                    "recommendation": f"Address gap: {gap.get('type')}",
                    "actions": [gap.get("remediation", "Implement appropriate controls")]
                })
        
        # Training recommendations
        if result.detection_rate < 80:
            recommendations.append({
                "category": "training",
                "priority": "medium",
                "recommendation": "Enhance team training",
                "actions": [
                    "Conduct threat hunting training",
                    "Practice incident response procedures",
                    "Review detection use cases"
                ]
            })
        
        return recommendations


class PurpleTeamAutomationFramework:
    """Main purple team automation framework"""
    
    def __init__(self, db_config: Dict[str, Any], config: Dict[str, Any]):
        self.db_config = db_config
        self.config = config
        self.orchestrator = PurpleTeamOrchestrator(config)
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
                CREATE TABLE IF NOT EXISTS purple_team_exercises (
                    exercise_id VARCHAR(64) PRIMARY KEY,
                    scenario_id VARCHAR(50) NOT NULL,
                    exercise_type VARCHAR(50) NOT NULL,
                    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
                    end_time TIMESTAMP WITH TIME ZONE,
                    detection_rate FLOAT,
                    prevention_rate FLOAT,
                    mean_time_to_detect FLOAT,
                    status VARCHAR(50) NOT NULL,
                    created_by VARCHAR(255),
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS purple_team_actions (
                    action_id VARCHAR(64) PRIMARY KEY,
                    exercise_id VARCHAR(64) REFERENCES purple_team_exercises(exercise_id),
                    team_role VARCHAR(20) NOT NULL,
                    action_type VARCHAR(50) NOT NULL,
                    ttp VARCHAR(20),
                    phase VARCHAR(50),
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN,
                    details JSONB,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS purple_team_gaps (
                    gap_id SERIAL PRIMARY KEY,
                    exercise_id VARCHAR(64) REFERENCES purple_team_exercises(exercise_id),
                    gap_type VARCHAR(50) NOT NULL,
                    description TEXT NOT NULL,
                    impact VARCHAR(20) NOT NULL,
                    remediation TEXT,
                    status VARCHAR(50) DEFAULT 'identified',
                    identified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    resolved_at TIMESTAMP WITH TIME ZONE,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS purple_team_recommendations (
                    recommendation_id SERIAL PRIMARY KEY,
                    exercise_id VARCHAR(64) REFERENCES purple_team_exercises(exercise_id),
                    category VARCHAR(50) NOT NULL,
                    priority VARCHAR(20) NOT NULL,
                    recommendation TEXT NOT NULL,
                    actions JSONB,
                    status VARCHAR(50) DEFAULT 'pending',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    implemented_at TIMESTAMP WITH TIME ZONE,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS detection_improvements (
                    improvement_id SERIAL PRIMARY KEY,
                    ttp VARCHAR(20) NOT NULL,
                    current_detection_rate FLOAT,
                    target_detection_rate FLOAT,
                    improvement_actions JSONB,
                    status VARCHAR(50) DEFAULT 'planned',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP WITH TIME ZONE,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_purple_exercises_scenario ON purple_team_exercises(scenario_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_purple_actions_exercise ON purple_team_actions(exercise_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_purple_gaps_exercise ON purple_team_gaps(exercise_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_purple_gaps_status ON purple_team_gaps(status)")
    
    async def run_exercise(self, scenario_id: str, exercise_type: ExerciseType = ExerciseType.TECHNICAL) -> Dict[str, Any]:
        """Run a purple team exercise"""
        # Execute exercise
        result = await self.orchestrator.execute_exercise(scenario_id, exercise_type)
        
        # Store exercise results
        await self._store_exercise_results(result, exercise_type)
        
        # Track improvements
        await self._track_detection_improvements(result)
        
        return {
            "exercise_id": result.exercise_id,
            "scenario_id": result.scenario_id,
            "detection_rate": result.detection_rate,
            "prevention_rate": result.prevention_rate,
            "mean_time_to_detect": result.mean_time_to_detect,
            "gaps_identified": len(result.gaps_identified),
            "recommendations": len(result.recommendations),
            "duration": (result.end_time - result.start_time).total_seconds() / 60
        }
    
    async def _store_exercise_results(self, result: ExerciseResult, exercise_type: ExerciseType):
        """Store exercise results in database"""
        async with self.db_pool.acquire() as conn:
            # Store main exercise record
            await conn.execute("""
                INSERT INTO purple_team_exercises
                (exercise_id, scenario_id, exercise_type, start_time, end_time,
                 detection_rate, prevention_rate, mean_time_to_detect, status, 
                 created_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """, result.exercise_id, result.scenario_id, exercise_type.value,
                result.start_time, result.end_time, result.detection_rate,
                result.prevention_rate, result.mean_time_to_detect,
                'completed', 'system', 'default')
            
            # Store red team actions
            for action in result.red_team_actions:
                await conn.execute("""
                    INSERT INTO purple_team_actions
                    (action_id, exercise_id, team_role, action_type, ttp, phase,
                     timestamp, success, details, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                """, str(uuid.uuid4()), result.exercise_id, TeamRole.RED_TEAM.value,
                    'attack', action.get('ttp'), action.get('phase'),
                    datetime.utcnow(), action.get('success'),
                    json.dumps(action), 'default')
            
            # Store blue team detections
            for detection in result.blue_team_detections:
                await conn.execute("""
                    INSERT INTO purple_team_actions
                    (action_id, exercise_id, team_role, action_type, ttp,
                     timestamp, success, details, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, str(uuid.uuid4()), result.exercise_id, TeamRole.BLUE_TEAM.value,
                    'detection', detection.get('ttp_detected'),
                    datetime.utcnow(), True,
                    json.dumps(detection), 'default')
            
            # Store identified gaps
            for gap in result.gaps_identified:
                await conn.execute("""
                    INSERT INTO purple_team_gaps
                    (exercise_id, gap_type, description, impact, remediation, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, result.exercise_id, gap.get('type', 'unknown'),
                    gap.get('description', str(gap)),
                    gap.get('impact', 'medium'),
                    gap.get('remediation', ''), 'default')
            
            # Store recommendations
            for rec in result.recommendations:
                await conn.execute("""
                    INSERT INTO purple_team_recommendations
                    (exercise_id, category, priority, recommendation, actions, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, result.exercise_id, rec['category'], rec['priority'],
                    rec['recommendation'], json.dumps(rec.get('actions', [])),
                    'default')
    
    async def _track_detection_improvements(self, result: ExerciseResult):
        """Track detection improvements needed"""
        detected_ttps = {d.get("ttp_detected") for d in result.blue_team_detections}
        all_ttps = {a.get("ttp") for a in result.red_team_actions}
        missed_ttps = all_ttps - detected_ttps
        
        async with self.db_pool.acquire() as conn:
            for ttp in missed_ttps:
                if ttp:  # Check if ttp is not None
                    await conn.execute("""
                        INSERT INTO detection_improvements
                        (ttp, current_detection_rate, target_detection_rate,
                         improvement_actions, tenant_id)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (ttp, tenant_id) DO UPDATE
                        SET current_detection_rate = $2,
                            improvement_actions = $4
                    """, ttp, 0.0, 80.0,
                        json.dumps(["Implement detection rule", "Add to SIEM"]),
                        'default')
    
    async def get_exercise_history(self, days: int = 30) -> Dict[str, Any]:
        """Get purple team exercise history"""
        async with self.db_pool.acquire() as conn:
            exercises = await conn.fetch("""
                SELECT * FROM purple_team_exercises
                WHERE start_time > NOW() - INTERVAL '%s days'
                AND tenant_id = 'default'
                ORDER BY start_time DESC
            """, days)
            
            gaps = await conn.fetch("""
                SELECT gap_type, impact, COUNT(*) as count
                FROM purple_team_gaps
                WHERE identified_at > NOW() - INTERVAL '%s days'
                AND tenant_id = 'default'
                GROUP BY gap_type, impact
            """, days)
            
            improvements = await conn.fetch("""
                SELECT * FROM detection_improvements
                WHERE status != 'completed'
                AND tenant_id = 'default'
            """)
        
        # Calculate statistics
        total_exercises = len(exercises)
        avg_detection_rate = sum(e['detection_rate'] for e in exercises) / total_exercises if total_exercises > 0 else 0
        avg_prevention_rate = sum(e['prevention_rate'] for e in exercises) / total_exercises if total_exercises > 0 else 0
        
        return {
            "summary": {
                "total_exercises": total_exercises,
                "average_detection_rate": avg_detection_rate,
                "average_prevention_rate": avg_prevention_rate,
                "total_gaps": sum(g['count'] for g in gaps),
                "pending_improvements": len(improvements)
            },
            "recent_exercises": [dict(e) for e in exercises[:10]],
            "gap_distribution": [dict(g) for g in gaps],
            "pending_improvements": [dict(i) for i in improvements[:10]]
        }
    
    async def generate_readiness_report(self) -> Dict[str, Any]:
        """Generate security readiness report based on purple team exercises"""
        async with self.db_pool.acquire() as conn:
            # Get TTP coverage
            ttp_coverage = await conn.fetch("""
                SELECT ttp, 
                       COUNT(CASE WHEN team_role = 'blue_team' THEN 1 END) as detections,
                       COUNT(CASE WHEN team_role = 'red_team' THEN 1 END) as attempts
                FROM purple_team_actions
                WHERE ttp IS NOT NULL
                AND tenant_id = 'default'
                GROUP BY ttp
            """)
            
            # Get improvement status
            improvements = await conn.fetch("""
                SELECT status, COUNT(*) as count
                FROM detection_improvements
                WHERE tenant_id = 'default'
                GROUP BY status
            """)
            
            # Get recommendations status
            recommendations = await conn.fetch("""
                SELECT priority, status, COUNT(*) as count
                FROM purple_team_recommendations
                WHERE tenant_id = 'default'
                GROUP BY priority, status
            """)
        
        # Calculate readiness score
        ttp_scores = []
        for ttp in ttp_coverage:
            if ttp['attempts'] > 0:
                detection_rate = ttp['detections'] / ttp['attempts']
                ttp_scores.append(detection_rate)
        
        readiness_score = sum(ttp_scores) / len(ttp_scores) * 100 if ttp_scores else 0
        
        return {
            "readiness_score": readiness_score,
            "ttp_coverage": [dict(t) for t in ttp_coverage],
            "improvement_status": [dict(i) for i in improvements],
            "recommendation_status": [dict(r) for r in recommendations],
            "assessment": self._assess_readiness(readiness_score)
        }
    
    def _assess_readiness(self, score: float) -> str:
        """Assess security readiness based on score"""
        if score >= 80:
            return "Excellent - Security controls are highly effective"
        elif score >= 60:
            return "Good - Security controls are generally effective with some gaps"
        elif score >= 40:
            return "Fair - Significant security gaps need addressing"
        else:
            return "Poor - Critical security improvements required"
    
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
        'notification_webhook': 'https://security.isectech.com/webhook'
    }
    
    # Initialize framework
    purple_team = PurpleTeamAutomationFramework(db_config, config)
    await purple_team.initialize()
    
    # Run APT29 exercise
    apt29_result = await purple_team.run_exercise("APT29", ExerciseType.TECHNICAL)
    print(f"APT29 Exercise: Detection rate: {apt29_result['detection_rate']:.1f}%")
    
    # Run ransomware exercise
    ransomware_result = await purple_team.run_exercise("RANSOMWARE", ExerciseType.TECHNICAL)
    print(f"Ransomware Exercise: Prevention rate: {ransomware_result['prevention_rate']:.1f}%")
    
    # Get exercise history
    history = await purple_team.get_exercise_history(30)
    print(f"Exercise History: {history['summary']}")
    
    # Generate readiness report
    readiness = await purple_team.generate_readiness_report()
    print(f"Security Readiness: {readiness['readiness_score']:.1f}% - {readiness['assessment']}")
    
    await purple_team.close()


if __name__ == "__main__":
    asyncio.run(main())