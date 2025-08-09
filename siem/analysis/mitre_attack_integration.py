#!/usr/bin/env python3
"""
iSECTECH SIEM MITRE ATT&CK Integration
Production-grade MITRE ATT&CK framework integration for threat detection and analysis
Advanced technique mapping, detection coverage analysis, and threat intelligence correlation
"""

import asyncio
import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from dataclasses import dataclass, asdict
import requests
import yaml
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique data structure"""
    technique_id: str
    name: str
    description: str
    tactic: str
    platform: List[str]
    detection_sources: List[str]
    sub_techniques: List[str] = None
    kill_chain_phases: List[str] = None
    permissions_required: List[str] = None
    effective_permissions: List[str] = None
    data_sources: List[str] = None
    defenses_bypassed: List[str] = None
    is_sub_technique: bool = False
    parent_technique: Optional[str] = None

@dataclass
class MitreTactic:
    """MITRE ATT&CK tactic data structure"""
    tactic_id: str
    name: str
    description: str
    techniques: List[str]
    shortname: str

@dataclass
class DetectionRule:
    """Detection rule mapped to MITRE techniques"""
    rule_id: str
    name: str
    description: str
    technique_ids: List[str]
    data_sources: List[str]
    severity: str
    confidence: float
    coverage_score: float
    query_text: str
    false_positive_rate: float = 0.0
    last_updated: datetime = None

@dataclass
class CoverageAssessment:
    """Detection coverage assessment"""
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    gaps: List[str]
    strengths: List[str]
    recommendations: List[str]
    coverage_by_tactic: Dict[str, float]
    assessment_date: datetime

class MitreAttackIntegration:
    """MITRE ATT&CK framework integration and analysis platform"""
    
    def __init__(self, config_path: str = "/opt/siem/analysis/config/analysis_config.yaml"):
        """Initialize MITRE ATT&CK integration"""
        self.config_path = config_path
        self.config = self._load_config()
        self.mitre_data_path = Path("/opt/siem/analysis/mitre")
        self.mitre_data_path.mkdir(parents=True, exist_ok=True)
        
        # MITRE ATT&CK data
        self.techniques: Dict[str, MitreTechnique] = {}
        self.tactics: Dict[str, MitreTactic] = {}
        self.detection_rules: Dict[str, DetectionRule] = {}
        self.data_sources: Dict[str, List[str]] = {}
        
        # Analysis components
        self.technique_graph = nx.DiGraph()
        self.coverage_matrix = None
        
        # Initialize framework data
        asyncio.create_task(self._initialize_framework_data())
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return {}
    
    async def _initialize_framework_data(self):
        """Initialize MITRE ATT&CK framework data"""
        try:
            await self._download_mitre_data()
            await self._load_techniques()
            await self._load_tactics()
            await self._load_data_sources()
            await self._build_technique_graph()
            logger.info("MITRE ATT&CK framework data initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize MITRE ATT&CK data: {e}")
    
    async def _download_mitre_data(self):
        """Download latest MITRE ATT&CK data"""
        try:
            # MITRE ATT&CK STIX data URL
            stix_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            
            response = requests.get(stix_url, timeout=30)
            response.raise_for_status()
            
            mitre_data_file = self.mitre_data_path / "enterprise-attack.json"
            with open(mitre_data_file, 'w') as f:
                json.dump(response.json(), f, indent=2)
            
            logger.info("MITRE ATT&CK data downloaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to download MITRE data: {e}")
            # Use existing data if available
            if not (self.mitre_data_path / "enterprise-attack.json").exists():
                await self._create_sample_mitre_data()
    
    async def _create_sample_mitre_data(self):
        """Create sample MITRE data for demonstration"""
        sample_data = {
            "type": "bundle",
            "id": "bundle--sample",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0a3ead4e-6d47-4ccb-854c-a6a4f9d96b22",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1003",
                            "url": "https://attack.mitre.org/techniques/T1003"
                        }
                    ],
                    "name": "OS Credential Dumping",
                    "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "credential-access"
                        }
                    ],
                    "x_mitre_platforms": ["Windows", "Linux", "macOS"],
                    "x_mitre_data_sources": ["Process monitoring", "API monitoring"]
                }
            ]
        }
        
        mitre_data_file = self.mitre_data_path / "enterprise-attack.json"
        with open(mitre_data_file, 'w') as f:
            json.dump(sample_data, f, indent=2)
    
    async def _load_techniques(self):
        """Load MITRE ATT&CK techniques"""
        try:
            mitre_data_file = self.mitre_data_path / "enterprise-attack.json"
            with open(mitre_data_file, 'r') as f:
                mitre_data = json.load(f)
            
            for obj in mitre_data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    technique_id = None
                    
                    # Extract technique ID from external references
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            technique_id = ref.get('external_id')
                            break
                    
                    if technique_id:
                        # Determine if this is a sub-technique
                        is_sub_technique = '.' in technique_id
                        parent_technique = technique_id.split('.')[0] if is_sub_technique else None
                        
                        # Extract tactic from kill chain phases
                        tactic = None
                        for phase in obj.get('kill_chain_phases', []):
                            if phase.get('kill_chain_name') == 'mitre-attack':
                                tactic = phase.get('phase_name', '').replace('-', '_')
                                break
                        
                        technique = MitreTechnique(
                            technique_id=technique_id,
                            name=obj.get('name', ''),
                            description=obj.get('description', ''),
                            tactic=tactic or 'unknown',
                            platform=obj.get('x_mitre_platforms', []),
                            detection_sources=obj.get('x_mitre_data_sources', []),
                            sub_techniques=[],
                            kill_chain_phases=[phase.get('phase_name') for phase in obj.get('kill_chain_phases', [])],
                            permissions_required=obj.get('x_mitre_permissions_required', []),
                            effective_permissions=obj.get('x_mitre_effective_permissions', []),
                            data_sources=obj.get('x_mitre_data_sources', []),
                            defenses_bypassed=obj.get('x_mitre_defense_bypassed', []),
                            is_sub_technique=is_sub_technique,
                            parent_technique=parent_technique
                        )
                        
                        self.techniques[technique_id] = technique
            
            # Build sub-technique relationships
            for technique_id, technique in self.techniques.items():
                if technique.parent_technique and technique.parent_technique in self.techniques:
                    self.techniques[technique.parent_technique].sub_techniques.append(technique_id)
            
            logger.info(f"Loaded {len(self.techniques)} MITRE ATT&CK techniques")
            
        except Exception as e:
            logger.error(f"Failed to load MITRE techniques: {e}")
    
    async def _load_tactics(self):
        """Load MITRE ATT&CK tactics"""
        try:
            mitre_data_file = self.mitre_data_path / "enterprise-attack.json"
            with open(mitre_data_file, 'r') as f:
                mitre_data = json.load(f)
            
            for obj in mitre_data.get('objects', []):
                if obj.get('type') == 'x-mitre-tactic':
                    tactic_id = None
                    
                    # Extract tactic ID from external references
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            tactic_id = ref.get('external_id')
                            break
                    
                    if tactic_id:
                        tactic = MitreTactic(
                            tactic_id=tactic_id,
                            name=obj.get('name', ''),
                            description=obj.get('description', ''),
                            techniques=[],
                            shortname=obj.get('x_mitre_shortname', '')
                        )
                        
                        self.tactics[tactic_id] = tactic
            
            # Map techniques to tactics
            for technique in self.techniques.values():
                if technique.tactic in [t.shortname for t in self.tactics.values()]:
                    for tactic in self.tactics.values():
                        if tactic.shortname == technique.tactic:
                            tactic.techniques.append(technique.technique_id)
                            break
            
            logger.info(f"Loaded {len(self.tactics)} MITRE ATT&CK tactics")
            
        except Exception as e:
            logger.error(f"Failed to load MITRE tactics: {e}")
    
    async def _load_data_sources(self):
        """Load and organize MITRE data sources"""
        try:
            # Extract unique data sources from techniques
            all_data_sources = set()
            for technique in self.techniques.values():
                all_data_sources.update(technique.data_sources)
            
            # Map data sources to techniques
            self.data_sources = defaultdict(list)
            for technique in self.techniques.values():
                for source in technique.data_sources:
                    self.data_sources[source].append(technique.technique_id)
            
            logger.info(f"Organized {len(all_data_sources)} unique data sources")
            
        except Exception as e:
            logger.error(f"Failed to load data sources: {e}")
    
    async def _build_technique_graph(self):
        """Build technique relationship graph"""
        try:
            self.technique_graph = nx.DiGraph()
            
            # Add technique nodes
            for technique_id, technique in self.techniques.items():
                self.technique_graph.add_node(
                    technique_id,
                    name=technique.name,
                    tactic=technique.tactic,
                    is_sub_technique=technique.is_sub_technique
                )
            
            # Add edges for sub-technique relationships
            for technique_id, technique in self.techniques.items():
                if technique.parent_technique:
                    self.technique_graph.add_edge(technique.parent_technique, technique_id)
            
            logger.info(f"Built technique graph with {self.technique_graph.number_of_nodes()} nodes and {self.technique_graph.number_of_edges()} edges")
            
        except Exception as e:
            logger.error(f"Failed to build technique graph: {e}")
    
    async def load_detection_rules(self, rules_path: str) -> int:
        """Load detection rules from file or database"""
        try:
            # For demo, create sample detection rules
            sample_rules = [
                DetectionRule(
                    rule_id="DR-001",
                    name="Credential Dumping Detection",
                    description="Detects credential dumping activities",
                    technique_ids=["T1003"],
                    data_sources=["Process monitoring", "API monitoring"],
                    severity="high",
                    confidence=0.8,
                    coverage_score=0.7,
                    query_text="process_name:mimikatz OR process_name:procdump",
                    false_positive_rate=0.05,
                    last_updated=datetime.now(timezone.utc)
                ),
                DetectionRule(
                    rule_id="DR-002",
                    name="Process Injection Detection",
                    description="Detects process injection techniques",
                    technique_ids=["T1055"],
                    data_sources=["Process monitoring"],
                    severity="high",
                    confidence=0.75,
                    coverage_score=0.6,
                    query_text="event_id:8 OR event_id:10",
                    false_positive_rate=0.1,
                    last_updated=datetime.now(timezone.utc)
                )
            ]
            
            for rule in sample_rules:
                self.detection_rules[rule.rule_id] = rule
            
            logger.info(f"Loaded {len(self.detection_rules)} detection rules")
            return len(self.detection_rules)
            
        except Exception as e:
            logger.error(f"Failed to load detection rules: {e}")
            return 0
    
    async def assess_detection_coverage(self) -> CoverageAssessment:
        """Assess detection coverage across MITRE ATT&CK framework"""
        try:
            # Get all techniques covered by detection rules
            covered_techniques = set()
            for rule in self.detection_rules.values():
                covered_techniques.update(rule.technique_ids)
            
            # Calculate overall coverage
            total_techniques = len([t for t in self.techniques.values() if not t.is_sub_technique])
            covered_count = len([t for t in covered_techniques if not t.startswith('T') or '.' not in t])
            coverage_percentage = (covered_count / total_techniques) * 100 if total_techniques > 0 else 0
            
            # Calculate coverage by tactic
            coverage_by_tactic = {}
            for tactic_id, tactic in self.tactics.items():
                tactic_techniques = set(tactic.techniques)
                tactic_covered = tactic_techniques.intersection(covered_techniques)
                tactic_coverage = (len(tactic_covered) / len(tactic_techniques)) * 100 if tactic_techniques else 0
                coverage_by_tactic[tactic.name] = round(tactic_coverage, 2)
            
            # Identify gaps and strengths
            all_technique_ids = set(self.techniques.keys())
            gaps = list(all_technique_ids - covered_techniques)
            strengths = list(covered_techniques)
            
            # Generate recommendations
            recommendations = await self._generate_coverage_recommendations(gaps, coverage_by_tactic)
            
            assessment = CoverageAssessment(
                total_techniques=total_techniques,
                covered_techniques=covered_count,
                coverage_percentage=round(coverage_percentage, 2),
                gaps=gaps[:20],  # Top 20 gaps
                strengths=strengths[:20],  # Top 20 strengths
                recommendations=recommendations,
                coverage_by_tactic=coverage_by_tactic,
                assessment_date=datetime.now(timezone.utc)
            )
            
            logger.info(f"Coverage assessment completed: {coverage_percentage:.2f}% coverage")
            return assessment
            
        except Exception as e:
            logger.error(f"Failed to assess detection coverage: {e}")
            raise
    
    async def _generate_coverage_recommendations(self, gaps: List[str], 
                                               coverage_by_tactic: Dict[str, float]) -> List[str]:
        """Generate recommendations for improving detection coverage"""
        recommendations = []
        
        # Identify tactics with low coverage
        low_coverage_tactics = [tactic for tactic, coverage in coverage_by_tactic.items() if coverage < 50]
        if low_coverage_tactics:
            recommendations.append(f"Focus on improving coverage for tactics: {', '.join(low_coverage_tactics)}")
        
        # Identify high-priority techniques without coverage
        high_priority_gaps = []
        for gap in gaps[:10]:  # Top 10 gaps
            if gap in self.techniques:
                technique = self.techniques[gap]
                if technique.tactic in ['credential_access', 'lateral_movement', 'persistence']:
                    high_priority_gaps.append(f"{gap}: {technique.name}")
        
        if high_priority_gaps:
            recommendations.append(f"High-priority detection gaps: {', '.join(high_priority_gaps[:3])}")
        
        # Data source recommendations
        uncovered_data_sources = []
        for source, techniques in self.data_sources.items():
            covered = any(t in gaps for t in techniques)
            if not covered:
                uncovered_data_sources.append(source)
        
        if uncovered_data_sources:
            recommendations.append(f"Consider implementing data sources: {', '.join(uncovered_data_sources[:3])}")
        
        return recommendations
    
    async def map_alert_to_mitre(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map security alert to MITRE ATT&CK techniques"""
        try:
            mapped_techniques = []
            
            # Extract relevant fields from alert
            process_name = alert_data.get('process_name', '').lower()
            command_line = alert_data.get('command_line', '').lower()
            event_category = alert_data.get('event_category', '').lower()
            
            # Simple mapping logic (would be more sophisticated in production)
            if 'mimikatz' in process_name or 'lsadump' in command_line:
                mapped_techniques.append('T1003')  # OS Credential Dumping
            
            if 'powershell' in process_name and 'encoded' in command_line:
                mapped_techniques.append('T1027')  # Obfuscated Files or Information
                mapped_techniques.append('T1059.001')  # PowerShell
            
            if 'rundll32' in process_name or 'regsvr32' in process_name:
                mapped_techniques.append('T1218')  # Signed Binary Proxy Execution
            
            # Get technique details
            technique_details = []
            for technique_id in mapped_techniques:
                if technique_id in self.techniques:
                    technique = self.techniques[technique_id]
                    technique_details.append({
                        'technique_id': technique_id,
                        'name': technique.name,
                        'tactic': technique.tactic,
                        'description': technique.description[:200] + '...' if len(technique.description) > 200 else technique.description
                    })
            
            mapping_result = {
                'alert_id': alert_data.get('alert_id', str(uuid.uuid4())),
                'mapped_techniques': technique_details,
                'confidence_score': 0.8 if technique_details else 0.0,
                'mapping_timestamp': datetime.now(timezone.utc).isoformat(),
                'data_sources_used': alert_data.get('data_sources', [])
            }
            
            return mapping_result
            
        except Exception as e:
            logger.error(f"Failed to map alert to MITRE: {e}")
            return {}
    
    async def generate_attack_path_analysis(self, techniques: List[str]) -> Dict[str, Any]:
        """Generate attack path analysis for given techniques"""
        try:
            # Build attack path graph
            attack_graph = nx.DiGraph()
            
            # Group techniques by tactic
            techniques_by_tactic = defaultdict(list)
            for technique_id in techniques:
                if technique_id in self.techniques:
                    technique = self.techniques[technique_id]
                    techniques_by_tactic[technique.tactic].append(technique_id)
            
            # Define typical attack progression
            tactic_order = [
                'initial_access', 'execution', 'persistence', 'privilege_escalation',
                'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
                'collection', 'command_and_control', 'exfiltration', 'impact'
            ]
            
            # Build attack path
            attack_path = []
            for i, tactic in enumerate(tactic_order):
                if tactic in techniques_by_tactic:
                    phase = {
                        'phase': i + 1,
                        'tactic': tactic,
                        'techniques': techniques_by_tactic[tactic],
                        'technique_details': []
                    }
                    
                    for technique_id in techniques_by_tactic[tactic]:
                        if technique_id in self.techniques:
                            technique = self.techniques[technique_id]
                            phase['technique_details'].append({
                                'id': technique_id,
                                'name': technique.name,
                                'platforms': technique.platform
                            })
                    
                    attack_path.append(phase)
            
            # Calculate attack complexity
            complexity_score = len(attack_path) / len(tactic_order)
            
            # Generate insights
            insights = await self._generate_attack_path_insights(attack_path, complexity_score)
            
            analysis_result = {
                'attack_path': attack_path,
                'complexity_score': round(complexity_score, 2),
                'total_phases': len(attack_path),
                'coverage_tactics': list(techniques_by_tactic.keys()),
                'insights': insights,
                'analysis_timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Failed to generate attack path analysis: {e}")
            return {}
    
    async def _generate_attack_path_insights(self, attack_path: List[Dict], 
                                           complexity_score: float) -> List[str]:
        """Generate insights for attack path analysis"""
        insights = []
        
        if complexity_score > 0.7:
            insights.append("This appears to be a sophisticated, multi-stage attack campaign")
        elif complexity_score > 0.4:
            insights.append("This represents a moderate complexity attack with multiple tactics")
        else:
            insights.append("This appears to be a focused attack targeting specific objectives")
        
        # Identify critical phases
        if any(phase['tactic'] == 'credential_access' for phase in attack_path):
            insights.append("Credential access detected - potential for lateral movement")
        
        if any(phase['tactic'] == 'persistence' for phase in attack_path):
            insights.append("Persistence mechanisms identified - threat may return")
        
        if any(phase['tactic'] == 'exfiltration' for phase in attack_path):
            insights.append("Data exfiltration activity detected - assess data impact")
        
        return insights
    
    async def generate_technique_recommendations(self, current_techniques: List[str]) -> List[Dict[str, Any]]:
        """Generate recommendations for additional techniques to monitor"""
        try:
            recommendations = []
            
            # Analyze current technique coverage
            current_tactics = set()
            for technique_id in current_techniques:
                if technique_id in self.techniques:
                    current_tactics.add(self.techniques[technique_id].tactic)
            
            # Find gaps in tactic coverage
            all_tactics = set(tactic.shortname for tactic in self.tactics.values())
            missing_tactics = all_tactics - current_tactics
            
            for tactic in missing_tactics:
                # Find high-value techniques for this tactic
                tactic_techniques = []
                for technique in self.techniques.values():
                    if technique.tactic == tactic and not technique.is_sub_technique:
                        tactic_techniques.append(technique)
                
                # Prioritize techniques by data source availability
                for technique in tactic_techniques[:3]:  # Top 3 per tactic
                    recommendation = {
                        'technique_id': technique.technique_id,
                        'name': technique.name,
                        'tactic': technique.tactic,
                        'priority': 'high' if technique.tactic in ['credential_access', 'lateral_movement'] else 'medium',
                        'data_sources': technique.data_sources,
                        'platforms': technique.platform,
                        'rationale': f"Enhance {technique.tactic} detection capabilities"
                    }
                    recommendations.append(recommendation)
            
            # Sort by priority
            priority_order = {'high': 1, 'medium': 2, 'low': 3}
            recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
            
            return recommendations[:10]  # Top 10 recommendations
            
        except Exception as e:
            logger.error(f"Failed to generate technique recommendations: {e}")
            return []
    
    async def export_coverage_report(self, assessment: CoverageAssessment, 
                                   output_path: str) -> str:
        """Export coverage assessment report"""
        try:
            report_data = {
                'assessment_summary': asdict(assessment),
                'detailed_coverage': {},
                'recommendations_detailed': [],
                'technique_matrix': {}
            }
            
            # Add detailed coverage by tactic
            for tactic_id, tactic in self.tactics.items():
                covered_techniques = []
                uncovered_techniques = []
                
                for technique_id in tactic.techniques:
                    if technique_id in assessment.strengths:
                        covered_techniques.append({
                            'id': technique_id,
                            'name': self.techniques.get(technique_id, {}).name if technique_id in self.techniques else 'Unknown'
                        })
                    elif technique_id in assessment.gaps:
                        uncovered_techniques.append({
                            'id': technique_id,
                            'name': self.techniques.get(technique_id, {}).name if technique_id in self.techniques else 'Unknown'
                        })
                
                report_data['detailed_coverage'][tactic.name] = {
                    'covered': covered_techniques,
                    'uncovered': uncovered_techniques,
                    'coverage_percentage': assessment.coverage_by_tactic.get(tactic.name, 0)
                }
            
            # Save report
            output_file = Path(output_path) / f"mitre_coverage_report_{assessment.assessment_date.strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"Coverage report exported to: {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to export coverage report: {e}")
            raise
    
    async def get_technique_details(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific technique"""
        if technique_id not in self.techniques:
            return None
        
        technique = self.techniques[technique_id]
        
        # Get related detection rules
        related_rules = []
        for rule in self.detection_rules.values():
            if technique_id in rule.technique_ids:
                related_rules.append({
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'confidence': rule.confidence,
                    'severity': rule.severity
                })
        
        # Get sub-techniques
        sub_techniques = []
        for sub_id in technique.sub_techniques:
            if sub_id in self.techniques:
                sub_technique = self.techniques[sub_id]
                sub_techniques.append({
                    'id': sub_id,
                    'name': sub_technique.name,
                    'description': sub_technique.description[:100] + '...' if len(sub_technique.description) > 100 else sub_technique.description
                })
        
        return {
            'technique': asdict(technique),
            'related_rules': related_rules,
            'sub_techniques': sub_techniques,
            'detection_coverage': len(related_rules) > 0,
            'data_source_count': len(technique.data_sources),
            'platform_count': len(technique.platform)
        }

if __name__ == "__main__":
    # Example usage
    async def main():
        mitre_integration = MitreAttackIntegration()
        
        # Wait for initialization
        await asyncio.sleep(2)
        
        # Load detection rules
        await mitre_integration.load_detection_rules("/opt/siem/rules")
        
        # Assess coverage
        assessment = await mitre_integration.assess_detection_coverage()
        print(f"Detection Coverage: {assessment.coverage_percentage}%")
        
        # Map sample alert
        sample_alert = {
            'alert_id': 'ALT-001',
            'process_name': 'mimikatz.exe',
            'command_line': 'mimikatz.exe sekurlsa::logonpasswords',
            'event_category': 'process_creation'
        }
        
        mapping = await mitre_integration.map_alert_to_mitre(sample_alert)
        print(f"Mapped techniques: {[t['technique_id'] for t in mapping.get('mapped_techniques', [])]}")
        
        # Generate attack path analysis
        attack_techniques = ['T1078', 'T1055', 'T1003', 'T1021']
        path_analysis = await mitre_integration.generate_attack_path_analysis(attack_techniques)
        print(f"Attack path complexity: {path_analysis.get('complexity_score', 0)}")
    
    asyncio.run(main())