#!/usr/bin/env python3
"""
iSECTECH SIEM Investigation Engine
Production-grade security investigation and analysis platform
Advanced threat hunting, forensic analysis, and incident investigation tools
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
from elasticsearch import Elasticsearch, helpers
import psycopg2
from psycopg2.extras import RealDictCursor
import redis.asyncio as redis
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
import yaml
import uuid
import hashlib
import re
from collections import defaultdict, Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import base64
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Investigation:
    """Investigation case data structure"""
    investigation_id: str
    title: str
    description: str
    priority: str  # critical, high, medium, low
    status: str    # open, in_progress, pending, closed
    investigator: str
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    indicators: List[Dict[str, Any]]
    timeline_events: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    related_alerts: List[str]
    related_cases: List[str]
    metadata: Dict[str, Any]

@dataclass
class ThreatHuntQuery:
    """Threat hunting query definition"""
    query_id: str
    name: str
    description: str
    query_type: str  # elasticsearch, sql, graph, statistical
    query_text: str
    parameters: Dict[str, Any]
    data_sources: List[str]
    indicators: List[str]
    mitre_techniques: List[str]
    created_by: str
    created_at: datetime
    last_executed: Optional[datetime] = None
    execution_count: int = 0

@dataclass
class AnalysisResult:
    """Analysis result data structure"""
    result_id: str
    analysis_type: str
    query_id: Optional[str]
    investigation_id: Optional[str]
    title: str
    summary: str
    findings: List[Dict[str, Any]]
    visualizations: List[Dict[str, Any]]
    recommendations: List[str]
    confidence_score: float
    risk_level: str
    created_at: datetime
    created_by: str
    metadata: Dict[str, Any]

class InvestigationEngine:
    """
    Advanced security investigation and analysis engine
    Provides threat hunting, forensic analysis, and investigation management
    """
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.es_client = None
        self.db_connection = None
        self.redis_client = None
        
        # Investigation storage
        self.active_investigations = {}
        self.threat_hunt_queries = {}
        self.analysis_templates = {}
        
        # Graph database for relationship analysis
        self.relationship_graph = nx.MultiDiGraph()
        
        # Analysis engines
        self.behavioral_analyzer = None
        self.network_analyzer = None
        self.temporal_analyzer = None
        
    async def initialize(self):
        """Initialize the investigation engine"""
        try:
            await self._load_config()
            await self._setup_elasticsearch()
            await self._setup_database()
            await self._setup_redis()
            await self._load_threat_hunt_queries()
            await self._load_analysis_templates()
            await self._initialize_analyzers()
            logger.info("Investigation Engine initialized successfully")
        except Exception as e:
            logger.error(f"Investigation Engine initialization failed: {e}")
            raise
            
    async def _load_config(self):
        """Load investigation configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default configuration
            self.config = {
                'elasticsearch': {'hosts': ['localhost:9200']},
                'database': {'host': 'localhost', 'port': 5432, 'database': 'siem_investigations'},
                'redis': {'host': 'localhost', 'port': 6379, 'db': 6},
                'analysis': {'max_results': 10000, 'timeout_seconds': 300}
            }
            
    async def _setup_elasticsearch(self):
        """Setup Elasticsearch connection"""
        try:
            es_config = self.config.get('elasticsearch', {})
            self.es_client = Elasticsearch(
                hosts=es_config.get('hosts', ['localhost:9200']),
                verify_certs=es_config.get('verify_certs', False),
                use_ssl=es_config.get('use_ssl', False),
                timeout=es_config.get('timeout', 60)
            )
            
            if self.es_client.ping():
                logger.info("Elasticsearch connection established")
            else:
                logger.warning("Elasticsearch connection failed")
                self.es_client = None
                
        except Exception as e:
            logger.warning(f"Elasticsearch setup failed: {e}")
            self.es_client = None
            
    async def _setup_database(self):
        """Setup PostgreSQL connection"""
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'siem_investigations'),
                user=db_config.get('user', 'investigation_user'),
                password=db_config.get('password', 'investigation_password'),
                cursor_factory=RealDictCursor
            )
            self.db_connection.autocommit = True
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            self.db_connection = None
            
    async def _setup_redis(self):
        """Setup Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 6),
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
            
    async def _load_threat_hunt_queries(self):
        """Load predefined threat hunting queries"""
        try:
            # Load from database if available
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT query_id, name, description, query_type, query_text,
                           parameters, data_sources, indicators, mitre_techniques,
                           created_by, created_at, last_executed, execution_count
                    FROM threat_hunt_queries 
                    WHERE enabled = true
                """)
                
                for row in cursor.fetchall():
                    query = ThreatHuntQuery(
                        query_id=row['query_id'],
                        name=row['name'],
                        description=row['description'],
                        query_type=row['query_type'],
                        query_text=row['query_text'],
                        parameters=json.loads(row['parameters']),
                        data_sources=json.loads(row['data_sources']),
                        indicators=json.loads(row['indicators']),
                        mitre_techniques=json.loads(row['mitre_techniques']),
                        created_by=row['created_by'],
                        created_at=row['created_at'],
                        last_executed=row['last_executed'],
                        execution_count=row['execution_count']
                    )
                    self.threat_hunt_queries[row['query_id']] = query
                    
                cursor.close()
                logger.info(f"Loaded {len(self.threat_hunt_queries)} threat hunt queries")
                
            # Create default queries if none exist
            if not self.threat_hunt_queries:
                await self._create_default_hunt_queries()
                
        except Exception as e:
            logger.error(f"Failed to load threat hunt queries: {e}")
            await self._create_default_hunt_queries()
            
    async def _create_default_hunt_queries(self):
        """Create default threat hunting queries"""
        default_queries = [
            {
                'query_id': 'lateral_movement_detection',
                'name': 'Lateral Movement Detection',
                'description': 'Detect potential lateral movement using administrative tools',
                'query_type': 'elasticsearch',
                'query_text': '''
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"terms": {"process.name": ["psexec.exe", "wmic.exe", "powershell.exe"]}},
                                {"range": {"@timestamp": {"gte": "now-1h"}}},
                                {"exists": {"field": "destination.ip"}}
                            ]
                        }
                    },
                    "aggs": {
                        "by_source": {
                            "terms": {"field": "source.ip", "size": 50}
                        }
                    }
                }
                ''',
                'parameters': {'time_range': '1h', 'min_connections': 3},
                'data_sources': ['windows_logs', 'network_logs'],
                'indicators': ['process.name', 'source.ip', 'destination.ip'],
                'mitre_techniques': ['T1021', 'T1047', 'T1059']
            },
            {
                'query_id': 'credential_stuffing_detection',
                'name': 'Credential Stuffing Detection',
                'description': 'Detect credential stuffing attacks',
                'query_type': 'elasticsearch',
                'query_text': '''
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"event.action": "login"}},
                                {"term": {"event.outcome": "failure"}},
                                {"range": {"@timestamp": {"gte": "now-10m"}}}
                            ]
                        }
                    },
                    "aggs": {
                        "by_source_ip": {
                            "terms": {"field": "source.ip", "size": 100},
                            "aggs": {
                                "unique_users": {"cardinality": {"field": "user.name"}},
                                "failure_count": {"value_count": {"field": "_id"}}
                            }
                        }
                    }
                }
                ''',
                'parameters': {'time_range': '10m', 'min_failures': 10, 'min_users': 5},
                'data_sources': ['authentication_logs'],
                'indicators': ['source.ip', 'user.name', 'event.outcome'],
                'mitre_techniques': ['T1110', 'T1078']
            },
            {
                'query_id': 'data_exfiltration_detection',
                'name': 'Data Exfiltration Detection',
                'description': 'Detect potential data exfiltration based on volume',
                'query_type': 'elasticsearch',
                'query_text': '''
                {
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"network.bytes": {"gte": 1000000}}},
                                {"range": {"@timestamp": {"gte": "now-1h"}}},
                                {"term": {"network.direction": "outbound"}}
                            ]
                        }
                    },
                    "aggs": {
                        "by_source": {
                            "terms": {"field": "source.ip", "size": 50},
                            "aggs": {
                                "total_bytes": {"sum": {"field": "network.bytes"}},
                                "destination_count": {"cardinality": {"field": "destination.ip"}}
                            }
                        }
                    }
                }
                ''',
                'parameters': {'time_range': '1h', 'min_bytes': 1000000},
                'data_sources': ['network_logs', 'firewall_logs'],
                'indicators': ['source.ip', 'destination.ip', 'network.bytes'],
                'mitre_techniques': ['T1041', 'T1567']
            }
        ]
        
        for query_data in default_queries:
            query = ThreatHuntQuery(
                **query_data,
                created_by='system',
                created_at=datetime.now(timezone.utc)
            )
            self.threat_hunt_queries[query.query_id] = query
            
    async def _load_analysis_templates(self):
        """Load analysis templates"""
        self.analysis_templates = {
            'incident_timeline': {
                'name': 'Incident Timeline Analysis',
                'description': 'Generate comprehensive timeline of incident events',
                'required_fields': ['@timestamp', 'event.action', 'source.ip'],
                'visualization_type': 'timeline'
            },
            'network_flow_analysis': {
                'name': 'Network Flow Analysis',
                'description': 'Analyze network communication patterns',
                'required_fields': ['source.ip', 'destination.ip', 'network.bytes'],
                'visualization_type': 'network_graph'
            },
            'user_behavior_analysis': {
                'name': 'User Behavior Analysis',
                'description': 'Analyze user activity patterns for anomalies',
                'required_fields': ['user.name', 'event.action', '@timestamp'],
                'visualization_type': 'behavior_chart'
            }
        }
        
    async def _initialize_analyzers(self):
        """Initialize specialized analysis engines"""
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.temporal_analyzer = TemporalAnalyzer()
        
    async def create_investigation(self, investigation_data: Dict[str, Any]) -> Investigation:
        """Create a new security investigation"""
        try:
            investigation = Investigation(
                investigation_id=investigation_data.get('investigation_id', self._generate_investigation_id()),
                title=investigation_data['title'],
                description=investigation_data['description'],
                priority=investigation_data.get('priority', 'medium'),
                status='open',
                investigator=investigation_data['investigator'],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                tags=investigation_data.get('tags', []),
                indicators=investigation_data.get('indicators', []),
                timeline_events=[],
                findings=[],
                evidence=[],
                related_alerts=investigation_data.get('related_alerts', []),
                related_cases=investigation_data.get('related_cases', []),
                metadata=investigation_data.get('metadata', {})
            )
            
            # Store investigation
            await self._store_investigation(investigation)
            
            # Initialize investigation workspace
            await self._initialize_investigation_workspace(investigation)
            
            self.active_investigations[investigation.investigation_id] = investigation
            
            logger.info(f"Investigation created: {investigation.investigation_id}")
            return investigation
            
        except Exception as e:
            logger.error(f"Failed to create investigation: {e}")
            raise
            
    async def execute_threat_hunt(self, query_id: str, parameters: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """Execute threat hunting query"""
        try:
            if query_id not in self.threat_hunt_queries:
                raise ValueError(f"Unknown threat hunt query: {query_id}")
                
            query = self.threat_hunt_queries[query_id]
            
            # Merge parameters
            merged_params = query.parameters.copy()
            if parameters:
                merged_params.update(parameters)
                
            # Execute query based on type
            if query.query_type == 'elasticsearch':
                results = await self._execute_elasticsearch_hunt(query, merged_params)
            elif query.query_type == 'sql':
                results = await self._execute_sql_hunt(query, merged_params)
            elif query.query_type == 'graph':
                results = await self._execute_graph_hunt(query, merged_params)
            else:
                raise ValueError(f"Unsupported query type: {query.query_type}")
                
            # Create analysis result
            analysis_result = AnalysisResult(
                result_id=self._generate_result_id(),
                analysis_type='threat_hunt',
                query_id=query_id,
                investigation_id=None,
                title=f"Threat Hunt: {query.name}",
                summary=await self._generate_hunt_summary(results, query),
                findings=results.get('findings', []),
                visualizations=results.get('visualizations', []),
                recommendations=await self._generate_hunt_recommendations(results, query),
                confidence_score=results.get('confidence_score', 0.5),
                risk_level=await self._calculate_risk_level(results),
                created_at=datetime.now(timezone.utc),
                created_by='system',
                metadata={'query_parameters': merged_params}
            )
            
            # Update query execution stats
            query.last_executed = datetime.now(timezone.utc)
            query.execution_count += 1
            await self._update_hunt_query_stats(query)
            
            # Store analysis result
            await self._store_analysis_result(analysis_result)
            
            logger.info(f"Threat hunt executed: {query_id}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Threat hunt execution failed: {e}")
            raise
            
    async def _execute_elasticsearch_hunt(self, query: ThreatHuntQuery, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Elasticsearch-based threat hunt"""
        if not self.es_client:
            raise ValueError("Elasticsearch not available")
            
        try:
            # Parse query template
            query_template = json.loads(query.query_text)
            
            # Apply time range parameter
            time_range = parameters.get('time_range', '1h')
            time_filter = {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{time_range}"
                    }
                }
            }
            
            # Add time filter to query
            if 'bool' in query_template['query']:
                if 'must' not in query_template['query']['bool']:
                    query_template['query']['bool']['must'] = []
                query_template['query']['bool']['must'].append(time_filter)
            else:
                query_template['query'] = {
                    "bool": {
                        "must": [query_template['query'], time_filter]
                    }
                }
                
            # Execute search
            indices = ','.join(query.data_sources) if query.data_sources else '_all'
            response = self.es_client.search(
                index=indices,
                body=query_template,
                size=parameters.get('size', 100)
            )
            
            # Process results
            findings = []
            hits = response.get('hits', {}).get('hits', [])
            
            for hit in hits:
                finding = {
                    'event_id': hit['_id'],
                    'source': hit['_source'],
                    'score': hit['_score'],
                    'indicators': await self._extract_indicators(hit['_source'], query.indicators)
                }
                findings.append(finding)
                
            # Process aggregations
            aggregations = response.get('aggregations', {})
            visualizations = await self._create_hunt_visualizations(aggregations, query.name)
            
            # Calculate confidence score
            confidence_score = min(len(findings) / 100.0, 1.0)  # Simplified scoring
            
            return {
                'findings': findings,
                'aggregations': aggregations,
                'visualizations': visualizations,
                'confidence_score': confidence_score,
                'total_hits': response['hits']['total']['value']
            }
            
        except Exception as e:
            logger.error(f"Elasticsearch hunt execution failed: {e}")
            raise
            
    async def _execute_sql_hunt(self, query: ThreatHuntQuery, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SQL-based threat hunt"""
        if not self.db_connection:
            raise ValueError("Database not available")
            
        try:
            # Apply parameters to SQL query
            sql_query = query.query_text
            for key, value in parameters.items():
                sql_query = sql_query.replace(f"${key}", str(value))
                
            # Execute query
            cursor = self.db_connection.cursor()
            cursor.execute(sql_query)
            results = cursor.fetchall()
            cursor.close()
            
            # Process results
            findings = []
            for row in results:
                finding = {
                    'data': dict(row),
                    'indicators': await self._extract_indicators(dict(row), query.indicators)
                }
                findings.append(finding)
                
            return {
                'findings': findings,
                'confidence_score': min(len(findings) / 50.0, 1.0),
                'total_results': len(findings)
            }
            
        except Exception as e:
            logger.error(f"SQL hunt execution failed: {e}")
            raise
            
    async def _execute_graph_hunt(self, query: ThreatHuntQuery, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute graph-based threat hunt"""
        try:
            # Build relationship graph from recent data
            await self._build_relationship_graph(parameters.get('time_range', '1h'))
            
            # Execute graph analysis based on query
            findings = []
            
            if 'lateral_movement' in query.query_text:
                findings = await self._detect_lateral_movement_patterns()
            elif 'data_exfiltration' in query.query_text:
                findings = await self._detect_exfiltration_patterns()
                
            return {
                'findings': findings,
                'confidence_score': min(len(findings) / 20.0, 1.0),
                'graph_stats': {
                    'nodes': self.relationship_graph.number_of_nodes(),
                    'edges': self.relationship_graph.number_of_edges()
                }
            }
            
        except Exception as e:
            logger.error(f"Graph hunt execution failed: {e}")
            raise
            
    async def analyze_incident_timeline(self, investigation_id: str, 
                                      time_range: Tuple[datetime, datetime]) -> AnalysisResult:
        """Analyze incident timeline"""
        try:
            investigation = self.active_investigations.get(investigation_id)
            if not investigation:
                raise ValueError(f"Investigation not found: {investigation_id}")
                
            # Gather events from multiple sources
            events = await self._gather_timeline_events(investigation, time_range)
            
            # Sort events by timestamp
            events.sort(key=lambda x: x['timestamp'])
            
            # Identify key events and patterns
            key_events = await self._identify_key_events(events)
            patterns = await self._identify_temporal_patterns(events)
            
            # Create timeline visualization
            timeline_viz = await self._create_timeline_visualization(events, key_events)
            
            # Generate findings
            findings = []
            for event in key_events:
                findings.append({
                    'type': 'key_event',
                    'timestamp': event['timestamp'],
                    'description': event['description'],
                    'indicators': event.get('indicators', []),
                    'severity': event.get('severity', 'medium')
                })
                
            for pattern in patterns:
                findings.append({
                    'type': 'temporal_pattern',
                    'pattern_name': pattern['name'],
                    'description': pattern['description'],
                    'confidence': pattern['confidence'],
                    'timeframe': pattern['timeframe']
                })
                
            # Create analysis result
            result = AnalysisResult(
                result_id=self._generate_result_id(),
                analysis_type='timeline_analysis',
                query_id=None,
                investigation_id=investigation_id,
                title=f"Timeline Analysis: {investigation.title}",
                summary=f"Analyzed {len(events)} events over {time_range[1] - time_range[0]}",
                findings=findings,
                visualizations=[timeline_viz],
                recommendations=await self._generate_timeline_recommendations(key_events, patterns),
                confidence_score=0.8,
                risk_level=await self._calculate_timeline_risk_level(key_events),
                created_at=datetime.now(timezone.utc),
                created_by='system',
                metadata={'event_count': len(events), 'time_range': [time_range[0].isoformat(), time_range[1].isoformat()]}
            )
            
            await self._store_analysis_result(result)
            
            logger.info(f"Timeline analysis completed for investigation: {investigation_id}")
            return result
            
        except Exception as e:
            logger.error(f"Timeline analysis failed: {e}")
            raise
            
    async def analyze_network_behavior(self, investigation_id: str, 
                                     focus_ips: List[str]) -> AnalysisResult:
        """Analyze network behavior patterns"""
        try:
            investigation = self.active_investigations.get(investigation_id)
            if not investigation:
                raise ValueError(f"Investigation not found: {investigation_id}")
                
            # Gather network data
            network_data = await self._gather_network_data(focus_ips, '24h')
            
            # Analyze communication patterns
            patterns = await self.network_analyzer.analyze_communication_patterns(network_data)
            
            # Detect anomalies
            anomalies = await self.network_analyzer.detect_network_anomalies(network_data)
            
            # Create network visualization
            network_viz = await self._create_network_visualization(network_data, focus_ips)
            
            # Generate findings
            findings = []
            for pattern in patterns:
                findings.append({
                    'type': 'communication_pattern',
                    'pattern_type': pattern['type'],
                    'description': pattern['description'],
                    'affected_ips': pattern['ips'],
                    'confidence': pattern['confidence']
                })
                
            for anomaly in anomalies:
                findings.append({
                    'type': 'network_anomaly',
                    'anomaly_type': anomaly['type'],
                    'description': anomaly['description'],
                    'indicators': anomaly['indicators'],
                    'severity': anomaly['severity']
                })
                
            # Create analysis result
            result = AnalysisResult(
                result_id=self._generate_result_id(),
                analysis_type='network_analysis',
                query_id=None,
                investigation_id=investigation_id,
                title=f"Network Analysis: {investigation.title}",
                summary=f"Analyzed network behavior for {len(focus_ips)} IP addresses",
                findings=findings,
                visualizations=[network_viz],
                recommendations=await self._generate_network_recommendations(patterns, anomalies),
                confidence_score=0.75,
                risk_level=await self._calculate_network_risk_level(anomalies),
                created_at=datetime.now(timezone.utc),
                created_by='system',
                metadata={'focus_ips': focus_ips, 'data_points': len(network_data)}
            )
            
            await self._store_analysis_result(result)
            
            logger.info(f"Network analysis completed for investigation: {investigation_id}")
            return result
            
        except Exception as e:
            logger.error(f"Network analysis failed: {e}")
            raise
            
    async def generate_investigation_report(self, investigation_id: str) -> Dict[str, Any]:
        """Generate comprehensive investigation report"""
        try:
            investigation = self.active_investigations.get(investigation_id)
            if not investigation:
                raise ValueError(f"Investigation not found: {investigation_id}")
                
            # Gather all analysis results for this investigation
            analysis_results = await self._get_investigation_analysis_results(investigation_id)
            
            # Generate executive summary
            executive_summary = await self._generate_executive_summary(investigation, analysis_results)
            
            # Compile findings
            all_findings = []
            for result in analysis_results:
                all_findings.extend(result.findings)
                
            # Group findings by type
            findings_by_type = defaultdict(list)
            for finding in all_findings:
                findings_by_type[finding.get('type', 'unknown')].append(finding)
                
            # Generate timeline
            timeline = await self._generate_investigation_timeline(investigation, analysis_results)
            
            # Compile evidence
            evidence_summary = await self._compile_evidence_summary(investigation)
            
            # Generate recommendations
            recommendations = await self._generate_investigation_recommendations(investigation, analysis_results)
            
            # Create visualizations
            visualizations = await self._create_report_visualizations(investigation, analysis_results)
            
            # Compile report
            report = {
                'investigation': asdict(investigation),
                'executive_summary': executive_summary,
                'findings_summary': {
                    'total_findings': len(all_findings),
                    'by_type': {k: len(v) for k, v in findings_by_type.items()},
                    'high_priority': len([f for f in all_findings if f.get('severity') == 'high'])
                },
                'detailed_findings': findings_by_type,
                'timeline': timeline,
                'evidence': evidence_summary,
                'analysis_results': [asdict(result) for result in analysis_results],
                'recommendations': recommendations,
                'visualizations': visualizations,
                'metadata': {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'generated_by': 'investigation_engine',
                    'report_version': '1.0'
                }
            }
            
            # Store report
            await self._store_investigation_report(investigation_id, report)
            
            logger.info(f"Investigation report generated: {investigation_id}")
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
            
    # Helper methods
    
    def _generate_investigation_id(self) -> str:
        """Generate unique investigation ID"""
        timestamp = int(datetime.now().timestamp())
        return f"INV-{timestamp}-{hash(str(timestamp)) % 10000:04d}"
        
    def _generate_result_id(self) -> str:
        """Generate unique result ID"""
        return str(uuid.uuid4())
        
    async def _store_investigation(self, investigation: Investigation):
        """Store investigation in database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO investigations 
                    (investigation_id, title, description, priority, status, investigator,
                     created_at, updated_at, tags, indicators, timeline_events, findings,
                     evidence, related_alerts, related_cases, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    investigation.investigation_id, investigation.title, investigation.description,
                    investigation.priority, investigation.status, investigation.investigator,
                    investigation.created_at, investigation.updated_at,
                    json.dumps(investigation.tags), json.dumps(investigation.indicators),
                    json.dumps(investigation.timeline_events), json.dumps(investigation.findings),
                    json.dumps(investigation.evidence), json.dumps(investigation.related_alerts),
                    json.dumps(investigation.related_cases), json.dumps(investigation.metadata)
                ))
                cursor.close()
                
        except Exception as e:
            logger.error(f"Failed to store investigation: {e}")
            
    async def _store_analysis_result(self, result: AnalysisResult):
        """Store analysis result in database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO analysis_results 
                    (result_id, analysis_type, query_id, investigation_id, title, summary,
                     findings, visualizations, recommendations, confidence_score, risk_level,
                     created_at, created_by, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    result.result_id, result.analysis_type, result.query_id,
                    result.investigation_id, result.title, result.summary,
                    json.dumps(result.findings), json.dumps(result.visualizations),
                    json.dumps(result.recommendations), result.confidence_score,
                    result.risk_level, result.created_at, result.created_by,
                    json.dumps(result.metadata)
                ))
                cursor.close()
                
        except Exception as e:
            logger.error(f"Failed to store analysis result: {e}")
            
    async def _extract_indicators(self, data: Dict[str, Any], indicator_fields: List[str]) -> List[str]:
        """Extract indicators from data"""
        indicators = []
        for field in indicator_fields:
            value = self._get_nested_value(data, field)
            if value:
                indicators.append(f"{field}:{value}")
        return indicators
        
    def _get_nested_value(self, data: Dict[str, Any], key_path: str) -> Any:
        """Get nested value from dictionary using dot notation"""
        keys = key_path.split('.')
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
        
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.db_connection:
                self.db_connection.close()
            if self.redis_client:
                await self.redis_client.close()
            if self.es_client:
                self.es_client.close()
            logger.info("Investigation Engine cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

# Specialized analyzer classes

class BehavioralAnalyzer:
    """Behavioral analysis engine"""
    
    async def analyze_user_behavior(self, user_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze user behavior patterns"""
        patterns = []
        
        # Group by user
        user_activities = defaultdict(list)
        for event in user_data:
            user = event.get('user', {}).get('name')
            if user:
                user_activities[user].append(event)
                
        # Analyze each user
        for user, activities in user_activities.items():
            # Time-based analysis
            timestamps = [datetime.fromisoformat(a['@timestamp']) for a in activities if '@timestamp' in a]
            if timestamps:
                # Detect unusual hours
                hours = [ts.hour for ts in timestamps]
                unusual_hours = [h for h in hours if h < 6 or h > 22]
                
                if len(unusual_hours) > len(hours) * 0.3:  # More than 30% outside normal hours
                    patterns.append({
                        'type': 'unusual_hours',
                        'user': user,
                        'description': f'User {user} active during unusual hours',
                        'confidence': 0.7,
                        'evidence': f'{len(unusual_hours)} activities outside normal hours'
                    })
                    
        return patterns

class NetworkAnalyzer:
    """Network analysis engine"""
    
    async def analyze_communication_patterns(self, network_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze network communication patterns"""
        patterns = []
        
        # Group by source IP
        ip_communications = defaultdict(list)
        for event in network_data:
            source_ip = event.get('source', {}).get('ip')
            if source_ip:
                ip_communications[source_ip].append(event)
                
        # Analyze each IP
        for ip, communications in ip_communications.items():
            # Count unique destinations
            destinations = set()
            total_bytes = 0
            
            for comm in communications:
                dest_ip = comm.get('destination', {}).get('ip')
                if dest_ip:
                    destinations.add(dest_ip)
                bytes_transferred = comm.get('network', {}).get('bytes', 0)
                total_bytes += bytes_transferred
                
            # Detect scanning behavior
            if len(destinations) > 50:
                patterns.append({
                    'type': 'potential_scanning',
                    'source_ip': ip,
                    'description': f'IP {ip} communicated with {len(destinations)} unique destinations',
                    'confidence': 0.8,
                    'ips': [ip] + list(destinations)[:10]  # Include first 10 destinations
                })
                
            # Detect high volume transfers
            if total_bytes > 1000000000:  # 1GB
                patterns.append({
                    'type': 'high_volume_transfer',
                    'source_ip': ip,
                    'description': f'IP {ip} transferred {total_bytes:,} bytes',
                    'confidence': 0.6,
                    'ips': [ip]
                })
                
        return patterns
        
    async def detect_network_anomalies(self, network_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect network anomalies"""
        anomalies = []
        
        # Analyze traffic volumes
        hourly_volumes = defaultdict(int)
        for event in network_data:
            timestamp = event.get('@timestamp')
            if timestamp:
                hour = datetime.fromisoformat(timestamp).hour
                bytes_transferred = event.get('network', {}).get('bytes', 0)
                hourly_volumes[hour] += bytes_transferred
                
        # Detect volume anomalies
        volumes = list(hourly_volumes.values())
        if volumes:
            mean_volume = np.mean(volumes)
            std_volume = np.std(volumes)
            
            for hour, volume in hourly_volumes.items():
                if volume > mean_volume + 3 * std_volume:  # 3 sigma rule
                    anomalies.append({
                        'type': 'volume_spike',
                        'description': f'Unusual traffic volume at hour {hour}',
                        'indicators': {'hour': hour, 'volume': volume, 'mean': mean_volume},
                        'severity': 'medium'
                    })
                    
        return anomalies

class TemporalAnalyzer:
    """Temporal analysis engine"""
    
    async def analyze_temporal_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze temporal patterns in events"""
        patterns = []
        
        # Extract timestamps
        timestamps = []
        for event in events:
            timestamp_str = event.get('@timestamp')
            if timestamp_str:
                try:
                    ts = datetime.fromisoformat(timestamp_str)
                    timestamps.append(ts)
                except:
                    continue
                    
        if len(timestamps) < 2:
            return patterns
            
        # Sort timestamps
        timestamps.sort()
        
        # Analyze time intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
            
        # Detect regular intervals (potential automated activity)
        if intervals:
            interval_counter = Counter(intervals)
            most_common_interval, count = interval_counter.most_common(1)[0]
            
            if count > len(intervals) * 0.5:  # More than 50% same interval
                patterns.append({
                    'name': 'regular_intervals',
                    'description': f'Events occurring at regular {most_common_interval}s intervals',
                    'confidence': 0.8,
                    'timeframe': f'{timestamps[0]} to {timestamps[-1]}'
                })
                
        return patterns

if __name__ == "__main__":
    # Example usage
    async def main():
        engine = InvestigationEngine("/path/to/investigation_config.yaml")
        await engine.initialize()
        
        # Create test investigation
        investigation_data = {
            'title': 'Suspicious Network Activity',
            'description': 'Investigating unusual network traffic patterns',
            'investigator': 'security.analyst@isectech.com',
            'priority': 'high',
            'tags': ['network', 'anomaly', 'investigation'],
            'indicators': ['192.168.1.100', 'user.suspicious']
        }
        
        investigation = await engine.create_investigation(investigation_data)
        print(f"Investigation created: {investigation.investigation_id}")
        
        # Execute threat hunt
        hunt_result = await engine.execute_threat_hunt('lateral_movement_detection')
        print(f"Threat hunt completed: {hunt_result.title}")
        
        # Generate report
        report = await engine.generate_investigation_report(investigation.investigation_id)
        print(f"Report generated with {len(report['detailed_findings'])} finding types")
        
        await engine.cleanup()
        
    # Run example
    # asyncio.run(main())