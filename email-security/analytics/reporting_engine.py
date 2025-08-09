"""
ISECTECH Email Security Analytics and Reporting Engine
=====================================================

Production-grade reporting and analytics system for email security metrics,
compliance reporting, and executive dashboards. Provides real-time insights
into email threats, security posture, and operational effectiveness.

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import aiofiles
from pathlib import Path
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import base64
from io import BytesIO
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import schedule
import threading
import time


class ReportType(Enum):
    """Report type classifications"""
    EXECUTIVE_SUMMARY = "executive_summary"
    SECURITY_POSTURE = "security_posture"  
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE_AUDIT = "compliance_audit"
    OPERATIONAL_METRICS = "operational_metrics"
    INCIDENT_ANALYSIS = "incident_analysis"
    USER_BEHAVIOR = "user_behavior"
    TREND_ANALYSIS = "trend_analysis"


class ReportFrequency(Enum):
    """Report generation frequency"""
    REAL_TIME = "real_time"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"
    ON_DEMAND = "on_demand"


class MetricType(Enum):
    """Email security metric types"""
    THREAT_COUNT = "threat_count"
    BLOCKED_EMAILS = "blocked_emails"
    QUARANTINED_EMAILS = "quarantined_emails"
    FALSE_POSITIVES = "false_positives"
    AUTHENTICATION_FAILURES = "authentication_failures"
    PHISHING_ATTEMPTS = "phishing_attempts"
    MALWARE_DETECTIONS = "malware_detections"
    SPAM_BLOCKED = "spam_blocked"
    USER_REPORTS = "user_reports"
    RESPONSE_TIME = "response_time"
    SYSTEM_AVAILABILITY = "system_availability"
    PROCESSING_VOLUME = "processing_volume"


@dataclass
class ReportMetric:
    """Individual metric for reporting"""
    metric_type: MetricType
    value: Union[int, float]
    timestamp: datetime
    category: str
    subcategory: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ComplianceRequirement:
    """Compliance framework requirement"""
    framework: str  # SOC2, ISO27001, GDPR, etc.
    requirement_id: str
    description: str
    status: str  # compliant, non_compliant, partial
    evidence: List[str]
    last_assessed: datetime
    next_review: datetime


@dataclass
class SecurityIncidentSummary:
    """Security incident summary for reporting"""
    incident_id: str
    incident_type: str
    severity: str
    status: str
    created_date: datetime
    resolution_date: Optional[datetime]
    affected_users: int
    business_impact: str
    remediation_actions: List[str]


@dataclass
class ReportConfig:
    """Report configuration"""
    report_type: ReportType
    frequency: ReportFrequency
    recipients: List[str]
    filters: Dict[str, Any]
    template_path: Optional[str] = None
    format: str = "html"  # html, pdf, json
    include_charts: bool = True
    include_raw_data: bool = False


class EmailSecurityAnalytics:
    """Email security analytics and metrics engine"""

    def __init__(self, db_path: str = "/var/lib/isectech/email_security.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.metrics_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self._init_analytics_db()

    def _init_analytics_db(self):
        """Initialize analytics database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                -- Metrics storage table
                CREATE TABLE IF NOT EXISTS email_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_type TEXT NOT NULL,
                    value REAL NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    category TEXT NOT NULL,
                    subcategory TEXT,
                    metadata TEXT,
                    INDEX idx_metric_type_timestamp (metric_type, timestamp),
                    INDEX idx_category_timestamp (category, timestamp)
                );

                -- Dashboard configurations
                CREATE TABLE IF NOT EXISTS dashboards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    config TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                );

                -- Report schedules
                CREATE TABLE IF NOT EXISTS report_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    report_type TEXT NOT NULL,
                    frequency TEXT NOT NULL,
                    recipients TEXT NOT NULL,
                    config TEXT NOT NULL,
                    last_run DATETIME,
                    next_run DATETIME,
                    is_active BOOLEAN DEFAULT 1,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                -- Compliance tracking
                CREATE TABLE IF NOT EXISTS compliance_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework TEXT NOT NULL,
                    requirement_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    evidence TEXT,
                    last_assessed DATETIME DEFAULT CURRENT_TIMESTAMP,
                    next_review DATETIME,
                    assessed_by TEXT,
                    UNIQUE(framework, requirement_id)
                );

                -- Report generation history
                CREATE TABLE IF NOT EXISTS report_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_name TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    generated_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    file_path TEXT,
                    file_size INTEGER,
                    generation_time REAL,
                    recipients TEXT,
                    status TEXT DEFAULT 'completed'
                );
            """)

    async def record_metric(self, metric: ReportMetric) -> bool:
        """Record a security metric"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO email_metrics 
                    (metric_type, value, timestamp, category, subcategory, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    metric.metric_type.value,
                    metric.value,
                    metric.timestamp,
                    metric.category,
                    metric.subcategory,
                    json.dumps(metric.metadata) if metric.metadata else None
                ))
                
            # Clear relevant cache entries
            self._clear_metrics_cache(metric.metric_type.value, metric.category)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to record metric: {e}")
            return False

    async def get_metrics(self, 
                         metric_types: List[MetricType],
                         start_date: datetime,
                         end_date: datetime,
                         category: Optional[str] = None) -> List[ReportMetric]:
        """Retrieve metrics for specified time range"""
        try:
            cache_key = f"{'-'.join([m.value for m in metric_types])}_{start_date}_{end_date}_{category}"
            
            # Check cache first
            if cache_key in self.metrics_cache:
                cache_entry = self.metrics_cache[cache_key]
                if datetime.now() - cache_entry['timestamp'] < timedelta(seconds=self.cache_ttl):
                    return cache_entry['data']

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = """
                    SELECT * FROM email_metrics 
                    WHERE metric_type IN ({}) 
                    AND timestamp BETWEEN ? AND ?
                """.format(','.join(['?' for _ in metric_types]))
                
                params = [mt.value for mt in metric_types] + [start_date, end_date]
                
                if category:
                    query += " AND category = ?"
                    params.append(category)
                    
                query += " ORDER BY timestamp DESC"
                
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                
                metrics = []
                for row in rows:
                    metric = ReportMetric(
                        metric_type=MetricType(row['metric_type']),
                        value=row['value'],
                        timestamp=datetime.fromisoformat(row['timestamp']),
                        category=row['category'],
                        subcategory=row['subcategory'],
                        metadata=json.loads(row['metadata']) if row['metadata'] else None
                    )
                    metrics.append(metric)
                
                # Cache results
                self.metrics_cache[cache_key] = {
                    'data': metrics,
                    'timestamp': datetime.now()
                }
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve metrics: {e}")
            return []

    def _clear_metrics_cache(self, metric_type: str, category: str):
        """Clear relevant cache entries"""
        keys_to_remove = []
        for key in self.metrics_cache:
            if metric_type in key or category in key:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.metrics_cache[key]

    async def calculate_security_score(self, days: int = 30) -> Dict[str, Any]:
        """Calculate overall security effectiveness score"""
        try:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            # Get metrics for score calculation
            all_metrics = await self.get_metrics([
                MetricType.THREAT_COUNT,
                MetricType.BLOCKED_EMAILS,
                MetricType.FALSE_POSITIVES,
                MetricType.AUTHENTICATION_FAILURES,
                MetricType.RESPONSE_TIME,
                MetricType.SYSTEM_AVAILABILITY
            ], start_date, end_date)
            
            # Calculate component scores
            threat_detection_score = self._calculate_threat_detection_score(all_metrics)
            false_positive_score = self._calculate_false_positive_score(all_metrics)
            response_time_score = self._calculate_response_time_score(all_metrics)
            availability_score = self._calculate_availability_score(all_metrics)
            authentication_score = self._calculate_authentication_score(all_metrics)
            
            # Weighted overall score
            overall_score = (
                threat_detection_score * 0.25 +
                false_positive_score * 0.20 +
                response_time_score * 0.20 +
                availability_score * 0.20 +
                authentication_score * 0.15
            )
            
            return {
                'overall_score': round(overall_score, 1),
                'component_scores': {
                    'threat_detection': round(threat_detection_score, 1),
                    'false_positive_rate': round(false_positive_score, 1),
                    'response_time': round(response_time_score, 1),
                    'system_availability': round(availability_score, 1),
                    'authentication': round(authentication_score, 1)
                },
                'calculation_period': f"{days} days",
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to calculate security score: {e}")
            return {'overall_score': 0, 'error': str(e)}

    def _calculate_threat_detection_score(self, metrics: List[ReportMetric]) -> float:
        """Calculate threat detection effectiveness score"""
        threat_metrics = [m for m in metrics if m.metric_type == MetricType.THREAT_COUNT]
        blocked_metrics = [m for m in metrics if m.metric_type == MetricType.BLOCKED_EMAILS]
        
        if not threat_metrics or not blocked_metrics:
            return 75.0  # Default score
            
        total_threats = sum(m.value for m in threat_metrics)
        total_blocked = sum(m.value for m in blocked_metrics)
        
        if total_threats == 0:
            return 100.0
            
        detection_rate = (total_blocked / total_threats) * 100
        return min(detection_rate, 100.0)

    def _calculate_false_positive_score(self, metrics: List[ReportMetric]) -> float:
        """Calculate false positive score (lower FP rate = higher score)"""
        fp_metrics = [m for m in metrics if m.metric_type == MetricType.FALSE_POSITIVES]
        blocked_metrics = [m for m in metrics if m.metric_type == MetricType.BLOCKED_EMAILS]
        
        if not fp_metrics or not blocked_metrics:
            return 85.0  # Default score
            
        total_fp = sum(m.value for m in fp_metrics)
        total_blocked = sum(m.value for m in blocked_metrics)
        
        if total_blocked == 0:
            return 100.0
            
        fp_rate = (total_fp / total_blocked) * 100
        return max(100 - fp_rate, 0.0)

    def _calculate_response_time_score(self, metrics: List[ReportMetric]) -> float:
        """Calculate response time score"""
        response_metrics = [m for m in metrics if m.metric_type == MetricType.RESPONSE_TIME]
        
        if not response_metrics:
            return 80.0  # Default score
            
        avg_response_time = sum(m.value for m in response_metrics) / len(response_metrics)
        
        # Score based on response time (lower is better)
        if avg_response_time <= 1.0:  # 1 second
            return 100.0
        elif avg_response_time <= 5.0:  # 5 seconds
            return 90.0
        elif avg_response_time <= 10.0:  # 10 seconds
            return 75.0
        elif avg_response_time <= 30.0:  # 30 seconds
            return 60.0
        else:
            return 40.0

    def _calculate_availability_score(self, metrics: List[ReportMetric]) -> float:
        """Calculate system availability score"""
        availability_metrics = [m for m in metrics if m.metric_type == MetricType.SYSTEM_AVAILABILITY]
        
        if not availability_metrics:
            return 95.0  # Default score
            
        avg_availability = sum(m.value for m in availability_metrics) / len(availability_metrics)
        return min(avg_availability, 100.0)

    def _calculate_authentication_score(self, metrics: List[ReportMetric]) -> float:
        """Calculate email authentication score"""
        auth_failures = [m for m in metrics if m.metric_type == MetricType.AUTHENTICATION_FAILURES]
        
        if not auth_failures:
            return 95.0  # Default score
            
        total_failures = sum(m.value for m in auth_failures)
        
        # Score based on failure count (fewer failures = higher score)
        if total_failures == 0:
            return 100.0
        elif total_failures <= 10:
            return 95.0
        elif total_failures <= 50:
            return 85.0
        elif total_failures <= 100:
            return 75.0
        else:
            return 60.0


class ReportingEngine:
    """Advanced reporting engine for email security analytics"""

    def __init__(self, 
                 db_path: str = "/var/lib/isectech/email_security.db",
                 template_dir: str = "/etc/isectech/email-security/templates",
                 output_dir: str = "/var/lib/isectech/reports"):
        self.db_path = db_path
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.analytics = EmailSecurityAnalytics(db_path)
        self.logger = logging.getLogger(__name__)
        
        # Ensure directories exist
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self._init_report_templates()

    def _init_report_templates(self):
        """Initialize default report templates"""
        templates = {
            'executive_summary.html': self._get_executive_template(),
            'security_posture.html': self._get_security_posture_template(),
            'compliance_audit.html': self._get_compliance_template(),
            'threat_intelligence.html': self._get_threat_intelligence_template()
        }
        
        for template_name, content in templates.items():
            template_path = self.template_dir / template_name
            if not template_path.exists():
                with open(template_path, 'w') as f:
                    f.write(content)

    async def generate_report(self, 
                            report_type: ReportType,
                            start_date: datetime,
                            end_date: datetime,
                            config: Optional[ReportConfig] = None) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            report_start_time = time.time()
            
            # Get report data based on type
            report_data = await self._collect_report_data(report_type, start_date, end_date, config)
            
            # Generate visualizations
            charts = await self._generate_charts(report_type, report_data)
            
            # Render report
            report_content = await self._render_report(report_type, report_data, charts, config)
            
            # Save report
            report_filename = f"{report_type.value}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.html"
            report_path = self.output_dir / report_filename
            
            async with aiofiles.open(report_path, 'w') as f:
                await f.write(report_content)
            
            generation_time = time.time() - report_start_time
            
            # Record report generation
            await self._record_report_generation(
                report_type.value,
                str(report_path),
                report_path.stat().st_size,
                generation_time,
                config.recipients if config else []
            )
            
            return {
                'success': True,
                'report_path': str(report_path),
                'report_size': report_path.stat().st_size,
                'generation_time': generation_time,
                'data_points': len(report_data.get('metrics', [])),
                'charts_generated': len(charts)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return {'success': False, 'error': str(e)}

    async def _collect_report_data(self, 
                                  report_type: ReportType,
                                  start_date: datetime,
                                  end_date: datetime,
                                  config: Optional[ReportConfig]) -> Dict[str, Any]:
        """Collect data for report generation"""
        data = {
            'report_type': report_type.value,
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'days': (end_date - start_date).days
            },
            'generated_at': datetime.now().isoformat()
        }
        
        if report_type == ReportType.EXECUTIVE_SUMMARY:
            data.update(await self._collect_executive_data(start_date, end_date))
        elif report_type == ReportType.SECURITY_POSTURE:
            data.update(await self._collect_security_posture_data(start_date, end_date))
        elif report_type == ReportType.THREAT_INTELLIGENCE:
            data.update(await self._collect_threat_intelligence_data(start_date, end_date))
        elif report_type == ReportType.COMPLIANCE_AUDIT:
            data.update(await self._collect_compliance_data(start_date, end_date))
        elif report_type == ReportType.OPERATIONAL_METRICS:
            data.update(await self._collect_operational_data(start_date, end_date))
        elif report_type == ReportType.INCIDENT_ANALYSIS:
            data.update(await self._collect_incident_data(start_date, end_date))
        
        return data

    async def _collect_executive_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect executive summary data"""
        # Get security score
        security_score = await self.analytics.calculate_security_score(
            (end_date - start_date).days
        )
        
        # Get key metrics
        key_metrics = await self.analytics.get_metrics([
            MetricType.BLOCKED_EMAILS,
            MetricType.THREAT_COUNT,
            MetricType.FALSE_POSITIVES,
            MetricType.PROCESSING_VOLUME
        ], start_date, end_date)
        
        # Calculate summary statistics
        total_blocked = sum(m.value for m in key_metrics if m.metric_type == MetricType.BLOCKED_EMAILS)
        total_threats = sum(m.value for m in key_metrics if m.metric_type == MetricType.THREAT_COUNT)
        total_fps = sum(m.value for m in key_metrics if m.metric_type == MetricType.FALSE_POSITIVES)
        total_processed = sum(m.value for m in key_metrics if m.metric_type == MetricType.PROCESSING_VOLUME)
        
        return {
            'security_score': security_score,
            'key_statistics': {
                'emails_processed': int(total_processed),
                'threats_blocked': int(total_blocked),
                'threats_detected': int(total_threats),
                'false_positives': int(total_fps),
                'detection_rate': round((total_blocked / total_threats * 100) if total_threats > 0 else 0, 1),
                'false_positive_rate': round((total_fps / total_blocked * 100) if total_blocked > 0 else 0, 2)
            },
            'metrics': [asdict(m) for m in key_metrics]
        }

    async def _collect_security_posture_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect security posture assessment data"""
        # Get all security-related metrics
        security_metrics = await self.analytics.get_metrics([
            MetricType.PHISHING_ATTEMPTS,
            MetricType.MALWARE_DETECTIONS,
            MetricType.SPAM_BLOCKED,
            MetricType.AUTHENTICATION_FAILURES,
            MetricType.USER_REPORTS
        ], start_date, end_date)
        
        # Get security score breakdown
        security_score = await self.analytics.calculate_security_score(
            (end_date - start_date).days
        )
        
        # Analyze trends
        threat_trends = self._analyze_threat_trends(security_metrics)
        
        return {
            'security_score_breakdown': security_score,
            'threat_breakdown': {
                'phishing': sum(m.value for m in security_metrics if m.metric_type == MetricType.PHISHING_ATTEMPTS),
                'malware': sum(m.value for m in security_metrics if m.metric_type == MetricType.MALWARE_DETECTIONS),
                'spam': sum(m.value for m in security_metrics if m.metric_type == MetricType.SPAM_BLOCKED),
                'auth_failures': sum(m.value for m in security_metrics if m.metric_type == MetricType.AUTHENTICATION_FAILURES)
            },
            'user_engagement': {
                'reports_submitted': sum(m.value for m in security_metrics if m.metric_type == MetricType.USER_REPORTS)
            },
            'trends': threat_trends,
            'metrics': [asdict(m) for m in security_metrics]
        }

    async def _collect_threat_intelligence_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect threat intelligence report data"""
        # Get threat-specific metrics
        threat_metrics = await self.analytics.get_metrics([
            MetricType.PHISHING_ATTEMPTS,
            MetricType.MALWARE_DETECTIONS,
            MetricType.THREAT_COUNT
        ], start_date, end_date)
        
        # Analyze threat patterns
        threat_patterns = self._analyze_threat_patterns(threat_metrics)
        
        # Get recent incidents
        incidents = await self._get_recent_incidents(start_date, end_date)
        
        return {
            'threat_summary': {
                'total_threats': sum(m.value for m in threat_metrics if m.metric_type == MetricType.THREAT_COUNT),
                'phishing_attempts': sum(m.value for m in threat_metrics if m.metric_type == MetricType.PHISHING_ATTEMPTS),
                'malware_detections': sum(m.value for m in threat_metrics if m.metric_type == MetricType.MALWARE_DETECTIONS)
            },
            'threat_patterns': threat_patterns,
            'recent_incidents': incidents,
            'metrics': [asdict(m) for m in threat_metrics]
        }

    async def _collect_compliance_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect compliance audit data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get compliance status
                cursor = conn.execute("""
                    SELECT framework, requirement_id, description, status, 
                           evidence, last_assessed, next_review, assessed_by
                    FROM compliance_status
                    ORDER BY framework, requirement_id
                """)
                compliance_records = cursor.fetchall()
                
                # Group by framework
                compliance_by_framework = {}
                for record in compliance_records:
                    framework = record['framework']
                    if framework not in compliance_by_framework:
                        compliance_by_framework[framework] = []
                    
                    compliance_by_framework[framework].append({
                        'requirement_id': record['requirement_id'],
                        'description': record['description'],
                        'status': record['status'],
                        'evidence': json.loads(record['evidence']) if record['evidence'] else [],
                        'last_assessed': record['last_assessed'],
                        'next_review': record['next_review'],
                        'assessed_by': record['assessed_by']
                    })
                
                # Calculate compliance scores
                compliance_scores = {}
                for framework, requirements in compliance_by_framework.items():
                    total_reqs = len(requirements)
                    compliant_reqs = len([r for r in requirements if r['status'] == 'compliant'])
                    compliance_scores[framework] = round((compliant_reqs / total_reqs * 100) if total_reqs > 0 else 0, 1)
                
                return {
                    'compliance_by_framework': compliance_by_framework,
                    'compliance_scores': compliance_scores,
                    'total_requirements': sum(len(reqs) for reqs in compliance_by_framework.values()),
                    'compliant_requirements': sum(
                        len([r for r in reqs if r['status'] == 'compliant']) 
                        for reqs in compliance_by_framework.values()
                    )
                }
                
        except Exception as e:
            self.logger.error(f"Failed to collect compliance data: {e}")
            return {'error': str(e)}

    async def _collect_operational_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect operational metrics data"""
        ops_metrics = await self.analytics.get_metrics([
            MetricType.PROCESSING_VOLUME,
            MetricType.RESPONSE_TIME,
            MetricType.SYSTEM_AVAILABILITY
        ], start_date, end_date)
        
        # Calculate operational KPIs
        processing_volume = [m for m in ops_metrics if m.metric_type == MetricType.PROCESSING_VOLUME]
        response_times = [m for m in ops_metrics if m.metric_type == MetricType.RESPONSE_TIME]
        availability = [m for m in ops_metrics if m.metric_type == MetricType.SYSTEM_AVAILABILITY]
        
        return {
            'processing_statistics': {
                'total_volume': sum(m.value for m in processing_volume),
                'average_daily_volume': sum(m.value for m in processing_volume) / len(processing_volume) if processing_volume else 0,
                'peak_volume': max((m.value for m in processing_volume), default=0)
            },
            'performance_metrics': {
                'average_response_time': sum(m.value for m in response_times) / len(response_times) if response_times else 0,
                'fastest_response': min((m.value for m in response_times), default=0),
                'slowest_response': max((m.value for m in response_times), default=0)
            },
            'availability_metrics': {
                'average_availability': sum(m.value for m in availability) / len(availability) if availability else 0,
                'minimum_availability': min((m.value for m in availability), default=0),
                'uptime_percentage': sum(m.value for m in availability) / len(availability) if availability else 0
            },
            'metrics': [asdict(m) for m in ops_metrics]
        }

    async def _collect_incident_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Collect incident analysis data"""
        incidents = await self._get_recent_incidents(start_date, end_date)
        
        # Analyze incident patterns
        incident_by_type = {}
        incident_by_severity = {}
        resolution_times = []
        
        for incident in incidents:
            # Group by type
            incident_type = incident.get('type', 'unknown')
            incident_by_type[incident_type] = incident_by_type.get(incident_type, 0) + 1
            
            # Group by severity
            severity = incident.get('severity', 'unknown')
            incident_by_severity[severity] = incident_by_severity.get(severity, 0) + 1
            
            # Calculate resolution times
            if incident.get('resolution_date') and incident.get('created_date'):
                resolution_time = (
                    datetime.fromisoformat(incident['resolution_date']) - 
                    datetime.fromisoformat(incident['created_date'])
                ).total_seconds() / 3600  # Hours
                resolution_times.append(resolution_time)
        
        return {
            'incident_summary': {
                'total_incidents': len(incidents),
                'by_type': incident_by_type,
                'by_severity': incident_by_severity,
                'average_resolution_time': sum(resolution_times) / len(resolution_times) if resolution_times else 0,
                'fastest_resolution': min(resolution_times) if resolution_times else 0,
                'slowest_resolution': max(resolution_times) if resolution_times else 0
            },
            'recent_incidents': incidents[:10]  # Top 10 most recent
        }

    def _analyze_threat_trends(self, metrics: List[ReportMetric]) -> Dict[str, Any]:
        """Analyze threat trends from metrics"""
        # Group metrics by day
        daily_threats = {}
        for metric in metrics:
            day = metric.timestamp.date()
            if day not in daily_threats:
                daily_threats[day] = {'phishing': 0, 'malware': 0, 'spam': 0, 'auth_failures': 0}
            
            if metric.metric_type == MetricType.PHISHING_ATTEMPTS:
                daily_threats[day]['phishing'] += metric.value
            elif metric.metric_type == MetricType.MALWARE_DETECTIONS:
                daily_threats[day]['malware'] += metric.value
            elif metric.metric_type == MetricType.SPAM_BLOCKED:
                daily_threats[day]['spam'] += metric.value
            elif metric.metric_type == MetricType.AUTHENTICATION_FAILURES:
                daily_threats[day]['auth_failures'] += metric.value
        
        # Calculate trends (simple moving average)
        sorted_days = sorted(daily_threats.keys())
        if len(sorted_days) >= 7:
            recent_avg = sum(sum(daily_threats[day].values()) for day in sorted_days[-7:]) / 7
            previous_avg = sum(sum(daily_threats[day].values()) for day in sorted_days[-14:-7]) / 7 if len(sorted_days) >= 14 else recent_avg
            trend_direction = 'increasing' if recent_avg > previous_avg else 'decreasing' if recent_avg < previous_avg else 'stable'
            trend_percentage = abs((recent_avg - previous_avg) / previous_avg * 100) if previous_avg > 0 else 0
        else:
            trend_direction = 'insufficient_data'
            trend_percentage = 0
        
        return {
            'trend_direction': trend_direction,
            'trend_percentage': round(trend_percentage, 1),
            'daily_breakdown': {str(day): threats for day, threats in daily_threats.items()}
        }

    def _analyze_threat_patterns(self, metrics: List[ReportMetric]) -> Dict[str, Any]:
        """Analyze threat patterns for threat intelligence"""
        # Analyze by hour of day
        hourly_distribution = {str(hour): 0 for hour in range(24)}
        
        # Analyze by day of week
        daily_distribution = {str(day): 0 for day in range(7)}  # 0=Monday
        
        for metric in metrics:
            hour = metric.timestamp.hour
            day_of_week = metric.timestamp.weekday()
            
            hourly_distribution[str(hour)] += metric.value
            daily_distribution[str(day_of_week)] += metric.value
        
        # Find peak hours and days
        peak_hour = max(hourly_distribution, key=hourly_distribution.get)
        peak_day = max(daily_distribution, key=daily_distribution.get)
        
        return {
            'hourly_distribution': hourly_distribution,
            'daily_distribution': daily_distribution,
            'peak_hour': int(peak_hour),
            'peak_day': int(peak_day),
            'peak_day_name': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'][int(peak_day)]
        }

    async def _get_recent_incidents(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get recent security incidents"""
        try:
            # This would typically query from incident management system
            # For now, return sample data structure
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Check if incidents table exists (from security response engine)
                cursor = conn.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='security_incidents'
                """)
                
                if cursor.fetchone():
                    cursor = conn.execute("""
                        SELECT incident_id, incident_type, severity, status,
                               created_date, resolution_date, affected_users,
                               business_impact, remediation_actions
                        FROM security_incidents
                        WHERE created_date BETWEEN ? AND ?
                        ORDER BY created_date DESC
                        LIMIT 50
                    """, (start_date, end_date))
                    
                    incidents = []
                    for row in cursor.fetchall():
                        incidents.append({
                            'incident_id': row['incident_id'],
                            'type': row['incident_type'],
                            'severity': row['severity'],
                            'status': row['status'],
                            'created_date': row['created_date'],
                            'resolution_date': row['resolution_date'],
                            'affected_users': row['affected_users'],
                            'business_impact': row['business_impact'],
                            'remediation_actions': json.loads(row['remediation_actions']) if row['remediation_actions'] else []
                        })
                    
                    return incidents
                else:
                    return []
                    
        except Exception as e:
            self.logger.error(f"Failed to get recent incidents: {e}")
            return []

    async def _generate_charts(self, report_type: ReportType, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for report"""
        charts = {}
        
        try:
            if report_type == ReportType.EXECUTIVE_SUMMARY:
                charts.update(await self._generate_executive_charts(data))
            elif report_type == ReportType.SECURITY_POSTURE:
                charts.update(await self._generate_security_posture_charts(data))
            elif report_type == ReportType.THREAT_INTELLIGENCE:
                charts.update(await self._generate_threat_intelligence_charts(data))
            elif report_type == ReportType.COMPLIANCE_AUDIT:
                charts.update(await self._generate_compliance_charts(data))
            elif report_type == ReportType.OPERATIONAL_METRICS:
                charts.update(await self._generate_operational_charts(data))
                
        except Exception as e:
            self.logger.error(f"Failed to generate charts: {e}")
            
        return charts

    async def _generate_executive_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate executive summary charts"""
        charts = {}
        
        # Security score gauge
        if 'security_score' in data:
            score = data['security_score'].get('overall_score', 0)
            
            fig = go.Figure(go.Indicator(
                mode = "gauge+number+delta",
                value = score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Overall Security Score"},
                delta = {'reference': 85},
                gauge = {
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 50], 'color': "lightgray"},
                        {'range': [50, 75], 'color': "yellow"},
                        {'range': [75, 100], 'color': "lightgreen"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 90
                    }
                }
            ))
            
            charts['security_score_gauge'] = self._fig_to_base64(fig)
        
        # Key statistics bar chart
        if 'key_statistics' in data:
            stats = data['key_statistics']
            
            fig = go.Figure(data=[
                go.Bar(
                    x=['Emails Processed', 'Threats Blocked', 'False Positives'],
                    y=[stats.get('emails_processed', 0), 
                       stats.get('threats_blocked', 0), 
                       stats.get('false_positives', 0)],
                    marker_color=['blue', 'red', 'orange']
                )
            ])
            
            fig.update_layout(
                title='Email Security Key Statistics',
                yaxis_title='Count'
            )
            
            charts['key_statistics_bar'] = self._fig_to_base64(fig)
        
        return charts

    async def _generate_security_posture_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate security posture charts"""
        charts = {}
        
        # Threat breakdown pie chart
        if 'threat_breakdown' in data:
            threats = data['threat_breakdown']
            
            fig = go.Figure(data=[go.Pie(
                labels=list(threats.keys()),
                values=list(threats.values()),
                hole=.3
            )])
            
            fig.update_layout(title_text="Threat Distribution")
            charts['threat_breakdown_pie'] = self._fig_to_base64(fig)
        
        # Security score components radar chart
        if 'security_score_breakdown' in data and 'component_scores' in data['security_score_breakdown']:
            components = data['security_score_breakdown']['component_scores']
            
            fig = go.Figure()
            
            fig.add_trace(go.Scatterpolar(
                r=list(components.values()),
                theta=list(components.keys()),
                fill='toself',
                name='Security Components'
            ))
            
            fig.update_layout(
                polar=dict(
                    radialaxis=dict(
                        visible=True,
                        range=[0, 100]
                    )),
                title="Security Score Breakdown"
            )
            
            charts['security_components_radar'] = self._fig_to_base64(fig)
        
        return charts

    async def _generate_threat_intelligence_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate threat intelligence charts"""
        charts = {}
        
        # Threat patterns heatmap
        if 'threat_patterns' in data:
            patterns = data['threat_patterns']
            
            if 'hourly_distribution' in patterns:
                hourly = patterns['hourly_distribution']
                hours = list(range(24))
                values = [hourly.get(str(h), 0) for h in hours]
                
                fig = go.Figure(data=go.Heatmap(
                    z=[values],
                    x=hours,
                    y=['Threats'],
                    colorscale='Reds'
                ))
                
                fig.update_layout(
                    title='Threat Activity by Hour of Day',
                    xaxis_title='Hour',
                    yaxis_title=''
                )
                
                charts['hourly_threat_heatmap'] = self._fig_to_base64(fig)
        
        return charts

    async def _generate_compliance_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate compliance charts"""
        charts = {}
        
        # Compliance scores by framework
        if 'compliance_scores' in data:
            scores = data['compliance_scores']
            
            fig = go.Figure(data=[
                go.Bar(
                    x=list(scores.keys()),
                    y=list(scores.values()),
                    marker_color=['green' if score >= 80 else 'orange' if score >= 60 else 'red' 
                                 for score in scores.values()]
                )
            ])
            
            fig.update_layout(
                title='Compliance Scores by Framework',
                yaxis_title='Compliance Percentage',
                yaxis=dict(range=[0, 100])
            )
            
            charts['compliance_scores_bar'] = self._fig_to_base64(fig)
        
        return charts

    async def _generate_operational_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate operational metrics charts"""
        charts = {}
        
        # Processing volume over time
        if 'metrics' in data:
            metrics = data['metrics']
            processing_metrics = [m for m in metrics if m.get('metric_type') == 'processing_volume']
            
            if processing_metrics:
                timestamps = [datetime.fromisoformat(m['timestamp']) for m in processing_metrics]
                values = [m['value'] for m in processing_metrics]
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=timestamps,
                    y=values,
                    mode='lines+markers',
                    name='Processing Volume'
                ))
                
                fig.update_layout(
                    title='Email Processing Volume Over Time',
                    xaxis_title='Time',
                    yaxis_title='Volume'
                )
                
                charts['processing_volume_timeline'] = self._fig_to_base64(fig)
        
        return charts

    def _fig_to_base64(self, fig) -> str:
        """Convert plotly figure to base64 string"""
        img_bytes = fig.to_image(format="png")
        img_base64 = base64.b64encode(img_bytes).decode()
        return f"data:image/png;base64,{img_base64}"

    async def _render_report(self, 
                           report_type: ReportType,
                           data: Dict[str, Any],
                           charts: Dict[str, str],
                           config: Optional[ReportConfig]) -> str:
        """Render report to HTML"""
        try:
            template_name = f"{report_type.value}.html"
            template_path = self.template_dir / template_name
            
            if template_path.exists():
                async with aiofiles.open(template_path, 'r') as f:
                    template = await f.read()
            else:
                template = self._get_default_template()
            
            # Replace template variables
            template = template.replace('{{report_title}}', f"ISECTECH Email Security - {report_type.value.replace('_', ' ').title()}")
            template = template.replace('{{generated_at}}', data.get('generated_at', ''))
            template = template.replace('{{period_start}}', data.get('period', {}).get('start', ''))
            template = template.replace('{{period_end}}', data.get('period', {}).get('end', ''))
            
            # Insert data sections
            if report_type == ReportType.EXECUTIVE_SUMMARY:
                template = self._render_executive_content(template, data, charts)
            elif report_type == ReportType.SECURITY_POSTURE:
                template = self._render_security_posture_content(template, data, charts)
            elif report_type == ReportType.COMPLIANCE_AUDIT:
                template = self._render_compliance_content(template, data, charts)
            
            return template
            
        except Exception as e:
            self.logger.error(f"Failed to render report: {e}")
            return f"<html><body><h1>Report Generation Error</h1><p>{str(e)}</p></body></html>"

    def _render_executive_content(self, template: str, data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Render executive summary content"""
        content = "<div class='executive-summary'>"
        
        # Security score section
        if 'security_score' in data:
            score = data['security_score']
            content += f"""
            <div class='security-score-section'>
                <h2>Overall Security Score: {score.get('overall_score', 0)}/100</h2>
                {charts.get('security_score_gauge', '')}
                <div class='component-scores'>
                    <h3>Component Breakdown:</h3>
                    <ul>
            """
            
            for component, score_val in score.get('component_scores', {}).items():
                content += f"<li>{component.replace('_', ' ').title()}: {score_val}/100</li>"
            
            content += "</ul></div></div>"
        
        # Key statistics
        if 'key_statistics' in data:
            stats = data['key_statistics']
            content += f"""
            <div class='key-statistics'>
                <h2>Key Statistics</h2>
                {charts.get('key_statistics_bar', '')}
                <div class='stats-grid'>
                    <div class='stat-item'>
                        <h3>{stats.get('emails_processed', 0):,}</h3>
                        <p>Emails Processed</p>
                    </div>
                    <div class='stat-item'>
                        <h3>{stats.get('threats_blocked', 0):,}</h3>
                        <p>Threats Blocked</p>
                    </div>
                    <div class='stat-item'>
                        <h3>{stats.get('detection_rate', 0)}%</h3>
                        <p>Detection Rate</p>
                    </div>
                    <div class='stat-item'>
                        <h3>{stats.get('false_positive_rate', 0)}%</h3>
                        <p>False Positive Rate</p>
                    </div>
                </div>
            </div>
            """
        
        content += "</div>"
        return template.replace('{{content}}', content)

    def _render_security_posture_content(self, template: str, data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Render security posture content"""
        content = "<div class='security-posture'>"
        
        # Threat breakdown
        if 'threat_breakdown' in data:
            threats = data['threat_breakdown']
            content += f"""
            <div class='threat-breakdown'>
                <h2>Threat Breakdown</h2>
                {charts.get('threat_breakdown_pie', '')}
                <div class='threat-stats'>
                    <div class='threat-stat'>
                        <h3>{threats.get('phishing', 0):,}</h3>
                        <p>Phishing Attempts</p>
                    </div>
                    <div class='threat-stat'>
                        <h3>{threats.get('malware', 0):,}</h3>
                        <p>Malware Detections</p>
                    </div>
                    <div class='threat-stat'>
                        <h3>{threats.get('spam', 0):,}</h3>
                        <p>Spam Blocked</p>
                    </div>
                    <div class='threat-stat'>
                        <h3>{threats.get('auth_failures', 0):,}</h3>
                        <p>Auth Failures</p>
                    </div>
                </div>
            </div>
            """
        
        # Security components radar
        if 'security_components_radar' in charts:
            content += f"""
            <div class='security-components'>
                <h2>Security Component Analysis</h2>
                {charts['security_components_radar']}
            </div>
            """
        
        content += "</div>"
        return template.replace('{{content}}', content)

    def _render_compliance_content(self, template: str, data: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Render compliance audit content"""
        content = "<div class='compliance-audit'>"
        
        # Compliance scores
        if 'compliance_scores' in data:
            content += f"""
            <div class='compliance-scores'>
                <h2>Compliance Status</h2>
                {charts.get('compliance_scores_bar', '')}
            </div>
            """
        
        # Compliance details by framework
        if 'compliance_by_framework' in data:
            frameworks = data['compliance_by_framework']
            content += "<div class='compliance-details'>"
            
            for framework, requirements in frameworks.items():
                compliant_count = len([r for r in requirements if r['status'] == 'compliant'])
                total_count = len(requirements)
                compliance_pct = round((compliant_count / total_count * 100) if total_count > 0 else 0, 1)
                
                content += f"""
                <div class='framework-section'>
                    <h3>{framework}</h3>
                    <p>Compliance: {compliance_pct}% ({compliant_count}/{total_count} requirements)</p>
                    <div class='requirements-list'>
                """
                
                for req in requirements:
                    status_class = req['status'].replace('_', '-')
                    content += f"""
                    <div class='requirement-item {status_class}'>
                        <strong>{req['requirement_id']}</strong>: {req['description']}
                        <span class='status'>{req['status'].title()}</span>
                    </div>
                    """
                
                content += "</div></div>"
            
            content += "</div>"
        
        content += "</div>"
        return template.replace('{{content}}', content)

    async def _record_report_generation(self, 
                                      report_type: str,
                                      file_path: str,
                                      file_size: int,
                                      generation_time: float,
                                      recipients: List[str]):
        """Record report generation in history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO report_history 
                    (report_name, report_type, file_path, file_size, generation_time, recipients)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    Path(file_path).name,
                    report_type,
                    file_path,
                    file_size,
                    generation_time,
                    json.dumps(recipients)
                ))
                
        except Exception as e:
            self.logger.error(f"Failed to record report generation: {e}")

    def _get_executive_template(self) -> str:
        """Get executive summary HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{report_title}}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                .security-score-section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }
                .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 20px; }
                .stat-item { text-align: center; background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .stat-item h3 { margin: 0; font-size: 24px; color: #333; }
                .stat-item p { margin: 5px 0 0 0; color: #666; }
                img { max-width: 100%; height: auto; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{report_title}}</h1>
                <p>Report Period: {{period_start}} to {{period_end}}</p>
                <p>Generated: {{generated_at}}</p>
            </div>
            {{content}}
        </body>
        </html>
        """

    def _get_security_posture_template(self) -> str:
        """Get security posture HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{report_title}}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                .threat-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
                .threat-stat { text-align: center; background: #f8f9fa; padding: 15px; border-radius: 5px; }
                .threat-stat h3 { margin: 0; font-size: 20px; color: #d73027; }
                .threat-stat p { margin: 5px 0 0 0; color: #666; }
                img { max-width: 100%; height: auto; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{report_title}}</h1>
                <p>Report Period: {{period_start}} to {{period_end}}</p>
                <p>Generated: {{generated_at}}</p>
            </div>
            {{content}}
        </body>
        </html>
        """

    def _get_compliance_template(self) -> str:
        """Get compliance audit HTML template"""  
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{report_title}}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                .framework-section { margin: 30px 0; }
                .requirement-item { padding: 10px; margin: 5px 0; border-left: 4px solid #ccc; background: #f9f9f9; }
                .requirement-item.compliant { border-left-color: #28a745; }
                .requirement-item.non-compliant { border-left-color: #dc3545; }
                .requirement-item.partial { border-left-color: #ffc107; }
                .status { float: right; padding: 2px 8px; border-radius: 3px; font-size: 12px; }
                img { max-width: 100%; height: auto; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{report_title}}</h1>
                <p>Report Period: {{period_start}} to {{period_end}}</p>
                <p>Generated: {{generated_at}}</p>
            </div>
            {{content}}
        </body>
        </html>
        """

    def _get_threat_intelligence_template(self) -> str:
        """Get threat intelligence HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{report_title}}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                .threat-summary { background: #fff3cd; padding: 20px; margin: 20px 0; border-radius: 8px; border: 1px solid #ffeaa7; }
                .incident-list { margin: 20px 0; }
                .incident-item { padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 5px; border-left: 4px solid #007bff; }
                img { max-width: 100%; height: auto; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{report_title}}</h1>
                <p>Report Period: {{period_start}} to {{period_end}}</p>
                <p>Generated: {{generated_at}}</p>
            </div>
            {{content}}
        </body>
        </html>
        """

    def _get_default_template(self) -> str:
        """Get default HTML template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{report_title}}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
                .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
                h1, h2, h3 { color: #333; }
                img { max-width: 100%; height: auto; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{report_title}}</h1>
                <p>Report Period: {{period_start}} to {{period_end}}</p>
                <p>Generated: {{generated_at}}</p>
            </div>
            <div class="content">
                {{content}}
            </div>
        </body>
        </html>
        """


class ReportScheduler:
    """Automated report scheduling and distribution"""

    def __init__(self, reporting_engine: ReportingEngine):
        self.reporting_engine = reporting_engine
        self.logger = logging.getLogger(__name__)
        self.scheduler_thread = None
        self.is_running = False

    def start_scheduler(self):
        """Start the report scheduler"""
        if self.is_running:
            return
            
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        self.logger.info("Report scheduler started")

    def stop_scheduler(self):
        """Stop the report scheduler"""
        self.is_running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        self.logger.info("Report scheduler stopped")

    def _run_scheduler(self):
        """Run the scheduler loop"""
        while self.is_running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

    async def schedule_report(self, config: ReportConfig) -> bool:
        """Schedule a report for automatic generation"""
        try:
            # Store schedule in database
            with sqlite3.connect(self.reporting_engine.db_path) as conn:
                next_run = self._calculate_next_run(config.frequency)
                
                conn.execute("""
                    INSERT OR REPLACE INTO report_schedules 
                    (name, report_type, frequency, recipients, config, next_run)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    f"{config.report_type.value}_{config.frequency.value}",
                    config.report_type.value,
                    config.frequency.value,
                    json.dumps(config.recipients),
                    json.dumps(asdict(config)),
                    next_run
                ))
            
            # Add to schedule
            if config.frequency == ReportFrequency.DAILY:
                schedule.every().day.at("06:00").do(
                    self._generate_scheduled_report, config
                )
            elif config.frequency == ReportFrequency.WEEKLY:
                schedule.every().monday.at("06:00").do(
                    self._generate_scheduled_report, config
                )
            elif config.frequency == ReportFrequency.MONTHLY:
                schedule.every().month.do(
                    self._generate_scheduled_report, config
                )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to schedule report: {e}")
            return False

    def _calculate_next_run(self, frequency: ReportFrequency) -> datetime:
        """Calculate next run time for report"""
        now = datetime.now()
        
        if frequency == ReportFrequency.HOURLY:
            return now + timedelta(hours=1)
        elif frequency == ReportFrequency.DAILY:
            return now.replace(hour=6, minute=0, second=0) + timedelta(days=1)
        elif frequency == ReportFrequency.WEEKLY:
            days_ahead = 0 - now.weekday()  # Monday is 0
            if days_ahead <= 0:
                days_ahead += 7
            return now.replace(hour=6, minute=0, second=0) + timedelta(days=days_ahead)
        elif frequency == ReportFrequency.MONTHLY:
            if now.month == 12:
                return now.replace(year=now.year+1, month=1, day=1, hour=6, minute=0, second=0)
            else:
                return now.replace(month=now.month+1, day=1, hour=6, minute=0, second=0)
        else:
            return now + timedelta(days=1)

    async def _generate_scheduled_report(self, config: ReportConfig):
        """Generate and distribute scheduled report"""
        try:
            # Calculate date range based on frequency
            end_date = datetime.now()
            
            if config.frequency == ReportFrequency.DAILY:
                start_date = end_date - timedelta(days=1)
            elif config.frequency == ReportFrequency.WEEKLY:
                start_date = end_date - timedelta(weeks=1)
            elif config.frequency == ReportFrequency.MONTHLY:
                start_date = end_date - timedelta(days=30)
            else:
                start_date = end_date - timedelta(days=1)
            
            # Generate report
            result = await self.reporting_engine.generate_report(
                config.report_type,
                start_date,
                end_date,
                config
            )
            
            if result.get('success'):
                # Distribute report
                await self._distribute_report(result['report_path'], config.recipients)
                
                # Update last run time
                with sqlite3.connect(self.reporting_engine.db_path) as conn:
                    conn.execute("""
                        UPDATE report_schedules 
                        SET last_run = ?, next_run = ?
                        WHERE name = ?
                    """, (
                        datetime.now(),
                        self._calculate_next_run(config.frequency),
                        f"{config.report_type.value}_{config.frequency.value}"
                    ))
                
                self.logger.info(f"Scheduled report generated: {result['report_path']}")
            else:
                self.logger.error(f"Failed to generate scheduled report: {result.get('error')}")
                
        except Exception as e:
            self.logger.error(f"Error in scheduled report generation: {e}")

    async def _distribute_report(self, report_path: str, recipients: List[str]):
        """Distribute report to recipients"""
        try:
            # Read report content
            async with aiofiles.open(report_path, 'r') as f:
                report_content = await f.read()
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = "security-reports@isectech.com"
            msg['Subject'] = f"ISECTECH Email Security Report - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Add HTML content
            msg.attach(MIMEText(report_content, 'html'))
            
            # Send to each recipient
            for recipient in recipients:
                try:
                    msg['To'] = recipient
                    
                    # Send email (configure SMTP settings as needed)
                    with smtplib.SMTP('localhost', 587) as server:
                        server.send_message(msg)
                    
                    self.logger.info(f"Report sent to {recipient}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to send report to {recipient}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to distribute report: {e}")


# Example usage and testing
async def main():
    """Example usage of the reporting engine"""
    # Initialize components
    analytics = EmailSecurityAnalytics()
    reporting = ReportingEngine()
    scheduler = ReportScheduler(reporting)
    
    # Record some sample metrics
    await analytics.record_metric(ReportMetric(
        metric_type=MetricType.BLOCKED_EMAILS,
        value=156,
        timestamp=datetime.now(),
        category="security",
        metadata={"source": "phishing_filter"}
    ))
    
    await analytics.record_metric(ReportMetric(
        metric_type=MetricType.THREAT_COUNT,
        value=89,
        timestamp=datetime.now(),
        category="threats",
        metadata={"type": "phishing"}
    ))
    
    # Generate executive summary report
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    result = await reporting.generate_report(
        ReportType.EXECUTIVE_SUMMARY,
        start_date,
        end_date
    )
    
    print(f"Report generated: {result}")
    
    # Schedule daily reports
    config = ReportConfig(
        report_type=ReportType.SECURITY_POSTURE,
        frequency=ReportFrequency.DAILY,
        recipients=["security-team@isectech.com", "ciso@isectech.com"],
        filters={"severity": ["high", "critical"]}
    )
    
    await scheduler.schedule_report(config)
    
    # Start scheduler
    scheduler.start_scheduler()
    
    print("Reporting system initialized and scheduler started")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())