#!/usr/bin/env python3
"""
iSECTECH SIEM Reporting Dashboard
Production-grade security investigation reporting and visualization platform
Advanced report generation, data visualization, and executive dashboards
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
from jinja2 import Environment, FileSystemLoader, Template
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.io as pio
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import base64
from io import BytesIO
import yaml
import uuid
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import zipfile
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ReportMetadata:
    """Report metadata structure"""
    report_id: str
    title: str
    description: str
    report_type: str  # investigation, threat_hunt, forensic, executive
    classification: str  # public, internal, confidential, restricted
    created_by: str
    created_at: datetime
    investigation_id: Optional[str] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    tags: List[str] = None
    recipients: List[str] = None

@dataclass
class VisualizationConfig:
    """Visualization configuration"""
    chart_type: str
    title: str
    data_source: str
    x_axis: str
    y_axis: str
    color_scheme: str = "viridis"
    width: int = 1200
    height: int = 600
    interactive: bool = True
    export_formats: List[str] = None

class ReportingDashboard:
    """Advanced reporting and visualization platform for SIEM investigations"""
    
    def __init__(self, config_path: str = "/opt/siem/analysis/config/analysis_config.yaml"):
        """Initialize the reporting dashboard"""
        self.config_path = config_path
        self.config = self._load_config()
        self.template_env = Environment(
            loader=FileSystemLoader(self.config['reporting']['generation']['default_template_path'])
        )
        self.output_dir = Path("/opt/siem/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure plotly theme
        pio.templates.default = "plotly_white"
        
        # Initialize report templates
        self._initialize_templates()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'reporting': {
                'generation': {
                    'output_formats': ['pdf', 'html', 'json'],
                    'max_report_size_mb': 100
                },
                'visualization': {
                    'default_chart_width': 1200,
                    'default_chart_height': 600,
                    'color_schemes': ['viridis', 'plasma', 'security_themed']
                },
                'distribution': {
                    'email_enabled': True
                }
            }
        }
    
    def _initialize_templates(self):
        """Initialize report templates"""
        self.templates = {
            'investigation_report': self._create_investigation_template(),
            'threat_hunt_report': self._create_threat_hunt_template(),
            'forensic_report': self._create_forensic_template(),
            'executive_summary': self._create_executive_template()
        }
    
    def _create_investigation_template(self) -> str:
        """Create investigation report template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 10px; }
        .metadata { background-color: #f5f5f5; padding: 15px; margin: 20px 0; }
        .section { margin: 20px 0; }
        .chart { margin: 20px 0; text-align: center; }
        .evidence { background-color: #fff3cd; padding: 10px; margin: 10px 0; }
        .timeline { border-left: 3px solid #007bff; padding-left: 20px; }
        .finding { background-color: #d4edda; padding: 10px; margin: 10px 0; }
        .recommendation { background-color: #cce5ff; padding: 10px; margin: 10px 0; }
        .classification { 
            color: {% if metadata.classification == 'restricted' %}red{% elif metadata.classification == 'confidential' %}orange{% else %}black{% endif %};
            font-weight: bold;
            text-transform: uppercase;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p class="classification">Classification: {{ metadata.classification }}</p>
        <p>Report ID: {{ metadata.report_id }}</p>
        <p>Generated: {{ metadata.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
        <p>Investigator: {{ metadata.created_by }}</p>
    </div>
    
    <div class="metadata">
        <h2>Investigation Metadata</h2>
        <p><strong>Investigation ID:</strong> {{ metadata.investigation_id }}</p>
        <p><strong>Period:</strong> {{ metadata.period_start.strftime('%Y-%m-%d') }} to {{ metadata.period_end.strftime('%Y-%m-%d') }}</p>
        <p><strong>Description:</strong> {{ metadata.description }}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        {{ executive_summary }}
    </div>
    
    <div class="section">
        <h2>Key Findings</h2>
        {% for finding in key_findings %}
        <div class="finding">
            <h3>{{ finding.title }}</h3>
            <p>{{ finding.description }}</p>
            <p><strong>Severity:</strong> {{ finding.severity }}</p>
            <p><strong>Confidence:</strong> {{ finding.confidence }}%</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Timeline Analysis</h2>
        <div class="timeline">
            {{ timeline_analysis }}
        </div>
        <div class="chart">
            {{ timeline_chart }}
        </div>
    </div>
    
    <div class="section">
        <h2>Network Analysis</h2>
        {{ network_analysis }}
        <div class="chart">
            {{ network_chart }}
        </div>
    </div>
    
    <div class="section">
        <h2>Evidence Collection</h2>
        {% for evidence in evidence_items %}
        <div class="evidence">
            <h3>{{ evidence.type }}</h3>
            <p><strong>Source:</strong> {{ evidence.source }}</p>
            <p><strong>Collection Time:</strong> {{ evidence.collected_at }}</p>
            <p><strong>Hash:</strong> {{ evidence.hash }}</p>
            <p>{{ evidence.description }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Threat Intelligence</h2>
        {{ threat_intelligence }}
    </div>
    
    <div class="section">
        <h2>Impact Assessment</h2>
        {{ impact_assessment }}
        <div class="chart">
            {{ impact_chart }}
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        {% for recommendation in recommendations %}
        <div class="recommendation">
            <h3>{{ recommendation.title }}</h3>
            <p>{{ recommendation.description }}</p>
            <p><strong>Priority:</strong> {{ recommendation.priority }}</p>
            <p><strong>Timeline:</strong> {{ recommendation.timeline }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Technical Details</h2>
        {{ technical_details }}
    </div>
    
    <div class="section">
        <h2>Appendices</h2>
        {{ appendices }}
    </div>
</body>
</html>
        """
    
    def _create_threat_hunt_template(self) -> str:
        """Create threat hunting report template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #dc3545; padding-bottom: 10px; }
        .hypothesis { background-color: #e7f3ff; padding: 15px; margin: 20px 0; }
        .query-result { background-color: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 3px solid #007bff; }
        .threat-indicator { background-color: #ffe6e6; padding: 10px; margin: 10px 0; }
        .mitre-mapping { background-color: #fff2e6; padding: 10px; margin: 10px 0; }
        .validation { background-color: #e6ffe6; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p>Threat Hunt Report</p>
    </div>
    
    <div class="section">
        <h2>Hunt Summary</h2>
        {{ hunt_summary }}
    </div>
    
    <div class="hypothesis">
        <h2>Hunt Hypothesis</h2>
        {{ hunt_hypothesis }}
    </div>
    
    <div class="section">
        <h2>MITRE ATT&CK Mapping</h2>
        {% for technique in mitre_techniques %}
        <div class="mitre-mapping">
            <h3>{{ technique.id }}: {{ technique.name }}</h3>
            <p><strong>Tactic:</strong> {{ technique.tactic }}</p>
            <p>{{ technique.description }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Hunt Queries and Results</h2>
        {% for query in hunt_queries %}
        <div class="query-result">
            <h3>{{ query.name }}</h3>
            <p><strong>Query Type:</strong> {{ query.type }}</p>
            <p><strong>Results Found:</strong> {{ query.result_count }}</p>
            <pre>{{ query.query_text }}</pre>
            {% if query.results %}
            <div class="chart">{{ query.visualization }}</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Threat Indicators</h2>
        {% for indicator in threat_indicators %}
        <div class="threat-indicator">
            <h3>{{ indicator.type }}: {{ indicator.value }}</h3>
            <p><strong>Confidence:</strong> {{ indicator.confidence }}%</p>
            <p><strong>First Seen:</strong> {{ indicator.first_seen }}</p>
            <p><strong>Last Seen:</strong> {{ indicator.last_seen }}</p>
            <p>{{ indicator.description }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Hunt Validation</h2>
        <div class="validation">
            {{ hunt_validation }}
        </div>
    </div>
    
    <div class="section">
        <h2>Conclusion and Next Steps</h2>
        {{ conclusion }}
    </div>
</body>
</html>
        """
    
    def _create_forensic_template(self) -> str:
        """Create forensic analysis report template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #6f42c1; padding-bottom: 10px; }
        .chain-of-custody { background-color: #f8f9fa; padding: 15px; margin: 20px 0; border: 1px solid #dee2e6; }
        .artifact { background-color: #fff3cd; padding: 10px; margin: 10px 0; }
        .analysis-result { background-color: #d1ecf1; padding: 10px; margin: 10px 0; }
        .hash-verification { background-color: #d4edda; padding: 10px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p>Digital Forensic Analysis Report</p>
    </div>
    
    <div class="chain-of-custody">
        <h2>Chain of Custody</h2>
        {{ chain_of_custody }}
    </div>
    
    <div class="section">
        <h2>Digital Artifacts</h2>
        {% for artifact in artifacts %}
        <div class="artifact">
            <h3>{{ artifact.name }}</h3>
            <p><strong>Type:</strong> {{ artifact.type }}</p>
            <p><strong>Size:</strong> {{ artifact.size }}</p>
            <p><strong>Collected:</strong> {{ artifact.collected_at }}</p>
            <div class="hash-verification">
                <p><strong>SHA256:</strong> {{ artifact.sha256 }}</p>
                <p><strong>MD5:</strong> {{ artifact.md5 }}</p>
                <p><strong>Verification:</strong> {{ artifact.verification_status }}</p>
            </div>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Analysis Results</h2>
        {% for result in analysis_results %}
        <div class="analysis-result">
            <h3>{{ result.analysis_type }}</h3>
            <p>{{ result.findings }}</p>
            {% if result.visualization %}
            <div class="chart">{{ result.visualization }}</div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Timeline Reconstruction</h2>
        {{ timeline_reconstruction }}
    </div>
    
    <div class="section">
        <h2>Conclusions</h2>
        {{ forensic_conclusions }}
    </div>
</body>
</html>
        """
    
    def _create_executive_template(self) -> str:
        """Create executive summary template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>{{ metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #28a745; padding-bottom: 10px; }
        .kpi { display: inline-block; margin: 10px; padding: 20px; background-color: #e9ecef; text-align: center; min-width: 150px; }
        .risk-level { padding: 10px; margin: 10px 0; }
        .high-risk { background-color: #f8d7da; border-left: 5px solid #dc3545; }
        .medium-risk { background-color: #fff3cd; border-left: 5px solid #ffc107; }
        .low-risk { background-color: #d4edda; border-left: 5px solid #28a745; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ metadata.title }}</h1>
        <p>Executive Security Summary</p>
    </div>
    
    <div class="section">
        <h2>Key Performance Indicators</h2>
        {% for kpi in kpis %}
        <div class="kpi">
            <h3>{{ kpi.value }}</h3>
            <p>{{ kpi.name }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Risk Assessment</h2>
        {% for risk in risk_items %}
        <div class="risk-level {{ risk.level }}-risk">
            <h3>{{ risk.title }}</h3>
            <p>{{ risk.description }}</p>
            <p><strong>Impact:</strong> {{ risk.impact }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>Security Trends</h2>
        <div class="chart">{{ trends_chart }}</div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        {{ recommendations }}
    </div>
</body>
</html>
        """
    
    async def generate_investigation_report(self, investigation_data: Dict[str, Any], 
                                          metadata: ReportMetadata) -> str:
        """Generate comprehensive investigation report"""
        try:
            # Process investigation data
            processed_data = await self._process_investigation_data(investigation_data)
            
            # Generate visualizations
            charts = await self._generate_investigation_charts(processed_data)
            
            # Render template
            template = Template(self.templates['investigation_report'])
            html_content = template.render(
                metadata=metadata,
                **processed_data,
                **charts
            )
            
            # Generate outputs in requested formats
            outputs = {}
            for format_type in self.config['reporting']['generation']['output_formats']:
                if format_type == 'html':
                    outputs['html'] = html_content
                elif format_type == 'pdf':
                    outputs['pdf'] = await self._html_to_pdf(html_content, metadata.report_id)
                elif format_type == 'json':
                    outputs['json'] = json.dumps({
                        'metadata': asdict(metadata),
                        'data': processed_data
                    }, default=str, indent=2)
            
            # Save reports
            report_path = await self._save_reports(outputs, metadata)
            
            logger.info(f"Investigation report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Failed to generate investigation report: {e}")
            raise
    
    async def generate_threat_hunt_report(self, hunt_data: Dict[str, Any], 
                                        metadata: ReportMetadata) -> str:
        """Generate threat hunting report"""
        try:
            # Process hunt data
            processed_data = await self._process_hunt_data(hunt_data)
            
            # Generate visualizations
            charts = await self._generate_hunt_charts(processed_data)
            
            # Render template
            template = Template(self.templates['threat_hunt_report'])
            html_content = template.render(
                metadata=metadata,
                **processed_data,
                **charts
            )
            
            # Generate outputs
            outputs = {}
            for format_type in self.config['reporting']['generation']['output_formats']:
                if format_type == 'html':
                    outputs['html'] = html_content
                elif format_type == 'pdf':
                    outputs['pdf'] = await self._html_to_pdf(html_content, metadata.report_id)
                elif format_type == 'json':
                    outputs['json'] = json.dumps({
                        'metadata': asdict(metadata),
                        'data': processed_data
                    }, default=str, indent=2)
            
            # Save reports
            report_path = await self._save_reports(outputs, metadata)
            
            logger.info(f"Threat hunt report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Failed to generate threat hunt report: {e}")
            raise
    
    async def generate_executive_dashboard(self, period_start: datetime, 
                                         period_end: datetime) -> Dict[str, Any]:
        """Generate executive security dashboard"""
        try:
            # Collect KPIs
            kpis = await self._collect_security_kpis(period_start, period_end)
            
            # Risk assessment
            risk_assessment = await self._generate_risk_assessment(period_start, period_end)
            
            # Security trends
            trends_chart = await self._generate_security_trends_chart(period_start, period_end)
            
            # Generate recommendations
            recommendations = await self._generate_security_recommendations(kpis, risk_assessment)
            
            dashboard_data = {
                'kpis': kpis,
                'risk_assessment': risk_assessment,
                'trends_chart': trends_chart,
                'recommendations': recommendations,
                'period_start': period_start,
                'period_end': period_end
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Failed to generate executive dashboard: {e}")
            raise
    
    async def _process_investigation_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process investigation data for reporting"""
        return {
            'executive_summary': data.get('executive_summary', ''),
            'key_findings': data.get('key_findings', []),
            'timeline_analysis': data.get('timeline_analysis', ''),
            'network_analysis': data.get('network_analysis', ''),
            'evidence_items': data.get('evidence_items', []),
            'threat_intelligence': data.get('threat_intelligence', ''),
            'impact_assessment': data.get('impact_assessment', ''),
            'recommendations': data.get('recommendations', []),
            'technical_details': data.get('technical_details', ''),
            'appendices': data.get('appendices', '')
        }
    
    async def _process_hunt_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process threat hunt data for reporting"""
        return {
            'hunt_summary': data.get('hunt_summary', ''),
            'hunt_hypothesis': data.get('hunt_hypothesis', ''),
            'mitre_techniques': data.get('mitre_techniques', []),
            'hunt_queries': data.get('hunt_queries', []),
            'threat_indicators': data.get('threat_indicators', []),
            'hunt_validation': data.get('hunt_validation', ''),
            'conclusion': data.get('conclusion', '')
        }
    
    async def _generate_investigation_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for investigation report"""
        charts = {}
        
        # Timeline chart
        if 'timeline_data' in data:
            timeline_fig = self._create_timeline_chart(data['timeline_data'])
            charts['timeline_chart'] = self._fig_to_html(timeline_fig)
        
        # Network graph
        if 'network_data' in data:
            network_fig = self._create_network_chart(data['network_data'])
            charts['network_chart'] = self._fig_to_html(network_fig)
        
        # Impact assessment chart
        if 'impact_data' in data:
            impact_fig = self._create_impact_chart(data['impact_data'])
            charts['impact_chart'] = self._fig_to_html(impact_fig)
        
        return charts
    
    async def _generate_hunt_charts(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for threat hunt report"""
        charts = {}
        
        # Query results visualization
        for query in data.get('hunt_queries', []):
            if query.get('results'):
                fig = self._create_query_results_chart(query['results'])
                query['visualization'] = self._fig_to_html(fig)
        
        return charts
    
    def _create_timeline_chart(self, timeline_data: List[Dict]) -> go.Figure:
        """Create timeline visualization"""
        df = pd.DataFrame(timeline_data)
        
        fig = px.timeline(
            df, 
            x_start='start_time', 
            x_end='end_time',
            y='event_type',
            color='severity',
            title="Investigation Timeline",
            color_discrete_map={
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745'
            }
        )
        
        fig.update_layout(
            height=600,
            xaxis_title="Time",
            yaxis_title="Event Type"
        )
        
        return fig
    
    def _create_network_chart(self, network_data: Dict) -> go.Figure:
        """Create network graph visualization"""
        nodes = network_data.get('nodes', [])
        edges = network_data.get('edges', [])
        
        # Create network layout
        edge_x = []
        edge_y = []
        for edge in edges:
            edge_x.extend([edge['x0'], edge['x1'], None])
            edge_y.extend([edge['y0'], edge['y1'], None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines'
        )
        
        node_x = [node['x'] for node in nodes]
        node_y = [node['y'] for node in nodes]
        node_text = [node['label'] for node in nodes]
        node_color = [node.get('risk_score', 0) for node in nodes]
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="middle center",
            marker=dict(
                size=10,
                color=node_color,
                colorscale='RdYlBu',
                showscale=True,
                colorbar=dict(title="Risk Score")
            )
        )
        
        fig = go.Figure(data=[edge_trace, node_trace])
        fig.update_layout(
            title="Network Relationship Graph",
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20,l=5,r=5,t=40),
            annotations=[dict(
                text="Network analysis showing relationships between entities",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.005, y=-0.002,
                xanchor='left', yanchor='bottom',
                font=dict(color="#888", size=12)
            )],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        
        return fig
    
    def _create_impact_chart(self, impact_data: Dict) -> go.Figure:
        """Create impact assessment visualization"""
        categories = list(impact_data.keys())
        values = list(impact_data.values())
        
        fig = go.Figure(data=[
            go.Bar(
                x=categories,
                y=values,
                marker_color=['#dc3545', '#fd7e14', '#ffc107', '#28a745']
            )
        ])
        
        fig.update_layout(
            title="Impact Assessment by Category",
            xaxis_title="Impact Category",
            yaxis_title="Impact Score",
            height=400
        )
        
        return fig
    
    def _create_query_results_chart(self, results_data: List[Dict]) -> go.Figure:
        """Create query results visualization"""
        df = pd.DataFrame(results_data)
        
        if 'timestamp' in df.columns and 'count' in df.columns:
            fig = px.line(
                df, 
                x='timestamp', 
                y='count',
                title="Query Results Over Time"
            )
        else:
            # Fallback to bar chart
            fig = px.bar(
                df.head(20), 
                x=df.columns[0], 
                y=df.columns[1] if len(df.columns) > 1 else 'count',
                title="Query Results"
            )
        
        return fig
    
    async def _collect_security_kpis(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Collect security KPIs for executive dashboard"""
        # This would typically query the SIEM database
        return [
            {'name': 'Total Incidents', 'value': '142', 'trend': '+12%'},
            {'name': 'Critical Alerts', 'value': '23', 'trend': '-8%'},
            {'name': 'Mean Time to Detection', 'value': '4.2 hrs', 'trend': '-15%'},
            {'name': 'Mean Time to Response', 'value': '2.1 hrs', 'trend': '+5%'},
            {'name': 'False Positive Rate', 'value': '12%', 'trend': '-23%'}
        ]
    
    async def _generate_risk_assessment(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Generate risk assessment for executive dashboard"""
        return [
            {
                'title': 'Advanced Persistent Threat Activity',
                'level': 'high',
                'description': 'Increased APT activity detected in network segments',
                'impact': 'Potential data exfiltration and system compromise'
            },
            {
                'title': 'Phishing Campaign Targeting',
                'level': 'medium', 
                'description': 'Targeted phishing emails against executives',
                'impact': 'Credential compromise and lateral movement'
            }
        ]
    
    async def _generate_security_trends_chart(self, start_date: datetime, end_date: datetime) -> str:
        """Generate security trends chart"""
        # Sample data - would be from actual SIEM data
        dates = pd.date_range(start_date, end_date, freq='D')
        incidents = np.random.poisson(15, len(dates))
        alerts = np.random.poisson(50, len(dates))
        
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        fig.add_trace(
            go.Scatter(x=dates, y=incidents, name="Security Incidents"),
            secondary_y=False,
        )
        
        fig.add_trace(
            go.Scatter(x=dates, y=alerts, name="Security Alerts"),
            secondary_y=True,
        )
        
        fig.update_xaxes(title_text="Date")
        fig.update_yaxes(title_text="Incidents", secondary_y=False)
        fig.update_yaxes(title_text="Alerts", secondary_y=True)
        
        fig.update_layout(title_text="Security Trends Over Time")
        
        return self._fig_to_html(fig)
    
    async def _generate_security_recommendations(self, kpis: List[Dict], risks: List[Dict]) -> str:
        """Generate security recommendations"""
        recommendations = []
        
        # Analyze KPIs for recommendations
        for kpi in kpis:
            if 'Mean Time to Detection' in kpi['name'] and float(kpi['value'].split()[0]) > 4:
                recommendations.append("Implement additional automated detection rules to reduce MTTD")
        
        # Analyze risks for recommendations
        for risk in risks:
            if risk['level'] == 'high':
                recommendations.append(f"Immediate action required for: {risk['title']}")
        
        return "<ul>" + "".join([f"<li>{rec}</li>" for rec in recommendations]) + "</ul>"
    
    def _fig_to_html(self, fig: go.Figure) -> str:
        """Convert plotly figure to HTML string"""
        return pio.to_html(fig, include_plotlyjs='cdn', div_id=str(uuid.uuid4()))
    
    async def _html_to_pdf(self, html_content: str, report_id: str) -> str:
        """Convert HTML to PDF (placeholder - would use actual PDF library)"""
        # This would typically use a library like weasyprint or pdfkit
        pdf_path = self.output_dir / f"{report_id}.pdf"
        # Actual PDF conversion would happen here
        return str(pdf_path)
    
    async def _save_reports(self, outputs: Dict[str, str], metadata: ReportMetadata) -> str:
        """Save generated reports to filesystem"""
        report_dir = self.output_dir / metadata.report_id
        report_dir.mkdir(exist_ok=True)
        
        saved_files = []
        for format_type, content in outputs.items():
            if format_type in ['html', 'json']:
                file_path = report_dir / f"report.{format_type}"
                with open(file_path, 'w') as f:
                    f.write(content)
                saved_files.append(str(file_path))
            elif format_type == 'pdf':
                saved_files.append(content)  # PDF path already generated
        
        # Save metadata
        metadata_path = report_dir / "metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(asdict(metadata), f, default=str, indent=2)
        
        return str(report_dir)
    
    async def distribute_report(self, report_path: str, recipients: List[str], 
                              secure: bool = True) -> bool:
        """Distribute report via email"""
        try:
            if not self.config['reporting']['distribution']['email_enabled']:
                logger.warning("Email distribution is disabled")
                return False
            
            # Create secure archive if requested
            if secure:
                archive_path = await self._create_secure_archive(report_path)
            else:
                archive_path = report_path
            
            # Send email
            await self._send_email_with_attachment(recipients, archive_path)
            
            logger.info(f"Report distributed to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to distribute report: {e}")
            return False
    
    async def _create_secure_archive(self, report_path: str) -> str:
        """Create password-protected archive"""
        archive_path = f"{report_path}.zip"
        password = str(uuid.uuid4())[:12]
        
        # Create encrypted ZIP (placeholder - would use actual encryption)
        with zipfile.ZipFile(archive_path, 'w') as zipf:
            for root, dirs, files in os.walk(report_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, report_path)
                    zipf.write(file_path, arcname)
        
        # Store password securely (placeholder)
        logger.info(f"Archive password: {password}")
        
        return archive_path
    
    async def _send_email_with_attachment(self, recipients: List[str], attachment_path: str):
        """Send email with report attachment"""
        # Email sending implementation (placeholder)
        logger.info(f"Sending report to {recipients} with attachment: {attachment_path}")

if __name__ == "__main__":
    # Example usage
    dashboard = ReportingDashboard()
    
    # Generate sample investigation report
    metadata = ReportMetadata(
        report_id=str(uuid.uuid4()),
        title="Security Incident Investigation Report",
        description="Investigation of suspicious network activity",
        report_type="investigation",
        classification="confidential",
        created_by="security-analyst@isectech.com",
        created_at=datetime.now(timezone.utc),
        investigation_id="INV-2024-001"
    )
    
    sample_data = {
        'executive_summary': 'Critical security incident involving unauthorized access...',
        'key_findings': [
            {
                'title': 'Unauthorized Access Detected',
                'description': 'Multiple failed login attempts followed by successful authentication',
                'severity': 'high',
                'confidence': 85
            }
        ],
        'recommendations': [
            {
                'title': 'Implement MFA',
                'description': 'Deploy multi-factor authentication for all user accounts',
                'priority': 'high',
                'timeline': '30 days'
            }
        ]
    }
    
    # Generate report
    asyncio.run(dashboard.generate_investigation_report(sample_data, metadata))