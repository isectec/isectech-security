#!/usr/bin/env python3
"""
Automated Penetration Testing Framework
Enterprise-grade security testing orchestrator for iSECTECH platform
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import yaml
import aiohttp
import asyncpg
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
import hashlib
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Types of security scans"""
    WEB_APPLICATION = "web_application"
    NETWORK = "network"
    KUBERNETES = "kubernetes"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    API = "api"
    DATABASE = "database"
    CONTAINER = "container"
    SOURCE_CODE = "source_code"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "info"


@dataclass
class ScanConfiguration:
    """Configuration for a security scan"""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: ScanType = ScanType.WEB_APPLICATION
    target: str = ""
    tools: List[str] = field(default_factory=list)
    schedule: Optional[str] = None
    enabled: bool = True
    configuration: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanResult:
    """Results from a security scan"""
    scan_id: str
    scan_type: ScanType
    target: str
    tool: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"
    vulnerabilities: List[Dict] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    raw_output: Optional[str] = None
    report_path: Optional[str] = None


class SecurityTool:
    """Base class for security testing tools"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.executable = config.get('executable', name)
        self.version = config.get('version', 'latest')
        
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute security scan"""
        raise NotImplementedError
        
    async def is_available(self) -> bool:
        """Check if tool is installed and available"""
        try:
            result = await asyncio.create_subprocess_exec(
                self.executable, '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.communicate()
            return result.returncode == 0
        except Exception:
            return False


class ZAPScanner(SecurityTool):
    """OWASP ZAP scanner implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__('zap', config)
        self.api_key = config.get('api_key', 'changeme')
        self.api_url = config.get('api_url', 'http://localhost:8080')
        
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute ZAP scan"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.WEB_APPLICATION,
            target=target,
            tool='zap',
            started_at=datetime.utcnow()
        )
        
        try:
            # Start ZAP spider
            async with aiohttp.ClientSession() as session:
                spider_url = f"{self.api_url}/JSON/spider/action/scan/"
                params = {
                    'apikey': self.api_key,
                    'url': target,
                    'maxChildren': options.get('max_children', 10),
                    'recurse': 'true'
                }
                
                async with session.get(spider_url, params=params) as resp:
                    spider_data = await resp.json()
                    spider_id = spider_data.get('scan')
                
                # Wait for spider to complete
                await self._wait_for_spider(session, spider_id)
                
                # Start active scan
                ascan_url = f"{self.api_url}/JSON/ascan/action/scan/"
                params = {
                    'apikey': self.api_key,
                    'url': target,
                    'recurse': 'true',
                    'inScopeOnly': 'false',
                    'scanPolicyName': options.get('policy', 'Default Policy')
                }
                
                async with session.get(ascan_url, params=params) as resp:
                    ascan_data = await resp.json()
                    scan_id = ascan_data.get('scan')
                
                # Wait for active scan to complete
                await self._wait_for_scan(session, scan_id)
                
                # Get scan results
                alerts_url = f"{self.api_url}/JSON/core/view/alerts/"
                params = {
                    'apikey': self.api_key,
                    'baseurl': target
                }
                
                async with session.get(alerts_url, params=params) as resp:
                    alerts_data = await resp.json()
                    alerts = alerts_data.get('alerts', [])
                
                # Process vulnerabilities
                vulnerabilities = []
                severity_counts = {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
                
                for alert in alerts:
                    severity = self._map_risk_to_severity(alert.get('risk'))
                    severity_counts[severity] += 1
                    
                    vulnerabilities.append({
                        'id': hashlib.md5(f"{alert.get('name')}{alert.get('url')}".encode()).hexdigest(),
                        'name': alert.get('name'),
                        'severity': severity,
                        'confidence': alert.get('confidence'),
                        'url': alert.get('url'),
                        'description': alert.get('description'),
                        'solution': alert.get('solution'),
                        'reference': alert.get('reference'),
                        'cwe_id': alert.get('cweid'),
                        'wasc_id': alert.get('wascid')
                    })
                
                result.vulnerabilities = vulnerabilities
                result.summary = severity_counts
                result.status = 'completed'
                result.completed_at = datetime.utcnow()
                
                # Generate report
                report_path = await self._generate_report(target, vulnerabilities)
                result.report_path = report_path
                
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            result.status = 'failed'
            result.completed_at = datetime.utcnow()
            
        return result
    
    async def _wait_for_spider(self, session: aiohttp.ClientSession, spider_id: str):
        """Wait for spider scan to complete"""
        status_url = f"{self.api_url}/JSON/spider/view/status/"
        while True:
            params = {'apikey': self.api_key, 'scanId': spider_id}
            async with session.get(status_url, params=params) as resp:
                data = await resp.json()
                status = int(data.get('status', 0))
                if status >= 100:
                    break
            await asyncio.sleep(2)
    
    async def _wait_for_scan(self, session: aiohttp.ClientSession, scan_id: str):
        """Wait for active scan to complete"""
        status_url = f"{self.api_url}/JSON/ascan/view/status/"
        while True:
            params = {'apikey': self.api_key, 'scanId': scan_id}
            async with session.get(status_url, params=params) as resp:
                data = await resp.json()
                status = int(data.get('status', 0))
                if status >= 100:
                    break
            await asyncio.sleep(5)
    
    def _map_risk_to_severity(self, risk: str) -> str:
        """Map ZAP risk levels to standard severity"""
        risk_map = {
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Informational': 'info'
        }
        return risk_map.get(risk, 'info')
    
    async def _generate_report(self, target: str, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report"""
        report_dir = Path('/reports/penetration-testing')
        report_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        report_path = report_dir / f"zap_scan_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ZAP Security Scan Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #1a73e8; color: white; padding: 20px; }}
                .vulnerability {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .critical {{ border-left: 5px solid #d32f2f; }}
                .high {{ border-left: 5px solid #f57c00; }}
                .medium {{ border-left: 5px solid #fbc02d; }}
                .low {{ border-left: 5px solid #388e3c; }}
                .info {{ border-left: 5px solid #1976d2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Target: {target}</p>
                <p>Scan Date: {datetime.utcnow().isoformat()}</p>
                <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
            </div>
        """
        
        for vuln in sorted(vulnerabilities, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x['severity'])):
            html_content += f"""
            <div class="vulnerability {vuln['severity']}">
                <h3>{vuln['name']}</h3>
                <p><strong>Severity:</strong> {vuln['severity'].upper()}</p>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Solution:</strong> {vuln['solution']}</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        report_path.write_text(html_content)
        return str(report_path)


class NmapScanner(SecurityTool):
    """Nmap network scanner implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__('nmap', config)
        
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute Nmap scan"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.NETWORK,
            target=target,
            tool='nmap',
            started_at=datetime.utcnow()
        )
        
        try:
            # Build Nmap command
            cmd = [
                'nmap',
                '-sV',  # Version detection
                '-sC',  # Default scripts
                '-O',   # OS detection
                '-A',   # Aggressive scan
                '-oX', f'/tmp/nmap_{scan_id}.xml',  # XML output
                target
            ]
            
            if options.get('ports'):
                cmd.extend(['-p', options['ports']])
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse results
                vulnerabilities = await self._parse_nmap_results(f'/tmp/nmap_{scan_id}.xml')
                result.vulnerabilities = vulnerabilities
                result.summary = self._calculate_summary(vulnerabilities)
                result.status = 'completed'
            else:
                result.status = 'failed'
                logger.error(f"Nmap scan failed: {stderr.decode()}")
            
            result.completed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            result.status = 'failed'
            result.completed_at = datetime.utcnow()
            
        return result
    
    async def _parse_nmap_results(self, xml_path: str) -> List[Dict]:
        """Parse Nmap XML output"""
        import xml.etree.ElementTree as ET
        
        vulnerabilities = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                ip = host.find('.//address[@addrtype="ipv4"]').get('addr')
                
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state').get('state')
                    
                    if state == 'open':
                        service = port.find('service')
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        service_version = service.get('version', '') if service is not None else ''
                        
                        # Check for vulnerabilities in scripts
                        for script in port.findall('.//script'):
                            if 'vuln' in script.get('id', ''):
                                vulnerabilities.append({
                                    'id': hashlib.md5(f"{ip}:{port_id}:{script.get('id')}".encode()).hexdigest(),
                                    'name': script.get('id'),
                                    'severity': self._assess_severity(script.get('id')),
                                    'host': ip,
                                    'port': port_id,
                                    'protocol': protocol,
                                    'service': f"{service_name} {service_version}".strip(),
                                    'description': script.get('output', ''),
                                    'solution': 'Review and patch vulnerable service'
                                })
        
        except Exception as e:
            logger.error(f"Failed to parse Nmap results: {e}")
        
        finally:
            # Clean up XML file
            Path(xml_path).unlink(missing_ok=True)
        
        return vulnerabilities
    
    def _assess_severity(self, script_id: str) -> str:
        """Assess vulnerability severity based on script ID"""
        if 'cve' in script_id.lower():
            return 'high'
        elif 'dos' in script_id.lower():
            return 'medium'
        else:
            return 'low'
    
    def _calculate_summary(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability summary"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            summary[severity] += 1
        
        return summary


class NucleiScanner(SecurityTool):
    """Nuclei vulnerability scanner implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__('nuclei', config)
        self.templates_dir = config.get('templates_dir', '/nuclei-templates')
        
    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        """Execute Nuclei scan"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.WEB_APPLICATION,
            target=target,
            tool='nuclei',
            started_at=datetime.utcnow()
        )
        
        try:
            output_file = f'/tmp/nuclei_{scan_id}.json'
            
            # Build Nuclei command
            cmd = [
                'nuclei',
                '-u', target,
                '-t', self.templates_dir,
                '-json',
                '-o', output_file,
                '-severity', options.get('severity', 'critical,high,medium'),
                '-stats'
            ]
            
            if options.get('templates'):
                cmd.extend(['-t', options['templates']])
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            vulnerabilities = await self._parse_nuclei_results(output_file)
            result.vulnerabilities = vulnerabilities
            result.summary = self._calculate_summary(vulnerabilities)
            result.status = 'completed'
            result.completed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            result.status = 'failed'
            result.completed_at = datetime.utcnow()
            
        return result
    
    async def _parse_nuclei_results(self, json_path: str) -> List[Dict]:
        """Parse Nuclei JSON output"""
        vulnerabilities = []
        
        try:
            with open(json_path, 'r') as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        vulnerabilities.append({
                            'id': hashlib.md5(f"{finding.get('matched-at')}{finding.get('template-id')}".encode()).hexdigest(),
                            'name': finding.get('info', {}).get('name', finding.get('template-id')),
                            'severity': finding.get('info', {}).get('severity', 'info'),
                            'url': finding.get('matched-at'),
                            'template_id': finding.get('template-id'),
                            'description': finding.get('info', {}).get('description', ''),
                            'reference': finding.get('info', {}).get('reference', []),
                            'tags': finding.get('info', {}).get('tags', []),
                            'matcher_name': finding.get('matcher-name'),
                            'curl_command': finding.get('curl-command')
                        })
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            logger.error(f"Failed to parse Nuclei results: {e}")
        
        finally:
            # Clean up JSON file
            Path(json_path).unlink(missing_ok=True)
        
        return vulnerabilities
    
    def _calculate_summary(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability summary"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary


class AutomatedPenetrationTestingFramework:
    """Main orchestrator for automated penetration testing"""
    
    def __init__(self, config_path: str = '/etc/security-validation/config.yaml'):
        self.config = self._load_config(config_path)
        self.db_pool = None
        self.scanners = self._initialize_scanners()
        self.scan_queue = asyncio.Queue()
        self.active_scans = {}
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('max_workers', 4))
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return {
                'database': {
                    'host': 'localhost',
                    'port': 5432,
                    'database': 'security_validation',
                    'user': 'security_user'
                },
                'scanners': {
                    'zap': {'enabled': True},
                    'nmap': {'enabled': True},
                    'nuclei': {'enabled': True}
                },
                'reporting': {
                    'jira': {'enabled': False},
                    'slack': {'enabled': False}
                }
            }
    
    def _initialize_scanners(self) -> Dict[str, SecurityTool]:
        """Initialize security scanning tools"""
        scanners = {}
        
        scanner_configs = self.config.get('scanners', {})
        
        if scanner_configs.get('zap', {}).get('enabled', True):
            scanners['zap'] = ZAPScanner(scanner_configs.get('zap', {}))
        
        if scanner_configs.get('nmap', {}).get('enabled', True):
            scanners['nmap'] = NmapScanner(scanner_configs.get('nmap', {}))
        
        if scanner_configs.get('nuclei', {}).get('enabled', True):
            scanners['nuclei'] = NucleiScanner(scanner_configs.get('nuclei', {}))
        
        logger.info(f"Initialized {len(scanners)} security scanners")
        return scanners
    
    async def initialize(self):
        """Initialize database connection and other resources"""
        db_config = self.config.get('database', {})
        self.db_pool = await asyncpg.create_pool(
            host=db_config.get('host', 'localhost'),
            port=db_config.get('port', 5432),
            database=db_config.get('database', 'security_validation'),
            user=db_config.get('user', 'security_user'),
            password=os.getenv('DB_PASSWORD', 'password')
        )
        
        # Create tables if needed
        await self._create_tables()
        
        # Verify scanner availability
        for name, scanner in self.scanners.items():
            if await scanner.is_available():
                logger.info(f"Scanner {name} is available")
            else:
                logger.warning(f"Scanner {name} is not available")
    
    async def _create_tables(self):
        """Create database tables for scan management"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_configurations (
                    scan_id UUID PRIMARY KEY,
                    scan_type VARCHAR(50) NOT NULL,
                    target VARCHAR(500) NOT NULL,
                    tools TEXT[],
                    schedule VARCHAR(100),
                    enabled BOOLEAN DEFAULT TRUE,
                    configuration JSONB,
                    metadata JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_id UUID REFERENCES scan_configurations(scan_id),
                    scan_type VARCHAR(50) NOT NULL,
                    target VARCHAR(500) NOT NULL,
                    tool VARCHAR(50) NOT NULL,
                    started_at TIMESTAMP NOT NULL,
                    completed_at TIMESTAMP,
                    status VARCHAR(20) NOT NULL,
                    vulnerabilities JSONB,
                    summary JSONB,
                    report_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_result_id UUID REFERENCES scan_results(result_id),
                    vulnerability_id VARCHAR(100),
                    name VARCHAR(500),
                    severity VARCHAR(20),
                    cvss_score FLOAT,
                    cve_id VARCHAR(20),
                    cwe_id VARCHAR(20),
                    target VARCHAR(500),
                    description TEXT,
                    solution TEXT,
                    reference TEXT,
                    false_positive BOOLEAN DEFAULT FALSE,
                    remediation_status VARCHAR(50) DEFAULT 'open',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id ON scan_results(scan_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(remediation_status)")
    
    async def create_scan_configuration(
        self,
        scan_type: ScanType,
        target: str,
        tools: List[str],
        schedule: Optional[str] = None,
        configuration: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None
    ) -> str:
        """Create a new scan configuration"""
        scan_config = ScanConfiguration(
            scan_type=scan_type,
            target=target,
            tools=tools,
            schedule=schedule,
            configuration=configuration or {},
            metadata=metadata or {}
        )
        
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO scan_configurations (
                    scan_id, scan_type, target, tools, schedule,
                    enabled, configuration, metadata
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, 
                uuid.UUID(scan_config.scan_id),
                scan_config.scan_type.value,
                scan_config.target,
                scan_config.tools,
                scan_config.schedule,
                scan_config.enabled,
                json.dumps(scan_config.configuration),
                json.dumps(scan_config.metadata)
            )
        
        logger.info(f"Created scan configuration {scan_config.scan_id}")
        return scan_config.scan_id
    
    async def execute_scan(self, scan_id: str) -> List[ScanResult]:
        """Execute a configured scan"""
        # Fetch scan configuration
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM scan_configurations WHERE scan_id = $1",
                uuid.UUID(scan_id)
            )
        
        if not row:
            raise ValueError(f"Scan configuration {scan_id} not found")
        
        scan_type = ScanType(row['scan_type'])
        target = row['target']
        tools = row['tools']
        configuration = json.loads(row['configuration']) if row['configuration'] else {}
        
        results = []
        
        # Execute scan with each configured tool
        for tool_name in tools:
            if tool_name not in self.scanners:
                logger.warning(f"Scanner {tool_name} not available")
                continue
            
            scanner = self.scanners[tool_name]
            logger.info(f"Starting {tool_name} scan on {target}")
            
            try:
                result = await scanner.scan(target, configuration.get(tool_name, {}))
                results.append(result)
                
                # Store result in database
                await self._store_scan_result(scan_id, result)
                
                # Process vulnerabilities
                await self._process_vulnerabilities(result)
                
                # Send notifications if configured
                await self._send_notifications(result)
                
            except Exception as e:
                logger.error(f"Scan failed with {tool_name}: {e}")
        
        return results
    
    async def _store_scan_result(self, scan_id: str, result: ScanResult):
        """Store scan result in database"""
        async with self.db_pool.acquire() as conn:
            result_id = await conn.fetchval("""
                INSERT INTO scan_results (
                    scan_id, scan_type, target, tool, started_at,
                    completed_at, status, vulnerabilities, summary, report_path
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING result_id
            """,
                uuid.UUID(scan_id),
                result.scan_type.value,
                result.target,
                result.tool,
                result.started_at,
                result.completed_at,
                result.status,
                json.dumps(result.vulnerabilities),
                json.dumps(result.summary),
                result.report_path
            )
            
            # Store individual vulnerabilities
            for vuln in result.vulnerabilities:
                await conn.execute("""
                    INSERT INTO vulnerabilities (
                        scan_result_id, vulnerability_id, name, severity,
                        target, description, solution, reference
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                    result_id,
                    vuln.get('id'),
                    vuln.get('name'),
                    vuln.get('severity'),
                    vuln.get('url', vuln.get('host', result.target)),
                    vuln.get('description'),
                    vuln.get('solution'),
                    json.dumps(vuln.get('reference', []))
                )
    
    async def _process_vulnerabilities(self, result: ScanResult):
        """Process and enrich vulnerability data"""
        for vuln in result.vulnerabilities:
            # Check for CVE information
            if 'cve' in vuln.get('name', '').lower() or vuln.get('cve_id'):
                await self._enrich_cve_data(vuln)
            
            # Calculate CVSS score if not present
            if not vuln.get('cvss_score'):
                vuln['cvss_score'] = self._estimate_cvss_score(vuln)
    
    async def _enrich_cve_data(self, vulnerability: Dict):
        """Enrich vulnerability with CVE data"""
        # This would integrate with CVE databases
        pass
    
    def _estimate_cvss_score(self, vulnerability: Dict) -> float:
        """Estimate CVSS score based on severity"""
        severity_scores = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'info': 0.0
        }
        return severity_scores.get(vulnerability.get('severity', 'info'), 0.0)
    
    async def _send_notifications(self, result: ScanResult):
        """Send notifications for scan results"""
        if result.summary.get('critical', 0) > 0 or result.summary.get('high', 0) > 0:
            await self._send_critical_alert(result)
        
        # Send to configured channels
        if self.config.get('reporting', {}).get('slack', {}).get('enabled'):
            await self._send_slack_notification(result)
        
        if self.config.get('reporting', {}).get('jira', {}).get('enabled'):
            await self._create_jira_tickets(result)
    
    async def _send_critical_alert(self, result: ScanResult):
        """Send critical vulnerability alert"""
        message = f"""
        🚨 CRITICAL VULNERABILITIES DETECTED
        
        Target: {result.target}
        Tool: {result.tool}
        Critical: {result.summary.get('critical', 0)}
        High: {result.summary.get('high', 0)}
        
        Immediate action required!
        """
        
        logger.critical(message)
        
        # Send to SOC webhook
        if soc_webhook := os.getenv('SOC_WEBHOOK'):
            async with aiohttp.ClientSession() as session:
                await session.post(soc_webhook, json={
                    'alert_type': 'vulnerability_scan',
                    'severity': 'critical',
                    'target': result.target,
                    'summary': result.summary,
                    'scan_id': result.scan_id
                })
    
    async def _send_slack_notification(self, result: ScanResult):
        """Send Slack notification for scan results"""
        slack_webhook = self.config.get('reporting', {}).get('slack', {}).get('webhook')
        if not slack_webhook:
            return
        
        color = 'danger' if result.summary.get('critical', 0) > 0 else 'warning'
        
        async with aiohttp.ClientSession() as session:
            await session.post(slack_webhook, json={
                'attachments': [{
                    'color': color,
                    'title': f'Security Scan Completed - {result.target}',
                    'fields': [
                        {'title': 'Tool', 'value': result.tool, 'short': True},
                        {'title': 'Status', 'value': result.status, 'short': True},
                        {'title': 'Critical', 'value': result.summary.get('critical', 0), 'short': True},
                        {'title': 'High', 'value': result.summary.get('high', 0), 'short': True},
                        {'title': 'Medium', 'value': result.summary.get('medium', 0), 'short': True},
                        {'title': 'Low', 'value': result.summary.get('low', 0), 'short': True}
                    ],
                    'footer': 'iSECTECH Security Platform',
                    'ts': int(time.time())
                }]
            })
    
    async def _create_jira_tickets(self, result: ScanResult):
        """Create JIRA tickets for vulnerabilities"""
        jira_config = self.config.get('reporting', {}).get('jira', {})
        if not jira_config:
            return
        
        # Create tickets for critical and high vulnerabilities
        for vuln in result.vulnerabilities:
            if vuln.get('severity') in ['critical', 'high']:
                # Create JIRA ticket
                pass  # Implementation would integrate with JIRA API
    
    async def schedule_scans(self):
        """Process scheduled scans"""
        while True:
            try:
                # Check for scheduled scans
                async with self.db_pool.acquire() as conn:
                    rows = await conn.fetch("""
                        SELECT scan_id, schedule FROM scan_configurations
                        WHERE enabled = TRUE AND schedule IS NOT NULL
                    """)
                
                for row in rows:
                    # Check if scan should run based on schedule
                    if self._should_run_scan(row['schedule']):
                        await self.scan_queue.put(str(row['scan_id']))
                
                # Process scan queue
                while not self.scan_queue.empty():
                    scan_id = await self.scan_queue.get()
                    asyncio.create_task(self.execute_scan(scan_id))
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)
    
    def _should_run_scan(self, schedule: str) -> bool:
        """Check if scan should run based on schedule"""
        # Simple implementation - would use cron expression parser in production
        if schedule == 'daily':
            # Run at midnight
            now = datetime.utcnow()
            return now.hour == 0 and now.minute < 1
        elif schedule == 'weekly':
            # Run on Sunday at midnight
            now = datetime.utcnow()
            return now.weekday() == 6 and now.hour == 0 and now.minute < 1
        elif schedule == 'hourly':
            # Run at the start of each hour
            now = datetime.utcnow()
            return now.minute < 1
        return False
    
    async def get_scan_results(self, scan_id: Optional[str] = None) -> List[Dict]:
        """Get scan results from database"""
        async with self.db_pool.acquire() as conn:
            if scan_id:
                query = """
                    SELECT * FROM scan_results 
                    WHERE scan_id = $1
                    ORDER BY started_at DESC
                """
                rows = await conn.fetch(query, uuid.UUID(scan_id))
            else:
                query = """
                    SELECT * FROM scan_results
                    ORDER BY started_at DESC
                    LIMIT 100
                """
                rows = await conn.fetch(query)
        
        return [dict(row) for row in rows]
    
    async def get_vulnerability_statistics(self) -> Dict[str, Any]:
        """Get vulnerability statistics"""
        async with self.db_pool.acquire() as conn:
            # Total vulnerabilities by severity
            severity_stats = await conn.fetch("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE remediation_status = 'open'
                GROUP BY severity
            """)
            
            # Recent scan statistics
            recent_scans = await conn.fetchval("""
                SELECT COUNT(*) FROM scan_results
                WHERE started_at > NOW() - INTERVAL '24 hours'
            """)
            
            # Most vulnerable targets
            vulnerable_targets = await conn.fetch("""
                SELECT target, COUNT(*) as vuln_count
                FROM vulnerabilities
                WHERE remediation_status = 'open'
                GROUP BY target
                ORDER BY vuln_count DESC
                LIMIT 10
            """)
        
        return {
            'severity_distribution': {row['severity']: row['count'] for row in severity_stats},
            'recent_scans_24h': recent_scans,
            'most_vulnerable_targets': [dict(row) for row in vulnerable_targets],
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.db_pool:
            await self.db_pool.close()
        self.executor.shutdown(wait=True)


async def main():
    """Main entry point for the penetration testing framework"""
    framework = AutomatedPenetrationTestingFramework()
    
    try:
        await framework.initialize()
        
        # Create sample scan configuration
        scan_id = await framework.create_scan_configuration(
            scan_type=ScanType.WEB_APPLICATION,
            target='https://testapp.isectech.com',
            tools=['zap', 'nuclei'],
            schedule='daily',
            configuration={
                'zap': {'policy': 'Default Policy'},
                'nuclei': {'severity': 'critical,high,medium'}
            }
        )
        
        logger.info(f"Created scan configuration: {scan_id}")
        
        # Start scheduler
        scheduler_task = asyncio.create_task(framework.schedule_scans())
        
        # Keep running
        await asyncio.Event().wait()
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await framework.cleanup()


if __name__ == '__main__':
    asyncio.run(main())