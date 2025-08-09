#!/usr/bin/env python3
"""
iSECTECH Platform - Continuous Security Scanning Pipeline
Production-Grade Automated Security Testing Integration
"""

import asyncio
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
import yaml
import subprocess
import tempfile

import aiohttp
import schedule
from kubernetes import client, config as k8s_config
import docker
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Prometheus metrics
SCAN_COUNTER = Counter('security_scans_total', 'Total security scans executed', ['scan_type', 'status'])
SCAN_DURATION = Histogram('security_scan_duration_seconds', 'Time spent on security scans', ['scan_type'])
VULNERABILITIES_GAUGE = Gauge('vulnerabilities_found', 'Current number of vulnerabilities', ['severity'])
SCAN_ERRORS = Counter('security_scan_errors_total', 'Total security scan errors', ['scan_type', 'error_type'])

class ScanType(Enum):
    """Security scan types"""
    VULNERABILITY_SCAN = "vulnerability_scan"
    DEPENDENCY_SCAN = "dependency_scan"
    CONTAINER_SCAN = "container_scan"
    CODE_ANALYSIS = "code_analysis"
    INFRASTRUCTURE_SCAN = "infrastructure_scan"
    API_SECURITY_SCAN = "api_security_scan"
    COMPLIANCE_SCAN = "compliance_scan"

class ScanStatus(Enum):
    """Security scan status"""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class ScanConfiguration:
    """Security scan configuration"""
    scan_type: ScanType
    enabled: bool
    schedule: str  # Cron-style schedule
    targets: List[str]
    tools: List[str]
    timeout_minutes: int
    alert_thresholds: Dict[str, int]  # severity -> count threshold
    notification_channels: List[str]
    remediation_auto: bool

@dataclass
class SecurityFinding:
    """Security finding data structure"""
    id: str
    scan_id: str
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: float
    affected_target: str
    tool: str
    category: str
    cwe_id: Optional[str]
    cve_id: Optional[str]
    remediation: str
    first_seen: datetime
    last_seen: datetime
    status: str
    false_positive: bool

@dataclass
class ScanResult:
    """Security scan result"""
    scan_id: str
    scan_type: ScanType
    start_time: datetime
    end_time: Optional[datetime]
    status: ScanStatus
    targets: List[str]
    tools_used: List[str]
    findings: List[SecurityFinding]
    summary: Dict[str, Any]
    errors: List[str]

class VulnerabilityScanner:
    """Automated vulnerability scanning"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        
    async def run_nessus_scan(self, targets: List[str]) -> List[SecurityFinding]:
        """Run Nessus vulnerability scan"""
        findings = []
        
        try:
            # For production use, integrate with actual Nessus API
            # This is a simplified implementation for demonstration
            
            for target in targets:
                logger.info(f"Running Nessus scan on {target}")
                
                # Simulate Nessus scan results
                scan_command = [
                    "nessus_scan",
                    "--target", target,
                    "--policy", "full_scan",
                    "--format", "json"
                ]
                
                result = await self._run_scan_command(scan_command)
                
                if result["returncode"] == 0:
                    # Parse Nessus results
                    findings.extend(self._parse_nessus_results(result["stdout"], target))
                else:
                    logger.error(f"Nessus scan failed: {result['stderr']}")
                    
        except Exception as e:
            logger.error(f"Nessus vulnerability scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="nessus", error_type="execution").inc()
            
        return findings
        
    async def run_openvas_scan(self, targets: List[str]) -> List[SecurityFinding]:
        """Run OpenVAS vulnerability scan"""
        findings = []
        
        try:
            for target in targets:
                logger.info(f"Running OpenVAS scan on {target}")
                
                scan_command = [
                    "gvm-cli", "tls",
                    "--hostname", "openvas-manager",
                    "--port", "9390",
                    "--gmp-username", "admin",
                    "--gmp-password", os.getenv("OPENVAS_PASSWORD", ""),
                    "socket",
                    f"<create_target><name>iSECTECH-{target}</name><hosts>{target}</hosts></create_target>"
                ]
                
                result = await self._run_scan_command(scan_command)
                findings.extend(self._parse_openvas_results(result["stdout"], target))
                
        except Exception as e:
            logger.error(f"OpenVAS vulnerability scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="openvas", error_type="execution").inc()
            
        return findings
        
    def _parse_nessus_results(self, scan_output: str, target: str) -> List[SecurityFinding]:
        """Parse Nessus scan results"""
        findings = []
        
        try:
            # Parse Nessus JSON output
            results = json.loads(scan_output)
            
            for vulnerability in results.get("vulnerabilities", []):
                finding = SecurityFinding(
                    id=vulnerability.get("id", ""),
                    scan_id=vulnerability.get("scan_id", ""),
                    title=vulnerability.get("name", ""),
                    description=vulnerability.get("description", ""),
                    severity=SeverityLevel(vulnerability.get("severity", "info")),
                    cvss_score=vulnerability.get("cvss_score", 0.0),
                    affected_target=target,
                    tool="Nessus",
                    category=vulnerability.get("category", "General"),
                    cwe_id=vulnerability.get("cwe_id"),
                    cve_id=vulnerability.get("cve_id"),
                    remediation=vulnerability.get("solution", ""),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    status="new",
                    false_positive=False
                )
                findings.append(finding)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Nessus results: {e}")
            
        return findings

class DependencyScanner:
    """Dependency vulnerability scanning"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        
    async def run_snyk_scan(self, project_path: str) -> List[SecurityFinding]:
        """Run Snyk dependency scan"""
        findings = []
        
        try:
            logger.info(f"Running Snyk scan on {project_path}")
            
            scan_command = [
                "snyk", "test",
                "--json",
                "--severity-threshold=low",
                project_path
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_snyk_results(result["stdout"], project_path)
            
        except Exception as e:
            logger.error(f"Snyk dependency scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="snyk", error_type="execution").inc()
            
        return findings
        
    async def run_safety_scan(self, requirements_file: str) -> List[SecurityFinding]:
        """Run Safety Python dependency scan"""
        findings = []
        
        try:
            logger.info(f"Running Safety scan on {requirements_file}")
            
            scan_command = [
                "safety", "check",
                "--json",
                "--file", requirements_file
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_safety_results(result["stdout"], requirements_file)
            
        except Exception as e:
            logger.error(f"Safety dependency scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="safety", error_type="execution").inc()
            
        return findings
        
    async def run_npm_audit(self, package_json_path: str) -> List[SecurityFinding]:
        """Run npm audit for Node.js dependencies"""
        findings = []
        
        try:
            logger.info(f"Running npm audit on {package_json_path}")
            
            scan_command = [
                "npm", "audit",
                "--json",
                "--prefix", os.path.dirname(package_json_path)
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_npm_audit_results(result["stdout"], package_json_path)
            
        except Exception as e:
            logger.error(f"npm audit scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="npm_audit", error_type="execution").inc()
            
        return findings
        
    def _parse_snyk_results(self, scan_output: str, project_path: str) -> List[SecurityFinding]:
        """Parse Snyk scan results"""
        findings = []
        
        try:
            results = json.loads(scan_output)
            
            for vulnerability in results.get("vulnerabilities", []):
                finding = SecurityFinding(
                    id=vulnerability.get("id", ""),
                    scan_id="snyk-" + str(int(time.time())),
                    title=vulnerability.get("title", ""),
                    description=vulnerability.get("description", ""),
                    severity=SeverityLevel(vulnerability.get("severity", "info")),
                    cvss_score=vulnerability.get("cvssScore", 0.0),
                    affected_target=project_path,
                    tool="Snyk",
                    category="Dependencies",
                    cwe_id=vulnerability.get("cwe"),
                    cve_id=vulnerability.get("cve"),
                    remediation=vulnerability.get("remediation", {}).get("advice", ""),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    status="new",
                    false_positive=False
                )
                findings.append(finding)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Snyk results: {e}")
            
        return findings

class ContainerScanner:
    """Container security scanning"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        self.docker_client = docker.from_env()
        
    async def run_trivy_scan(self, image_name: str) -> List[SecurityFinding]:
        """Run Trivy container scan"""
        findings = []
        
        try:
            logger.info(f"Running Trivy scan on {image_name}")
            
            scan_command = [
                "trivy", "image",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                image_name
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_trivy_results(result["stdout"], image_name)
            
        except Exception as e:
            logger.error(f"Trivy container scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="trivy", error_type="execution").inc()
            
        return findings
        
    async def run_clair_scan(self, image_name: str) -> List[SecurityFinding]:
        """Run Clair container scan"""
        findings = []
        
        try:
            logger.info(f"Running Clair scan on {image_name}")
            
            # Push image to local registry for Clair scanning
            registry_url = "localhost:5000"
            tagged_image = f"{registry_url}/{image_name}"
            
            # Tag and push image
            self.docker_client.images.get(image_name).tag(tagged_image)
            
            # Scan with Clair
            scan_command = [
                "clairctl", "analyze",
                "--config", "/etc/clair/config.yml",
                tagged_image
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_clair_results(result["stdout"], image_name)
            
        except Exception as e:
            logger.error(f"Clair container scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="clair", error_type="execution").inc()
            
        return findings
        
    def _parse_trivy_results(self, scan_output: str, image_name: str) -> List[SecurityFinding]:
        """Parse Trivy scan results"""
        findings = []
        
        try:
            results = json.loads(scan_output)
            
            for result in results.get("Results", []):
                for vulnerability in result.get("Vulnerabilities", []):
                    finding = SecurityFinding(
                        id=vulnerability.get("VulnerabilityID", ""),
                        scan_id="trivy-" + str(int(time.time())),
                        title=vulnerability.get("Title", ""),
                        description=vulnerability.get("Description", ""),
                        severity=SeverityLevel(vulnerability.get("Severity", "info").lower()),
                        cvss_score=vulnerability.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                        affected_target=image_name,
                        tool="Trivy",
                        category="Container",
                        cwe_id=None,
                        cve_id=vulnerability.get("VulnerabilityID"),
                        remediation=vulnerability.get("FixedVersion", "Update package"),
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        status="new",
                        false_positive=False
                    )
                    findings.append(finding)
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Trivy results: {e}")
            
        return findings

class CodeAnalysisScanner:
    """Static code analysis security scanning"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        
    async def run_sonarqube_scan(self, project_path: str) -> List[SecurityFinding]:
        """Run SonarQube security analysis"""
        findings = []
        
        try:
            logger.info(f"Running SonarQube scan on {project_path}")
            
            scan_command = [
                "sonar-scanner",
                f"-Dsonar.projectBaseDir={project_path}",
                "-Dsonar.sources=.",
                "-Dsonar.host.url=http://sonarqube:9000",
                f"-Dsonar.login={os.getenv('SONAR_TOKEN', '')}",
                "-Dsonar.projectKey=isectech",
                "-Dsonar.projectName=iSECTECH"
            ]
            
            result = await self._run_scan_command(scan_command, cwd=project_path)
            
            # Get results from SonarQube API
            findings = await self._fetch_sonarqube_results("isectech")
            
        except Exception as e:
            logger.error(f"SonarQube code analysis failed: {e}")
            SCAN_ERRORS.labels(scan_type="sonarqube", error_type="execution").inc()
            
        return findings
        
    async def run_semgrep_scan(self, project_path: str) -> List[SecurityFinding]:
        """Run Semgrep static analysis"""
        findings = []
        
        try:
            logger.info(f"Running Semgrep scan on {project_path}")
            
            scan_command = [
                "semgrep",
                "--config=auto",
                "--json",
                "--severity=WARNING",
                "--severity=ERROR",
                project_path
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_semgrep_results(result["stdout"], project_path)
            
        except Exception as e:
            logger.error(f"Semgrep code analysis failed: {e}")
            SCAN_ERRORS.labels(scan_type="semgrep", error_type="execution").inc()
            
        return findings
        
    async def run_bandit_scan(self, project_path: str) -> List[SecurityFinding]:
        """Run Bandit Python security scan"""
        findings = []
        
        try:
            logger.info(f"Running Bandit scan on {project_path}")
            
            scan_command = [
                "bandit",
                "-r", project_path,
                "-f", "json",
                "-ll"  # Low confidence, low severity
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_bandit_results(result["stdout"], project_path)
            
        except Exception as e:
            logger.error(f"Bandit code analysis failed: {e}")
            SCAN_ERRORS.labels(scan_type="bandit", error_type="execution").inc()
            
        return findings
        
    def _parse_semgrep_results(self, scan_output: str, project_path: str) -> List[SecurityFinding]:
        """Parse Semgrep scan results"""
        findings = []
        
        try:
            results = json.loads(scan_output)
            
            for result in results.get("results", []):
                finding = SecurityFinding(
                    id=result.get("check_id", ""),
                    scan_id="semgrep-" + str(int(time.time())),
                    title=result.get("message", ""),
                    description=result.get("extra", {}).get("message", ""),
                    severity=self._map_semgrep_severity(result.get("extra", {}).get("severity")),
                    cvss_score=self._calculate_cvss_from_severity(result.get("extra", {}).get("severity")),
                    affected_target=result.get("path", ""),
                    tool="Semgrep",
                    category="SAST",
                    cwe_id=result.get("extra", {}).get("metadata", {}).get("cwe"),
                    cve_id=None,
                    remediation=result.get("extra", {}).get("fix", "Review and fix the identified issue"),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    status="new",
                    false_positive=False
                )
                findings.append(finding)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep results: {e}")
            
        return findings
        
    def _map_semgrep_severity(self, severity: str) -> SeverityLevel:
        """Map Semgrep severity to standard severity levels"""
        mapping = {
            "ERROR": SeverityLevel.HIGH,
            "WARNING": SeverityLevel.MEDIUM,
            "INFO": SeverityLevel.LOW
        }
        return mapping.get(severity, SeverityLevel.INFO)

class InfrastructureScanner:
    """Infrastructure security scanning"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        
    async def run_nmap_scan(self, targets: List[str]) -> List[SecurityFinding]:
        """Run Nmap network scan"""
        findings = []
        
        try:
            for target in targets:
                logger.info(f"Running Nmap scan on {target}")
                
                scan_command = [
                    "nmap",
                    "-sV",  # Service version detection
                    "-sC",  # Default scripts
                    "--script", "vuln",  # Vulnerability scripts
                    "-oX", "-",  # XML output to stdout
                    target
                ]
                
                result = await self._run_scan_command(scan_command)
                findings.extend(self._parse_nmap_results(result["stdout"], target))
                
        except Exception as e:
            logger.error(f"Nmap infrastructure scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="nmap", error_type="execution").inc()
            
        return findings
        
    async def run_kube_bench_scan(self) -> List[SecurityFinding]:
        """Run kube-bench Kubernetes security scan"""
        findings = []
        
        try:
            logger.info("Running kube-bench Kubernetes security scan")
            
            scan_command = [
                "kube-bench",
                "--json"
            ]
            
            result = await self._run_scan_command(scan_command)
            findings = self._parse_kube_bench_results(result["stdout"])
            
        except Exception as e:
            logger.error(f"kube-bench scanning failed: {e}")
            SCAN_ERRORS.labels(scan_type="kube_bench", error_type="execution").inc()
            
        return findings

class ContinuousSecurityPipeline:
    """Main continuous security scanning pipeline"""
    
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.scan_configs = self._load_scan_configs()
        self.scan_history: Dict[str, List[ScanResult]] = {}
        self.findings_db = {}  # In production, use proper database
        
        # Initialize scanners
        self.vulnerability_scanner = VulnerabilityScanner(
            self.scan_configs.get(ScanType.VULNERABILITY_SCAN)
        )
        self.dependency_scanner = DependencyScanner(
            self.scan_configs.get(ScanType.DEPENDENCY_SCAN)
        )
        self.container_scanner = ContainerScanner(
            self.scan_configs.get(ScanType.CONTAINER_SCAN)
        )
        self.code_analysis_scanner = CodeAnalysisScanner(
            self.scan_configs.get(ScanType.CODE_ANALYSIS)
        )
        self.infrastructure_scanner = InfrastructureScanner(
            self.scan_configs.get(ScanType.INFRASTRUCTURE_SCAN)
        )
        
        # Start Prometheus metrics server
        start_http_server(8000)
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load pipeline configuration"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
            
    def _load_scan_configs(self) -> Dict[ScanType, ScanConfiguration]:
        """Load scan configurations"""
        scan_configs = {}
        
        for scan_type_str, config_data in self.config.get("scans", {}).items():
            scan_type = ScanType(scan_type_str)
            scan_configs[scan_type] = ScanConfiguration(
                scan_type=scan_type,
                enabled=config_data.get("enabled", True),
                schedule=config_data.get("schedule", "0 2 * * *"),  # Daily at 2 AM
                targets=config_data.get("targets", []),
                tools=config_data.get("tools", []),
                timeout_minutes=config_data.get("timeout_minutes", 60),
                alert_thresholds=config_data.get("alert_thresholds", {}),
                notification_channels=config_data.get("notification_channels", []),
                remediation_auto=config_data.get("remediation_auto", False)
            )
            
        return scan_configs
        
    async def start_continuous_pipeline(self):
        """Start continuous security scanning pipeline"""
        logger.info("Starting continuous security scanning pipeline...")
        
        # Schedule scans based on configuration
        for scan_type, scan_config in self.scan_configs.items():
            if scan_config.enabled:
                schedule.every().day.at("02:00").do(
                    lambda st=scan_type: asyncio.create_task(self.run_scheduled_scan(st))
                )
                
                # Schedule more frequent scans for critical components
                if scan_type == ScanType.VULNERABILITY_SCAN:
                    schedule.every(6).hours.do(
                        lambda st=scan_type: asyncio.create_task(self.run_scheduled_scan(st))
                    )
                    
        # Run initial baseline scans
        await self.run_baseline_scans()
        
        # Start scheduler loop
        while True:
            schedule.run_pending()
            await asyncio.sleep(60)  # Check every minute
            
    async def run_baseline_scans(self):
        """Run initial baseline security scans"""
        logger.info("Running baseline security scans...")
        
        baseline_tasks = []
        
        for scan_type, scan_config in self.scan_configs.items():
            if scan_config.enabled:
                baseline_tasks.append(self.run_scan(scan_type))
                
        # Run baseline scans concurrently
        await asyncio.gather(*baseline_tasks, return_exceptions=True)
        
    async def run_scheduled_scan(self, scan_type: ScanType):
        """Run scheduled security scan"""
        logger.info(f"Running scheduled {scan_type.value} scan")
        
        try:
            await self.run_scan(scan_type)
        except Exception as e:
            logger.error(f"Scheduled scan failed: {e}")
            SCAN_ERRORS.labels(scan_type=scan_type.value, error_type="scheduled").inc()
            
    async def run_scan(self, scan_type: ScanType) -> ScanResult:
        """Run specific type of security scan"""
        scan_config = self.scan_configs.get(scan_type)
        if not scan_config or not scan_config.enabled:
            return None
            
        scan_id = f"{scan_type.value}-{int(time.time())}"
        start_time = datetime.now(timezone.utc)
        
        logger.info(f"Starting {scan_type.value} scan (ID: {scan_id})")
        
        with SCAN_DURATION.labels(scan_type=scan_type.value).time():
            try:
                findings = []
                
                if scan_type == ScanType.VULNERABILITY_SCAN:
                    findings = await self._run_vulnerability_scan(scan_config)
                elif scan_type == ScanType.DEPENDENCY_SCAN:
                    findings = await self._run_dependency_scan(scan_config)
                elif scan_type == ScanType.CONTAINER_SCAN:
                    findings = await self._run_container_scan(scan_config)
                elif scan_type == ScanType.CODE_ANALYSIS:
                    findings = await self._run_code_analysis_scan(scan_config)
                elif scan_type == ScanType.INFRASTRUCTURE_SCAN:
                    findings = await self._run_infrastructure_scan(scan_config)
                    
                end_time = datetime.now(timezone.utc)
                
                scan_result = ScanResult(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    start_time=start_time,
                    end_time=end_time,
                    status=ScanStatus.COMPLETED,
                    targets=scan_config.targets,
                    tools_used=scan_config.tools,
                    findings=findings,
                    summary=self._generate_scan_summary(findings),
                    errors=[]
                )
                
                # Store scan results
                await self._store_scan_results(scan_result)
                
                # Check alert thresholds and send notifications
                await self._check_alert_thresholds(scan_result)
                
                # Update Prometheus metrics
                SCAN_COUNTER.labels(scan_type=scan_type.value, status="success").inc()
                self._update_vulnerability_metrics(findings)
                
                logger.info(f"Completed {scan_type.value} scan: {len(findings)} findings")
                
                return scan_result
                
            except Exception as e:
                logger.error(f"Security scan failed: {e}")
                
                scan_result = ScanResult(
                    scan_id=scan_id,
                    scan_type=scan_type,
                    start_time=start_time,
                    end_time=datetime.now(timezone.utc),
                    status=ScanStatus.FAILED,
                    targets=scan_config.targets,
                    tools_used=scan_config.tools,
                    findings=[],
                    summary={},
                    errors=[str(e)]
                )
                
                SCAN_COUNTER.labels(scan_type=scan_type.value, status="error").inc()
                return scan_result
                
    async def _run_vulnerability_scan(self, config: ScanConfiguration) -> List[SecurityFinding]:
        """Run vulnerability scanning"""
        findings = []
        
        if "nessus" in config.tools:
            findings.extend(await self.vulnerability_scanner.run_nessus_scan(config.targets))
            
        if "openvas" in config.tools:
            findings.extend(await self.vulnerability_scanner.run_openvas_scan(config.targets))
            
        return findings
        
    async def _run_dependency_scan(self, config: ScanConfiguration) -> List[SecurityFinding]:
        """Run dependency scanning"""
        findings = []
        
        for target in config.targets:
            if "snyk" in config.tools:
                findings.extend(await self.dependency_scanner.run_snyk_scan(target))
                
            if "safety" in config.tools and target.endswith("requirements.txt"):
                findings.extend(await self.dependency_scanner.run_safety_scan(target))
                
            if "npm" in config.tools and target.endswith("package.json"):
                findings.extend(await self.dependency_scanner.run_npm_audit(target))
                
        return findings
        
    async def _run_container_scan(self, config: ScanConfiguration) -> List[SecurityFinding]:
        """Run container scanning"""
        findings = []
        
        for image in config.targets:
            if "trivy" in config.tools:
                findings.extend(await self.container_scanner.run_trivy_scan(image))
                
            if "clair" in config.tools:
                findings.extend(await self.container_scanner.run_clair_scan(image))
                
        return findings
        
    async def _run_code_analysis_scan(self, config: ScanConfiguration) -> List[SecurityFinding]:
        """Run static code analysis scanning"""
        findings = []
        
        for project_path in config.targets:
            if "sonarqube" in config.tools:
                findings.extend(await self.code_analysis_scanner.run_sonarqube_scan(project_path))
                
            if "semgrep" in config.tools:
                findings.extend(await self.code_analysis_scanner.run_semgrep_scan(project_path))
                
            if "bandit" in config.tools:
                findings.extend(await self.code_analysis_scanner.run_bandit_scan(project_path))
                
        return findings
        
    async def _run_infrastructure_scan(self, config: ScanConfiguration) -> List[SecurityFinding]:
        """Run infrastructure scanning"""
        findings = []
        
        if "nmap" in config.tools:
            findings.extend(await self.infrastructure_scanner.run_nmap_scan(config.targets))
            
        if "kube-bench" in config.tools:
            findings.extend(await self.infrastructure_scanner.run_kube_bench_scan())
            
        return findings
        
    def _generate_scan_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate scan summary statistics"""
        summary = {
            "total_findings": len(findings),
            "severity_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "new_findings": 0,
            "fixed_findings": 0,
            "risk_score": 0.0
        }
        
        for finding in findings:
            summary["severity_breakdown"][finding.severity.value] += 1
            
        # Calculate risk score based on severity distribution
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        total_weighted_score = sum(
            summary["severity_breakdown"][sev] * weight 
            for sev, weight in weights.items()
        )
        summary["risk_score"] = min(total_weighted_score / 10.0, 10.0)
        
        return summary
        
    async def _store_scan_results(self, scan_result: ScanResult):
        """Store scan results in database"""
        # In production, store in proper database (PostgreSQL, MongoDB, etc.)
        scan_type_key = scan_result.scan_type.value
        
        if scan_type_key not in self.scan_history:
            self.scan_history[scan_type_key] = []
            
        self.scan_history[scan_type_key].append(scan_result)
        
        # Keep only last 100 scan results per type
        self.scan_history[scan_type_key] = self.scan_history[scan_type_key][-100:]
        
        # Store findings in findings database
        for finding in scan_result.findings:
            self.findings_db[finding.id] = finding
            
    async def _check_alert_thresholds(self, scan_result: ScanResult):
        """Check alert thresholds and send notifications"""
        scan_config = self.scan_configs.get(scan_result.scan_type)
        
        for severity, threshold in scan_config.alert_thresholds.items():
            severity_count = scan_result.summary["severity_breakdown"].get(severity, 0)
            
            if severity_count >= threshold:
                await self._send_alert_notification(
                    scan_result, severity, severity_count, threshold
                )
                
    async def _send_alert_notification(self, scan_result: ScanResult, 
                                     severity: str, count: int, threshold: int):
        """Send security alert notification"""
        message = (
            f"🚨 Security Alert: {scan_result.scan_type.value}\n"
            f"Severity: {severity.upper()}\n" 
            f"Found: {count} vulnerabilities (threshold: {threshold})\n"
            f"Scan ID: {scan_result.scan_id}\n"
            f"Risk Score: {scan_result.summary.get('risk_score', 0):.1f}/10"
        )
        
        # Send notifications to configured channels
        scan_config = self.scan_configs.get(scan_result.scan_type)
        
        for channel in scan_config.notification_channels:
            try:
                if channel.startswith("slack://"):
                    await self._send_slack_notification(channel, message)
                elif channel.startswith("email://"):
                    await self._send_email_notification(channel, message)
                elif channel.startswith("pagerduty://"):
                    await self._send_pagerduty_alert(channel, message, severity)
                    
            except Exception as e:
                logger.error(f"Failed to send notification to {channel}: {e}")
                
    def _update_vulnerability_metrics(self, findings: List[SecurityFinding]):
        """Update Prometheus vulnerability metrics"""
        # Reset gauges
        for severity in SeverityLevel:
            VULNERABILITIES_GAUGE.labels(severity=severity.value).set(0)
            
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            
        # Update gauges
        for severity, count in severity_counts.items():
            VULNERABILITIES_GAUGE.labels(severity=severity).set(count)

    async def get_scan_status(self) -> Dict[str, Any]:
        """Get current pipeline status"""
        status = {
            "pipeline_status": "running",
            "last_scans": {},
            "total_findings": len(self.findings_db),
            "risk_summary": {
                "critical": 0,
                "high": 0, 
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        # Get last scan for each type
        for scan_type, scan_history in self.scan_history.items():
            if scan_history:
                last_scan = scan_history[-1]
                status["last_scans"][scan_type] = {
                    "scan_id": last_scan.scan_id,
                    "status": last_scan.status.value,
                    "end_time": last_scan.end_time.isoformat() if last_scan.end_time else None,
                    "findings_count": len(last_scan.findings)
                }
                
        # Calculate risk summary from all findings
        for finding in self.findings_db.values():
            status["risk_summary"][finding.severity.value] += 1
            
        return status

# Default configuration template
DEFAULT_PIPELINE_CONFIG = {
    "scans": {
        "vulnerability_scan": {
            "enabled": True,
            "schedule": "0 2 * * *",  # Daily at 2 AM
            "targets": ["isectech.com", "api.isectech.com"],
            "tools": ["nessus", "openvas"],
            "timeout_minutes": 120,
            "alert_thresholds": {
                "critical": 1,
                "high": 5,
                "medium": 20
            },
            "notification_channels": [
                "slack://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                "email://security-team@isectech.com"
            ],
            "remediation_auto": False
        },
        "dependency_scan": {
            "enabled": True,
            "schedule": "0 6 * * *",  # Daily at 6 AM
            "targets": ["./", "./backend", "./frontend"],
            "tools": ["snyk", "safety", "npm"],
            "timeout_minutes": 60,
            "alert_thresholds": {
                "critical": 1,
                "high": 10
            },
            "notification_channels": [
                "slack://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
            ],
            "remediation_auto": True
        },
        "container_scan": {
            "enabled": True,
            "schedule": "0 4 * * *",  # Daily at 4 AM
            "targets": ["isectech/frontend:latest", "isectech/backend:latest"],
            "tools": ["trivy", "clair"],
            "timeout_minutes": 90,
            "alert_thresholds": {
                "critical": 0,
                "high": 5
            },
            "notification_channels": [
                "slack://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
            ],
            "remediation_auto": False
        },
        "code_analysis": {
            "enabled": True,
            "schedule": "0 8 * * *",  # Daily at 8 AM
            "targets": ["./"],
            "tools": ["sonarqube", "semgrep", "bandit"],
            "timeout_minutes": 90,
            "alert_thresholds": {
                "critical": 0,
                "high": 10
            },
            "notification_channels": [
                "slack://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
            ],
            "remediation_auto": False
        },
        "infrastructure_scan": {
            "enabled": True,
            "schedule": "0 10 * * 0",  # Weekly on Sunday at 10 AM
            "targets": ["10.0.0.0/16"],
            "tools": ["nmap", "kube-bench"],
            "timeout_minutes": 180,
            "alert_thresholds": {
                "critical": 0,
                "high": 3
            },
            "notification_channels": [
                "slack://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
                "pagerduty://security-infrastructure"
            ],
            "remediation_auto": False
        }
    }
}

async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="iSECTECH Continuous Security Scanning Pipeline")
    parser.add_argument("--config", required=True, help="Path to configuration file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    try:
        pipeline = ContinuousSecurityPipeline(args.config)
        await pipeline.start_continuous_pipeline()
        
    except KeyboardInterrupt:
        logger.info("Shutting down continuous security pipeline...")
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))