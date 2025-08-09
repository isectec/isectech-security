"""
CI/CD Security Integration Framework
Integrates comprehensive security validation into the CI/CD pipeline
"""

import asyncio
import json
import uuid
import hashlib
import subprocess
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
import asyncpg
import aiohttp
import yaml
from pathlib import Path
import re
import tempfile
import shutil


class PipelineStage(Enum):
    """CI/CD pipeline stages"""
    SOURCE = "source"
    BUILD = "build"
    TEST = "test"
    SECURITY_SCAN = "security_scan"
    STAGING = "staging"
    PRODUCTION = "production"


class SecurityCheckType(Enum):
    """Types of security checks in pipeline"""
    SAST = "sast"  # Static Application Security Testing
    DAST = "dast"  # Dynamic Application Security Testing
    SCA = "sca"    # Software Composition Analysis
    CONTAINER_SCAN = "container_scan"
    IaC_SCAN = "iac_scan"  # Infrastructure as Code
    SECRETS_SCAN = "secrets_scan"
    LICENSE_CHECK = "license_check"
    COMPLIANCE_CHECK = "compliance_check"


class SecurityGate(Enum):
    """Security gate decisions"""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    MANUAL_REVIEW = "manual_review"


@dataclass
class SecurityPolicy:
    """Security policy for CI/CD pipeline"""
    policy_id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    severity_thresholds: Dict[str, int]
    exceptions: List[str]
    enforcement_level: str  # block, warn, monitor


@dataclass
class ScanResult:
    """Security scan result"""
    scan_id: str
    scan_type: SecurityCheckType
    start_time: datetime
    end_time: Optional[datetime]
    status: str
    findings: List[Dict[str, Any]]
    severity_counts: Dict[str, int]
    gate_decision: SecurityGate
    details: Dict[str, Any]


class SecurityScanner:
    """Executes various security scans"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scan_tools = self._initialize_scan_tools()
        
    def _initialize_scan_tools(self) -> Dict[str, Any]:
        """Initialize security scanning tools"""
        return {
            SecurityCheckType.SAST: {
                "tool": "semgrep",
                "config": self.config.get("sast_config", {})
            },
            SecurityCheckType.DAST: {
                "tool": "zap",
                "config": self.config.get("dast_config", {})
            },
            SecurityCheckType.SCA: {
                "tool": "snyk",
                "config": self.config.get("sca_config", {})
            },
            SecurityCheckType.CONTAINER_SCAN: {
                "tool": "trivy",
                "config": self.config.get("container_config", {})
            },
            SecurityCheckType.IaC_SCAN: {
                "tool": "checkov",
                "config": self.config.get("iac_config", {})
            },
            SecurityCheckType.SECRETS_SCAN: {
                "tool": "trufflehog",
                "config": self.config.get("secrets_config", {})
            }
        }
    
    async def run_sast_scan(self, code_path: str) -> ScanResult:
        """Run Static Application Security Testing"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=SecurityCheckType.SAST,
            start_time=datetime.utcnow(),
            end_time=None,
            status="running",
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            gate_decision=SecurityGate.PASS,
            details={}
        )
        
        try:
            # Run Semgrep scan
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "--severity", "ERROR,WARNING",
                code_path
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                scan_output = json.loads(stdout.decode())
                result.findings = self._parse_semgrep_results(scan_output)
                result.severity_counts = self._count_severities(result.findings)
                result.status = "completed"
            else:
                result.status = "failed"
                result.details["error"] = stderr.decode()
                
        except Exception as e:
            result.status = "error"
            result.details["error"] = str(e)
        
        finally:
            result.end_time = datetime.utcnow()
            result.gate_decision = self._evaluate_gate_decision(result)
        
        return result
    
    async def run_sca_scan(self, project_path: str) -> ScanResult:
        """Run Software Composition Analysis"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=SecurityCheckType.SCA,
            start_time=datetime.utcnow(),
            end_time=None,
            status="running",
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            gate_decision=SecurityGate.PASS,
            details={}
        )
        
        try:
            # Simulate dependency vulnerability scan
            vulnerabilities = await self._scan_dependencies(project_path)
            
            for vuln in vulnerabilities:
                finding = {
                    "type": "vulnerable_dependency",
                    "package": vuln["package"],
                    "version": vuln["version"],
                    "vulnerability": vuln["cve"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "remediation": vuln["remediation"]
                }
                result.findings.append(finding)
            
            result.severity_counts = self._count_severities(result.findings)
            result.status = "completed"
            
        except Exception as e:
            result.status = "error"
            result.details["error"] = str(e)
        
        finally:
            result.end_time = datetime.utcnow()
            result.gate_decision = self._evaluate_gate_decision(result)
        
        return result
    
    async def run_container_scan(self, image_name: str) -> ScanResult:
        """Run container image security scan"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=SecurityCheckType.CONTAINER_SCAN,
            start_time=datetime.utcnow(),
            end_time=None,
            status="running",
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            gate_decision=SecurityGate.PASS,
            details={"image": image_name}
        )
        
        try:
            # Run Trivy scan
            cmd = [
                "trivy", "image",
                "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM",
                image_name
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                scan_output = json.loads(stdout.decode())
                result.findings = self._parse_trivy_results(scan_output)
                result.severity_counts = self._count_severities(result.findings)
                result.status = "completed"
            else:
                result.status = "failed"
                result.details["error"] = stderr.decode()
                
        except Exception as e:
            result.status = "error"
            result.details["error"] = str(e)
        
        finally:
            result.end_time = datetime.utcnow()
            result.gate_decision = self._evaluate_gate_decision(result)
        
        return result
    
    async def run_iac_scan(self, iac_path: str) -> ScanResult:
        """Run Infrastructure as Code security scan"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=SecurityCheckType.IaC_SCAN,
            start_time=datetime.utcnow(),
            end_time=None,
            status="running",
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            gate_decision=SecurityGate.PASS,
            details={}
        )
        
        try:
            # Run Checkov scan
            cmd = [
                "checkov",
                "-d", iac_path,
                "--output", "json",
                "--framework", "terraform,cloudformation,kubernetes"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if stdout:
                scan_output = json.loads(stdout.decode())
                result.findings = self._parse_checkov_results(scan_output)
                result.severity_counts = self._count_severities(result.findings)
                result.status = "completed"
            else:
                result.status = "failed"
                result.details["error"] = "No scan output"
                
        except Exception as e:
            result.status = "error"
            result.details["error"] = str(e)
        
        finally:
            result.end_time = datetime.utcnow()
            result.gate_decision = self._evaluate_gate_decision(result)
        
        return result
    
    async def run_secrets_scan(self, repo_path: str) -> ScanResult:
        """Run secrets detection scan"""
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            scan_type=SecurityCheckType.SECRETS_SCAN,
            start_time=datetime.utcnow(),
            end_time=None,
            status="running",
            findings=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
            gate_decision=SecurityGate.PASS,
            details={}
        )
        
        try:
            # Simulate secrets scan
            secrets = await self._scan_for_secrets(repo_path)
            
            for secret in secrets:
                finding = {
                    "type": "exposed_secret",
                    "file": secret["file"],
                    "line": secret["line"],
                    "secret_type": secret["type"],
                    "severity": "critical",
                    "description": f"Potential {secret['type']} exposed",
                    "remediation": "Remove secret and rotate credentials"
                }
                result.findings.append(finding)
                result.severity_counts["critical"] += 1
            
            result.status = "completed"
            
        except Exception as e:
            result.status = "error"
            result.details["error"] = str(e)
        
        finally:
            result.end_time = datetime.utcnow()
            result.gate_decision = self._evaluate_gate_decision(result)
        
        return result
    
    async def _scan_dependencies(self, project_path: str) -> List[Dict[str, Any]]:
        """Scan project dependencies for vulnerabilities"""
        # Simulate dependency scanning
        vulnerabilities = []
        
        # Check for package.json (Node.js)
        package_json = Path(project_path) / "package.json"
        if package_json.exists():
            # Simulate finding vulnerabilities
            vulnerabilities.append({
                "package": "lodash",
                "version": "4.17.11",
                "cve": "CVE-2021-23337",
                "severity": "high",
                "description": "Command injection vulnerability",
                "remediation": "Upgrade to lodash@4.17.21"
            })
        
        # Check for requirements.txt (Python)
        requirements = Path(project_path) / "requirements.txt"
        if requirements.exists():
            vulnerabilities.append({
                "package": "django",
                "version": "2.2.0",
                "cve": "CVE-2021-32052",
                "severity": "medium",
                "description": "Header injection vulnerability",
                "remediation": "Upgrade to django>=2.2.22"
            })
        
        return vulnerabilities
    
    async def _scan_for_secrets(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scan repository for exposed secrets"""
        secrets = []
        
        # Patterns for common secrets
        secret_patterns = {
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "api_key": r"api[_-]?key[_-]?=[\'\"]?[0-9a-zA-Z]{32,}[\'\"]?",
            "private_key": r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----"
        }
        
        # Simulate finding secrets
        for root, dirs, files in os.walk(repo_path):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            
            for file in files[:10]:  # Limit scan for simulation
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    for secret_type, pattern in secret_patterns.items():
                        if re.search(pattern, content):
                            secrets.append({
                                "file": file_path,
                                "line": 1,  # Simplified
                                "type": secret_type
                            })
                            break
                except:
                    pass
        
        return secrets
    
    def _parse_semgrep_results(self, output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Semgrep scan results"""
        findings = []
        
        for result in output.get("results", []):
            finding = {
                "type": "code_vulnerability",
                "file": result.get("path"),
                "line": result.get("start", {}).get("line"),
                "rule": result.get("check_id"),
                "severity": self._map_severity(result.get("extra", {}).get("severity", "medium")),
                "description": result.get("extra", {}).get("message", ""),
                "remediation": result.get("extra", {}).get("fix", "")
            }
            findings.append(finding)
        
        return findings
    
    def _parse_trivy_results(self, output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Trivy scan results"""
        findings = []
        
        for result in output.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                finding = {
                    "type": "container_vulnerability",
                    "package": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "vulnerability": vuln.get("VulnerabilityID"),
                    "severity": self._map_severity(vuln.get("Severity", "medium")),
                    "description": vuln.get("Description", ""),
                    "remediation": f"Upgrade to {vuln.get('FixedVersion', 'latest')}"
                }
                findings.append(finding)
        
        return findings
    
    def _parse_checkov_results(self, output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Checkov scan results"""
        findings = []
        
        for check in output.get("results", {}).get("failed_checks", []):
            finding = {
                "type": "iac_misconfiguration",
                "file": check.get("file_path"),
                "resource": check.get("resource"),
                "check_id": check.get("check_id"),
                "severity": self._map_severity(check.get("severity", "medium")),
                "description": check.get("check_name", ""),
                "remediation": check.get("guideline", "")
            }
            findings.append(finding)
        
        return findings
    
    def _map_severity(self, severity: str) -> str:
        """Map severity levels to standard format"""
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info",
            "ERROR": "high",
            "WARNING": "medium"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "medium")
            counts[severity] = counts.get(severity, 0) + 1
        
        return counts
    
    def _evaluate_gate_decision(self, result: ScanResult) -> SecurityGate:
        """Evaluate security gate decision based on findings"""
        if result.status == "error" or result.status == "failed":
            return SecurityGate.FAIL
        
        # Check against thresholds
        if result.severity_counts.get("critical", 0) > 0:
            return SecurityGate.FAIL
        elif result.severity_counts.get("high", 0) > 3:
            return SecurityGate.MANUAL_REVIEW
        elif result.severity_counts.get("medium", 0) > 10:
            return SecurityGate.WARN
        else:
            return SecurityGate.PASS


class CICDSecurityOrchestrator:
    """Orchestrates security checks in CI/CD pipeline"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scanner = SecurityScanner(config)
        self.policies = self._load_security_policies()
        
    def _load_security_policies(self) -> Dict[str, SecurityPolicy]:
        """Load security policies for pipeline"""
        policies = {}
        
        policies["default"] = SecurityPolicy(
            policy_id="default",
            name="Default Security Policy",
            description="Standard security policy for all pipelines",
            rules=[
                {"type": "max_critical", "value": 0},
                {"type": "max_high", "value": 5},
                {"type": "required_scans", "value": ["sast", "sca", "secrets"]},
                {"type": "min_code_coverage", "value": 80}
            ],
            severity_thresholds={
                "critical": 0,
                "high": 5,
                "medium": 20,
                "low": 50
            },
            exceptions=[],
            enforcement_level="block"
        )
        
        policies["production"] = SecurityPolicy(
            policy_id="production",
            name="Production Security Policy",
            description="Strict security policy for production deployments",
            rules=[
                {"type": "max_critical", "value": 0},
                {"type": "max_high", "value": 0},
                {"type": "max_medium", "value": 5},
                {"type": "required_scans", "value": ["sast", "dast", "sca", "container", "secrets"]},
                {"type": "min_code_coverage", "value": 90},
                {"type": "require_approval", "value": True}
            ],
            severity_thresholds={
                "critical": 0,
                "high": 0,
                "medium": 5,
                "low": 20
            },
            exceptions=[],
            enforcement_level="block"
        )
        
        return policies
    
    async def run_pipeline_security_checks(self, 
                                          pipeline_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run all security checks for pipeline"""
        pipeline_id = pipeline_config.get("pipeline_id", str(uuid.uuid4()))
        policy_id = pipeline_config.get("policy", "default")
        policy = self.policies.get(policy_id, self.policies["default"])
        
        results = {
            "pipeline_id": pipeline_id,
            "policy": policy_id,
            "start_time": datetime.utcnow().isoformat(),
            "scans": [],
            "overall_status": "running",
            "gate_decision": SecurityGate.PASS,
            "summary": {}
        }
        
        # Determine required scans
        required_scans = []
        for rule in policy.rules:
            if rule["type"] == "required_scans":
                required_scans = rule["value"]
                break
        
        # Run security scans
        for scan_type in required_scans:
            if scan_type == "sast":
                scan_result = await self.scanner.run_sast_scan(
                    pipeline_config.get("source_path", ".")
                )
            elif scan_type == "sca":
                scan_result = await self.scanner.run_sca_scan(
                    pipeline_config.get("source_path", ".")
                )
            elif scan_type == "container":
                scan_result = await self.scanner.run_container_scan(
                    pipeline_config.get("image_name", "app:latest")
                )
            elif scan_type == "iac":
                scan_result = await self.scanner.run_iac_scan(
                    pipeline_config.get("iac_path", "./infrastructure")
                )
            elif scan_type == "secrets":
                scan_result = await self.scanner.run_secrets_scan(
                    pipeline_config.get("source_path", ".")
                )
            else:
                continue
            
            results["scans"].append({
                "type": scan_type,
                "scan_id": scan_result.scan_id,
                "status": scan_result.status,
                "findings_count": len(scan_result.findings),
                "severity_counts": scan_result.severity_counts,
                "gate_decision": scan_result.gate_decision.value
            })
        
        # Evaluate overall gate decision
        results["gate_decision"] = self._evaluate_pipeline_gate(results["scans"], policy)
        results["overall_status"] = "completed"
        results["end_time"] = datetime.utcnow().isoformat()
        
        # Generate summary
        results["summary"] = self._generate_pipeline_summary(results)
        
        return results
    
    def _evaluate_pipeline_gate(self, scans: List[Dict[str, Any]], 
                               policy: SecurityPolicy) -> SecurityGate:
        """Evaluate overall pipeline security gate"""
        # Aggregate severity counts
        total_severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for scan in scans:
            for severity, count in scan["severity_counts"].items():
                total_severities[severity] += count
        
        # Check against policy thresholds
        if total_severities["critical"] > policy.severity_thresholds["critical"]:
            return SecurityGate.FAIL
        elif total_severities["high"] > policy.severity_thresholds["high"]:
            if policy.enforcement_level == "block":
                return SecurityGate.FAIL
            else:
                return SecurityGate.MANUAL_REVIEW
        elif total_severities["medium"] > policy.severity_thresholds["medium"]:
            return SecurityGate.WARN
        
        # Check individual scan decisions
        for scan in scans:
            if scan["gate_decision"] == SecurityGate.FAIL.value:
                return SecurityGate.FAIL
        
        return SecurityGate.PASS
    
    def _generate_pipeline_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate pipeline security summary"""
        total_findings = sum(scan["findings_count"] for scan in results["scans"])
        
        # Aggregate severity counts
        total_severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for scan in results["scans"]:
            for severity, count in scan["severity_counts"].items():
                total_severities[severity] = total_severities.get(severity, 0) + count
        
        passed_scans = sum(1 for scan in results["scans"] 
                          if scan["gate_decision"] == SecurityGate.PASS.value)
        
        return {
            "total_scans": len(results["scans"]),
            "passed_scans": passed_scans,
            "failed_scans": len(results["scans"]) - passed_scans,
            "total_findings": total_findings,
            "critical_findings": total_severities["critical"],
            "high_findings": total_severities["high"],
            "gate_decision": results["gate_decision"].value,
            "recommendation": self._get_recommendation(results["gate_decision"])
        }
    
    def _get_recommendation(self, gate_decision: SecurityGate) -> str:
        """Get recommendation based on gate decision"""
        if gate_decision == SecurityGate.PASS:
            return "Pipeline security checks passed. Safe to proceed."
        elif gate_decision == SecurityGate.WARN:
            return "Minor security issues detected. Review before proceeding."
        elif gate_decision == SecurityGate.MANUAL_REVIEW:
            return "Security review required before deployment."
        else:
            return "Critical security issues found. Deployment blocked."


class CICDSecurityFramework:
    """Main CI/CD security integration framework"""
    
    def __init__(self, db_config: Dict[str, Any], config: Dict[str, Any]):
        self.db_config = db_config
        self.config = config
        self.orchestrator = CICDSecurityOrchestrator(config)
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
                CREATE TABLE IF NOT EXISTS pipeline_security_scans (
                    scan_id VARCHAR(64) PRIMARY KEY,
                    pipeline_id VARCHAR(255) NOT NULL,
                    scan_type VARCHAR(50) NOT NULL,
                    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
                    end_time TIMESTAMP WITH TIME ZONE,
                    status VARCHAR(50) NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    severity_counts JSONB,
                    gate_decision VARCHAR(50),
                    scan_results JSONB,
                    created_by VARCHAR(255),
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_executions (
                    execution_id VARCHAR(64) PRIMARY KEY,
                    pipeline_id VARCHAR(255) NOT NULL,
                    pipeline_name VARCHAR(255),
                    branch VARCHAR(255),
                    commit_sha VARCHAR(64),
                    policy_id VARCHAR(50),
                    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
                    end_time TIMESTAMP WITH TIME ZONE,
                    gate_decision VARCHAR(50),
                    summary JSONB,
                    created_by VARCHAR(255),
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS security_findings (
                    finding_id SERIAL PRIMARY KEY,
                    scan_id VARCHAR(64) REFERENCES pipeline_security_scans(scan_id),
                    finding_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    description TEXT,
                    remediation TEXT,
                    false_positive BOOLEAN DEFAULT FALSE,
                    resolved BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS security_metrics (
                    metric_id SERIAL PRIMARY KEY,
                    pipeline_id VARCHAR(255) NOT NULL,
                    metric_name VARCHAR(100) NOT NULL,
                    metric_value FLOAT NOT NULL,
                    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default'
                )
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_scans_pipeline ON pipeline_security_scans(pipeline_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_scans_type ON pipeline_security_scans(scan_type)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_executions_pipeline ON pipeline_executions(pipeline_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON security_findings(scan_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON security_findings(severity)")
    
    async def execute_pipeline_security(self, pipeline_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute security checks for CI/CD pipeline"""
        execution_id = str(uuid.uuid4())
        pipeline_id = pipeline_config.get("pipeline_id", str(uuid.uuid4()))
        
        # Store pipeline execution
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO pipeline_executions
                (execution_id, pipeline_id, pipeline_name, branch, commit_sha, 
                 policy_id, start_time, created_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """, execution_id, pipeline_id, 
                pipeline_config.get("name", "unnamed"),
                pipeline_config.get("branch", "main"),
                pipeline_config.get("commit", "HEAD"),
                pipeline_config.get("policy", "default"),
                datetime.utcnow(), 'system', 'default')
        
        # Run security checks
        results = await self.orchestrator.run_pipeline_security_checks(pipeline_config)
        
        # Store scan results
        for scan in results["scans"]:
            await self._store_scan_result(scan, pipeline_id)
        
        # Update pipeline execution
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                UPDATE pipeline_executions
                SET end_time = $1, gate_decision = $2, summary = $3
                WHERE execution_id = $4
            """, datetime.utcnow(), results["gate_decision"].value,
                json.dumps(results["summary"]), execution_id)
        
        # Store metrics
        await self._store_security_metrics(pipeline_id, results)
        
        return {
            "execution_id": execution_id,
            "pipeline_id": pipeline_id,
            "gate_decision": results["gate_decision"].value,
            "summary": results["summary"],
            "duration": self._calculate_duration(
                results.get("start_time"), results.get("end_time")
            )
        }
    
    async def _store_scan_result(self, scan: Dict[str, Any], pipeline_id: str):
        """Store individual scan result"""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO pipeline_security_scans
                (scan_id, pipeline_id, scan_type, start_time, end_time,
                 status, findings_count, severity_counts, gate_decision,
                 scan_results, created_by, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """, scan["scan_id"], pipeline_id, scan["type"],
                datetime.utcnow(), datetime.utcnow(),
                scan["status"], scan["findings_count"],
                json.dumps(scan["severity_counts"]),
                scan["gate_decision"], json.dumps(scan),
                'system', 'default')
    
    async def _store_security_metrics(self, pipeline_id: str, results: Dict[str, Any]):
        """Store security metrics for pipeline"""
        metrics = [
            ("total_findings", results["summary"]["total_findings"]),
            ("critical_findings", results["summary"]["critical_findings"]),
            ("high_findings", results["summary"]["high_findings"]),
            ("scan_pass_rate", results["summary"]["passed_scans"] / results["summary"]["total_scans"] * 100)
        ]
        
        async with self.db_pool.acquire() as conn:
            for metric_name, metric_value in metrics:
                await conn.execute("""
                    INSERT INTO security_metrics
                    (pipeline_id, metric_name, metric_value, tenant_id)
                    VALUES ($1, $2, $3, $4)
                """, pipeline_id, metric_name, metric_value, 'default')
    
    def _calculate_duration(self, start_time: str, end_time: str) -> float:
        """Calculate duration in seconds"""
        if not start_time or not end_time:
            return 0
        
        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)
        return (end - start).total_seconds()
    
    async def get_pipeline_security_trends(self, pipeline_id: str, days: int = 30) -> Dict[str, Any]:
        """Get security trends for a pipeline"""
        async with self.db_pool.acquire() as conn:
            # Get recent executions
            executions = await conn.fetch("""
                SELECT * FROM pipeline_executions
                WHERE pipeline_id = $1
                AND start_time > NOW() - INTERVAL '%s days'
                AND tenant_id = 'default'
                ORDER BY start_time DESC
            """, pipeline_id, days)
            
            # Get finding trends
            findings = await conn.fetch("""
                SELECT 
                    DATE(ps.start_time) as scan_date,
                    SUM((ps.severity_counts->>'critical')::int) as critical,
                    SUM((ps.severity_counts->>'high')::int) as high,
                    SUM((ps.severity_counts->>'medium')::int) as medium,
                    SUM((ps.severity_counts->>'low')::int) as low
                FROM pipeline_security_scans ps
                WHERE ps.pipeline_id = $1
                AND ps.start_time > NOW() - INTERVAL '%s days'
                AND ps.tenant_id = 'default'
                GROUP BY DATE(ps.start_time)
                ORDER BY scan_date
            """, pipeline_id, days)
            
            # Get metrics
            metrics = await conn.fetch("""
                SELECT metric_name, AVG(metric_value) as avg_value
                FROM security_metrics
                WHERE pipeline_id = $1
                AND measured_at > NOW() - INTERVAL '%s days'
                AND tenant_id = 'default'
                GROUP BY metric_name
            """, pipeline_id, days)
        
        # Calculate pass rate
        pass_rate = sum(1 for e in executions if e['gate_decision'] == 'pass') / len(executions) * 100 if executions else 0
        
        return {
            "pipeline_id": pipeline_id,
            "period_days": days,
            "total_executions": len(executions),
            "pass_rate": pass_rate,
            "finding_trends": [dict(f) for f in findings],
            "average_metrics": {m['metric_name']: m['avg_value'] for m in metrics},
            "recent_executions": [dict(e) for e in executions[:10]]
        }
    
    async def generate_security_report(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate comprehensive security report for CI/CD pipelines"""
        async with self.db_pool.acquire() as conn:
            # Get execution statistics
            exec_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_executions,
                    COUNT(CASE WHEN gate_decision = 'pass' THEN 1 END) as passed,
                    COUNT(CASE WHEN gate_decision = 'fail' THEN 1 END) as failed,
                    COUNT(DISTINCT pipeline_id) as unique_pipelines
                FROM pipeline_executions
                WHERE start_time BETWEEN $1 AND $2
                AND tenant_id = 'default'
            """, start_date, end_date)
            
            # Get finding statistics
            finding_stats = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_findings,
                    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
                    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
                    COUNT(CASE WHEN resolved = true THEN 1 END) as resolved
                FROM security_findings sf
                JOIN pipeline_security_scans ps ON sf.scan_id = ps.scan_id
                WHERE ps.start_time BETWEEN $1 AND $2
                AND sf.tenant_id = 'default'
            """, start_date, end_date)
            
            # Get top vulnerable pipelines
            vulnerable_pipelines = await conn.fetch("""
                SELECT 
                    ps.pipeline_id,
                    COUNT(sf.finding_id) as finding_count,
                    SUM(CASE WHEN sf.severity = 'critical' THEN 1 ELSE 0 END) as critical_count
                FROM pipeline_security_scans ps
                JOIN security_findings sf ON ps.scan_id = sf.scan_id
                WHERE ps.start_time BETWEEN $1 AND $2
                AND ps.tenant_id = 'default'
                GROUP BY ps.pipeline_id
                ORDER BY critical_count DESC, finding_count DESC
                LIMIT 10
            """, start_date, end_date)
        
        return {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "execution_statistics": dict(exec_stats) if exec_stats else {},
            "finding_statistics": dict(finding_stats) if finding_stats else {},
            "security_score": self._calculate_security_score(exec_stats, finding_stats),
            "top_vulnerable_pipelines": [dict(p) for p in vulnerable_pipelines],
            "recommendations": self._generate_report_recommendations(exec_stats, finding_stats)
        }
    
    def _calculate_security_score(self, exec_stats, finding_stats) -> float:
        """Calculate overall security score"""
        if not exec_stats or exec_stats['total_executions'] == 0:
            return 0
        
        pass_rate = (exec_stats['passed'] / exec_stats['total_executions']) * 100
        
        # Penalize for critical findings
        if finding_stats and finding_stats['total_findings'] > 0:
            critical_penalty = (finding_stats['critical'] / finding_stats['total_findings']) * 20
            pass_rate -= critical_penalty
        
        return max(0, min(100, pass_rate))
    
    def _generate_report_recommendations(self, exec_stats, finding_stats) -> List[str]:
        """Generate recommendations based on statistics"""
        recommendations = []
        
        if exec_stats and exec_stats['failed'] > exec_stats['passed']:
            recommendations.append("High failure rate detected. Review security policies and provide developer training.")
        
        if finding_stats and finding_stats['critical'] > 0:
            recommendations.append(f"Critical vulnerabilities found: {finding_stats['critical']}. Immediate remediation required.")
        
        if finding_stats and finding_stats['resolved'] < finding_stats['total_findings'] * 0.5:
            recommendations.append("Low resolution rate for security findings. Implement automated remediation workflows.")
        
        if not recommendations:
            recommendations.append("Security posture is good. Continue monitoring and improving.")
        
        return recommendations
    
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
        'notification_webhook': 'https://security.isectech.com/webhook',
        'sast_config': {'enabled': True},
        'sca_config': {'enabled': True},
        'container_config': {'enabled': True}
    }
    
    # Initialize framework
    cicd_security = CICDSecurityFramework(db_config, config)
    await cicd_security.initialize()
    
    # Execute pipeline security checks
    pipeline_config = {
        "pipeline_id": "pipeline-001",
        "name": "main-application",
        "branch": "main",
        "commit": "abc123",
        "source_path": "/code/app",
        "image_name": "app:latest",
        "policy": "production"
    }
    
    result = await cicd_security.execute_pipeline_security(pipeline_config)
    print(f"Pipeline Security Check: {result['gate_decision']}")
    print(f"Summary: {result['summary']}")
    
    # Get pipeline trends
    trends = await cicd_security.get_pipeline_security_trends("pipeline-001", 30)
    print(f"Pipeline Pass Rate: {trends['pass_rate']:.1f}%")
    
    # Generate security report
    report = await cicd_security.generate_security_report(
        datetime.utcnow() - timedelta(days=30),
        datetime.utcnow()
    )
    print(f"Security Score: {report['security_score']:.1f}")
    print(f"Recommendations: {report['recommendations']}")
    
    await cicd_security.close()


if __name__ == "__main__":
    asyncio.run(main())