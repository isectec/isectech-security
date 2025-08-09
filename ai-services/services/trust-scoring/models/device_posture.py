"""
Device Posture Assessment for Trust Scoring

This module implements comprehensive device security posture assessment
for the trust scoring system, evaluating device compliance, security
controls, and risk indicators for continuous verification.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class DeviceType(str, Enum):
    """Device type classifications."""
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    MOBILE = "mobile"
    TABLET = "tablet"
    SERVER = "server"
    IOT = "iot"
    UNKNOWN = "unknown"


class OperatingSystem(str, Enum):
    """Operating system classifications."""
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks for device assessment."""
    CIS = "cis"
    NIST = "nist"
    SOC2 = "soc2"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    CUSTOM = "custom"


class SecurityControlStatus(str, Enum):
    """Status of security controls on device."""
    ENABLED = "enabled"
    DISABLED = "disabled"
    NOT_INSTALLED = "not_installed"
    OUTDATED = "outdated"
    MISCONFIGURED = "misconfigured"
    UNKNOWN = "unknown"


@dataclass
class SecurityControl:
    """Individual security control on a device."""
    control_id: str
    name: str
    status: SecurityControlStatus
    version: Optional[str] = None
    last_updated: Optional[datetime] = None
    configuration: Dict[str, Any] = field(default_factory=dict)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 = no risk, 1.0 = high risk
    remediation_required: bool = False
    remediation_instructions: Optional[str] = None


@dataclass
class DeviceHardwareInfo:
    """Device hardware information."""
    cpu_architecture: Optional[str] = None
    memory_gb: Optional[float] = None
    storage_gb: Optional[float] = None
    has_tpm: bool = False
    tpm_version: Optional[str] = None
    has_secure_enclave: bool = False
    has_biometric_auth: bool = False
    encryption_capable: bool = False
    device_model: Optional[str] = None
    manufacturer: Optional[str] = None


@dataclass
class NetworkConfiguration:
    """Device network configuration."""
    wifi_security_protocols: List[str] = field(default_factory=list)
    vpn_configured: bool = False
    firewall_enabled: bool = False
    bluetooth_enabled: bool = False
    network_interfaces: List[str] = field(default_factory=list)
    proxy_configured: bool = False
    dns_servers: List[str] = field(default_factory=list)


@dataclass
class DevicePosture:
    """Complete device security posture assessment."""
    device_id: str
    tenant_id: str
    user_id: Optional[str] = None
    assessment_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Device identification
    device_type: DeviceType = DeviceType.UNKNOWN
    operating_system: OperatingSystem = OperatingSystem.UNKNOWN
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    device_name: Optional[str] = None
    
    # Hardware information
    hardware_info: DeviceHardwareInfo = field(default_factory=DeviceHardwareInfo)
    
    # Network configuration
    network_config: NetworkConfiguration = field(default_factory=NetworkConfiguration)
    
    # Security controls
    security_controls: List[SecurityControl] = field(default_factory=list)
    
    # Patch management
    last_patch_date: Optional[datetime] = None
    patches_pending: int = 0
    critical_patches_pending: int = 0
    automatic_updates_enabled: bool = False
    
    # Application security
    applications_installed: List[str] = field(default_factory=list)
    suspicious_applications: List[str] = field(default_factory=list)
    unsigned_applications: List[str] = field(default_factory=list)
    
    # Device management
    is_domain_joined: bool = False
    is_managed_device: bool = False
    mdm_enrolled: bool = False
    mdm_compliant: bool = False
    
    # Security incidents
    malware_detected: bool = False
    malware_types: List[str] = field(default_factory=list)
    security_incidents_count: int = 0
    last_incident_date: Optional[datetime] = None
    
    # Compliance status
    compliance_scores: Dict[ComplianceFramework, float] = field(default_factory=dict)
    compliance_violations: List[str] = field(default_factory=list)
    
    # Risk assessment
    overall_risk_score: float = 0.5  # 0.0 = low risk, 1.0 = high risk
    risk_factors: List[str] = field(default_factory=list)
    trust_score: float = 0.5  # 0.0 = untrusted, 1.0 = fully trusted
    
    def calculate_posture_score(self) -> float:
        """Calculate overall device posture score."""
        scores = []
        
        # OS and patch management (25% weight)
        patch_score = self._calculate_patch_score()
        scores.append(("patch_management", patch_score, 0.25))
        
        # Security controls (30% weight)
        security_score = self._calculate_security_controls_score()
        scores.append(("security_controls", security_score, 0.30))
        
        # Hardware security (15% weight)
        hardware_score = self._calculate_hardware_score()
        scores.append(("hardware_security", hardware_score, 0.15))
        
        # Device management (20% weight)
        management_score = self._calculate_management_score()
        scores.append(("device_management", management_score, 0.20))
        
        # Incident history (10% weight)
        incident_score = self._calculate_incident_score()
        scores.append(("incident_history", incident_score, 0.10))
        
        # Calculate weighted average
        total_score = sum(score * weight for _, score, weight in scores)
        
        logger.debug(f"Device posture calculation for {self.device_id}: {scores}")
        return max(0.0, min(1.0, total_score))
    
    def _calculate_patch_score(self) -> float:
        """Calculate patch management score."""
        if self.last_patch_date is None:
            return 0.0
        
        days_since_patch = (datetime.utcnow() - self.last_patch_date).days
        
        # Scoring based on patch recency
        if days_since_patch <= 7:
            patch_recency_score = 1.0
        elif days_since_patch <= 30:
            patch_recency_score = 0.8
        elif days_since_patch <= 90:
            patch_recency_score = 0.6
        elif days_since_patch <= 180:
            patch_recency_score = 0.4
        else:
            patch_recency_score = 0.2
        
        # Penalty for pending critical patches
        critical_penalty = min(0.5, self.critical_patches_pending * 0.1)
        
        # Bonus for automatic updates
        auto_update_bonus = 0.1 if self.automatic_updates_enabled else 0.0
        
        return max(0.0, patch_recency_score - critical_penalty + auto_update_bonus)
    
    def _calculate_security_controls_score(self) -> float:
        """Calculate security controls score."""
        if not self.security_controls:
            return 0.0
        
        control_scores = []
        for control in self.security_controls:
            if control.status == SecurityControlStatus.ENABLED:
                control_scores.append(1.0 - control.risk_score)
            elif control.status == SecurityControlStatus.DISABLED:
                control_scores.append(0.0)
            elif control.status == SecurityControlStatus.OUTDATED:
                control_scores.append(0.3)
            elif control.status == SecurityControlStatus.MISCONFIGURED:
                control_scores.append(0.2)
            else:  # NOT_INSTALLED or UNKNOWN
                control_scores.append(0.0)
        
        return sum(control_scores) / len(control_scores) if control_scores else 0.0
    
    def _calculate_hardware_score(self) -> float:
        """Calculate hardware security score."""
        score = 0.0
        
        # TPM presence and version
        if self.hardware_info.has_tpm:
            score += 0.3
            if self.hardware_info.tpm_version == "2.0":
                score += 0.1
        
        # Secure enclave/element
        if self.hardware_info.has_secure_enclave:
            score += 0.2
        
        # Biometric authentication
        if self.hardware_info.has_biometric_auth:
            score += 0.2
        
        # Encryption capability
        if self.hardware_info.encryption_capable:
            score += 0.2
        
        return min(1.0, score)
    
    def _calculate_management_score(self) -> float:
        """Calculate device management score."""
        score = 0.0
        
        if self.is_managed_device:
            score += 0.4
        
        if self.mdm_enrolled:
            score += 0.3
            if self.mdm_compliant:
                score += 0.2
        
        if self.is_domain_joined:
            score += 0.1
        
        return min(1.0, score)
    
    def _calculate_incident_score(self) -> float:
        """Calculate incident history score."""
        if self.security_incidents_count == 0 and not self.malware_detected:
            return 1.0
        
        # Base score reduction for incidents
        incident_penalty = min(0.8, self.security_incidents_count * 0.1)
        
        # Additional penalty for malware
        malware_penalty = 0.3 if self.malware_detected else 0.0
        
        # Time decay for old incidents
        time_decay = 0.0
        if self.last_incident_date:
            days_since_incident = (datetime.utcnow() - self.last_incident_date).days
            if days_since_incident > 90:
                time_decay = min(0.2, days_since_incident / 365 * 0.2)
        
        return max(0.0, 1.0 - incident_penalty - malware_penalty + time_decay)
    
    def get_critical_issues(self) -> List[str]:
        """Get list of critical security issues requiring immediate attention."""
        issues = []
        
        # Critical patches
        if self.critical_patches_pending > 0:
            issues.append(f"{self.critical_patches_pending} critical patches pending")
        
        # Outdated OS
        if self.last_patch_date and (datetime.utcnow() - self.last_patch_date).days > 90:
            issues.append("Operating system severely outdated (>90 days)")
        
        # Disabled critical controls
        for control in self.security_controls:
            if (control.name.lower() in ["antivirus", "firewall", "encryption"] and
                control.status == SecurityControlStatus.DISABLED):
                issues.append(f"{control.name} is disabled")
        
        # Active malware
        if self.malware_detected:
            issues.append(f"Active malware detected: {', '.join(self.malware_types)}")
        
        # Unmanaged device in high-risk environment
        if not self.is_managed_device and not self.mdm_enrolled:
            issues.append("Device is not under management control")
        
        # Unsigned applications
        if self.unsigned_applications:
            issues.append(f"{len(self.unsigned_applications)} unsigned applications installed")
        
        return issues
    
    def get_remediation_plan(self) -> List[str]:
        """Get prioritized remediation plan for identified issues."""
        plan = []
        
        # High priority remediations
        if self.malware_detected:
            plan.append("1. URGENT: Run full system malware scan and removal")
        
        if self.critical_patches_pending > 0:
            plan.append("2. URGENT: Install all critical security patches")
        
        # Medium priority remediations
        disabled_critical_controls = [
            c for c in self.security_controls
            if c.name.lower() in ["antivirus", "firewall", "encryption"] and
            c.status == SecurityControlStatus.DISABLED
        ]
        
        for control in disabled_critical_controls:
            plan.append(f"3. Enable and configure {control.name}")
        
        # Device management
        if not self.is_managed_device and not self.mdm_enrolled:
            plan.append("4. Enroll device in mobile device management (MDM)")
        
        # Application security
        if self.unsigned_applications:
            plan.append("5. Review and remove unauthorized unsigned applications")
        
        # Hardware security
        if not self.hardware_info.has_tpm and self.device_type in [DeviceType.DESKTOP, DeviceType.LAPTOP]:
            plan.append("6. Consider hardware upgrade for TPM support")
        
        return plan
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device posture to dictionary for serialization."""
        return {
            "device_id": self.device_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "assessment_timestamp": self.assessment_timestamp.isoformat(),
            "device_type": self.device_type.value,
            "operating_system": self.operating_system.value,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "device_name": self.device_name,
            "hardware_info": {
                "cpu_architecture": self.hardware_info.cpu_architecture,
                "memory_gb": self.hardware_info.memory_gb,
                "storage_gb": self.hardware_info.storage_gb,
                "has_tpm": self.hardware_info.has_tpm,
                "tpm_version": self.hardware_info.tpm_version,
                "has_secure_enclave": self.hardware_info.has_secure_enclave,
                "has_biometric_auth": self.hardware_info.has_biometric_auth,
                "encryption_capable": self.hardware_info.encryption_capable,
                "device_model": self.hardware_info.device_model,
                "manufacturer": self.hardware_info.manufacturer
            },
            "network_config": {
                "wifi_security_protocols": self.network_config.wifi_security_protocols,
                "vpn_configured": self.network_config.vpn_configured,
                "firewall_enabled": self.network_config.firewall_enabled,
                "bluetooth_enabled": self.network_config.bluetooth_enabled,
                "network_interfaces": self.network_config.network_interfaces,
                "proxy_configured": self.network_config.proxy_configured,
                "dns_servers": self.network_config.dns_servers
            },
            "security_controls": [
                {
                    "control_id": c.control_id,
                    "name": c.name,
                    "status": c.status.value,
                    "version": c.version,
                    "last_updated": c.last_updated.isoformat() if c.last_updated else None,
                    "configuration": c.configuration,
                    "compliance_frameworks": [f.value for f in c.compliance_frameworks],
                    "risk_score": c.risk_score,
                    "remediation_required": c.remediation_required,
                    "remediation_instructions": c.remediation_instructions
                } for c in self.security_controls
            ],
            "last_patch_date": self.last_patch_date.isoformat() if self.last_patch_date else None,
            "patches_pending": self.patches_pending,
            "critical_patches_pending": self.critical_patches_pending,
            "automatic_updates_enabled": self.automatic_updates_enabled,
            "applications_installed": self.applications_installed,
            "suspicious_applications": self.suspicious_applications,
            "unsigned_applications": self.unsigned_applications,
            "is_domain_joined": self.is_domain_joined,
            "is_managed_device": self.is_managed_device,
            "mdm_enrolled": self.mdm_enrolled,
            "mdm_compliant": self.mdm_compliant,
            "malware_detected": self.malware_detected,
            "malware_types": self.malware_types,
            "security_incidents_count": self.security_incidents_count,
            "last_incident_date": self.last_incident_date.isoformat() if self.last_incident_date else None,
            "compliance_scores": {k.value: v for k, v in self.compliance_scores.items()},
            "compliance_violations": self.compliance_violations,
            "overall_risk_score": self.overall_risk_score,
            "risk_factors": self.risk_factors,
            "trust_score": self.trust_score,
            "posture_score": self.calculate_posture_score(),
            "critical_issues": self.get_critical_issues(),
            "remediation_plan": self.get_remediation_plan()
        }


class DevicePostureCollector:
    """Collects device posture information from various sources."""
    
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.device_cache: Dict[str, DevicePosture] = {}
        self.cache_ttl = timedelta(hours=1)  # Cache device posture for 1 hour
        
        # Default security controls to check
        self.default_security_controls = [
            ("antivirus", "Antivirus Protection"),
            ("firewall", "Host Firewall"),
            ("encryption", "Disk Encryption"),
            ("auto_updates", "Automatic Updates"),
            ("screen_lock", "Screen Lock"),
            ("password_policy", "Password Policy"),
            ("remote_wipe", "Remote Wipe Capability"),
            ("app_whitelisting", "Application Whitelisting")
        ]
    
    async def collect_device_posture(self, 
                                   device_id: str, 
                                   user_id: Optional[str] = None,
                                   force_refresh: bool = False) -> DevicePosture:
        """Collect comprehensive device posture information."""
        
        # Check cache first
        if not force_refresh and device_id in self.device_cache:
            cached_posture = self.device_cache[device_id]
            if datetime.utcnow() - cached_posture.assessment_timestamp < self.cache_ttl:
                logger.debug(f"Returning cached device posture for {device_id}")
                return cached_posture
        
        logger.info(f"Collecting device posture for device {device_id}")
        
        try:
            # Initialize device posture
            posture = DevicePosture(
                device_id=device_id,
                tenant_id=self.tenant_id,
                user_id=user_id
            )
            
            # Collect device information from various sources
            await self._collect_basic_device_info(posture)
            await self._collect_hardware_info(posture)
            await self._collect_network_config(posture)
            await self._collect_security_controls(posture)
            await self._collect_patch_information(posture)
            await self._collect_application_info(posture)
            await self._collect_management_info(posture)
            await self._collect_incident_history(posture)
            await self._calculate_compliance_scores(posture)
            
            # Calculate final scores
            posture.overall_risk_score = self._calculate_risk_score(posture)
            posture.trust_score = 1.0 - posture.overall_risk_score
            
            # Update cache
            self.device_cache[device_id] = posture
            
            logger.info(f"Device posture collected for {device_id}: trust_score={posture.trust_score:.3f}")
            return posture
            
        except Exception as e:
            logger.error(f"Error collecting device posture for {device_id}: {e}")
            # Return minimal posture with low trust score
            return DevicePosture(
                device_id=device_id,
                tenant_id=self.tenant_id,
                user_id=user_id,
                trust_score=0.2,
                overall_risk_score=0.8,
                risk_factors=["posture_collection_failed"]
            )
    
    async def _collect_basic_device_info(self, posture: DevicePosture):
        """Collect basic device identification information."""
        # In a real implementation, this would query device management APIs
        # For now, we'll simulate the data collection
        
        # This would typically integrate with:
        # - Microsoft Intune
        # - VMware Workspace ONE
        # - Google Device Management API
        # - JAMF for macOS
        # - Custom device agents
        
        logger.debug(f"Collecting basic device info for {posture.device_id}")
        
        # Simulated device information - replace with real API calls
        device_info = await self._query_device_management_api(posture.device_id)
        
        if device_info:
            posture.device_type = DeviceType(device_info.get("device_type", "unknown"))
            posture.operating_system = OperatingSystem(device_info.get("os", "unknown"))
            posture.os_version = device_info.get("os_version")
            posture.os_build = device_info.get("os_build")
            posture.device_name = device_info.get("device_name")
    
    async def _collect_hardware_info(self, posture: DevicePosture):
        """Collect device hardware security information."""
        logger.debug(f"Collecting hardware info for {posture.device_id}")
        
        # Query hardware capabilities from device management systems
        hardware_info = await self._query_hardware_capabilities(posture.device_id)
        
        if hardware_info:
            posture.hardware_info = DeviceHardwareInfo(
                cpu_architecture=hardware_info.get("cpu_architecture"),
                memory_gb=hardware_info.get("memory_gb"),
                storage_gb=hardware_info.get("storage_gb"),
                has_tpm=hardware_info.get("has_tpm", False),
                tpm_version=hardware_info.get("tpm_version"),
                has_secure_enclave=hardware_info.get("has_secure_enclave", False),
                has_biometric_auth=hardware_info.get("has_biometric_auth", False),
                encryption_capable=hardware_info.get("encryption_capable", False),
                device_model=hardware_info.get("device_model"),
                manufacturer=hardware_info.get("manufacturer")
            )
    
    async def _collect_network_config(self, posture: DevicePosture):
        """Collect device network configuration."""
        logger.debug(f"Collecting network config for {posture.device_id}")
        
        network_info = await self._query_network_configuration(posture.device_id)
        
        if network_info:
            posture.network_config = NetworkConfiguration(
                wifi_security_protocols=network_info.get("wifi_protocols", []),
                vpn_configured=network_info.get("vpn_configured", False),
                firewall_enabled=network_info.get("firewall_enabled", False),
                bluetooth_enabled=network_info.get("bluetooth_enabled", False),
                network_interfaces=network_info.get("network_interfaces", []),
                proxy_configured=network_info.get("proxy_configured", False),
                dns_servers=network_info.get("dns_servers", [])
            )
    
    async def _collect_security_controls(self, posture: DevicePosture):
        """Collect security control status."""
        logger.debug(f"Collecting security controls for {posture.device_id}")
        
        for control_id, control_name in self.default_security_controls:
            try:
                control_info = await self._query_security_control(posture.device_id, control_id)
                
                if control_info:
                    control = SecurityControl(
                        control_id=control_id,
                        name=control_name,
                        status=SecurityControlStatus(control_info.get("status", "unknown")),
                        version=control_info.get("version"),
                        last_updated=self._parse_datetime(control_info.get("last_updated")),
                        configuration=control_info.get("configuration", {}),
                        compliance_frameworks=[
                            ComplianceFramework(f) for f in control_info.get("compliance_frameworks", [])
                        ],
                        risk_score=control_info.get("risk_score", 0.5),
                        remediation_required=control_info.get("remediation_required", False),
                        remediation_instructions=control_info.get("remediation_instructions")
                    )
                    posture.security_controls.append(control)
                
            except Exception as e:
                logger.warning(f"Failed to collect security control {control_id}: {e}")
                # Add unknown control
                posture.security_controls.append(SecurityControl(
                    control_id=control_id,
                    name=control_name,
                    status=SecurityControlStatus.UNKNOWN,
                    risk_score=0.7  # Higher risk for unknown controls
                ))
    
    async def _collect_patch_information(self, posture: DevicePosture):
        """Collect patch and update information."""
        logger.debug(f"Collecting patch info for {posture.device_id}")
        
        patch_info = await self._query_patch_status(posture.device_id)
        
        if patch_info:
            posture.last_patch_date = self._parse_datetime(patch_info.get("last_patch_date"))
            posture.patches_pending = patch_info.get("patches_pending", 0)
            posture.critical_patches_pending = patch_info.get("critical_patches_pending", 0)
            posture.automatic_updates_enabled = patch_info.get("auto_updates_enabled", False)
    
    async def _collect_application_info(self, posture: DevicePosture):
        """Collect installed application information."""
        logger.debug(f"Collecting application info for {posture.device_id}")
        
        app_info = await self._query_application_inventory(posture.device_id)
        
        if app_info:
            posture.applications_installed = app_info.get("installed_apps", [])
            posture.suspicious_applications = app_info.get("suspicious_apps", [])
            posture.unsigned_applications = app_info.get("unsigned_apps", [])
    
    async def _collect_management_info(self, posture: DevicePosture):
        """Collect device management information."""
        logger.debug(f"Collecting management info for {posture.device_id}")
        
        mgmt_info = await self._query_device_management_status(posture.device_id)
        
        if mgmt_info:
            posture.is_domain_joined = mgmt_info.get("domain_joined", False)
            posture.is_managed_device = mgmt_info.get("managed_device", False)
            posture.mdm_enrolled = mgmt_info.get("mdm_enrolled", False)
            posture.mdm_compliant = mgmt_info.get("mdm_compliant", False)
    
    async def _collect_incident_history(self, posture: DevicePosture):
        """Collect security incident history."""
        logger.debug(f"Collecting incident history for {posture.device_id}")
        
        incident_info = await self._query_security_incidents(posture.device_id)
        
        if incident_info:
            posture.malware_detected = incident_info.get("malware_detected", False)
            posture.malware_types = incident_info.get("malware_types", [])
            posture.security_incidents_count = incident_info.get("incident_count", 0)
            posture.last_incident_date = self._parse_datetime(incident_info.get("last_incident_date"))
    
    async def _calculate_compliance_scores(self, posture: DevicePosture):
        """Calculate compliance scores for various frameworks."""
        logger.debug(f"Calculating compliance scores for {posture.device_id}")
        
        # Calculate compliance scores based on security controls
        for framework in ComplianceFramework:
            if framework == ComplianceFramework.CUSTOM:
                continue
                
            score = await self._calculate_framework_compliance(posture, framework)
            posture.compliance_scores[framework] = score
    
    async def _calculate_framework_compliance(self, 
                                           posture: DevicePosture, 
                                           framework: ComplianceFramework) -> float:
        """Calculate compliance score for a specific framework."""
        applicable_controls = [
            c for c in posture.security_controls 
            if framework in c.compliance_frameworks
        ]
        
        if not applicable_controls:
            return 0.5  # Unknown compliance
        
        compliant_controls = [
            c for c in applicable_controls 
            if c.status == SecurityControlStatus.ENABLED and not c.remediation_required
        ]
        
        return len(compliant_controls) / len(applicable_controls)
    
    def _calculate_risk_score(self, posture: DevicePosture) -> float:
        """Calculate overall device risk score."""
        risk_factors = []
        
        # Critical patches pending
        if posture.critical_patches_pending > 0:
            risk_factors.append(min(0.4, posture.critical_patches_pending * 0.1))
        
        # Malware detected
        if posture.malware_detected:
            risk_factors.append(0.5)
        
        # Unmanaged device
        if not posture.is_managed_device and not posture.mdm_enrolled:
            risk_factors.append(0.3)
        
        # Disabled critical controls
        critical_controls = ["antivirus", "firewall", "encryption"]
        for control in posture.security_controls:
            if (control.name.lower() in critical_controls and
                control.status == SecurityControlStatus.DISABLED):
                risk_factors.append(0.2)
        
        # Outdated OS
        if posture.last_patch_date and (datetime.utcnow() - posture.last_patch_date).days > 90:
            risk_factors.append(0.3)
        
        posture.risk_factors = [f"risk_factor_{i}" for i in range(len(risk_factors))]
        
        # Calculate combined risk (not simply additive to avoid over-penalization)
        if not risk_factors:
            return 0.1  # Base risk
        
        combined_risk = min(0.9, sum(risk_factors) / 2)  # Divide by 2 to moderate the impact
        return combined_risk
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime string safely."""
        if not dt_str:
            return None
        
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            logger.warning(f"Failed to parse datetime: {dt_str}")
            return None
    
    # API integration methods - can be overridden by subclasses for real connectors
    async def _query_device_management_api(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query device management API for basic device info."""
        # Default implementation provides mock data
        # Override in subclasses for real MDM integration
        return {
            "device_type": "laptop",
            "os": "windows",
            "os_version": "11.0.22621",
            "os_build": "22621",
            "device_name": f"DEV-{device_id[:8]}"
        }
    
    async def _query_hardware_capabilities(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query hardware capabilities from device management systems."""
        # Default implementation provides mock data
        return {
            "cpu_architecture": "x64",
            "memory_gb": 16.0,
            "storage_gb": 512.0,
            "has_tpm": True,
            "tpm_version": "2.0",
            "has_secure_enclave": False,
            "has_biometric_auth": True,
            "encryption_capable": True,
            "device_model": "ThinkPad T14",
            "manufacturer": "Lenovo"
        }
    
    async def _query_network_configuration(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query network configuration."""
        # Default implementation provides mock data
        return {
            "wifi_protocols": ["WPA2", "WPA3"],
            "vpn_configured": True,
            "firewall_enabled": True,
            "bluetooth_enabled": True,
            "network_interfaces": ["WiFi", "Ethernet"],
            "proxy_configured": False,
            "dns_servers": ["8.8.8.8", "1.1.1.1"]
        }
    
    async def _query_security_control(self, device_id: str, control_id: str) -> Optional[Dict[str, Any]]:
        """Query specific security control status."""
        # Default implementation provides mock data
        control_responses = {
            "antivirus": {
                "status": "enabled",
                "version": "1.2.3",
                "last_updated": "2024-01-15T10:00:00Z",
                "risk_score": 0.1,
                "compliance_frameworks": ["cis", "nist"]
            },
            "firewall": {
                "status": "enabled",
                "version": "built-in",
                "last_updated": "2024-01-10T15:30:00Z",
                "risk_score": 0.0,
                "compliance_frameworks": ["cis", "nist", "soc2"]
            },
            "encryption": {
                "status": "enabled",
                "version": "BitLocker",
                "last_updated": "2024-01-05T09:00:00Z",
                "risk_score": 0.0,
                "compliance_frameworks": ["cis", "nist", "soc2", "hipaa"]
            },
            "auto_updates": {
                "status": "enabled",
                "version": "built-in",
                "last_updated": "2024-01-10T12:00:00Z",
                "risk_score": 0.1,
                "compliance_frameworks": ["cis", "nist"]
            },
            "screen_lock": {
                "status": "enabled",
                "version": "built-in",
                "last_updated": "2024-01-01T00:00:00Z",
                "risk_score": 0.1,
                "compliance_frameworks": ["cis", "soc2"]
            },
            "password_policy": {
                "status": "enabled",
                "version": "Group Policy",
                "last_updated": "2024-01-01T00:00:00Z",
                "risk_score": 0.2,
                "compliance_frameworks": ["cis", "nist", "soc2"]
            },
            "remote_wipe": {
                "status": "enabled",
                "version": "MDM",
                "last_updated": "2024-01-01T00:00:00Z",
                "risk_score": 0.0,
                "compliance_frameworks": ["soc2"]
            },
            "app_whitelisting": {
                "status": "disabled",
                "version": "N/A",
                "last_updated": None,
                "risk_score": 0.4,
                "compliance_frameworks": ["cis"],
                "remediation_required": True,
                "remediation_instructions": "Enable application whitelisting for enhanced security"
            }
        }
        
        return control_responses.get(control_id, {"status": "unknown", "risk_score": 0.5})
    
    async def _query_patch_status(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query patch and update status."""
        # Default implementation provides mock data
        return {
            "last_patch_date": "2024-01-10T12:00:00Z",
            "patches_pending": 3,
            "critical_patches_pending": 0,
            "auto_updates_enabled": True
        }
    
    async def _query_application_inventory(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query installed application inventory."""
        # Default implementation provides mock data
        return {
            "installed_apps": ["Chrome", "Firefox", "Office365", "Slack", "Teams", "Outlook"],
            "suspicious_apps": [],
            "unsigned_apps": []
        }
    
    async def _query_device_management_status(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query device management status."""
        # Default implementation provides mock data
        return {
            "domain_joined": True,
            "managed_device": True,
            "mdm_enrolled": True,
            "mdm_compliant": True
        }
    
    async def _query_security_incidents(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Query security incident history."""
        # Default implementation provides mock data (no incidents)
        return {
            "malware_detected": False,
            "malware_types": [],
            "incident_count": 0,
            "last_incident_date": None
        }
    
    def cleanup_cache(self, max_age_hours: int = 24):
        """Clean up old cache entries."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        expired_devices = [
            device_id for device_id, posture in self.device_cache.items()
            if posture.assessment_timestamp < cutoff_time
        ]
        
        for device_id in expired_devices:
            del self.device_cache[device_id]
        
        if expired_devices:
            logger.info(f"Cleaned up {len(expired_devices)} expired device posture entries")


# Export main classes
__all__ = [
    "DeviceType",
    "OperatingSystem", 
    "ComplianceFramework",
    "SecurityControlStatus",
    "SecurityControl",
    "DeviceHardwareInfo",
    "NetworkConfiguration", 
    "DevicePosture",
    "DevicePostureCollector"
]