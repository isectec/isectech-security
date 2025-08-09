#!/usr/bin/env python3
"""
iSECTECH Cloud Security Posture Management - Network Security Assessment
Comprehensive network security analysis for security groups, firewalls, and network policies
"""

import asyncio
import ipaddress
import json
import logging
import re
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union

import boto3
import yaml
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from google.cloud import compute_v1


class NetworkRiskLevel(Enum):
    """Network security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NetworkRuleType(Enum):
    """Types of network rules"""
    INGRESS = "ingress"
    EGRESS = "egress"
    BIDIRECTIONAL = "bidirectional"


class ProtocolType(Enum):
    """Network protocol types"""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"
    ESP = "esp"
    GRE = "gre"


@dataclass
class NetworkRule:
    """Individual network security rule"""
    rule_id: str
    rule_type: NetworkRuleType
    protocol: ProtocolType
    source_cidr: str
    destination_cidr: str
    source_ports: List[Union[int, str]] = field(default_factory=list)
    destination_ports: List[Union[int, str]] = field(default_factory=list)
    action: str = "allow"  # allow, deny
    priority: int = 100
    description: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class NetworkSecurityGroup:
    """Network security group/firewall definition"""
    id: str
    name: str
    cloud_provider: str
    account_id: str
    region: str
    vpc_id: Optional[str] = None
    resource_group: Optional[str] = None
    associated_resources: List[str] = field(default_factory=list)
    ingress_rules: List[NetworkRule] = field(default_factory=list)
    egress_rules: List[NetworkRule] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    created_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    is_default: bool = False
    risk_score: float = 0.0


@dataclass
class NetworkViolation:
    """Network security violation"""
    violation_id: str
    rule_id: str
    security_group_id: str
    security_group_name: str
    cloud_provider: str
    account_id: str
    region: str
    risk_level: NetworkRiskLevel
    title: str
    description: str
    affected_rule: NetworkRule
    recommended_action: str
    impact_assessment: str
    remediation_steps: List[str]
    timestamp: datetime
    compliance_frameworks: List[str] = field(default_factory=list)
    exposed_services: List[str] = field(default_factory=list)


@dataclass
class NetworkAssessmentResult:
    """Network security assessment result"""
    assessment_id: str
    timestamp: datetime
    cloud_provider: str
    account_id: str
    region: str
    total_security_groups: int
    total_rules: int
    violations: List[NetworkViolation]
    high_risk_groups: List[str]
    exposed_services: Dict[str, List[str]]  # service -> exposed_groups
    overly_permissive_rules: List[str]
    unused_security_groups: List[str]
    network_recommendations: List[Dict[str, Any]]
    overall_risk_score: float
    execution_time_seconds: float


class NetworkSecurityAssessmentEngine:
    """Main network security assessment engine"""
    
    def __init__(self, config_path: str = "/etc/nsm/network_security.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # High-risk ports and services
        self.high_risk_ports = {
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'SQL Server',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5984: 'CouchDB',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        # Critical services that should never be exposed publicly
        self.critical_services = {
            22: 'SSH',
            23: 'Telnet',
            135: 'RPC',
            139: 'NetBIOS',
            445: 'SMB',
            1433: 'SQL Server',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # Common dangerous CIDR blocks
        self.dangerous_cidrs = {
            '0.0.0.0/0': 'Internet (All IPv4)',
            '::/0': 'Internet (All IPv6)',
            '10.0.0.0/8': 'Private Class A (if overly broad)',
            '172.16.0.0/12': 'Private Class B (if overly broad)',
            '192.168.0.0/16': 'Private Class C (if overly broad)'
        }
        
        # Assessment results storage
        self.assessment_results: List[NetworkAssessmentResult] = []
        
        # Load network assessment rules
        self.assessment_rules = self._load_assessment_rules()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return {
                'assessment_schedule': '0 4 * * *',  # Daily at 4 AM
                'max_acceptable_risk_score': 70.0,
                'enable_automated_remediation': False,
                'remediation_dry_run': True,
                'scan_unused_groups': True,
                'compliance_frameworks': ['CIS', 'NIST', 'SOC2']
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger('NetworkSecurityAssessmentEngine')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _load_assessment_rules(self) -> Dict[str, Any]:
        """Load network security assessment rules"""
        return {
            'unrestricted_ingress': {
                'description': 'Detect unrestricted ingress access from internet',
                'risk_level': NetworkRiskLevel.CRITICAL,
                'check_function': 'check_unrestricted_ingress'
            },
            'critical_service_exposure': {
                'description': 'Detect critical services exposed to internet',
                'risk_level': NetworkRiskLevel.CRITICAL,
                'check_function': 'check_critical_service_exposure'
            },
            'overly_permissive_egress': {
                'description': 'Detect overly permissive egress rules',
                'risk_level': NetworkRiskLevel.MEDIUM,
                'check_function': 'check_overly_permissive_egress'
            },
            'unused_security_groups': {
                'description': 'Detect unused security groups',
                'risk_level': NetworkRiskLevel.LOW,
                'check_function': 'check_unused_security_groups'
            },
            'default_security_group_usage': {
                'description': 'Detect usage of default security groups',
                'risk_level': NetworkRiskLevel.MEDIUM,
                'check_function': 'check_default_security_group_usage'
            },
            'duplicate_rules': {
                'description': 'Detect duplicate or redundant rules',
                'risk_level': NetworkRiskLevel.LOW,
                'check_function': 'check_duplicate_rules'
            }
        }
    
    async def assess_aws_network_security(self, account_id: str, regions: List[str] = None) -> NetworkAssessmentResult:
        """Assess AWS network security configuration"""
        if regions is None:
            regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        
        start_time = datetime.utcnow()
        self.logger.info(f"Starting AWS network security assessment for account {account_id}")
        
        all_violations = []
        all_security_groups = []
        
        for region in regions:
            try:
                session = boto3.Session(region_name=region)
                ec2_client = session.client('ec2')
                
                # Collect security groups
                region_sgs = await self._collect_aws_security_groups(ec2_client, account_id, region)
                all_security_groups.extend(region_sgs)
                
                # Assess each security group
                for sg in region_sgs:
                    sg_violations = await self._assess_aws_security_group(sg, ec2_client)
                    all_violations.extend(sg_violations)
                
                self.logger.info(f"Assessed {len(region_sgs)} security groups in region {region}")
                
            except Exception as e:
                self.logger.error(f"Error assessing AWS region {region}: {e}")
        
        # Calculate summary metrics
        high_risk_groups = [sg.name for sg in all_security_groups if sg.risk_score > 70]
        
        # Identify exposed services
        exposed_services = defaultdict(list)
        for violation in all_violations:
            if violation.exposed_services:
                for service in violation.exposed_services:
                    exposed_services[service].append(violation.security_group_name)
        
        # Identify overly permissive rules
        overly_permissive_rules = [
            f"{v.security_group_name}:{v.rule_id}" 
            for v in all_violations 
            if 'permissive' in v.title.lower()
        ]
        
        # Identify unused security groups (simplified check)
        unused_security_groups = [
            sg.name for sg in all_security_groups 
            if not sg.associated_resources and not sg.is_default
        ]
        
        # Generate recommendations
        recommendations = self._generate_network_recommendations(
            all_violations, high_risk_groups, exposed_services
        )
        
        # Calculate overall risk score
        if all_security_groups:
            avg_risk = sum(sg.risk_score for sg in all_security_groups) / len(all_security_groups)
            critical_violations = len([v for v in all_violations if v.risk_level == NetworkRiskLevel.CRITICAL])
            overall_risk = min(100.0, avg_risk + (critical_violations * 10))
        else:
            overall_risk = 0.0
        
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()
        
        result = NetworkAssessmentResult(
            assessment_id=f"aws_network_{account_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            cloud_provider="aws",
            account_id=account_id,
            region="multi-region",
            total_security_groups=len(all_security_groups),
            total_rules=sum(len(sg.ingress_rules) + len(sg.egress_rules) for sg in all_security_groups),
            violations=all_violations,
            high_risk_groups=high_risk_groups,
            exposed_services=dict(exposed_services),
            overly_permissive_rules=overly_permissive_rules,
            unused_security_groups=unused_security_groups,
            network_recommendations=recommendations,
            overall_risk_score=overall_risk,
            execution_time_seconds=execution_time
        )
        
        self.assessment_results.append(result)
        self.logger.info(f"AWS network assessment completed: {len(all_violations)} violations, {overall_risk:.1f}% risk score")
        
        return result
    
    async def _collect_aws_security_groups(self, ec2_client, account_id: str, region: str) -> List[NetworkSecurityGroup]:
        """Collect AWS security groups"""
        security_groups = []
        
        try:
            paginator = ec2_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg_data in page['SecurityGroups']:
                    sg = NetworkSecurityGroup(
                        id=sg_data['GroupId'],
                        name=sg_data['GroupName'],
                        cloud_provider='aws',
                        account_id=account_id,
                        region=region,
                        vpc_id=sg_data.get('VpcId'),
                        tags=self._extract_aws_tags(sg_data.get('Tags', [])),
                        is_default=sg_data['GroupName'] == 'default'
                    )
                    
                    # Parse ingress rules
                    for rule_data in sg_data.get('IpPermissions', []):
                        rule = self._parse_aws_ingress_rule(rule_data, sg.id)
                        sg.ingress_rules.append(rule)
                    
                    # Parse egress rules
                    for rule_data in sg_data.get('IpPermissionsEgress', []):
                        rule = self._parse_aws_egress_rule(rule_data, sg.id)
                        sg.egress_rules.append(rule)
                    
                    # Get associated resources (simplified)
                    sg.associated_resources = await self._get_aws_sg_associated_resources(
                        ec2_client, sg.id
                    )
                    
                    # Calculate risk score
                    sg.risk_score = self._calculate_sg_risk_score(sg)
                    
                    security_groups.append(sg)
        
        except Exception as e:
            self.logger.error(f"Error collecting AWS security groups: {e}")
        
        return security_groups
    
    def _extract_aws_tags(self, tags_list: List[Dict[str, str]]) -> Dict[str, str]:
        """Extract tags from AWS tags list format"""
        return {tag['Key']: tag['Value'] for tag in tags_list}
    
    def _parse_aws_ingress_rule(self, rule_data: Dict[str, Any], sg_id: str) -> NetworkRule:
        """Parse AWS ingress rule"""
        protocol = rule_data.get('IpProtocol', 'tcp')
        if protocol == '-1':
            protocol = 'all'
        
        from_port = rule_data.get('FromPort')
        to_port = rule_data.get('ToPort')
        
        # Get source CIDRs
        source_cidrs = []
        for ip_range in rule_data.get('IpRanges', []):
            source_cidrs.append(ip_range['CidrIp'])
        for ipv6_range in rule_data.get('Ipv6Ranges', []):
            source_cidrs.append(ipv6_range['CidrIpv6'])
        
        # Handle referenced security groups
        for sg_ref in rule_data.get('UserIdGroupPairs', []):
            source_cidrs.append(f"sg-{sg_ref['GroupId']}")
        
        source_cidr = ','.join(source_cidrs) if source_cidrs else 'unknown'
        
        # Create ports list
        ports = []
        if from_port is not None and to_port is not None:
            if from_port == to_port:
                ports = [from_port]
            else:
                ports = [f"{from_port}-{to_port}"]
        
        rule = NetworkRule(
            rule_id=f"{sg_id}_ingress_{hash(str(rule_data))}",
            rule_type=NetworkRuleType.INGRESS,
            protocol=ProtocolType(protocol.lower()) if protocol.lower() in [p.value for p in ProtocolType] else ProtocolType.TCP,
            source_cidr=source_cidr,
            destination_cidr="self",
            destination_ports=ports,
            description=rule_data.get('Description', '')
        )
        
        # Calculate risk score
        rule.risk_score = self._calculate_rule_risk_score(rule)
        
        return rule
    
    def _parse_aws_egress_rule(self, rule_data: Dict[str, Any], sg_id: str) -> NetworkRule:
        """Parse AWS egress rule"""
        protocol = rule_data.get('IpProtocol', 'tcp')
        if protocol == '-1':
            protocol = 'all'
        
        from_port = rule_data.get('FromPort')
        to_port = rule_data.get('ToPort')
        
        # Get destination CIDRs
        dest_cidrs = []
        for ip_range in rule_data.get('IpRanges', []):
            dest_cidrs.append(ip_range['CidrIp'])
        for ipv6_range in rule_data.get('Ipv6Ranges', []):
            dest_cidrs.append(ipv6_range['CidrIpv6'])
        
        # Handle referenced security groups
        for sg_ref in rule_data.get('UserIdGroupPairs', []):
            dest_cidrs.append(f"sg-{sg_ref['GroupId']}")
        
        destination_cidr = ','.join(dest_cidrs) if dest_cidrs else 'unknown'
        
        # Create ports list
        ports = []
        if from_port is not None and to_port is not None:
            if from_port == to_port:
                ports = [from_port]
            else:
                ports = [f"{from_port}-{to_port}"]
        
        rule = NetworkRule(
            rule_id=f"{sg_id}_egress_{hash(str(rule_data))}",
            rule_type=NetworkRuleType.EGRESS,
            protocol=ProtocolType(protocol.lower()) if protocol.lower() in [p.value for p in ProtocolType] else ProtocolType.TCP,
            source_cidr="self",
            destination_cidr=destination_cidr,
            destination_ports=ports,
            description=rule_data.get('Description', '')
        )
        
        # Calculate risk score
        rule.risk_score = self._calculate_rule_risk_score(rule)
        
        return rule
    
    async def _get_aws_sg_associated_resources(self, ec2_client, sg_id: str) -> List[str]:
        """Get resources associated with AWS security group"""
        associated_resources = []
        
        try:
            # Check EC2 instances
            instances_response = ec2_client.describe_instances(
                Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
            )
            for reservation in instances_response['Reservations']:
                for instance in reservation['Instances']:
                    associated_resources.append(f"ec2:{instance['InstanceId']}")
            
            # Check network interfaces
            eni_response = ec2_client.describe_network_interfaces(
                Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
            )
            for eni in eni_response['NetworkInterfaces']:
                associated_resources.append(f"eni:{eni['NetworkInterfaceId']}")
        
        except Exception as e:
            self.logger.warning(f"Error getting associated resources for SG {sg_id}: {e}")
        
        return associated_resources
    
    def _calculate_sg_risk_score(self, sg: NetworkSecurityGroup) -> float:
        """Calculate risk score for security group"""
        risk_score = 0.0
        
        # Base score from rules
        if sg.ingress_rules:
            avg_ingress_risk = sum(rule.risk_score for rule in sg.ingress_rules) / len(sg.ingress_rules)
            risk_score += avg_ingress_risk * 3.0
        
        if sg.egress_rules:
            avg_egress_risk = sum(rule.risk_score for rule in sg.egress_rules) / len(sg.egress_rules)
            risk_score += avg_egress_risk * 1.5  # Egress is less critical than ingress
        
        # High-risk factors
        public_ingress_rules = [
            rule for rule in sg.ingress_rules 
            if '0.0.0.0/0' in rule.source_cidr or '::/0' in rule.source_cidr
        ]
        if public_ingress_rules:
            risk_score += len(public_ingress_rules) * 15.0
        
        # Critical service exposure
        for rule in sg.ingress_rules:
            if '0.0.0.0/0' in rule.source_cidr:
                for port in rule.destination_ports:
                    port_num = self._extract_port_number(port)
                    if port_num in self.critical_services:
                        risk_score += 25.0  # Very high risk
        
        # Default security group usage
        if sg.is_default and sg.associated_resources:
            risk_score += 10.0
        
        return min(100.0, risk_score)
    
    def _calculate_rule_risk_score(self, rule: NetworkRule) -> float:
        """Calculate risk score for individual rule"""
        risk_score = 1.0
        
        # Internet exposure
        if '0.0.0.0/0' in rule.source_cidr or '::/0' in rule.source_cidr:
            risk_score *= 5.0
        
        # Protocol risk
        if rule.protocol == ProtocolType.ALL:
            risk_score *= 3.0
        
        # Port-based risk
        for port in rule.destination_ports:
            port_num = self._extract_port_number(port)
            if port_num in self.critical_services:
                risk_score *= 4.0
            elif port_num in self.high_risk_ports:
                risk_score *= 2.0
        
        # Wide port ranges
        for port in rule.destination_ports:
            if '-' in str(port):
                start, end = map(int, str(port).split('-'))
                if end - start > 1000:  # Very wide range
                    risk_score *= 2.0
        
        return min(10.0, risk_score)
    
    def _extract_port_number(self, port: Union[int, str]) -> int:
        """Extract port number from port specification"""
        if isinstance(port, int):
            return port
        
        port_str = str(port)
        if '-' in port_str:
            return int(port_str.split('-')[0])
        
        try:
            return int(port_str)
        except ValueError:
            return 0
    
    async def _assess_aws_security_group(self, sg: NetworkSecurityGroup, ec2_client) -> List[NetworkViolation]:
        """Assess individual AWS security group"""
        violations = []
        
        # Check for unrestricted ingress
        unrestricted_violations = self._check_unrestricted_ingress(sg)
        violations.extend(unrestricted_violations)
        
        # Check for critical service exposure
        critical_service_violations = self._check_critical_service_exposure(sg)
        violations.extend(critical_service_violations)
        
        # Check for overly permissive egress
        egress_violations = self._check_overly_permissive_egress(sg)
        violations.extend(egress_violations)
        
        # Check default security group usage
        default_sg_violations = self._check_default_security_group_usage(sg)
        violations.extend(default_sg_violations)
        
        # Check for duplicate rules
        duplicate_violations = self._check_duplicate_rules(sg)
        violations.extend(duplicate_violations)
        
        return violations
    
    def _check_unrestricted_ingress(self, sg: NetworkSecurityGroup) -> List[NetworkViolation]:
        """Check for unrestricted ingress access"""
        violations = []
        
        for rule in sg.ingress_rules:
            if '0.0.0.0/0' in rule.source_cidr or '::/0' in rule.source_cidr:
                # Determine exposed services
                exposed_services = []
                for port in rule.destination_ports:
                    port_num = self._extract_port_number(port)
                    if port_num in self.high_risk_ports:
                        exposed_services.append(self.high_risk_ports[port_num])
                
                violation = NetworkViolation(
                    violation_id=f"unrestricted_ingress_{sg.id}_{rule.rule_id}_{int(datetime.utcnow().timestamp())}",
                    rule_id=rule.rule_id,
                    security_group_id=sg.id,
                    security_group_name=sg.name,
                    cloud_provider=sg.cloud_provider,
                    account_id=sg.account_id,
                    region=sg.region,
                    risk_level=NetworkRiskLevel.CRITICAL,
                    title="Unrestricted Internet Access",
                    description=f"Security group {sg.name} allows unrestricted ingress from internet on ports {', '.join(map(str, rule.destination_ports))}",
                    affected_rule=rule,
                    recommended_action="Restrict source IP ranges to specific networks or IP addresses",
                    impact_assessment="High risk of unauthorized access and potential security breaches",
                    remediation_steps=[
                        "Review business requirements for internet access",
                        "Replace 0.0.0.0/0 with specific IP ranges",
                        "Consider using a bastion host or VPN for administrative access",
                        "Implement additional security controls (WAF, IDS/IPS)",
                        "Monitor access logs for suspicious activity"
                    ],
                    timestamp=datetime.utcnow(),
                    compliance_frameworks=["CIS", "NIST", "SOC2", "PCI-DSS"],
                    exposed_services=exposed_services
                )
                violations.append(violation)
        
        return violations
    
    def _check_critical_service_exposure(self, sg: NetworkSecurityGroup) -> List[NetworkViolation]:
        """Check for critical services exposed to internet"""
        violations = []
        
        for rule in sg.ingress_rules:
            if '0.0.0.0/0' in rule.source_cidr:
                for port in rule.destination_ports:
                    port_num = self._extract_port_number(port)
                    if port_num in self.critical_services:
                        service_name = self.critical_services[port_num]
                        
                        violation = NetworkViolation(
                            violation_id=f"critical_service_{sg.id}_{port_num}_{int(datetime.utcnow().timestamp())}",
                            rule_id=rule.rule_id,
                            security_group_id=sg.id,
                            security_group_name=sg.name,
                            cloud_provider=sg.cloud_provider,
                            account_id=sg.account_id,
                            region=sg.region,
                            risk_level=NetworkRiskLevel.CRITICAL,
                            title=f"Critical Service Exposed: {service_name}",
                            description=f"Critical service {service_name} (port {port_num}) is exposed to the internet",
                            affected_rule=rule,
                            recommended_action=f"Remove internet access to {service_name} or use secure alternatives",
                            impact_assessment=f"Critical risk: {service_name} exposure can lead to data breaches and system compromise",
                            remediation_steps=[
                                f"Remove public access to {service_name} immediately",
                                "Use VPN or bastion host for administrative access",
                                "Implement network segmentation",
                                "Enable service-specific security features",
                                "Monitor for unauthorized access attempts"
                            ],
                            timestamp=datetime.utcnow(),
                            compliance_frameworks=["CIS", "NIST", "SOC2", "PCI-DSS", "HIPAA"],
                            exposed_services=[service_name]
                        )
                        violations.append(violation)
        
        return violations
    
    def _check_overly_permissive_egress(self, sg: NetworkSecurityGroup) -> List[NetworkViolation]:
        """Check for overly permissive egress rules"""
        violations = []
        
        for rule in sg.egress_rules:
            # Check for unrestricted egress to internet
            if ('0.0.0.0/0' in rule.destination_cidr and 
                rule.protocol == ProtocolType.ALL and 
                not rule.destination_ports):
                
                violation = NetworkViolation(
                    violation_id=f"permissive_egress_{sg.id}_{rule.rule_id}_{int(datetime.utcnow().timestamp())}",
                    rule_id=rule.rule_id,
                    security_group_id=sg.id,
                    security_group_name=sg.name,
                    cloud_provider=sg.cloud_provider,
                    account_id=sg.account_id,
                    region=sg.region,
                    risk_level=NetworkRiskLevel.MEDIUM,
                    title="Overly Permissive Egress Rule",
                    description=f"Security group {sg.name} allows unrestricted egress to internet on all protocols and ports",
                    affected_rule=rule,
                    recommended_action="Restrict egress to specific protocols, ports, and destinations",
                    impact_assessment="Medium risk: Can facilitate data exfiltration and malware communication",
                    remediation_steps=[
                        "Identify required outbound connections",
                        "Create specific egress rules for required traffic only",
                        "Remove overly broad egress rules",
                        "Implement egress monitoring and filtering",
                        "Consider using NAT Gateway for controlled internet access"
                    ],
                    timestamp=datetime.utcnow(),
                    compliance_frameworks=["CIS", "NIST"],
                    exposed_services=[]
                )
                violations.append(violation)
        
        return violations
    
    def _check_default_security_group_usage(self, sg: NetworkSecurityGroup) -> List[NetworkViolation]:
        """Check for default security group usage"""
        violations = []
        
        if sg.is_default and sg.associated_resources:
            violation = NetworkViolation(
                violation_id=f"default_sg_usage_{sg.id}_{int(datetime.utcnow().timestamp())}",
                rule_id="default_sg_check",
                security_group_id=sg.id,
                security_group_name=sg.name,
                cloud_provider=sg.cloud_provider,
                account_id=sg.account_id,
                region=sg.region,
                risk_level=NetworkRiskLevel.MEDIUM,
                title="Default Security Group in Use",
                description=f"Default security group is being used by {len(sg.associated_resources)} resources",
                affected_rule=NetworkRule(
                    rule_id="default_sg",
                    rule_type=NetworkRuleType.INGRESS,
                    protocol=ProtocolType.ALL,
                    source_cidr="default",
                    destination_cidr="default"
                ),
                recommended_action="Create specific security groups for different resource types",
                impact_assessment="Medium risk: Default security groups often have overly permissive rules",
                remediation_steps=[
                    "Create purpose-specific security groups",
                    "Migrate resources from default security group",
                    "Apply principle of least privilege to new security groups",
                    "Remove or restrict rules in default security group",
                    "Document security group usage and requirements"
                ],
                timestamp=datetime.utcnow(),
                compliance_frameworks=["CIS", "NIST"],
                exposed_services=[]
            )
            violations.append(violation)
        
        return violations
    
    def _check_duplicate_rules(self, sg: NetworkSecurityGroup) -> List[NetworkViolation]:
        """Check for duplicate or redundant rules"""
        violations = []
        
        # Check ingress rules for duplicates
        seen_rules = set()
        for rule in sg.ingress_rules:
            rule_signature = (
                rule.rule_type.value,
                rule.protocol.value,
                rule.source_cidr,
                tuple(sorted(map(str, rule.destination_ports)))
            )
            
            if rule_signature in seen_rules:
                violation = NetworkViolation(
                    violation_id=f"duplicate_rule_{sg.id}_{rule.rule_id}_{int(datetime.utcnow().timestamp())}",
                    rule_id=rule.rule_id,
                    security_group_id=sg.id,
                    security_group_name=sg.name,
                    cloud_provider=sg.cloud_provider,
                    account_id=sg.account_id,
                    region=sg.region,
                    risk_level=NetworkRiskLevel.LOW,
                    title="Duplicate Security Group Rule",
                    description=f"Security group {sg.name} contains duplicate or redundant rules",
                    affected_rule=rule,
                    recommended_action="Remove duplicate rules to simplify management",
                    impact_assessment="Low risk: Duplicate rules can cause confusion and management overhead",
                    remediation_steps=[
                        "Identify and document all duplicate rules",
                        "Remove redundant rules",
                        "Consolidate similar rules where possible",
                        "Implement rule management procedures",
                        "Regular review and cleanup of security group rules"
                    ],
                    timestamp=datetime.utcnow(),
                    compliance_frameworks=["CIS"],
                    exposed_services=[]
                )
                violations.append(violation)
            else:
                seen_rules.add(rule_signature)
        
        return violations
    
    def _generate_network_recommendations(self, violations: List[NetworkViolation],
                                        high_risk_groups: List[str],
                                        exposed_services: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Generate network security recommendations"""
        recommendations = []
        
        if violations:
            critical_violations = [v for v in violations if v.risk_level == NetworkRiskLevel.CRITICAL]
            if critical_violations:
                recommendations.append({
                    'priority': 'critical',
                    'category': 'immediate_action',
                    'title': f'Address {len(critical_violations)} critical network violations',
                    'description': 'Immediately address critical network security violations',
                    'impact': 'Prevent potential security breaches and unauthorized access',
                    'affected_groups': list(set(v.security_group_name for v in critical_violations))
                })
        
        if high_risk_groups:
            recommendations.append({
                'priority': 'high',
                'category': 'risk_reduction',
                'title': f'Review {len(high_risk_groups)} high-risk security groups',
                'description': 'Review and tighten rules for high-risk security groups',
                'impact': 'Reduce overall network attack surface',
                'affected_groups': high_risk_groups[:10]
            })
        
        if exposed_services:
            recommendations.append({
                'priority': 'high',
                'category': 'service_hardening',
                'title': f'Secure {len(exposed_services)} exposed services',
                'description': 'Remove or properly secure services exposed to the internet',
                'impact': 'Prevent direct attacks on critical services',
                'exposed_services': dict(list(exposed_services.items())[:5])
            })
        
        # General best practices
        recommendations.append({
            'priority': 'medium',
            'category': 'best_practices',
            'title': 'Implement network security best practices',
            'description': 'Apply defense-in-depth and zero-trust principles',
            'impact': 'Improve overall security posture and compliance',
            'actions': [
                'Regular security group audits',
                'Implement least privilege access',
                'Use VPC Flow Logs for monitoring',
                'Enable GuardDuty or equivalent threat detection',
                'Implement network segmentation'
            ]
        })
        
        return recommendations
    
    async def assess_azure_network_security(self, subscription_id: str) -> NetworkAssessmentResult:
        """Assess Azure network security configuration"""
        start_time = datetime.utcnow()
        self.logger.info(f"Starting Azure network security assessment for subscription {subscription_id}")
        
        try:
            # This would contain actual Azure network security assessment
            # For now, returning a placeholder result
            
            result = NetworkAssessmentResult(
                assessment_id=f"azure_network_{subscription_id}_{int(start_time.timestamp())}",
                timestamp=start_time,
                cloud_provider="azure",
                account_id=subscription_id,
                region="global",
                total_security_groups=0,
                total_rules=0,
                violations=[],
                high_risk_groups=[],
                exposed_services={},
                overly_permissive_rules=[],
                unused_security_groups=[],
                network_recommendations=[],
                overall_risk_score=0.0,
                execution_time_seconds=1.0
            )
            
            self.assessment_results.append(result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error assessing Azure network security: {e}")
            raise
    
    async def assess_gcp_network_security(self, project_id: str) -> NetworkAssessmentResult:
        """Assess GCP network security configuration"""
        start_time = datetime.utcnow()
        self.logger.info(f"Starting GCP network security assessment for project {project_id}")
        
        try:
            # This would contain actual GCP network security assessment
            # For now, returning a placeholder result
            
            result = NetworkAssessmentResult(
                assessment_id=f"gcp_network_{project_id}_{int(start_time.timestamp())}",
                timestamp=start_time,
                cloud_provider="gcp",
                account_id=project_id,
                region="global",
                total_security_groups=0,
                total_rules=0,
                violations=[],
                high_risk_groups=[],
                exposed_services={},
                overly_permissive_rules=[],
                unused_security_groups=[],
                network_recommendations=[],
                overall_risk_score=0.0,
                execution_time_seconds=1.0
            )
            
            self.assessment_results.append(result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error assessing GCP network security: {e}")
            raise
    
    def generate_network_security_report(self, output_format: str = 'json') -> str:
        """Generate network security assessment report"""
        if not self.assessment_results:
            return "No network assessment results available"
        
        latest_result = max(self.assessment_results, key=lambda x: x.timestamp)
        
        if output_format.lower() == 'json':
            return json.dumps(asdict(latest_result), indent=2, default=str)
        
        elif output_format.lower() == 'text':
            report = []
            report.append("NETWORK SECURITY ASSESSMENT REPORT")
            report.append("=" * 60)
            report.append(f"Assessment ID: {latest_result.assessment_id}")
            report.append(f"Timestamp: {latest_result.timestamp}")
            report.append(f"Cloud Provider: {latest_result.cloud_provider}")
            report.append(f"Account/Subscription: {latest_result.account_id}")
            report.append(f"Total Security Groups: {latest_result.total_security_groups}")
            report.append(f"Total Rules: {latest_result.total_rules}")
            report.append(f"Total Violations: {len(latest_result.violations)}")
            report.append(f"Overall Risk Score: {latest_result.overall_risk_score:.1f}%")
            report.append("")
            
            # Violations by severity
            violations_by_severity = defaultdict(int)
            for violation in latest_result.violations:
                violations_by_severity[violation.risk_level.value] += 1
            
            if violations_by_severity:
                report.append("VIOLATIONS BY SEVERITY:")
                report.append("-" * 30)
                for severity, count in violations_by_severity.items():
                    report.append(f"  {severity.title()}: {count}")
                report.append("")
            
            # Critical violations
            critical_violations = [v for v in latest_result.violations if v.risk_level == NetworkRiskLevel.CRITICAL]
            if critical_violations:
                report.append("CRITICAL VIOLATIONS:")
                report.append("-" * 30)
                for violation in critical_violations[:5]:  # Show top 5
                    report.append(f"• {violation.title}")
                    report.append(f"  Security Group: {violation.security_group_name}")
                    report.append(f"  Impact: {violation.impact_assessment}")
                    report.append("")
            
            # Exposed services
            if latest_result.exposed_services:
                report.append("EXPOSED SERVICES:")
                report.append("-" * 30)
                for service, groups in latest_result.exposed_services.items():
                    report.append(f"• {service}: {len(groups)} security groups")
                report.append("")
            
            # Recommendations
            if latest_result.network_recommendations:
                report.append("RECOMMENDATIONS:")
                report.append("-" * 30)
                for rec in latest_result.network_recommendations:
                    report.append(f"• {rec['title']} (Priority: {rec['priority']})")
                    report.append(f"  {rec['description']}")
                    report.append("")
            
            return "\n".join(report)
        
        else:
            return f"Unsupported output format: {output_format}"


async def main():
    """Main function for testing network security assessment engine"""
    engine = NetworkSecurityAssessmentEngine()
    
    try:
        print("Network Security Assessment Engine initialized successfully")
        print(f"Loaded {len(engine.assessment_rules)} assessment rules")
        print(f"Monitoring {len(engine.high_risk_ports)} high-risk ports")
        print(f"Tracking {len(engine.critical_services)} critical services")
        
        # Example: Assess AWS network security (would need actual credentials)
        # result = await engine.assess_aws_network_security("123456789012", ["us-east-1"])
        # print(f"Assessment completed: {len(result.violations)} violations found")
        
        # Generate report
        # report = engine.generate_network_security_report('text')
        # print(report)
        
    except Exception as e:
        print(f"Error running network security assessment: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())