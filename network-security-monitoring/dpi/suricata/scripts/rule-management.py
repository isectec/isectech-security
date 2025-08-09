#!/usr/bin/env python3
# iSECTECH Suricata Rule Management System
# Production-grade signature management and optimization

import requests
import json
import yaml
import hashlib
import logging
import asyncio
import aiohttp
import aiofiles
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import re
import gzip
import tarfile
import tempfile
import shutil
import sqlite3
import subprocess
import time
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/nsm/rule-management.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RuleSource:
    """Represents a threat intelligence rule source"""
    name: str
    url: str
    format: str  # 'suricata', 'snort', 'emerging_threats'
    priority: int
    enabled: bool
    auth_required: bool = False
    api_key: Optional[str] = None
    update_frequency: int = 3600  # seconds
    last_updated: Optional[datetime] = None
    rule_count: int = 0
    checksum: Optional[str] = None
    
@dataclass 
class RuleMetadata:
    """Metadata for individual rules"""
    sid: int
    revision: int
    classification: str
    priority: int
    source: str
    enabled: bool
    performance_impact: str  # 'low', 'medium', 'high'
    false_positive_rate: float
    detection_count: int = 0
    last_triggered: Optional[datetime] = None
    mitre_tactics: List[str] = None
    mitre_techniques: List[str] = None

class RulePerformanceAnalyzer:
    """Analyzes rule performance and effectiveness"""
    
    def __init__(self, db_path: str = "/var/lib/nsm/rule_performance.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize performance tracking database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_performance (
                    sid INTEGER PRIMARY KEY,
                    total_matches INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    cpu_time_ms REAL DEFAULT 0.0,
                    memory_usage_kb INTEGER DEFAULT 0,
                    last_match TIMESTAMP,
                    performance_score REAL DEFAULT 0.0,
                    enabled BOOLEAN DEFAULT 1
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_statistics (
                    sid INTEGER,
                    date DATE,
                    matches INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    avg_cpu_time REAL DEFAULT 0.0,
                    PRIMARY KEY (sid, date)
                )
            """)
    
    def update_rule_stats(self, sid: int, matches: int, false_positives: int, cpu_time: float):
        """Update rule performance statistics"""
        with sqlite3.connect(self.db_path) as conn:
            # Update overall performance
            conn.execute("""
                INSERT OR REPLACE INTO rule_performance 
                (sid, total_matches, false_positives, cpu_time_ms, last_match, performance_score)
                VALUES (?, 
                    COALESCE((SELECT total_matches FROM rule_performance WHERE sid = ?), 0) + ?,
                    COALESCE((SELECT false_positives FROM rule_performance WHERE sid = ?), 0) + ?,
                    ?,
                    datetime('now'),
                    ?
                )
            """, (sid, sid, matches, sid, false_positives, cpu_time, self._calculate_performance_score(matches, false_positives, cpu_time)))
            
            # Update daily statistics
            conn.execute("""
                INSERT OR REPLACE INTO rule_statistics
                (sid, date, matches, false_positives, avg_cpu_time)
                VALUES (?, date('now'), ?, ?, ?)
            """, (sid, matches, false_positives, cpu_time))
    
    def _calculate_performance_score(self, matches: int, false_positives: int, cpu_time: float) -> float:
        """Calculate rule performance score (0-100)"""
        if matches == 0:
            return 50.0  # Neutral score for unused rules
        
        accuracy = 1.0 - (false_positives / matches) if matches > 0 else 1.0
        efficiency = max(0, 1.0 - (cpu_time / 1000.0))  # Penalize high CPU usage
        
        score = (accuracy * 0.7 + efficiency * 0.3) * 100
        return min(100.0, max(0.0, score))
    
    def get_low_performing_rules(self, threshold: float = 30.0) -> List[int]:
        """Get rules with performance scores below threshold"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT sid FROM rule_performance 
                WHERE performance_score < ? AND total_matches > 10
                ORDER BY performance_score ASC
            """, (threshold,))
            return [row[0] for row in cursor.fetchall()]
    
    def get_high_performing_rules(self, threshold: float = 80.0) -> List[int]:
        """Get rules with performance scores above threshold"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT sid FROM rule_performance 
                WHERE performance_score > ? AND total_matches > 5
                ORDER BY performance_score DESC
            """, (threshold,))
            return [row[0] for row in cursor.fetchall()]

class ThreatIntelligenceRuleGenerator:
    """Generates Suricata rules from threat intelligence indicators"""
    
    def __init__(self):
        self.generated_rules = []
        self.sid_counter = 20000000  # Start custom SIDs at 20M
    
    def generate_ip_reputation_rules(self, malicious_ips: List[str]) -> List[str]:
        """Generate rules for malicious IP addresses"""
        rules = []
        
        for ip in malicious_ips:
            self.sid_counter += 1
            rule = f'alert ip any any -> {ip} any (msg:"iSECTECH: Connection to known malicious IP {ip}"; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
            rules.append(rule)
            
            # Also create reverse rule
            self.sid_counter += 1
            rule = f'alert ip {ip} any -> any any (msg:"iSECTECH: Connection from known malicious IP {ip}"; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
            rules.append(rule)
        
        return rules
    
    def generate_domain_reputation_rules(self, malicious_domains: List[str]) -> List[str]:
        """Generate rules for malicious domains"""
        rules = []
        
        for domain in malicious_domains:
            self.sid_counter += 1
            rule = f'alert dns any any -> any 53 (msg:"iSECTECH: DNS query to known malicious domain {domain}"; dns.query; content:"{domain}"; nocase; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
            rules.append(rule)
            
            # HTTP rule for the domain
            self.sid_counter += 1
            rule = f'alert http any any -> any any (msg:"iSECTECH: HTTP request to known malicious domain {domain}"; http.host; content:"{domain}"; nocase; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
            rules.append(rule)
        
        return rules
    
    def generate_file_hash_rules(self, malicious_hashes: List[str]) -> List[str]:
        """Generate rules for malicious file hashes"""
        rules = []
        
        for file_hash in malicious_hashes:
            if len(file_hash) == 32:  # MD5
                self.sid_counter += 1
                rule = f'alert http any any -> any any (msg:"iSECTECH: Download of known malicious file (MD5: {file_hash})"; file.md5; content:"{file_hash}"; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
                rules.append(rule)
            elif len(file_hash) == 64:  # SHA256
                self.sid_counter += 1
                rule = f'alert http any any -> any any (msg:"iSECTECH: Download of known malicious file (SHA256: {file_hash[:16]}...)"; file.sha256; content:"{file_hash}"; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
                rules.append(rule)
        
        return rules
    
    def generate_yara_based_rules(self, yara_rules: List[str]) -> List[str]:
        """Convert YARA rules to Suricata format (simplified)"""
        rules = []
        
        for yara_rule in yara_rules:
            # Extract rule name and strings (simplified parsing)
            name_match = re.search(r'rule\s+(\w+)', yara_rule)
            if not name_match:
                continue
            
            rule_name = name_match.group(1)
            
            # Extract hex strings
            hex_strings = re.findall(r'\$\w+\s*=\s*\{\s*([a-fA-F0-9\s]+)\s*\}', yara_rule)
            
            for hex_string in hex_strings:
                hex_clean = hex_string.replace(' ', '').replace('\n', '')
                if len(hex_clean) >= 8:  # Minimum viable length
                    self.sid_counter += 1
                    rule = f'alert tcp any any -> any any (msg:"iSECTECH: {rule_name} malware signature detected"; content:"|{hex_clean}|"; reference:url,isectech.local/threat-intel; classtype:trojan-activity; sid:{self.sid_counter}; rev:1;)'
                    rules.append(rule)
        
        return rules

class RuleUpdateManager:
    """Manages automatic rule updates from multiple sources"""
    
    def __init__(self, config_path: str = "/etc/nsm/rule-sources.yaml"):
        self.config_path = config_path
        self.rule_sources: List[RuleSource] = []
        self.rule_directory = Path("/var/lib/suricata/rules")
        self.temp_directory = Path("/tmp/rule-updates")
        self.backup_directory = Path("/var/lib/suricata/rules/backups")
        
        # Ensure directories exist
        self.rule_directory.mkdir(parents=True, exist_ok=True)
        self.temp_directory.mkdir(parents=True, exist_ok=True)
        self.backup_directory.mkdir(parents=True, exist_ok=True)
        
        self.load_sources()
        
        # Initialize components
        self.performance_analyzer = RulePerformanceAnalyzer()
        self.intel_generator = ThreatIntelligenceRuleGenerator()
    
    def load_sources(self):
        """Load rule sources configuration"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            self.rule_sources = [
                RuleSource(**source) for source in config.get('sources', [])
            ]
            logger.info(f"Loaded {len(self.rule_sources)} rule sources")
            
        except FileNotFoundError:
            logger.warning(f"Configuration file {self.config_path} not found, using defaults")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default rule sources configuration"""
        default_sources = [
            {
                'name': 'emerging_threats',
                'url': 'https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz',
                'format': 'suricata',
                'priority': 1,
                'enabled': True,
                'update_frequency': 3600
            },
            {
                'name': 'suricata_update',
                'url': 'https://www.openinfosecfoundation.org/rules/index.yaml',
                'format': 'suricata',
                'priority': 2,
                'enabled': True,
                'update_frequency': 7200
            },
            {
                'name': 'abuse_ch_sslbl',
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.rules',
                'format': 'suricata',
                'priority': 3,
                'enabled': True,
                'update_frequency': 1800
            },
            {
                'name': 'isectech_custom',
                'url': 'file:///etc/nsm/custom-rules/',
                'format': 'suricata',
                'priority': 0,  # Highest priority
                'enabled': True,
                'update_frequency': 300
            }
        ]
        
        config = {'sources': default_sources}
        
        # Create config directory if it doesn't exist
        Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        self.rule_sources = [RuleSource(**source) for source in default_sources]
    
    async def download_rules(self, source: RuleSource) -> Optional[Path]:
        """Download rules from a source"""
        try:
            if source.url.startswith('file://'):
                # Local file source
                local_path = Path(source.url[7:])
                if local_path.exists():
                    return local_path
                else:
                    logger.warning(f"Local source path {local_path} does not exist")
                    return None
            
            # Download from URL
            temp_file = self.temp_directory / f"{source.name}_{int(time.time())}"
            
            async with aiohttp.ClientSession() as session:
                headers = {}
                if source.auth_required and source.api_key:
                    headers['Authorization'] = f"Bearer {source.api_key}"
                
                async with session.get(source.url, headers=headers) as response:
                    if response.status == 200:
                        async with aiofiles.open(temp_file, 'wb') as f:
                            async for chunk in response.content.iter_chunked(8192):
                                await f.write(chunk)
                        
                        logger.info(f"Downloaded rules from {source.name}")
                        return temp_file
                    else:
                        logger.error(f"Failed to download from {source.name}: HTTP {response.status}")
                        return None
                        
        except Exception as e:
            logger.error(f"Error downloading from {source.name}: {e}")
            return None
    
    def extract_rules(self, file_path: Path, source: RuleSource) -> List[str]:
        """Extract rules from downloaded file"""
        rules = []
        
        try:
            if file_path.suffix == '.gz':
                if file_path.name.endswith('.tar.gz'):
                    # Extract tar.gz archive
                    with tarfile.open(file_path, 'r:gz') as tar:
                        for member in tar.getmembers():
                            if member.isfile() and member.name.endswith('.rules'):
                                content = tar.extractfile(member).read().decode('utf-8')
                                rules.extend(self._parse_rule_content(content))
                else:
                    # Extract gzip file
                    with gzip.open(file_path, 'rt') as f:
                        content = f.read()
                        rules.extend(self._parse_rule_content(content))
            else:
                # Regular text file
                with open(file_path, 'r') as f:
                    content = f.read()
                    rules.extend(self._parse_rule_content(content))
                    
        except Exception as e:
            logger.error(f"Error extracting rules from {file_path}: {e}")
        
        return rules
    
    def _parse_rule_content(self, content: str) -> List[str]:
        """Parse rule content and return list of rules"""
        rules = []
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
                
            # Basic rule validation
            if re.match(r'^(alert|drop|pass|reject)', line):
                rules.append(line)
        
        return rules
    
    def validate_rules(self, rules: List[str]) -> Tuple[List[str], List[str]]:
        """Validate rules and return valid and invalid lists"""
        valid_rules = []
        invalid_rules = []
        
        for rule in rules:
            if self._validate_single_rule(rule):
                valid_rules.append(rule)
            else:
                invalid_rules.append(rule)
                
        return valid_rules, invalid_rules
    
    def _validate_single_rule(self, rule: str) -> bool:
        """Validate a single Suricata rule"""
        try:
            # Basic syntax validation
            parts = rule.split('(', 1)
            if len(parts) != 2:
                return False
            
            header = parts[0].strip()
            options = parts[1].rstrip(')')
            
            # Validate header format: action protocol src_ip src_port direction dst_ip dst_port
            header_parts = header.split()
            if len(header_parts) != 7:
                return False
            
            action, protocol, src_ip, src_port, direction, dst_ip, dst_port = header_parts
            
            # Validate action
            if action not in ['alert', 'drop', 'pass', 'reject']:
                return False
            
            # Validate direction
            if direction not in ['->', '<>', '<-']:
                return False
            
            # Validate required options (msg and sid)
            if 'msg:' not in options or 'sid:' not in options:
                return False
            
            return True
            
        except Exception:
            return False
    
    def optimize_rules(self, rules: List[str]) -> List[str]:
        """Optimize rules for performance"""
        optimized_rules = []
        
        for rule in rules:
            # Apply optimization techniques
            optimized_rule = self._optimize_single_rule(rule)
            optimized_rules.append(optimized_rule)
        
        return optimized_rules
    
    def _optimize_single_rule(self, rule: str) -> str:
        """Optimize a single rule for performance"""
        # Add fast_pattern to content matches where appropriate
        if 'content:' in rule and 'fast_pattern' not in rule:
            # Find the first substantial content match
            content_matches = re.findall(r'content:"([^"]+)"', rule)
            if content_matches:
                longest_content = max(content_matches, key=len)
                if len(longest_content) >= 4:
                    # Add fast_pattern to the longest content
                    rule = rule.replace(f'content:"{longest_content}"', f'content:"{longest_content}"; fast_pattern')
        
        return rule
    
    def merge_rules(self, rule_sets: Dict[str, List[str]]) -> List[str]:
        """Merge rules from multiple sources, handling conflicts"""
        merged_rules = []
        seen_sids = set()
        
        # Sort sources by priority (lower number = higher priority)
        sorted_sources = sorted(self.rule_sources, key=lambda x: x.priority)
        
        for source in sorted_sources:
            if source.name not in rule_sets:
                continue
                
            for rule in rule_sets[source.name]:
                # Extract SID
                sid_match = re.search(r'sid:(\d+)', rule)
                if sid_match:
                    sid = int(sid_match.group(1))
                    
                    if sid not in seen_sids:
                        merged_rules.append(rule)
                        seen_sids.add(sid)
                    else:
                        logger.warning(f"Duplicate SID {sid} found, skipping rule from {source.name}")
                else:
                    # Rule without SID, add it anyway
                    merged_rules.append(rule)
        
        return merged_rules
    
    def backup_current_rules(self):
        """Backup current rule files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_directory / f"rules_backup_{timestamp}"
        backup_path.mkdir(exist_ok=True)
        
        for rule_file in self.rule_directory.glob("*.rules"):
            shutil.copy2(rule_file, backup_path)
        
        logger.info(f"Rules backed up to {backup_path}")
        
        # Clean old backups (keep last 10)
        backups = sorted(self.backup_directory.glob("rules_backup_*"))
        while len(backups) > 10:
            oldest = backups.pop(0)
            shutil.rmtree(oldest)
    
    def write_rules(self, rules: List[str], filename: str = "isectech-managed.rules"):
        """Write rules to file"""
        output_path = self.rule_directory / filename
        
        with open(output_path, 'w') as f:
            f.write("# iSECTECH Managed Rules\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Total rules: {len(rules)}\n\n")
            
            for rule in rules:
                f.write(rule + '\n')
        
        logger.info(f"Wrote {len(rules)} rules to {output_path}")
    
    def reload_suricata(self):
        """Reload Suricata configuration"""
        try:
            # Send USR2 signal to reload rules
            subprocess.run(['pkill', '-USR2', 'suricata'], check=True)
            logger.info("Suricata rules reloaded successfully")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to reload Suricata: {e}")
            raise
    
    def test_rules(self, rules_file: str) -> bool:
        """Test rules with Suricata before deployment"""
        try:
            # Test configuration
            result = subprocess.run([
                'suricata', '-T', '-c', '/etc/suricata/suricata.yaml',
                '-S', str(self.rule_directory / rules_file)
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Rules in {rules_file} passed validation")
                return True
            else:
                logger.error(f"Rules validation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing rules: {e}")
            return False
    
    async def update_all_sources(self):
        """Update rules from all enabled sources"""
        logger.info("Starting rule update process")
        
        # Backup current rules
        self.backup_current_rules()
        
        rule_sets = {}
        
        # Download and process each source
        for source in self.rule_sources:
            if not source.enabled:
                continue
            
            # Check if update is needed
            if (source.last_updated and 
                datetime.now() - source.last_updated < timedelta(seconds=source.update_frequency)):
                logger.debug(f"Skipping {source.name}, not due for update")
                continue
            
            logger.info(f"Updating rules from {source.name}")
            
            # Download rules
            file_path = await self.download_rules(source)
            if not file_path:
                continue
            
            # Extract rules
            rules = self.extract_rules(file_path, source)
            
            # Validate rules
            valid_rules, invalid_rules = self.validate_rules(rules)
            
            if invalid_rules:
                logger.warning(f"Found {len(invalid_rules)} invalid rules in {source.name}")
            
            # Optimize rules
            optimized_rules = self.optimize_rules(valid_rules)
            
            rule_sets[source.name] = optimized_rules
            
            # Update source metadata
            source.last_updated = datetime.now()
            source.rule_count = len(optimized_rules)
            
            # Clean up temp file
            if file_path.exists() and file_path.parent == self.temp_directory:
                file_path.unlink()
        
        # Generate threat intelligence rules
        logger.info("Generating threat intelligence rules")
        intel_rules = await self._generate_intel_rules()
        if intel_rules:
            rule_sets['threat_intelligence'] = intel_rules
        
        # Merge all rule sets
        merged_rules = self.merge_rules(rule_sets)
        
        # Write merged rules
        self.write_rules(merged_rules)
        
        # Test rules before deployment
        if self.test_rules("isectech-managed.rules"):
            # Reload Suricata
            self.reload_suricata()
            logger.info(f"Rule update completed successfully. Total rules: {len(merged_rules)}")
        else:
            logger.error("Rule validation failed, keeping previous rules")
            # Restore from backup if needed
            self._restore_from_backup()
    
    async def _generate_intel_rules(self) -> List[str]:
        """Generate rules from threat intelligence"""
        intel_rules = []
        
        try:
            # This would integrate with your threat intelligence system
            # For now, simulate with some example indicators
            
            # Malicious IPs (would come from threat intel feeds)
            malicious_ips = [
                "192.0.2.100",  # Example IPs
                "198.51.100.50"
            ]
            
            # Malicious domains
            malicious_domains = [
                "evil.example.com",
                "malware.badsite.org"
            ]
            
            # Generate rules
            intel_rules.extend(self.intel_generator.generate_ip_reputation_rules(malicious_ips))
            intel_rules.extend(self.intel_generator.generate_domain_reputation_rules(malicious_domains))
            
        except Exception as e:
            logger.error(f"Error generating threat intelligence rules: {e}")
        
        return intel_rules
    
    def _restore_from_backup(self):
        """Restore rules from the most recent backup"""
        backups = sorted(self.backup_directory.glob("rules_backup_*"))
        if backups:
            latest_backup = backups[-1]
            for backup_file in latest_backup.glob("*.rules"):
                shutil.copy2(backup_file, self.rule_directory)
            logger.info(f"Restored rules from backup: {latest_backup}")
        else:
            logger.error("No backups available for restore")

async def main():
    """Main function for rule management"""
    manager = RuleUpdateManager()
    
    # Update all rule sources
    await manager.update_all_sources()
    
    # Performance analysis
    analyzer = manager.performance_analyzer
    low_performing = analyzer.get_low_performing_rules()
    if low_performing:
        logger.info(f"Found {len(low_performing)} low-performing rules: {low_performing[:10]}")
    
    high_performing = analyzer.get_high_performing_rules()
    logger.info(f"Found {len(high_performing)} high-performing rules")

if __name__ == "__main__":
    asyncio.run(main())