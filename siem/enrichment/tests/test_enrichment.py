#!/usr/bin/env python3
"""
Test Suite for iSECTECH SIEM Log Enrichment
Comprehensive validation of enrichment accuracy, performance, and reliability
Production-grade test framework for enrichment validation
"""

import asyncio
import json
import pytest
import yaml
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch, AsyncMock
import sys
import os
import time

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_enrichment_engine import LogEnrichmentEngine, EnrichmentConfig, EnrichmentResult
from threat_intel_feeds import ThreatIntelligenceFeedManager, ThreatFeedConfig, ThreatIndicator

class TestLogEnrichment:
    """Test suite for log enrichment engine"""
    
    @pytest.fixture
    async def enrichment_engine(self):
        """Create a test enrichment engine instance"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test asset inventory
            asset_inventory = {
                "assets": [
                    {
                        "asset_id": "ASSET-001",
                        "hostname": "WORKSTATION01",
                        "ip_addresses": ["192.168.1.100"],
                        "asset_type": "workstation",
                        "operating_system": "Windows 11",
                        "owner": "test.user@isectech.com",
                        "business_unit": "Engineering",
                        "criticality": "medium",
                        "location": "Test Office",
                        "compliance_tags": ["ISO27001"],
                        "last_updated": "2024-01-15T10:00:00Z"
                    },
                    {
                        "asset_id": "ASSET-002",
                        "hostname": "DB-SERVER-01",
                        "ip_addresses": ["192.168.2.100"],
                        "asset_type": "database_server",
                        "operating_system": "Linux",
                        "owner": "db.admin@isectech.com",
                        "business_unit": "IT Operations",
                        "criticality": "critical",
                        "location": "Data Center",
                        "compliance_tags": ["SOX", "PCI-DSS"],
                        "last_updated": "2024-01-15T10:00:00Z"
                    }
                ]
            }
            
            asset_file = temp_path / "asset_inventory.json"
            with open(asset_file, 'w') as f:
                json.dump(asset_inventory, f)
                
            # Create test network topology
            network_topology = {
                "network_segments": [
                    {
                        "subnet": "192.168.1.0/24",
                        "vlan_id": "100",
                        "network_zone": "corporate_workstations",
                        "network_type": "internal",
                        "security_level": "medium",
                        "gateway": "192.168.1.1"
                    },
                    {
                        "subnet": "192.168.2.0/24",
                        "vlan_id": "200",
                        "network_zone": "database_servers",
                        "network_type": "internal",
                        "security_level": "critical",
                        "gateway": "192.168.2.1"
                    }
                ]
            }
            
            network_file = temp_path / "network_topology.json"
            with open(network_file, 'w') as f:
                json.dump(network_topology, f)
                
            # Create ECS mapping config (minimal)
            ecs_mapping = {
                "version": "8.11.0",
                "event_fields": {},
                "transformations": {},
                "validation": {}
            }
            
            ecs_file = temp_path / "ecs_mapping.yaml"
            with open(ecs_file, 'w') as f:
                yaml.dump(ecs_mapping, f)
                
            # Create enrichment config
            config = EnrichmentConfig(
                asset_inventory_file=str(asset_file),
                network_topology_file=str(network_file),
                enable_geoip=False,
                enable_dns_lookup=False,
                enable_user_agent=False,
                cache_ttl_seconds=300
            )
            
            engine = LogEnrichmentEngine(config)
            await engine.initialize()
            yield engine
            await engine.cleanup()

class TestAssetEnrichment:
    """Test asset inventory enrichment"""
    
    @pytest.mark.asyncio
    async def test_hostname_asset_enrichment(self, enrichment_engine):
        """Test asset enrichment by hostname"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "login",
            "host.name": "WORKSTATION01"
        }
        
        result = await enrichment_engine.enrich_log(log_entry)
        
        assert result is not None
        assert "asset_inventory" in result.enrichment_sources
        assert result.enriched_fields.get("asset.id") == "ASSET-001"
        assert result.enriched_fields.get("asset.type") == "workstation"
        assert result.enriched_fields.get("asset.criticality") == "medium"
        assert result.enriched_fields.get("asset.business_unit") == "Engineering"
        
    @pytest.mark.asyncio
    async def test_ip_address_asset_enrichment(self, enrichment_engine):
        """Test asset enrichment by IP address"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "connection",
            "source.ip": "192.168.2.100"
        }
        
        result = await enrichment_engine.enrich_log(log_entry)
        
        assert result is not None
        assert "asset_inventory" in result.enrichment_sources
        assert result.enriched_fields.get("asset.id") == "ASSET-002"
        assert result.enriched_fields.get("asset.type") == "database_server"
        assert result.enriched_fields.get("asset.criticality") == "critical"
        assert "SOX" in result.enriched_fields.get("asset.compliance_tags", [])
        
    @pytest.mark.asyncio
    async def test_unknown_asset_no_enrichment(self, enrichment_engine):
        """Test no enrichment for unknown assets"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "login",
            "host.name": "UNKNOWN-HOST"
        }
        
        result = await enrichment_engine.enrich_log(log_entry)
        
        assert result is not None
        assert "asset_inventory" not in result.enrichment_sources
        assert "asset.id" not in result.enriched_fields

class TestThreatIntelEnrichment:
    """Test threat intelligence enrichment"""
    
    @pytest.mark.asyncio
    async def test_malicious_ip_enrichment(self, enrichment_engine):
        """Test threat intel enrichment for malicious IP"""
        # Mock threat intelligence lookup
        with patch.object(enrichment_engine, '_query_threat_feeds') as mock_query:
            mock_query.return_value = {
                "indicator": "203.0.113.100",
                "threat_type": "malware",
                "confidence_score": 90,
                "source": "test_feed",
                "first_seen": "2024-01-10T00:00:00Z",
                "last_seen": "2024-01-15T10:00:00Z",
                "description": "Known malicious IP"
            }
            
            log_entry = {
                "@timestamp": "2024-01-15T10:30:00Z",
                "event.action": "connection",
                "source.ip": "203.0.113.100"
            }
            
            result = await enrichment_engine.enrich_log(log_entry)
            
            assert result is not None
            assert "threat_intelligence" in result.enrichment_sources
            assert result.enriched_fields.get("threat.indicator.matched") is True
            assert result.enriched_fields.get("threat.indicator.confidence") == 90
            assert "malware" in result.enriched_fields.get("threat.indicator.types", [])
            
    @pytest.mark.asyncio
    async def test_clean_ip_no_enrichment(self, enrichment_engine):
        """Test no threat intel enrichment for clean IP"""
        with patch.object(enrichment_engine, '_query_threat_feeds') as mock_query:
            mock_query.return_value = None
            
            log_entry = {
                "@timestamp": "2024-01-15T10:30:00Z",
                "event.action": "connection",
                "source.ip": "8.8.8.8"
            }
            
            result = await enrichment_engine.enrich_log(log_entry)
            
            assert result is not None
            assert "threat_intelligence" not in result.enrichment_sources
            assert "threat.indicator.matched" not in result.enriched_fields

class TestUserContextEnrichment:
    """Test user context enrichment"""
    
    @pytest.mark.asyncio
    async def test_user_directory_enrichment(self, enrichment_engine):
        """Test user directory enrichment"""
        with patch.object(enrichment_engine, '_query_user_directory') as mock_query:
            mock_query.return_value = {
                "department": "IT Security",
                "job_title": "Security Analyst",
                "manager": "security.manager@isectech.com",
                "privileges": ["security_operator"],
                "groups": ["Security Team"],
                "risk_score": 25,
                "last_login": "2024-01-15T08:00:00Z"
            }
            
            log_entry = {
                "@timestamp": "2024-01-15T10:30:00Z",
                "event.action": "login",
                "user.name": "security.analyst"
            }
            
            result = await enrichment_engine.enrich_log(log_entry)
            
            assert result is not None
            assert "user_directory" in result.enrichment_sources
            assert result.enriched_fields.get("user.department") == "IT Security"
            assert result.enriched_fields.get("user.job_title") == "Security Analyst"
            assert "security_operator" in result.enriched_fields.get("user.privileges", [])
            assert result.enriched_fields.get("user.risk_score") == 25

class TestNetworkContextEnrichment:
    """Test network context enrichment"""
    
    @pytest.mark.asyncio
    async def test_network_zone_enrichment(self, enrichment_engine):
        """Test network zone enrichment"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "connection",
            "source.ip": "192.168.1.50",
            "destination.ip": "192.168.2.50"
        }
        
        result = await enrichment_engine.enrich_log(log_entry)
        
        assert result is not None
        assert "network_topology" in result.enrichment_sources
        assert result.enriched_fields.get("source.network.zone") == "corporate_workstations"
        assert result.enriched_fields.get("source.network.security_level") == "medium"
        assert result.enriched_fields.get("destination.network.zone") == "database_servers"
        assert result.enriched_fields.get("destination.network.security_level") == "critical"

class TestVulnerabilityEnrichment:
    """Test vulnerability data enrichment"""
    
    @pytest.mark.asyncio
    async def test_cve_enrichment(self, enrichment_engine):
        """Test CVE vulnerability enrichment"""
        with patch.object(enrichment_engine, '_query_vulnerability_db') as mock_query:
            mock_query.return_value = {
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.8,
                "severity": "critical",
                "description": "Remote code execution vulnerability",
                "exploits_available": True,
                "patches_available": True
            }
            
            log_entry = {
                "@timestamp": "2024-01-15T10:30:00Z",
                "event.action": "vulnerability_detected",
                "rule.name": "CVE-2024-1234 Detection Rule"
            }
            
            result = await enrichment_engine.enrich_log(log_entry)
            
            assert result is not None
            assert "vulnerability_database" in result.enrichment_sources
            assert "CVE-2024-1234" in result.enriched_fields.get("vulnerability.cve_ids", [])
            assert result.enriched_fields.get("vulnerability.max_cvss_score") == 9.8
            assert result.enriched_fields.get("vulnerability.exploits_available") is True

class TestBatchEnrichment:
    """Test batch enrichment functionality"""
    
    @pytest.mark.asyncio
    async def test_batch_enrichment_performance(self, enrichment_engine):
        """Test batch enrichment performance"""
        # Create batch of test logs
        log_entries = []
        for i in range(100):
            log_entry = {
                "@timestamp": "2024-01-15T10:30:00Z",
                "event.action": "test_action",
                "source.ip": f"192.168.1.{i % 254 + 1}",
                "user.name": f"test_user_{i}"
            }
            log_entries.append(log_entry)
            
        start_time = time.perf_counter()
        results = await enrichment_engine.enrich_batch(log_entries)
        end_time = time.perf_counter()
        
        processing_time = end_time - start_time
        throughput = len(results) / processing_time
        
        assert len(results) == 100
        assert throughput >= 50  # Should process at least 50 logs per second
        
        # Verify all logs were enriched
        for result in results:
            assert isinstance(result, EnrichmentResult)
            assert len(result.enrichment_sources) > 0

class TestEnrichmentMetadata:
    """Test enrichment metadata and versioning"""
    
    @pytest.mark.asyncio
    async def test_enrichment_metadata(self, enrichment_engine):
        """Test enrichment metadata fields"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "test",
            "host.name": "WORKSTATION01"
        }
        
        result = await enrichment_engine.enrich_log(log_entry)
        
        assert result is not None
        assert "enrichment.timestamp" in result.enriched_fields
        assert "enrichment.sources" in result.enriched_fields
        assert "enrichment.version" in result.enriched_fields
        assert result.enriched_fields["enrichment.version"] == "1.0.0"
        
        # Verify timestamp is recent
        enrichment_time = datetime.fromisoformat(result.enriched_fields["enrichment.timestamp"])
        time_diff = datetime.now(timezone.utc) - enrichment_time
        assert time_diff.total_seconds() < 10  # Should be within 10 seconds

class TestCaching:
    """Test enrichment caching functionality"""
    
    @pytest.mark.asyncio
    async def test_cache_hit_performance(self, enrichment_engine):
        """Test caching improves performance"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "test",
            "user.name": "test_user"
        }
        
        # Mock slow user directory lookup
        with patch.object(enrichment_engine, '_query_user_directory') as mock_query:
            mock_query.return_value = {
                "department": "Test Department",
                "job_title": "Test User"
            }
            
            # First enrichment - should hit external service
            start_time = time.perf_counter()
            result1 = await enrichment_engine.enrich_log(log_entry)
            first_time = time.perf_counter() - start_time
            
            # Second enrichment - should use cache
            start_time = time.perf_counter()
            result2 = await enrichment_engine.enrich_log(log_entry)
            second_time = time.perf_counter() - start_time
            
            # Cache should improve performance
            assert second_time < first_time
            assert mock_query.call_count == 1  # Should only call external service once
            
            # Results should be the same
            assert result1.enriched_fields.get("user.department") == result2.enriched_fields.get("user.department")

class TestErrorHandling:
    """Test error handling and resilience"""
    
    @pytest.mark.asyncio
    async def test_external_service_failure(self, enrichment_engine):
        """Test handling of external service failures"""
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "test",
            "user.name": "test_user"
        }
        
        # Mock external service failure
        with patch.object(enrichment_engine, '_query_user_directory') as mock_query:
            mock_query.side_effect = Exception("Service unavailable")
            
            result = await enrichment_engine.enrich_log(log_entry)
            
            # Should still return a result even with failures
            assert result is not None
            assert len(result.errors) > 0
            assert "Service unavailable" in result.errors[0]
            
    @pytest.mark.asyncio
    async def test_malformed_data_handling(self, enrichment_engine):
        """Test handling of malformed log data"""
        malformed_logs = [
            {},  # Empty log
            {"invalid": "data"},  # Missing required fields
            {"@timestamp": "invalid-timestamp"},  # Invalid timestamp
        ]
        
        for log_entry in malformed_logs:
            result = await enrichment_engine.enrich_log(log_entry)
            # Should handle gracefully without crashing
            assert result is not None

class TestThreatIntelFeeds:
    """Test threat intelligence feed management"""
    
    @pytest.fixture
    async def feed_manager(self):
        """Create test threat intelligence feed manager"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            test_config = {
                "threat_feeds": [
                    {
                        "feed_name": "test_feed",
                        "feed_url": "https://example.com/feed.json",
                        "feed_type": "json",
                        "confidence_weight": 0.8,
                        "enabled": True
                    }
                ]
            }
            yaml.dump(test_config, f)
            f.flush()
            
            manager = ThreatIntelligenceFeedManager(f.name)
            await manager.initialize()
            yield manager
            await manager.cleanup()
            
            os.unlink(f.name)
            
    @pytest.mark.asyncio
    async def test_indicator_detection(self, feed_manager):
        """Test IOC type detection"""
        test_cases = [
            ("192.168.1.100", "ip"),
            ("malicious.example.com", "domain"),
            ("https://evil.com/malware", "url"),
            ("d41d8cd98f00b204e9800998ecf8427e", "hash"),  # MD5
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash"),  # SHA1
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash"),  # SHA256
            ("evil@malicious.com", "email")
        ]
        
        for value, expected_type in test_cases:
            detected_type = feed_manager._detect_indicator_type(value)
            assert detected_type == expected_type, f"Failed to detect {value} as {expected_type}"
            
    @pytest.mark.asyncio
    async def test_feed_parsing(self, feed_manager):
        """Test different feed format parsing"""
        # Test JSON feed parsing
        json_feed_data = json.dumps([
            {
                "indicator": "192.168.1.100",
                "type": "ip",
                "threat_type": "malware",
                "confidence": 85
            }
        ])
        
        feed_config = ThreatFeedConfig(
            feed_url="test",
            feed_type="json",
            feed_name="test_json"
        )
        
        indicators = await feed_manager._parse_json_feed(json_feed_data, feed_config)
        
        assert len(indicators) == 1
        assert indicators[0].value == "192.168.1.100"
        assert indicators[0].indicator_type == "ip"
        assert indicators[0].confidence_score == int(85 * 1.0)  # confidence_weight = 1.0
        
        # Test CSV feed parsing
        csv_feed_data = "indicator,type,threat_type\n192.168.1.101,ip,botnet"
        
        csv_config = ThreatFeedConfig(
            feed_url="test",
            feed_type="csv",
            feed_name="test_csv"
        )
        
        indicators = await feed_manager._parse_csv_feed(csv_feed_data, csv_config)
        
        assert len(indicators) == 1
        assert indicators[0].value == "192.168.1.101"
        assert indicators[0].threat_type == "botnet"

class TestPerformance:
    """Test performance and scalability"""
    
    @pytest.mark.asyncio
    async def test_large_asset_inventory_performance(self, enrichment_engine):
        """Test performance with large asset inventory"""
        # Test with multiple asset lookups
        log_entries = []
        for i in range(1000):
            log_entry = {
                "@timestamp": "2024-01-15T10:30:00Z",
                "event.action": "test",
                "source.ip": f"192.168.{i % 254 + 1}.{i % 254 + 1}"
            }
            log_entries.append(log_entry)
            
        start_time = time.perf_counter()
        results = await enrichment_engine.enrich_batch(log_entries)
        end_time = time.perf_counter()
        
        processing_time = end_time - start_time
        avg_time_per_log = processing_time / len(results)
        
        # Should process each log in reasonable time
        assert avg_time_per_log < 0.1  # Less than 100ms per log
        assert len(results) == 1000
        
    @pytest.mark.asyncio
    async def test_concurrent_enrichment(self, enrichment_engine):
        """Test concurrent enrichment operations"""
        async def enrich_batch():
            log_entries = [
                {
                    "@timestamp": "2024-01-15T10:30:00Z",
                    "event.action": "test",
                    "host.name": f"HOST-{i}"
                }
                for i in range(10)
            ]
            return await enrichment_engine.enrich_batch(log_entries)
            
        # Run multiple concurrent batches
        tasks = [enrich_batch() for _ in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All batches should complete successfully
        assert len(results) == 5
        for batch_results in results:
            assert len(batch_results) == 10

class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_enrichment(self, enrichment_engine):
        """Test complete end-to-end enrichment"""
        # Complex log entry with multiple enrichment opportunities
        log_entry = {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "malware_detection",
            "host.name": "WORKSTATION01",
            "source.ip": "203.0.113.100",  # External IP
            "destination.ip": "192.168.2.100",  # Database server
            "user.name": "admin",
            "file.hash.sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "rule.name": "CVE-2024-1234 Exploit Detection"
        }
        
        # Mock external services
        with patch.object(enrichment_engine, '_query_threat_feeds') as mock_threat, \
             patch.object(enrichment_engine, '_query_user_directory') as mock_user, \
             patch.object(enrichment_engine, '_query_vulnerability_db') as mock_vuln:
            
            mock_threat.return_value = {
                "indicator": "203.0.113.100",
                "threat_type": "malware",
                "confidence_score": 95,
                "source": "test_feed"
            }
            
            mock_user.return_value = {
                "department": "IT Security",
                "privileges": ["admin"],
                "risk_score": 20
            }
            
            mock_vuln.return_value = {
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.8,
                "severity": "critical"
            }
            
            result = await enrichment_engine.enrich_log(log_entry)
            
            # Verify comprehensive enrichment
            assert result is not None
            assert len(result.enrichment_sources) >= 4  # asset, threat, user, network, vulnerability
            
            # Check specific enrichments
            assert result.enriched_fields.get("asset.criticality") == "medium"  # From WORKSTATION01
            assert result.enriched_fields.get("threat.indicator.matched") is True
            assert result.enriched_fields.get("user.department") == "IT Security"
            assert result.enriched_fields.get("destination.network.zone") == "database_servers"
            assert "CVE-2024-1234" in result.enriched_fields.get("vulnerability.cve_ids", [])
            
            # Check metadata
            assert "enrichment.timestamp" in result.enriched_fields
            assert "enrichment.sources" in result.enriched_fields
            assert result.processing_time_ms > 0

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])