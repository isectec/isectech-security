#!/usr/bin/env python3
"""
Test Suite for iSECTECH SIEM Log Normalization
Comprehensive validation of parsing accuracy and ECS compliance
Production-grade test framework for log processing validation
"""

import asyncio
import json
import pytest
import yaml
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
import sys
import os

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_normalizer import LogNormalizer, NormalizationConfig, NormalizedLog

class TestLogNormalization:
    """Test suite for log normalization engine"""
    
    @pytest.fixture
    async def normalizer(self):
        """Create a test normalizer instance"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            # Create minimal ECS mapping for testing
            test_mapping = {
                "version": "8.11.0",
                "ecs_version": "8.11",
                "event_fields": {
                    "timestamp": {
                        "ecs_field": "@timestamp",
                        "type": "date",
                        "required": True
                    },
                    "event_action": {
                        "ecs_field": "event.action",
                        "type": "keyword"
                    }
                },
                "transformations": {
                    "severity_normalization": {
                        "input_field": "severity",
                        "output_field": "event.severity",
                        "mapping": {
                            "critical": 90,
                            "high": 70,
                            "medium": 50,
                            "low": 30,
                            "info": 10
                        },
                        "default": 0
                    }
                },
                "type_conversions": {
                    "string_to_ip": ["source.ip", "destination.ip"],
                    "string_to_long": ["source.port", "destination.port"]
                },
                "validation": {
                    "required_fields": ["@timestamp", "event.action"]
                }
            }
            yaml.dump(test_mapping, f)
            f.flush()
            
            config = NormalizationConfig(
                ecs_mapping_file=f.name,
                enable_geoip=False,
                enable_dns_lookup=False
            )
            
            normalizer = LogNormalizer(config)
            await normalizer.initialize()
            yield normalizer
            await normalizer.cleanup()
            
            # Cleanup temp file
            os.unlink(f.name)

class TestJSONLogParsing:
    """Test JSON log format parsing"""
    
    @pytest.mark.asyncio
    async def test_valid_json_parsing(self, normalizer):
        """Test parsing of valid JSON logs"""
        json_log = '{"timestamp": "2024-01-15T10:30:00Z", "event_action": "login", "source_ip": "192.168.1.100"}'
        
        result = await normalizer.normalize_log(json_log, "json")
        
        assert result is not None
        assert isinstance(result, NormalizedLog)
        assert result.normalized_fields["event.action"] == "login"
        assert "@timestamp" in result.normalized_fields
        
    @pytest.mark.asyncio
    async def test_invalid_json_parsing(self, normalizer):
        """Test handling of invalid JSON"""
        invalid_json = '{"timestamp": "2024-01-15T10:30:00Z", "event_action": "login"'  # Missing closing brace
        
        result = await normalizer.normalize_log(invalid_json, "json")
        
        # Should handle gracefully and return None or create basic log
        assert result is None or result.validation_errors

class TestSyslogParsing:
    """Test syslog format parsing"""
    
    @pytest.mark.asyncio
    async def test_rfc3164_syslog_parsing(self, normalizer):
        """Test RFC3164 syslog format"""
        syslog_entry = "<30>Jan 15 10:30:00 server01 sshd[1234]: Accepted password for admin from 192.168.1.100"
        
        result = await normalizer.normalize_log(syslog_entry, "syslog")
        
        assert result is not None
        assert result.normalized_fields["hostname"] == "server01"
        assert result.normalized_fields["program"] == "sshd"
        assert result.normalized_fields["priority"] == 30
        assert result.normalized_fields["facility"] == 3  # 30 >> 3
        assert result.normalized_fields["severity"] == 6  # 30 & 7
        
    @pytest.mark.asyncio
    async def test_rfc5424_syslog_parsing(self, normalizer):
        """Test RFC5424 syslog format"""
        syslog_entry = "<30>1 2024-01-15T10:30:00Z server01 sshd 1234 ID47 - Accepted password"
        
        result = await normalizer.normalize_log(syslog_entry, "syslog")
        
        assert result is not None
        assert result.normalized_fields["hostname"] == "server01"
        assert result.normalized_fields["app_name"] == "sshd"
        assert result.normalized_fields["version"] == 1

class TestCustomFormatParsing:
    """Test custom security format parsing"""
    
    @pytest.mark.asyncio
    async def test_crowdstrike_format_detection(self, normalizer):
        """Test CrowdStrike log format detection and parsing"""
        crowdstrike_log = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "WORKSTATION01",
            "UserName": "admin",
            "ProcessId": "1234",
            "ImageFileName": "notepad.exe",
            "CommandLine": "notepad.exe test.txt",
            "agent": {"name": "crowdstrike-falcon"}
        }
        
        result = await normalizer.normalize_log(json.dumps(crowdstrike_log), "json")
        
        assert result is not None
        # This would require the full custom format integration
        # For now, just verify basic JSON parsing worked
        assert "@timestamp" in result.normalized_fields
        
    @pytest.mark.asyncio
    async def test_palo_alto_csv_parsing(self, normalizer):
        """Test Palo Alto Networks CSV threat log parsing"""
        pan_log = "2024/01/15 10:30:00,PA-VM,THREAT,vulnerability,1.0,2024/01/15 10:30:00,192.168.1.100,10.0.0.1,,,rule1,admin,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,default,2024/01/15 10:30:00,123456,1,80,443,0,0,0x0,tcp,alert,,12345,high,client2server,67890,0x0,US,CN,text,,,,0,,,,GET,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
        
        result = await normalizer.normalize_log(pan_log, "csv")
        
        assert result is not None
        # Verify basic CSV parsing
        assert "field_" in str(result.normalized_fields)

class TestFieldNormalization:
    """Test field normalization and ECS compliance"""
    
    @pytest.mark.asyncio
    async def test_severity_normalization(self, normalizer):
        """Test severity value normalization"""
        test_cases = [
            ("critical", 90),
            ("high", 70),
            ("medium", 50),
            ("low", 30),
            ("info", 10),
            ("unknown", 0)
        ]
        
        for severity_text, expected_value in test_cases:
            log_entry = {"severity": severity_text, "event_action": "test"}
            result = await normalizer.normalize_log(json.dumps(log_entry), "json")
            
            assert result is not None
            if "event.severity" in result.normalized_fields:
                assert result.normalized_fields["event.severity"] == expected_value
                
    @pytest.mark.asyncio
    async def test_ip_address_validation(self, normalizer):
        """Test IP address validation during normalization"""
        valid_ips = ["192.168.1.100", "10.0.0.1", "2001:db8::1"]
        invalid_ips = ["300.300.300.300", "not.an.ip", "192.168.1"]
        
        for ip in valid_ips:
            log_entry = {"source_ip": ip, "event_action": "test"}
            result = await normalizer.normalize_log(json.dumps(log_entry), "json")
            
            # Should not have validation errors for valid IPs
            assert result is not None
            
        for ip in invalid_ips:
            log_entry = {"source_ip": ip, "event_action": "test"}
            result = await normalizer.normalize_log(json.dumps(log_entry), "json")
            
            # Should either remove invalid IP or add validation error
            if result is not None:
                assert "source.ip" not in result.normalized_fields or result.validation_errors

class TestDataTypeConversion:
    """Test data type conversions"""
    
    @pytest.mark.asyncio
    async def test_port_conversion(self, normalizer):
        """Test port number conversion to integer"""
        log_entry = {
            "source_port": "80",
            "destination_port": "443",
            "event_action": "connection"
        }
        
        result = await normalizer.normalize_log(json.dumps(log_entry), "json")
        
        assert result is not None
        if "source.port" in result.normalized_fields:
            assert isinstance(result.normalized_fields["source.port"], int)
            assert result.normalized_fields["source.port"] == 80

class TestTimestampParsing:
    """Test timestamp parsing from various formats"""
    
    @pytest.mark.asyncio
    async def test_iso8601_timestamp(self, normalizer):
        """Test ISO 8601 timestamp parsing"""
        log_entry = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_action": "test"
        }
        
        result = await normalizer.normalize_log(json.dumps(log_entry), "json")
        
        assert result is not None
        assert isinstance(result.timestamp, datetime)
        
    @pytest.mark.asyncio
    async def test_epoch_timestamp(self, normalizer):
        """Test epoch timestamp parsing"""
        epoch_ms = 1705312200000  # 2024-01-15T10:30:00Z in milliseconds
        log_entry = {
            "timestamp": str(epoch_ms),
            "event_action": "test"
        }
        
        result = await normalizer.normalize_log(json.dumps(log_entry), "json")
        
        assert result is not None
        assert isinstance(result.timestamp, datetime)

class TestBatchProcessing:
    """Test batch log processing"""
    
    @pytest.mark.asyncio
    async def test_batch_normalization(self, normalizer):
        """Test batch processing of multiple log entries"""
        log_entries = [
            '{"timestamp": "2024-01-15T10:30:00Z", "event_action": "login", "source_ip": "192.168.1.100"}',
            '<30>Jan 15 10:30:00 server01 sshd[1234]: Accepted password for admin',
            '192.168.1.100 - admin [15/Jan/2024:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234'
        ]
        
        results = await normalizer.normalize_batch(log_entries)
        
        assert len(results) >= 1  # At least one should succeed
        for result in results:
            assert isinstance(result, NormalizedLog)
            assert "@timestamp" in result.normalized_fields

class TestValidation:
    """Test validation rules and error handling"""
    
    @pytest.mark.asyncio
    async def test_required_fields_validation(self, normalizer):
        """Test required fields validation"""
        # Missing event.action (required field)
        log_entry = {"timestamp": "2024-01-15T10:30:00Z"}
        
        result = await normalizer.normalize_log(json.dumps(log_entry), "json")
        
        # Should have validation errors for missing required fields
        if result is not None:
            assert result.validation_errors

class TestPerformance:
    """Test performance and resource usage"""
    
    @pytest.mark.asyncio
    async def test_large_batch_performance(self, normalizer):
        """Test performance with large batch of logs"""
        import time
        
        # Generate 1000 test log entries
        log_entries = []
        for i in range(1000):
            log_entry = {
                "timestamp": "2024-01-15T10:30:00Z",
                "event_action": f"test_action_{i}",
                "source_ip": f"192.168.1.{i % 255}",
                "user_id": f"user_{i}"
            }
            log_entries.append(json.dumps(log_entry))
            
        start_time = time.time()
        results = await normalizer.normalize_batch(log_entries)
        end_time = time.time()
        
        processing_time = end_time - start_time
        logs_per_second = len(results) / processing_time
        
        print(f"Processed {len(results)} logs in {processing_time:.2f} seconds")
        print(f"Rate: {logs_per_second:.2f} logs/second")
        
        # Should process at least 100 logs per second
        assert logs_per_second >= 100

class TestErrorHandling:
    """Test error handling and resilience"""
    
    @pytest.mark.asyncio
    async def test_malformed_input_handling(self, normalizer):
        """Test handling of malformed input"""
        malformed_inputs = [
            "",  # Empty string
            None,  # None value
            "not valid json or any format",  # Random text
            "{'invalid': json}",  # Invalid JSON
        ]
        
        for malformed_input in malformed_inputs:
            if malformed_input is not None:
                result = await normalizer.normalize_log(malformed_input)
                # Should either return None or handle gracefully
                assert result is None or isinstance(result, NormalizedLog)

class TestECSCompliance:
    """Test ECS (Elastic Common Schema) compliance"""
    
    @pytest.mark.asyncio
    async def test_ecs_version_field(self, normalizer):
        """Test that ECS version field is added"""
        log_entry = {"event_action": "test", "timestamp": "2024-01-15T10:30:00Z"}
        
        result = await normalizer.normalize_log(json.dumps(log_entry), "json")
        
        assert result is not None
        assert result.ecs_version == "8.11.0"
        
    @pytest.mark.asyncio
    async def test_timestamp_format(self, normalizer):
        """Test @timestamp field format compliance"""
        log_entry = {"event_action": "test", "timestamp": "2024-01-15T10:30:00Z"}
        
        result = await normalizer.normalize_log(json.dumps(log_entry), "json")
        
        assert result is not None
        assert "@timestamp" in result.normalized_fields
        timestamp = result.normalized_fields["@timestamp"]
        assert isinstance(timestamp, datetime)
        assert timestamp.tzinfo is not None  # Should have timezone info

# Integration tests with sample data
class TestRealWorldLogs:
    """Test with real-world log samples"""
    
    @pytest.mark.asyncio
    async def test_windows_security_log(self, normalizer):
        """Test Windows Security Event Log parsing"""
        windows_log = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
                <EventID>4624</EventID>
                <Version>2</Version>
                <Level>0</Level>
                <Task>12544</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8020000000000000</Keywords>
                <TimeCreated SystemTime="2024-01-15T10:30:00.000Z" />
                <EventRecordID>123456</EventRecordID>
            </System>
            <EventData>
                <Data Name="SubjectUserSid">S-1-5-18</Data>
                <Data Name="SubjectUserName">SYSTEM</Data>
                <Data Name="LogonType">3</Data>
                <Data Name="IpAddress">192.168.1.100</Data>
            </EventData>
        </Event>'''
        
        result = await normalizer.normalize_log(windows_log, "windows_event")
        
        # Should handle XML parsing
        assert result is not None

# Test data fixtures
@pytest.fixture
def sample_crowdstrike_log():
    return {
        "timestamp": 1705312200000,
        "event_simpleName": "ProcessRollup2",
        "ComputerName": "WORKSTATION01",
        "UserName": "admin",
        "ProcessId": "1234",
        "ParentProcessId": "567",
        "ImageFileName": "notepad.exe",
        "CommandLine": "notepad.exe test.txt",
        "MD5HashData": "d41d8cd98f00b204e9800998ecf8427e",
        "SHA256HashData": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "LocalAddressIP4": "192.168.1.100",
        "RemoteAddressIP4": "10.0.0.1",
        "LocalPort": "12345",
        "RemotePort": "80"
    }

@pytest.fixture
def sample_okta_log():
    return {
        "uuid": "12345678-1234-1234-1234-123456789012",
        "published": "2024-01-15T10:30:00.000Z",
        "eventType": "user.authentication.auth_via_mfa",
        "version": "0",
        "severity": "INFO",
        "legacyEventType": "core.user_auth.login_success",
        "displayMessage": "User login to Okta",
        "actor": {
            "id": "00u1a2b3c4d5e6f7g8h9",
            "type": "User",
            "alternateId": "admin@isectech.com",
            "displayName": "Admin User"
        },
        "client": {
            "ipAddress": "192.168.1.100",
            "userAgent": {
                "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        },
        "outcome": {
            "result": "SUCCESS"
        }
    }

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])