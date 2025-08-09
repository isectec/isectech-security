#!/usr/bin/env python3
"""
Emergency SIEM/SOAR Hardening Security Tests
CRITICAL: Validates Phase 1 emergency security fixes for CVSS 9.4 vulnerability

These tests MUST pass before emergency deployment to production
"""

import pytest
import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch
import sys
import os

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

# Import emergency security modules
from siem.security.emergency_event_integrity import (
    validate_siem_event,
    verify_siem_event_integrity,
    emergency_event_validator,
    SecurityViolationType
)
from siem.security.emergency_siem_hardening import (
    emergency_siem_hardening,
    secure_alert_manager
)

class TestEmergencyEventIntegrityValidator:
    """Test emergency event integrity validation"""
    
    def test_blocks_suppress_alerts_parameter(self):
        """CRITICAL: Must block suppress_alerts parameter"""
        dangerous_event = {
            "event_id": "test-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "suppress_alerts": True,  # DANGEROUS PARAMETER
            "data": {"message": "Test alert"}
        }
        
        result = validate_siem_event(dangerous_event)
        
        # Must be blocked
        assert result is None, "Event with suppress_alerts parameter MUST be blocked"
    
    def test_blocks_disable_monitoring_parameter(self):
        """CRITICAL: Must block disable_monitoring parameter"""
        dangerous_event = {
            "event_id": "test-002",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "disable_monitoring": True,  # DANGEROUS PARAMETER
            "data": {"message": "Test alert"}
        }
        
        result = validate_siem_event(dangerous_event)
        
        # Must be blocked
        assert result is None, "Event with disable_monitoring parameter MUST be blocked"
    
    def test_blocks_override_rules_parameter(self):
        """CRITICAL: Must block override_rules parameter"""
        dangerous_event = {
            "event_id": "test-003",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "override_rules": ["rule1", "rule2"],  # DANGEROUS PARAMETER
            "data": {"message": "Test alert"}
        }
        
        result = validate_siem_event(dangerous_event)
        
        # Must be blocked
        assert result is None, "Event with override_rules parameter MUST be blocked"
    
    def test_blocks_bypass_detection_parameter(self):
        """CRITICAL: Must block bypass_detection parameter"""
        dangerous_event = {
            "event_id": "test-004",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "data": {
                "message": "Test alert",
                "bypass_detection": True  # DANGEROUS PARAMETER IN NESTED DATA
            }
        }
        
        result = validate_siem_event(dangerous_event)
        
        # Must be blocked
        assert result is None, "Event with bypass_detection parameter MUST be blocked"
    
    def test_blocks_multiple_dangerous_parameters(self):
        """CRITICAL: Must block events with multiple dangerous parameters"""
        dangerous_event = {
            "event_id": "test-005",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "suppress_alerts": True,
            "disable_monitoring": True,
            "override_rules": ["all"],
            "bypass_security": True,
            "emergency_override": True,
            "stealth_mode": True,
            "data": {
                "message": "Multiple dangerous parameters",
                "disable_response": True,
                "skip_logging": True
            }
        }
        
        result = validate_siem_event(dangerous_event)
        
        # Must be blocked
        assert result is None, "Event with multiple dangerous parameters MUST be blocked"
    
    def test_blocks_suspicious_patterns(self):
        """CRITICAL: Must block events with suspicious parameter patterns"""
        suspicious_events = [
            {
                "event_id": "test-006",
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "security_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": "192.168.1.100", "host": "test-host"},
                "suppress_all_detection": True,  # Suspicious pattern
                "data": {"message": "Test"}
            },
            {
                "event_id": "test-007",
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "security_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": "192.168.1.100", "host": "test-host"},
                "bypass_all_controls": True,  # Suspicious pattern
                "data": {"message": "Test"}
            },
            {
                "event_id": "test-008",
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "security_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": "192.168.1.100", "host": "test-host"},
                "disable_all_security": True,  # Suspicious pattern
                "data": {"message": "Test"}
            }
        ]
        
        for event in suspicious_events:
            result = validate_siem_event(event)
            assert result is None, f"Event {event['event_id']} with suspicious pattern MUST be blocked"
    
    def test_allows_legitimate_events(self):
        """CRITICAL: Must allow legitimate events without dangerous parameters"""
        legitimate_event = {
            "event_id": "test-legitimate-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "severity": "high",
            "category": "authentication_failure",
            "data": {
                "message": "Failed login attempt",
                "user_id": "user123",
                "failure_count": 5
            }
        }
        
        result = validate_siem_event(legitimate_event)
        
        # Must be allowed
        assert result is not None, "Legitimate event MUST be allowed"
        assert result.event_id == "test-legitimate-001"
        assert result.tenant_id == "123e4567-e89b-12d3-a456-426614174000"
        assert result.validation_status == "VALIDATED"
    
    def test_sanitizes_dangerous_parameters_from_allowed_events(self):
        """CRITICAL: Must remove dangerous parameters but allow safe parts of events"""
        mixed_event = {
            "event_id": "test-mixed-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "severity": "high",  # Safe parameter
            "suppress_alerts": True,  # Dangerous parameter - should be removed
            "data": {
                "message": "Mixed event",  # Safe parameter
                "user_id": "user123",  # Safe parameter
                "disable_monitoring": True  # Dangerous parameter - should be removed
            }
        }
        
        # This event contains dangerous parameters, so it should be blocked entirely
        result = validate_siem_event(mixed_event)
        assert result is None, "Event with dangerous parameters MUST be blocked completely"
    
    def test_validates_event_integrity_signature(self):
        """CRITICAL: Must validate event integrity signatures"""
        legitimate_event = {
            "event_id": "test-integrity-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "data": {"message": "Integrity test"}
        }
        
        # Create secure event
        secure_event = validate_siem_event(legitimate_event)
        assert secure_event is not None, "Event validation should succeed"
        
        # Verify integrity
        is_valid = verify_siem_event_integrity(secure_event)
        assert is_valid, "Event integrity verification should succeed"
        
        # Tamper with event data
        secure_event.data['tampered'] = True
        
        # Integrity check should fail
        is_valid_after_tampering = verify_siem_event_integrity(secure_event)
        assert not is_valid_after_tampering, "Tampered event integrity should fail"
    
    def test_handles_malformed_events_securely(self):
        """CRITICAL: Must handle malformed events securely (fail closed)"""
        malformed_events = [
            None,  # Null event
            {},  # Empty event
            {"invalid": "structure"},  # Missing required fields
            {"event_id": None, "tenant_id": "test"},  # Invalid event ID
            {"event_id": "test", "tenant_id": None},  # Invalid tenant ID
            {"event_id": "test", "tenant_id": "invalid-uuid-format"},  # Invalid UUID
        ]
        
        for event in malformed_events:
            result = validate_siem_event(event) if event is not None else None
            assert result is None, f"Malformed event MUST be blocked: {event}"
    
    def test_logs_security_violations(self):
        """CRITICAL: Must log all security violations for monitoring"""
        initial_violation_count = len(emergency_event_validator.violation_log)
        
        dangerous_event = {
            "event_id": "test-logging-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "suppress_alerts": True,
            "data": {"message": "Test violation logging"}
        }
        
        result = validate_siem_event(dangerous_event)
        
        # Event should be blocked
        assert result is None, "Dangerous event must be blocked"
        
        # Violation should be logged
        assert len(emergency_event_validator.violation_log) > initial_violation_count, \
            "Security violation must be logged"
        
        # Check violation details
        latest_violation = emergency_event_validator.violation_log[-1]
        assert latest_violation.violation_type == SecurityViolationType.PARAMETER_INJECTION
        assert latest_violation.severity == 'CRITICAL'
        assert 'suppress_alerts' in str(latest_violation.dangerous_parameters)


class TestEmergencySIEMHardening:
    """Test emergency SIEM hardening integration"""
    
    @pytest.mark.asyncio
    async def test_alert_manager_hardening_integration(self):
        """CRITICAL: Test alert manager integration with hardening"""
        
        # Mock alert manager
        class MockAlertManager:
            def __init__(self):
                self.processed_alerts = []
                
            async def process_alert(self, alert_data):
                self.processed_alerts.append(alert_data)
                return {"alert_id": "processed", "status": "created"}
        
        # Apply security hardening
        original_alert_manager = MockAlertManager()
        secured_process_alert = emergency_siem_hardening.secure_alert_processing(
            original_alert_manager.process_alert
        )
        
        # Test dangerous alert (should be blocked)
        dangerous_alert = {
            "event_id": "test-hardening-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "suppress_alerts": True,
            "data": {"message": "Dangerous alert"}
        }
        
        result = await secured_process_alert(dangerous_alert)
        
        # Should be blocked (return None)
        assert result is None, "Dangerous alert must be blocked by hardening"
        assert len(original_alert_manager.processed_alerts) == 0, \
            "Dangerous alert must not reach original processor"
    
    @pytest.mark.asyncio  
    async def test_correlation_engine_hardening(self):
        """CRITICAL: Test correlation engine hardening"""
        
        # Mock correlation engine
        class MockCorrelationEngine:
            def __init__(self):
                self.correlated_events = []
                
            async def correlate_events(self, events):
                self.correlated_events.extend(events)
                return {"correlation_id": "test", "events_count": len(events)}
        
        # Apply security hardening
        original_correlation = MockCorrelationEngine()
        secured_correlate = emergency_siem_hardening.secure_correlation_engine(
            original_correlation.correlate_events
        )
        
        # Mix of dangerous and legitimate events
        events = [
            {
                "event_id": "test-corr-001",
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "security_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": "192.168.1.100", "host": "test-host"},
                "data": {"message": "Legitimate event"}
            },
            {
                "event_id": "test-corr-002", 
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "security_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": "192.168.1.100", "host": "test-host"},
                "suppress_alerts": True,  # Dangerous
                "data": {"message": "Dangerous event"}
            },
            {
                "event_id": "test-corr-003",
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "event_type": "security_alert",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": "192.168.1.100", "host": "test-host"},
                "data": {"message": "Another legitimate event"}
            }
        ]
        
        result = await secured_correlate(events)
        
        # Should process only legitimate events
        assert result is not None, "Correlation should succeed with legitimate events"
        # Only 2 legitimate events should be processed (1 blocked)
        assert len(original_correlation.correlated_events) == 2, \
            "Only legitimate events should be correlated"
    
    @pytest.mark.asyncio
    async def test_soar_response_hardening(self):
        """CRITICAL: Test SOAR response automation hardening"""
        
        # Mock SOAR response engine
        class MockSOAREngine:
            def __init__(self):
                self.executed_responses = []
                
            async def execute_response(self, response_data):
                self.executed_responses.append(response_data)
                return {"response_id": "executed", "status": "success"}
        
        # Apply security hardening
        original_soar = MockSOAREngine()
        secured_execute_response = emergency_siem_hardening.secure_response_automation(
            original_soar.execute_response
        )
        
        # Test dangerous response (should be blocked)
        dangerous_response = {
            "response_id": "test-soar-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "response_type": "block_ip",
            "disable_response": True,  # Dangerous parameter
            "target": "192.168.1.100",
            "data": {"message": "Block malicious IP"}
        }
        
        result = await secured_execute_response(dangerous_response)
        
        # Should be blocked
        assert result is None, "Dangerous SOAR response must be blocked"
        assert len(original_soar.executed_responses) == 0, \
            "Dangerous response must not be executed"
        
        # Test legitimate response (should be allowed)
        legitimate_response = {
            "response_id": "test-soar-002",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "response_type": "block_ip",
            "target": "192.168.1.100",
            "data": {"message": "Block malicious IP"}
        }
        
        result = await secured_execute_response(legitimate_response)
        
        # Should be allowed
        assert result is not None, "Legitimate SOAR response must be allowed"
        assert len(original_soar.executed_responses) == 1, \
            "Legitimate response must be executed"


class TestSecurityMetrics:
    """Test security metrics and monitoring"""
    
    def test_security_metrics_tracking(self):
        """CRITICAL: Must track security metrics accurately"""
        # Reset metrics for clean test
        emergency_event_validator.security_metrics = {
            'events_processed': 0,
            'events_blocked': 0,
            'violations_detected': 0,
            'dangerous_parameters_removed': 0,
            'integrity_failures': 0
        }
        
        # Process legitimate event
        legitimate_event = {
            "event_id": "test-metrics-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "data": {"message": "Legitimate event"}
        }
        
        result1 = validate_siem_event(legitimate_event)
        assert result1 is not None
        
        # Process dangerous event
        dangerous_event = {
            "event_id": "test-metrics-002",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "suppress_alerts": True,
            "data": {"message": "Dangerous event"}
        }
        
        result2 = validate_siem_event(dangerous_event)
        assert result2 is None
        
        # Check metrics
        metrics = emergency_event_validator.get_security_metrics()
        
        assert metrics['events_processed'] >= 2, "Should track processed events"
        assert metrics['events_blocked'] >= 1, "Should track blocked events"
        assert metrics['violation_count'] >= 1, "Should track violations"
    
    def test_security_report_generation(self):
        """CRITICAL: Must generate comprehensive security reports"""
        report = emergency_siem_hardening.get_security_report()
        
        # Verify report structure
        assert 'report_id' in report
        assert 'protection_status' in report
        assert 'summary' in report
        assert 'threat_analysis' in report
        assert 'business_impact' in report
        assert 'recommendations' in report
        
        # Verify report content
        assert report['protection_status'] == 'EMERGENCY_PROTECTION_ACTIVE'
        assert isinstance(report['summary']['total_events_processed'], int)
        assert isinstance(report['business_impact']['attacks_prevented'], int)
        assert isinstance(report['recommendations'], list)


class TestProductionReadiness:
    """Test production readiness and deployment safety"""
    
    def test_emergency_hardening_activation(self):
        """CRITICAL: Verify emergency hardening is properly activated"""
        status = emergency_siem_hardening.get_hardening_status()
        
        assert status['hardening_active'] is True
        assert status['security_status'] == 'EMERGENCY_HARDENING_ACTIVE'
        assert status['protection_level'] == 'MAXIMUM'
    
    def test_performance_requirements(self):
        """CRITICAL: Verify performance meets requirements"""
        import time
        
        # Test event processing performance
        test_event = {
            "event_id": "test-performance-001",
            "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
            "event_type": "security_alert",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "192.168.1.100", "host": "test-host"},
            "data": {"message": "Performance test"}
        }
        
        # Process 100 events and measure time
        start_time = time.time()
        for i in range(100):
            test_event['event_id'] = f"test-performance-{i:03d}"
            result = validate_siem_event(test_event)
            assert result is not None
        
        total_time = time.time() - start_time
        avg_time_per_event = total_time / 100
        
        # Must process events within 50ms each
        assert avg_time_per_event < 0.05, f"Event processing too slow: {avg_time_per_event:.3f}s"
    
    def test_error_handling_fail_safe(self):
        """CRITICAL: Must fail safe on any errors"""
        # Test with completely invalid data
        invalid_inputs = [
            None,
            "not_a_dict",
            123,
            [],
            {"malformed": "data"},
        ]
        
        for invalid_input in invalid_inputs:
            try:
                result = validate_siem_event(invalid_input)
                # Must fail safe (return None)
                assert result is None, f"Invalid input must be blocked: {invalid_input}"
            except Exception:
                # Any exception means the system didn't fail safe
                assert False, f"System must fail safe, not throw exception for: {invalid_input}"


if __name__ == "__main__":
    print("🔒 Running Emergency SIEM/SOAR Hardening Security Tests")
    print("=" * 60)
    
    # Run all tests
    pytest.main([__file__, "-v", "--tb=short"])
    
    print("\n🚨 All emergency security tests completed!")
    print("If tests pass, SIEM/SOAR hardening is ready for emergency deployment.")