"""
Unit Tests for Trust Scoring Engine

This module provides comprehensive unit tests for the FastAPI-based 
real-time trust scoring engine, validating functionality, performance, 
and error handling.
"""

import asyncio
import json
import pytest
import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import httpx

# Import the FastAPI app and dependencies
from ..api.trust_scoring_engine import app, get_trust_scoring_service, get_cache_service
from ..service.trust_scoring_service import TrustScoringService, TrustScoreResponse
from ..models.trust_calculator import TrustScoreResult, TrustLevel
from ..cache.redis_cache_service import RedisCacheService

@pytest.fixture
def mock_trust_service():
    """Mock trust scoring service."""
    service = AsyncMock(spec=TrustScoringService)
    
    # Mock successful trust score calculation
    mock_result = TrustScoreResult(
        entity_id="test_user",
        entity_type="user",
        trust_score=0.85,
        trust_level=TrustLevel.HIGH,
        confidence=0.92,
        data_sources=["behavioral_analysis", "device_management"],
        anomaly_indicators=[]
    )
    
    mock_response = TrustScoreResponse(
        request_id=str(uuid.uuid4()),
        trust_score_result=mock_result,
        processing_time_ms=45,
        cache_hit=False
    )
    
    service.calculate_trust_score.return_value = mock_response
    service.get_service_metrics.return_value = {
        "requests_processed": 100,
        "cache_hit_rate_percent": 75.5,
        "avg_processing_time_ms": 42.3,
        "error_count": 2
    }
    
    # Mock health check
    service.health_check.return_value = {
        "service": "trust_scoring",
        "status": "healthy",
        "checks": {
            "redis": "healthy",
            "behavior_collector": "healthy",
            "device_posture": "healthy"
        }
    }
    
    return service

@pytest.fixture
def mock_cache_service():
    """Mock cache service."""
    cache = AsyncMock(spec=RedisCacheService)
    cache.get_cache_statistics.return_value = {
        "total_operations": 1000,
        "cache_hits": 850,
        "cache_misses": 150,
        "hit_rate": 85.0,
        "memory_usage_mb": 128.5
    }
    cache.delete_from_cache.return_value = True
    return cache

@pytest.fixture
def client(mock_trust_service, mock_cache_service):
    """Test client with mocked dependencies."""
    
    app.dependency_overrides[get_trust_scoring_service] = lambda: mock_trust_service
    app.dependency_overrides[get_cache_service] = lambda: mock_cache_service
    
    yield TestClient(app)
    
    # Cleanup
    app.dependency_overrides.clear()

class TestHealthEndpoints:
    """Test health check and metrics endpoints."""
    
    def test_health_check_healthy(self, client):
        """Test health check with healthy services."""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data
        assert "checks" in data
        assert "metrics" in data
        
        # Verify individual checks
        assert data["checks"]["redis"] == "healthy"
        assert data["checks"]["behavior_collector"] == "healthy"
    
    def test_metrics_endpoint(self, client):
        """Test metrics endpoint."""
        response = client.get("/api/metrics")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "performance" in data
        assert "service_metrics" in data
        assert "cache_metrics" in data
        
        # Verify performance metrics structure
        perf_metrics = data["performance"]
        expected_keys = [
            "total_requests", "successful_requests", "error_count",
            "success_rate_percent", "cache_hit_rate_percent",
            "avg_response_time_ms", "p95_response_time_ms"
        ]
        for key in expected_keys:
            assert key in perf_metrics

class TestTrustScoreCalculation:
    """Test trust score calculation endpoints."""
    
    def test_calculate_trust_score_success(self, client):
        """Test successful trust score calculation."""
        request_data = {
            "entity_id": "test_user_123",
            "entity_type": "user",
            "user_id": "user_123",
            "device_id": "device_456",
            "tenant_id": "test_tenant",
            "current_ip": "192.168.1.100",
            "authentication_context": {
                "mfa_enabled": True,
                "session_encrypted": True
            },
            "network_context": {
                "is_corporate_network": True,
                "vpn_detected": False
            },
            "force_refresh": False,
            "include_trends": False,
            "include_risk_details": True
        }
        
        response = client.post("/api/trust-score/calculate", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "request_id" in data
        assert "entity_id" in data
        assert data["entity_id"] == "test_user_123"
        assert "trust_score" in data
        assert "trust_level" in data
        assert "confidence" in data
        assert "factor_scores" in data
        assert "risk_indicators" in data
        assert "risk_summary" in data
        assert "calculation_timestamp" in data
        assert "processing_time_ms" in data
        
        # Verify data types and ranges
        assert 0.0 <= data["trust_score"] <= 1.0
        assert 0.0 <= data["confidence"] <= 1.0
        assert isinstance(data["processing_time_ms"], int)
        assert isinstance(data["cache_hit"], bool)
    
    def test_calculate_trust_score_minimal_request(self, client):
        """Test trust score calculation with minimal request data."""
        request_data = {
            "entity_id": "minimal_user"
        }
        
        response = client.post("/api/trust-score/calculate", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["entity_id"] == "minimal_user"
        assert "trust_score" in data
        assert "trust_level" in data
    
    def test_calculate_trust_score_validation_error(self, client):
        """Test validation error with invalid entity type."""
        request_data = {
            "entity_id": "test_user",
            "entity_type": "invalid_type"  # Should fail validation
        }
        
        response = client.post("/api/trust-score/calculate", json=request_data)
        
        assert response.status_code == 422  # Validation error
        data = response.json()
        assert "detail" in data
    
    def test_calculate_trust_score_with_trends(self, client, mock_trust_service):
        """Test trust score calculation with trends requested."""
        # Mock trends data
        mock_trust_service.trust_calculator = MagicMock()
        mock_trust_service.trust_calculator.get_trust_trends.return_value = {
            "entity_id": "test_user",
            "current_score": 0.85,
            "avg_score": 0.82,
            "trend": "increasing",
            "volatility": 0.05
        }
        
        request_data = {
            "entity_id": "test_user",
            "include_trends": True
        }
        
        response = client.post("/api/trust-score/calculate", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        
        # Trends should be included when requested
        assert "trends" in data
        if data["trends"]:  # May be None if trends not available
            assert "entity_id" in data["trends"]
            assert "current_score" in data["trends"]

class TestBulkOperations:
    """Test bulk trust score calculation endpoints."""
    
    def test_bulk_calculate_success(self, client):
        """Test successful bulk trust score calculation."""
        bulk_requests = [
            {"entity_id": f"user_{i}", "entity_type": "user"}
            for i in range(5)
        ]
        
        request_data = {
            "requests": bulk_requests,
            "max_concurrent": 5,
            "timeout_seconds": 30
        }
        
        response = client.post("/api/trust-score/bulk", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify bulk response structure
        assert "batch_id" in data
        assert "total_requests" in data
        assert data["total_requests"] == 5
        assert "successful_responses" in data
        assert "failed_responses" in data
        assert "processing_time_ms" in data
        assert "cache_hit_rate" in data
        
        # Should have responses for all requests (mocked as successful)
        assert len(data["successful_responses"]) == 5
    
    def test_bulk_calculate_too_many_requests(self, client):
        """Test bulk calculation with too many requests."""
        bulk_requests = [
            {"entity_id": f"user_{i}"}
            for i in range(101)  # Exceeds max limit of 100
        ]
        
        request_data = {
            "requests": bulk_requests
        }
        
        response = client.post("/api/trust-score/bulk", json=request_data)
        
        assert response.status_code == 422  # Validation error
    
    def test_bulk_calculate_empty_requests(self, client):
        """Test bulk calculation with empty request list."""
        request_data = {
            "requests": []
        }
        
        response = client.post("/api/trust-score/bulk", json=request_data)
        
        assert response.status_code == 422  # Validation error

class TestPolicyDecision:
    """Test trust policy decision endpoint."""
    
    def test_policy_decision_allow(self, client, mock_trust_service):
        """Test policy decision that results in ALLOW."""
        # Mock high trust score
        mock_result = TrustScoreResult(
            entity_id="high_trust_user",
            entity_type="user",
            trust_score=0.9,  # High trust
            trust_level=TrustLevel.HIGH,
            confidence=0.95
        )
        
        mock_response = TrustScoreResponse(
            request_id=str(uuid.uuid4()),
            trust_score_result=mock_result,
            processing_time_ms=35
        )
        
        mock_trust_service.calculate_trust_score.return_value = mock_response
        
        response = client.post(
            "/api/trust-score/policy-decision",
            params={"entity_id": "high_trust_user"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["entity_id"] == "high_trust_user"
        assert data["decision"] == "ALLOW"
        assert data["trust_score"] == 0.9
        assert data["trust_level"] == "HIGH"
        assert "policy_matched" in data
        assert "expires_at" in data
    
    def test_policy_decision_deny(self, client, mock_trust_service):
        """Test policy decision that results in DENY."""
        # Mock low trust score
        mock_result = TrustScoreResult(
            entity_id="low_trust_user",
            entity_type="user",
            trust_score=0.2,  # Low trust
            trust_level=TrustLevel.LOW,
            confidence=0.8,
            anomaly_indicators=["suspicious_activity", "failed_logins"]
        )
        
        mock_response = TrustScoreResponse(
            request_id=str(uuid.uuid4()),
            trust_score_result=mock_result,
            processing_time_ms=42
        )
        
        mock_trust_service.calculate_trust_score.return_value = mock_response
        
        response = client.post(
            "/api/trust-score/policy-decision",
            params={"entity_id": "low_trust_user"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["entity_id"] == "low_trust_user"
        assert data["decision"] == "DENY"
        assert data["trust_score"] == 0.2
        assert data["trust_level"] == "LOW"
        assert "additional_actions" in data
        assert len(data["additional_actions"]) > 0  # Should have security actions

class TestUtilityEndpoints:
    """Test utility and management endpoints."""
    
    def test_get_trust_trends(self, client, mock_trust_service):
        """Test trust trends endpoint."""
        # Mock trends data
        mock_trust_service.trust_calculator = MagicMock()
        mock_trust_service.trust_calculator.get_trust_trends.return_value = {
            "entity_id": "test_user",
            "time_range_days": 7,
            "data_points": 50,
            "current_score": 0.85,
            "min_score": 0.72,
            "max_score": 0.91,
            "avg_score": 0.82,
            "volatility": 0.05,
            "trend": "increasing"
        }
        
        response = client.get("/api/trust-score/test_user/trends?days=7")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["entity_id"] == "test_user"
        assert data["time_range_days"] == 7
        assert "current_score" in data
        assert "trend" in data
    
    def test_clear_entity_cache(self, client, mock_cache_service):
        """Test cache clearing endpoint."""
        response = client.delete("/api/trust-score/test_user/cache")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["entity_id"] == "test_user"
        assert "cache_keys_cleared" in data
        assert "timestamp" in data
        
        # Verify cache service was called
        mock_cache_service.delete_from_cache.assert_called()
    
    def test_reset_metrics(self, client):
        """Test metrics reset endpoint."""
        response = client.post("/api/admin/reset-metrics")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "message" in data
        assert data["message"] == "Performance metrics reset"
        assert "timestamp" in data

class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_service_unavailable(self, client):
        """Test behavior when trust service is unavailable."""
        # Remove dependency override to simulate unavailable service
        app.dependency_overrides.clear()
        
        response = client.get("/api/health")
        
        assert response.status_code == 503
        data = response.json()
        assert "detail" in data
        assert "not initialized" in data["detail"].lower()
    
    def test_invalid_json_request(self, client):
        """Test handling of invalid JSON in request."""
        response = client.post(
            "/api/trust-score/calculate",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422
    
    def test_missing_required_fields(self, client):
        """Test handling of missing required fields."""
        response = client.post("/api/trust-score/calculate", json={})
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

class TestPerformanceCharacteristics:
    """Test performance-related characteristics."""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_handling(self, client):
        """Test handling of concurrent requests."""
        
        async def make_request():
            async with httpx.AsyncClient(app=app, base_url="http://test") as client:
                response = await client.post(
                    "/api/trust-score/calculate",
                    json={"entity_id": f"concurrent_user_{uuid.uuid4().hex[:8]}"}
                )
                return response.status_code
        
        # Make 10 concurrent requests
        with patch.object(app, 'dependency_overrides', {}):
            # Override dependencies for this test
            mock_service = AsyncMock(spec=TrustScoringService)
            mock_result = TrustScoreResult(
                entity_id="test",
                entity_type="user",
                trust_score=0.8,
                trust_level=TrustLevel.HIGH,
                confidence=0.9
            )
            mock_response = TrustScoreResponse(
                request_id=str(uuid.uuid4()),
                trust_score_result=mock_result,
                processing_time_ms=30
            )
            mock_service.calculate_trust_score.return_value = mock_response
            
            app.dependency_overrides[get_trust_scoring_service] = lambda: mock_service
            
            # Execute concurrent requests
            tasks = [make_request() for _ in range(10)]
            results = await asyncio.gather(*tasks)
            
            # All requests should succeed
            assert all(status == 200 for status in results)

@pytest.mark.integration
class TestIntegrationScenarios:
    """Integration test scenarios."""
    
    def test_end_to_end_trust_calculation(self, client):
        """Test complete end-to-end trust calculation flow."""
        request_data = {
            "entity_id": "e2e_test_user",
            "entity_type": "user", 
            "user_id": "user_123",
            "device_id": "device_456",
            "current_ip": "10.0.1.100",
            "authentication_context": {
                "mfa_enabled": True,
                "mfa_method": "totp",
                "session_encrypted": True,
                "recent_auth_success": True,
                "password_age_days": 45,
                "credential_strength_score": 0.8
            },
            "network_context": {
                "is_corporate_network": True,
                "vpn_detected": False,
                "geolocation_consistent": True,
                "ip_reputation_score": 0.9
            },
            "include_risk_details": True,
            "include_trends": False
        }
        
        # Calculate trust score
        response = client.post("/api/trust-score/calculate", json=request_data)
        assert response.status_code == 200
        
        trust_data = response.json()
        entity_id = trust_data["entity_id"]
        
        # Test policy decision based on trust score
        policy_response = client.post(
            "/api/trust-score/policy-decision",
            params={"entity_id": entity_id}
        )
        assert policy_response.status_code == 200
        
        policy_data = policy_response.json()
        
        # Verify consistency
        assert policy_data["entity_id"] == entity_id
        assert policy_data["trust_score"] == trust_data["trust_score"]
        assert policy_data["trust_level"] == trust_data["trust_level"]
    
    def test_cache_behavior_simulation(self, client, mock_trust_service):
        """Test cache hit/miss behavior simulation."""
        entity_id = "cache_test_user"
        
        # Mock cache miss first, then cache hit
        responses = [
            TrustScoreResponse(
                request_id=str(uuid.uuid4()),
                trust_score_result=TrustScoreResult(
                    entity_id=entity_id,
                    entity_type="user",
                    trust_score=0.8,
                    trust_level=TrustLevel.HIGH,
                    confidence=0.9
                ),
                processing_time_ms=85,
                cache_hit=False
            ),
            TrustScoreResponse(
                request_id=str(uuid.uuid4()),
                trust_score_result=TrustScoreResult(
                    entity_id=entity_id,
                    entity_type="user",
                    trust_score=0.8,
                    trust_level=TrustLevel.HIGH,
                    confidence=0.9
                ),
                processing_time_ms=15,
                cache_hit=True
            )
        ]
        
        mock_trust_service.calculate_trust_score.side_effect = responses
        
        request_data = {"entity_id": entity_id}
        
        # First request - cache miss
        response1 = client.post("/api/trust-score/calculate", json=request_data)
        assert response1.status_code == 200
        data1 = response1.json()
        assert data1["cache_hit"] == False
        
        # Second request - cache hit (simulated)
        response2 = client.post("/api/trust-score/calculate", json=request_data)
        assert response2.status_code == 200
        data2 = response2.json()
        assert data2["cache_hit"] == True
        assert data2["processing_time_ms"] < data1["processing_time_ms"]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])