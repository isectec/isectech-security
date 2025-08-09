"""
Real-Time Trust Scoring Engine API
Production-grade FastAPI implementation for real-time trust score calculations

This module provides REST APIs for calculating trust scores in real-time with 
sub-100ms response times, supporting high-frequency access patterns and 
modular factor integration.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json
import redis.asyncio as aioredis
import uuid
from dataclasses import dataclass, asdict
from enum import Enum

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import uvicorn

from ..service.trust_scoring_service import (
    TrustScoringService, 
    TrustScoreRequest, 
    TrustScoreResponse
)
from ..models.trust_parameters import TrustScoreConfiguration, TrustLevel
from ..models.trust_calculator import TrustScoreResult
from ..cache.redis_cache_service import RedisCacheService

logger = logging.getLogger(__name__)

# Performance tracking
performance_metrics = {
    "total_requests": 0,
    "successful_requests": 0,
    "cache_hits": 0,
    "avg_response_time_ms": 0.0,
    "p95_response_time_ms": 0.0,
    "error_count": 0,
    "concurrent_requests": 0,
    "last_reset": datetime.utcnow()
}

response_times = []  # Store last 1000 response times for percentile calculations

# API Models
class TrustScoreCalculationRequest(BaseModel):
    """Request model for trust score calculation."""
    entity_id: str = Field(..., description="Unique identifier for the entity (user/device/session)")
    entity_type: str = Field(default="user", description="Type of entity: user, device, session")
    
    # Optional identifiers
    user_id: Optional[str] = Field(None, description="User identifier if entity is user-related")
    device_id: Optional[str] = Field(None, description="Device identifier")
    session_id: Optional[str] = Field(None, description="Session identifier")
    tenant_id: str = Field(default="default", description="Tenant identifier for multi-tenancy")
    
    # Context information
    current_ip: Optional[str] = Field(None, description="Current IP address of the entity")
    user_agent: Optional[str] = Field(None, description="User agent string")
    
    # Authentication context
    authentication_context: Optional[Dict[str, Any]] = Field(
        None, 
        description="Authentication context including MFA, session details"
    )
    
    # Network context
    network_context: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional network context information"
    )
    
    # Control flags
    force_refresh: bool = Field(default=False, description="Force refresh of all cached data")
    include_trends: bool = Field(default=False, description="Include historical trends in response")
    include_risk_details: bool = Field(default=True, description="Include detailed risk analysis")
    
    @validator('entity_type')
    def validate_entity_type(cls, v):
        allowed_types = ['user', 'device', 'session', 'application']
        if v not in allowed_types:
            raise ValueError(f'entity_type must be one of: {allowed_types}')
        return v

class TrustScoreResponse(BaseModel):
    """Response model for trust score calculation."""
    request_id: str
    entity_id: str
    trust_score: float = Field(..., ge=0.0, le=1.0, description="Trust score from 0.0 to 1.0")
    trust_level: str = Field(..., description="Human-readable trust level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the score")
    
    # Factor breakdown
    factor_scores: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Individual factor scores and details"
    )
    
    # Risk analysis
    risk_indicators: List[str] = Field(default_factory=list, description="Identified risk indicators")
    risk_summary: Dict[str, Any] = Field(default_factory=dict, description="Risk analysis summary")
    
    # Metadata
    calculation_timestamp: str
    processing_time_ms: int
    cache_hit: bool = Field(default=False, description="Whether result was served from cache")
    data_sources: List[str] = Field(default_factory=list, description="Data sources used")
    
    # Trends (optional)
    trends: Optional[Dict[str, Any]] = Field(None, description="Historical trends if requested")
    
    # Performance info
    ttl_seconds: int = Field(default=300, description="Time to live for caching this result")

class BulkTrustScoreRequest(BaseModel):
    """Request model for bulk trust score calculations."""
    requests: List[TrustScoreCalculationRequest] = Field(..., max_items=100)
    
    # Global options
    max_concurrent: int = Field(default=10, ge=1, le=50, description="Max concurrent calculations")
    timeout_seconds: int = Field(default=30, ge=1, le=300, description="Timeout for bulk operation")

class BulkTrustScoreResponse(BaseModel):
    """Response model for bulk trust score calculations."""
    batch_id: str
    total_requests: int
    successful_responses: List[TrustScoreResponse]
    failed_responses: List[Dict[str, Any]]
    processing_time_ms: int
    cache_hit_rate: float

class HealthCheckResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Overall health status")
    timestamp: str
    version: str = Field(default="1.0.0", description="API version")
    checks: Dict[str, str] = Field(default_factory=dict, description="Individual component health")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Performance metrics")

class TrustPolicyDecision(BaseModel):
    """Trust policy decision response."""
    entity_id: str
    decision: str = Field(..., description="ALLOW, DENY, or CHALLENGE")
    trust_score: float
    trust_level: str
    policy_matched: str = Field(..., description="Policy rule that was matched")
    additional_actions: List[str] = Field(default_factory=list)
    expires_at: Optional[str] = None

# Global services
trust_scoring_service: Optional[TrustScoringService] = None
redis_cache_service: Optional[RedisCacheService] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global trust_scoring_service, redis_cache_service
    
    logger.info("Starting Real-Time Trust Scoring Engine...")
    
    try:
        # Initialize Redis cache service
        redis_cache_service = RedisCacheService(
            redis_cluster_config={
                "host": "localhost",
                "port": 6379,
                "db": 4
            }
        )
        await redis_cache_service.initialize()
        
        # Initialize trust scoring service with production config
        config = TrustScoreConfiguration.create_production_config()
        
        # Get Redis client from cache service
        redis_client = redis_cache_service.redis_client
        
        trust_scoring_service = TrustScoringService(
            config=config,
            redis_client=redis_client,
            tenant_id="default"
        )
        
        logger.info("Trust Scoring Engine initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize Trust Scoring Engine: {e}")
        raise
    
    yield
    
    logger.info("Shutting down Trust Scoring Engine...")
    
    # Cleanup
    if redis_cache_service:
        await redis_cache_service.close()

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="iSECTECH Real-Time Trust Scoring Engine",
    description="Production-grade trust scoring API for continuous verification and zero trust architecture",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

@app.middleware("http")
async def performance_middleware(request: Request, call_next):
    """Middleware to track performance metrics."""
    global performance_metrics, response_times
    
    start_time = time.time()
    performance_metrics["concurrent_requests"] += 1
    performance_metrics["total_requests"] += 1
    
    try:
        response = await call_next(request)
        
        # Track successful requests
        if 200 <= response.status_code < 400:
            performance_metrics["successful_requests"] += 1
        else:
            performance_metrics["error_count"] += 1
        
        return response
        
    except Exception as e:
        performance_metrics["error_count"] += 1
        logger.error(f"Request failed: {e}")
        raise
    finally:
        # Calculate response time
        response_time_ms = int((time.time() - start_time) * 1000)
        response_times.append(response_time_ms)
        
        # Keep only last 1000 response times for percentile calculation
        if len(response_times) > 1000:
            response_times = response_times[-1000:]
        
        # Update average response time
        performance_metrics["avg_response_time_ms"] = sum(response_times) / len(response_times)
        
        # Calculate 95th percentile
        if response_times:
            sorted_times = sorted(response_times)
            p95_index = int(0.95 * len(sorted_times))
            performance_metrics["p95_response_time_ms"] = sorted_times[p95_index]
        
        performance_metrics["concurrent_requests"] -= 1

def get_trust_scoring_service() -> TrustScoringService:
    """Dependency to get trust scoring service."""
    if trust_scoring_service is None:
        raise HTTPException(
            status_code=503, 
            detail="Trust scoring service not initialized"
        )
    return trust_scoring_service

def get_cache_service() -> RedisCacheService:
    """Dependency to get cache service."""
    if redis_cache_service is None:
        raise HTTPException(
            status_code=503, 
            detail="Cache service not initialized"
        )
    return redis_cache_service

@app.get("/api/health", response_model=HealthCheckResponse)
async def health_check(
    service: TrustScoringService = Depends(get_trust_scoring_service),
    cache: RedisCacheService = Depends(get_cache_service)
) -> HealthCheckResponse:
    """Comprehensive health check endpoint."""
    
    health_status = "healthy"
    checks = {}
    
    try:
        # Check trust scoring service health
        service_health = await service.health_check()
        checks.update(service_health["checks"])
        
        if service_health["status"] != "healthy":
            health_status = "degraded"
        
        # Check cache service health
        cache_stats = await cache.get_cache_statistics()
        checks["redis_cache"] = "healthy" if cache_stats else "degraded"
        
        if not cache_stats:
            health_status = "degraded"
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        health_status = "unhealthy"
        checks["system"] = f"error: {e}"
    
    return HealthCheckResponse(
        status=health_status,
        timestamp=datetime.utcnow().isoformat(),
        checks=checks,
        metrics=get_performance_metrics()
    )

@app.get("/api/metrics")
async def get_metrics():
    """Get detailed performance metrics."""
    return {
        "performance": get_performance_metrics(),
        "service_metrics": trust_scoring_service.get_service_metrics() if trust_scoring_service else {},
        "cache_metrics": await redis_cache_service.get_cache_statistics() if redis_cache_service else {}
    }

def get_performance_metrics() -> Dict[str, Any]:
    """Get current performance metrics."""
    global performance_metrics
    
    uptime_seconds = (datetime.utcnow() - performance_metrics["last_reset"]).total_seconds()
    success_rate = (
        performance_metrics["successful_requests"] / 
        max(performance_metrics["total_requests"], 1) * 100
    )
    cache_hit_rate = (
        performance_metrics["cache_hits"] / 
        max(performance_metrics["total_requests"], 1) * 100
    )
    
    return {
        "total_requests": performance_metrics["total_requests"],
        "successful_requests": performance_metrics["successful_requests"],
        "error_count": performance_metrics["error_count"],
        "success_rate_percent": round(success_rate, 2),
        "cache_hit_rate_percent": round(cache_hit_rate, 2),
        "concurrent_requests": performance_metrics["concurrent_requests"],
        "avg_response_time_ms": round(performance_metrics["avg_response_time_ms"], 2),
        "p95_response_time_ms": round(performance_metrics["p95_response_time_ms"], 2),
        "uptime_seconds": int(uptime_seconds),
        "requests_per_second": round(performance_metrics["total_requests"] / max(uptime_seconds, 1), 2)
    }

@app.post("/api/trust-score/calculate", response_model=TrustScoreResponse)
async def calculate_trust_score(
    request: TrustScoreCalculationRequest,
    background_tasks: BackgroundTasks,
    service: TrustScoringService = Depends(get_trust_scoring_service)
) -> TrustScoreResponse:
    """
    Calculate real-time trust score for an entity.
    
    This endpoint provides sub-100ms trust score calculations using cached data
    where possible, with intelligent refresh strategies for optimal performance.
    """
    
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    logger.info(f"Trust score calculation request {request_id} for entity {request.entity_id}")
    
    try:
        # Convert API request to service request
        service_request = TrustScoreRequest(
            entity_id=request.entity_id,
            entity_type=request.entity_type,
            user_id=request.user_id,
            device_id=request.device_id,
            session_id=request.session_id,
            tenant_id=request.tenant_id,
            force_behavior_refresh=request.force_refresh,
            force_device_refresh=request.force_refresh,
            include_trends=request.include_trends,
            current_ip=request.current_ip,
            authentication_context=request.authentication_context,
            network_context=request.network_context
        )
        
        # Calculate trust score
        service_response = await service.calculate_trust_score(service_request)
        
        # Update cache hit metrics
        if service_response.cache_hit:
            performance_metrics["cache_hits"] += 1
        
        # Build API response
        api_response = TrustScoreResponse(
            request_id=request_id,
            entity_id=request.entity_id,
            trust_score=service_response.trust_score_result.trust_score,
            trust_level=service_response.trust_score_result.trust_level.value,
            confidence=service_response.trust_score_result.confidence,
            factor_scores={
                factor_type.value: {
                    "score": factor_score.score,
                    "confidence": factor_score.confidence,
                    "weight": factor_score.weight,
                    "contributing_features": factor_score.contributing_features,
                    "risk_indicators": factor_score.risk_indicators
                }
                for factor_type, factor_score in service_response.trust_score_result.factor_scores.items()
            },
            risk_indicators=service_response.trust_score_result.anomaly_indicators,
            risk_summary=service_response.trust_score_result.get_risk_summary(),
            calculation_timestamp=service_response.trust_score_result.timestamp.isoformat(),
            processing_time_ms=service_response.processing_time_ms,
            cache_hit=service_response.cache_hit,
            data_sources=service_response.trust_score_result.data_sources,
            ttl_seconds=service_response.trust_score_result.ttl_seconds
        )
        
        # Add trends if requested
        if request.include_trends and hasattr(service.trust_calculator, 'get_trust_trends'):
            try:
                trends_data = service.trust_calculator.get_trust_trends(request.entity_id, days=7)
                api_response.trends = trends_data
            except Exception as e:
                logger.warning(f"Failed to get trends for {request.entity_id}: {e}")
        
        # Background task for analytics (non-blocking)
        background_tasks.add_task(
            log_trust_calculation, 
            request_id, 
            request.entity_id, 
            api_response.trust_score,
            api_response.processing_time_ms
        )
        
        logger.info(
            f"Trust score calculated for {request.entity_id}: {api_response.trust_score:.3f} "
            f"({api_response.trust_level}) in {api_response.processing_time_ms}ms"
        )
        
        return api_response
        
    except Exception as e:
        logger.error(f"Error calculating trust score for request {request_id}: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Trust score calculation failed: {str(e)}"
        )

@app.post("/api/trust-score/bulk", response_model=BulkTrustScoreResponse)
async def bulk_calculate_trust_scores(
    request: BulkTrustScoreRequest,
    service: TrustScoringService = Depends(get_trust_scoring_service)
) -> BulkTrustScoreResponse:
    """
    Bulk calculate trust scores for multiple entities.
    
    Efficiently processes multiple trust score calculations with controlled
    concurrency to maintain sub-100ms average response times.
    """
    
    batch_id = str(uuid.uuid4())
    start_time = time.time()
    
    logger.info(f"Bulk trust score calculation {batch_id} for {len(request.requests)} entities")
    
    successful_responses = []
    failed_responses = []
    cache_hits = 0
    
    # Create semaphore for concurrency control
    semaphore = asyncio.Semaphore(request.max_concurrent)
    
    async def calculate_single_score(calc_request: TrustScoreCalculationRequest):
        async with semaphore:
            try:
                # Use the single calculation endpoint logic
                service_request = TrustScoreRequest(
                    entity_id=calc_request.entity_id,
                    entity_type=calc_request.entity_type,
                    user_id=calc_request.user_id,
                    device_id=calc_request.device_id,
                    session_id=calc_request.session_id,
                    tenant_id=calc_request.tenant_id,
                    current_ip=calc_request.current_ip,
                    authentication_context=calc_request.authentication_context,
                    network_context=calc_request.network_context
                )
                
                service_response = await service.calculate_trust_score(service_request)
                
                api_response = TrustScoreResponse(
                    request_id=str(uuid.uuid4()),
                    entity_id=calc_request.entity_id,
                    trust_score=service_response.trust_score_result.trust_score,
                    trust_level=service_response.trust_score_result.trust_level.value,
                    confidence=service_response.trust_score_result.confidence,
                    factor_scores={
                        factor_type.value: {
                            "score": factor_score.score,
                            "confidence": factor_score.confidence,
                            "weight": factor_score.weight
                        }
                        for factor_type, factor_score in service_response.trust_score_result.factor_scores.items()
                    },
                    risk_indicators=service_response.trust_score_result.anomaly_indicators,
                    risk_summary=service_response.trust_score_result.get_risk_summary(),
                    calculation_timestamp=service_response.trust_score_result.timestamp.isoformat(),
                    processing_time_ms=service_response.processing_time_ms,
                    cache_hit=service_response.cache_hit,
                    data_sources=service_response.trust_score_result.data_sources
                )
                
                return {"success": True, "response": api_response, "cache_hit": service_response.cache_hit}
                
            except Exception as e:
                logger.error(f"Failed to calculate trust score for {calc_request.entity_id}: {e}")
                return {
                    "success": False, 
                    "entity_id": calc_request.entity_id,
                    "error": str(e)
                }
    
    try:
        # Execute all calculations with timeout
        tasks = [calculate_single_score(req) for req in request.requests]
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=request.timeout_seconds
        )
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                failed_responses.append({
                    "entity_id": "unknown",
                    "error": str(result)
                })
            elif result.get("success"):
                successful_responses.append(result["response"])
                if result.get("cache_hit"):
                    cache_hits += 1
            else:
                failed_responses.append({
                    "entity_id": result.get("entity_id", "unknown"),
                    "error": result.get("error", "Unknown error")
                })
        
        processing_time = int((time.time() - start_time) * 1000)
        cache_hit_rate = cache_hits / len(request.requests) * 100 if request.requests else 0
        
        logger.info(
            f"Bulk calculation {batch_id} completed: {len(successful_responses)} success, "
            f"{len(failed_responses)} failed, {cache_hit_rate:.1f}% cache hit rate in {processing_time}ms"
        )
        
        return BulkTrustScoreResponse(
            batch_id=batch_id,
            total_requests=len(request.requests),
            successful_responses=successful_responses,
            failed_responses=failed_responses,
            processing_time_ms=processing_time,
            cache_hit_rate=cache_hit_rate
        )
        
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=408, 
            detail=f"Bulk operation timed out after {request.timeout_seconds} seconds"
        )
    except Exception as e:
        logger.error(f"Bulk trust score calculation failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Bulk calculation failed: {str(e)}"
        )

@app.post("/api/trust-score/policy-decision", response_model=TrustPolicyDecision)
async def evaluate_trust_policy(
    entity_id: str,
    policy_context: Dict[str, Any] = None,
    service: TrustScoringService = Depends(get_trust_scoring_service)
) -> TrustPolicyDecision:
    """
    Evaluate trust-based policy decision for an entity.
    
    Calculates trust score and applies policy rules to determine access decisions.
    """
    
    try:
        # Calculate current trust score
        service_request = TrustScoreRequest(entity_id=entity_id)
        service_response = await service.calculate_trust_score(service_request)
        
        result = service_response.trust_score_result
        
        # Apply policy rules (simplified implementation)
        decision = "ALLOW"
        policy_matched = "default"
        additional_actions = []
        
        if result.trust_score < 0.3:
            decision = "DENY"
            policy_matched = "low_trust_deny"
            additional_actions = ["log_security_event", "alert_admin"]
        elif result.trust_score < 0.6:
            decision = "CHALLENGE"
            policy_matched = "medium_trust_challenge"
            additional_actions = ["require_mfa", "log_access_attempt"]
        elif result.trust_score >= 0.8:
            decision = "ALLOW"
            policy_matched = "high_trust_allow"
        else:
            decision = "ALLOW"
            policy_matched = "medium_trust_allow"
            additional_actions = ["log_access_attempt"]
        
        # Calculate expiration (trust-based TTL)
        ttl_seconds = int(300 * result.trust_score)  # 0-300 seconds based on trust
        expires_at = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
        
        return TrustPolicyDecision(
            entity_id=entity_id,
            decision=decision,
            trust_score=result.trust_score,
            trust_level=result.trust_level.value,
            policy_matched=policy_matched,
            additional_actions=additional_actions,
            expires_at=expires_at
        )
        
    except Exception as e:
        logger.error(f"Policy decision evaluation failed for {entity_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Policy decision failed: {str(e)}"
        )

@app.get("/api/trust-score/{entity_id}/trends")
async def get_trust_trends(
    entity_id: str,
    days: int = 7,
    service: TrustScoringService = Depends(get_trust_scoring_service)
):
    """Get historical trust score trends for an entity."""
    
    try:
        if hasattr(service.trust_calculator, 'get_trust_trends'):
            trends = service.trust_calculator.get_trust_trends(entity_id, days)
            return trends
        else:
            return {"message": "Trends not available"}
    except Exception as e:
        logger.error(f"Failed to get trends for {entity_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve trends: {str(e)}"
        )

@app.delete("/api/trust-score/{entity_id}/cache")
async def clear_entity_cache(
    entity_id: str,
    cache: RedisCacheService = Depends(get_cache_service)
):
    """Clear cached data for a specific entity."""
    
    try:
        # Clear various cache keys for the entity
        cache_keys = [
            f"trust_score:default:result:{entity_id}",
            f"trust_score:default:score:{entity_id}",
            f"trust_score:default:behavior:{entity_id}"
        ]
        
        cleared_count = 0
        for key in cache_keys:
            if await cache.delete_from_cache(key):
                cleared_count += 1
        
        return {
            "entity_id": entity_id,
            "cache_keys_cleared": cleared_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to clear cache for {entity_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Cache clear failed: {str(e)}"
        )

@app.post("/api/admin/reset-metrics")
async def reset_metrics():
    """Reset performance metrics (admin endpoint)."""
    global performance_metrics, response_times
    
    performance_metrics = {
        "total_requests": 0,
        "successful_requests": 0,
        "cache_hits": 0,
        "avg_response_time_ms": 0.0,
        "p95_response_time_ms": 0.0,
        "error_count": 0,
        "concurrent_requests": performance_metrics["concurrent_requests"],  # Keep current
        "last_reset": datetime.utcnow()
    }
    
    response_times.clear()
    
    return {
        "message": "Performance metrics reset",
        "timestamp": datetime.utcnow().isoformat()
    }

async def log_trust_calculation(request_id: str, entity_id: str, trust_score: float, processing_time: int):
    """Background task to log trust calculation for analytics."""
    try:
        # In production, this would send to analytics/SIEM systems
        logger.info(
            f"TRUST_CALCULATION: request_id={request_id}, entity_id={entity_id}, "
            f"trust_score={trust_score:.3f}, processing_time_ms={processing_time}"
        )
    except Exception as e:
        logger.warning(f"Failed to log trust calculation: {e}")

if __name__ == "__main__":
    # Production configuration
    uvicorn.run(
        "trust_scoring_engine:app",
        host="0.0.0.0",
        port=8080,
        workers=4,
        loop="uvloop",
        http="httptools",
        access_log=False,
        log_config={
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["default"],
            },
            "loggers": {
                "trust_scoring": {
                    "level": "INFO",
                    "handlers": ["default"],
                    "propagate": False,
                }
            }
        }
    )