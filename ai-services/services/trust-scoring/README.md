# Real-Time Trust Scoring Engine

Production-grade FastAPI-based trust scoring engine providing sub-100ms real-time trust score calculations for continuous verification and zero trust architecture.

## Overview

The Trust Scoring Engine is a high-performance microservice that calculates real-time trust scores based on multiple factors including user behavior, device posture, network context, and authentication patterns. It supports high-throughput operations with intelligent caching and provides RESTful APIs for integration with policy decision points.

## Key Features

### 🚀 **High Performance**
- **Sub-100ms response times** with intelligent caching
- **1000+ requests per second** throughput capability
- **Concurrent processing** with configurable limits
- **Redis cluster** for high-performance caching

### 🔒 **Comprehensive Trust Factors**
- **User Behavior Analysis**: Login patterns, resource access, session anomalies
- **Device Security Posture**: OS patches, security controls, compliance scores
- **Network Context**: IP reputation, geolocation, threat intelligence
- **Authentication Factors**: MFA status, credential strength, session security

### 📊 **Advanced Analytics**
- **Historical trend analysis** for trust score evolution
- **Risk indicator detection** and anomaly identification
- **Confidence scoring** for trust assessment quality
- **Policy decision support** with automated recommendations

### 🏗️ **Production-Ready Architecture**
- **FastAPI** with async/await for maximum performance
- **Kubernetes-native** deployment with auto-scaling
- **Health checks** and comprehensive monitoring
- **Graceful degradation** with fallback mechanisms

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Trust Scoring Engine                     │
├─────────────────────────────────────────────────────────────┤
│  FastAPI Application (api/trust_scoring_engine.py)         │
├─────────────────────────────────────────────────────────────┤
│  Trust Scoring Service (service/trust_scoring_service.py)  │
├─────────────────────────────────────────────────────────────┤
│  Trust Calculator (models/trust_calculator.py)             │
├─────────────────────────────────────────────────────────────┤
│  Data Collectors                                           │
│  ├─ Behavior Collector (models/behavior_collector.py)     │
│  ├─ Device Posture (models/device_posture.py)             │
│  ├─ Network Context (models/network_context.py)           │
│  └─ Authentication (auth contexts)                        │
├─────────────────────────────────────────────────────────────┤
│  Caching Layer (cache/redis_cache_service.py)             │
└─────────────────────────────────────────────────────────────┘

External Integrations:
├─ Redis Cluster (High-performance caching)
├─ PostgreSQL (Trust score history)
├─ MDM Systems (Device posture data)
├─ Threat Intelligence APIs (Network context)
└─ Behavioral Analysis Service (User patterns)
```

## API Endpoints

### Core Trust Scoring

#### POST `/api/trust-score/calculate`
Calculate real-time trust score for an entity.

**Request:**
```json
{
  "entity_id": "user_12345",
  "entity_type": "user",
  "user_id": "user_12345",
  "device_id": "device_67890",
  "current_ip": "192.168.1.100",
  "authentication_context": {
    "mfa_enabled": true,
    "session_encrypted": true
  },
  "network_context": {
    "is_corporate_network": true,
    "vpn_detected": false
  },
  "force_refresh": false,
  "include_trends": true
}
```

**Response:**
```json
{
  "request_id": "uuid-4",
  "entity_id": "user_12345",
  "trust_score": 0.85,
  "trust_level": "HIGH",
  "confidence": 0.92,
  "factor_scores": {
    "user_behavior": {
      "score": 0.88,
      "confidence": 0.95,
      "weight": 0.35
    },
    "device_posture": {
      "score": 0.82,
      "confidence": 0.90,
      "weight": 0.30
    }
  },
  "risk_indicators": [],
  "processing_time_ms": 45,
  "cache_hit": false
}
```

#### POST `/api/trust-score/bulk`
Bulk calculate trust scores for multiple entities.

**Request:**
```json
{
  "requests": [
    {"entity_id": "user_1", "entity_type": "user"},
    {"entity_id": "user_2", "entity_type": "user"}
  ],
  "max_concurrent": 10,
  "timeout_seconds": 30
}
```

#### POST `/api/trust-score/policy-decision`
Get trust-based policy decision for access control.

**Response:**
```json
{
  "entity_id": "user_12345",
  "decision": "ALLOW",
  "trust_score": 0.85,
  "trust_level": "HIGH",
  "policy_matched": "high_trust_allow",
  "additional_actions": ["log_access_attempt"],
  "expires_at": "2024-01-15T10:30:00Z"
}
```

### Monitoring & Management

#### GET `/api/health`
Comprehensive health check with component status.

#### GET `/api/metrics`
Detailed performance metrics and statistics.

#### GET `/api/trust-score/{entity_id}/trends`
Historical trust score trends and analytics.

#### DELETE `/api/trust-score/{entity_id}/cache`
Clear cached data for specific entity.

## Quick Start

### 1. Prerequisites

- Python 3.11+
- Redis 7.0+
- PostgreSQL 15+
- Docker (for containerized deployment)

### 2. Local Development

```bash
# Clone repository
git clone https://github.com/isectech/trust-scoring-engine.git
cd trust-scoring-engine

# Install dependencies
pip install -r requirements.trust-scoring.txt

# Set environment variables
export REDIS_URL="redis://localhost:6379/4"
export DATABASE_URL="postgresql://user:pass@localhost/trust_scoring"

# Start the development server
uvicorn api.trust_scoring_engine:app --host 0.0.0.0 --port 8080 --reload
```

### 3. Docker Deployment

```bash
# Build Docker image
docker build -f Dockerfile.trust-scoring -t trust-scoring-engine:latest .

# Run container
docker run -p 8080:8080 \
  -e REDIS_URL="redis://redis:6379/4" \
  -e DATABASE_URL="postgresql://db:5432/trust_scoring" \
  trust-scoring-engine:latest
```

### 4. Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/trust-scoring-deployment.yaml

# Check deployment status
kubectl get pods -l app=trust-scoring-engine

# Access service
kubectl port-forward svc/trust-scoring-service 8080:8080
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/4` |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `LOG_LEVEL` | Logging level | `INFO` |
| `WORKERS` | Number of worker processes | `4` |
| `MAX_CONCURRENT_CALCULATIONS` | Max concurrent trust calculations | `100` |
| `CACHE_TTL_SECONDS` | Cache TTL for trust scores | `300` |
| `TENANT_ID` | Default tenant identifier | `default` |

### Production Configuration

The engine uses a YAML-based configuration system for production deployments:

```yaml
# config/production.yaml
trust_scoring:
  performance:
    max_concurrent_calculations: 100
    request_timeout_seconds: 30
  
  calculation:
    factor_weights:
      user_behavior: 0.35
      device_posture: 0.30
      network_context: 0.20
      authentication: 0.15
```

## Performance Characteristics

### Response Time Targets

- **Cold cache**: < 100ms (95th percentile)
- **Warm cache**: < 50ms (95th percentile)
- **Bulk operations**: < 200ms for 10 entities

### Throughput Capabilities

- **Single instance**: 1,000+ RPS
- **Clustered deployment**: 10,000+ RPS
- **Cache hit rate**: 80%+ in typical usage

### Resource Requirements

| Deployment | CPU | Memory | Storage |
|------------|-----|--------|---------|
| Development | 0.5 cores | 512MB | 1GB |
| Production (single) | 1 core | 1GB | 10GB |
| Production (cluster) | 4 cores | 4GB | 50GB |

## Testing

### Unit Tests

```bash
# Run all unit tests
pytest tests/test_trust_scoring_engine.py -v

# Run with coverage
pytest tests/ --cov=api --cov-report=html
```

### Performance Tests

```bash
# Run performance test suite
python tests/performance_test.py

# Run load test with specific parameters
python -c "
import asyncio
from tests.performance_test import TrustScoringPerformanceTest

async def load_test():
    async with TrustScoringPerformanceTest('http://localhost:8080') as tester:
        results = await tester.load_test(
            concurrent_requests=50,
            total_requests=1000,
            unique_entities=100
        )
        print(f'Average response time: {results.avg_response_time_ms:.2f}ms')
        print(f'95th percentile: {results.p95_response_time_ms:.2f}ms')

asyncio.run(load_test())
"
```

### Integration Tests

```bash
# Start test environment
docker-compose -f docker-compose.test.yaml up -d

# Run integration tests
pytest tests/ -m integration

# Cleanup
docker-compose -f docker-compose.test.yaml down
```

## Monitoring & Observability

### Health Checks

The engine provides comprehensive health checks:

- **Service health**: Application status and component availability
- **Dependency health**: Redis, PostgreSQL, external services
- **Performance health**: Response times, error rates, resource usage

### Metrics

Prometheus-compatible metrics are exposed at `/api/metrics`:

- `trust_calculations_total`: Total trust score calculations
- `trust_calculation_duration_seconds`: Response time histogram
- `trust_cache_hits_total`: Cache hit/miss counters
- `trust_errors_total`: Error counters by type

### Logging

Structured JSON logging with configurable levels:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "message": "Trust score calculated",
  "entity_id": "user_12345",
  "trust_score": 0.85,
  "processing_time_ms": 45,
  "cache_hit": false
}
```

### Alerting

Recommended alerts:

- Error rate > 5%
- 95th percentile response time > 150ms
- Cache hit rate < 70%
- Memory usage > 80%
- Service unavailable

## Security Considerations

### Authentication & Authorization

- API key authentication for admin endpoints
- JWT-based session management
- Role-based access control (RBAC)
- Rate limiting per client/tenant

### Data Protection

- Encryption at rest and in transit
- PII anonymization in logs
- Secure credential storage
- Regular security scanning

### Network Security

- HTTPS/TLS 1.3 encryption
- CORS configuration
- IP whitelisting support
- WAF integration

## Deployment Patterns

### Single Instance

Suitable for development and small-scale production:

```yaml
replicas: 1
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

### High Availability

Production deployment with multiple replicas:

```yaml
replicas: 3
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1
    maxUnavailable: 0
```

### Auto-scaling

Dynamic scaling based on load:

```yaml
minReplicas: 3
maxReplicas: 10
metrics:
- type: Resource
  resource:
    name: cpu
    target:
      type: Utilization
      averageUtilization: 70
```

## Troubleshooting

### Common Issues

#### High Response Times

1. Check cache hit rates: `curl http://localhost:8080/api/metrics`
2. Monitor Redis performance: `redis-cli --latency-history`
3. Review database connection pool: Check PostgreSQL logs
4. Analyze concurrent requests: Check `concurrent_requests` metric

#### Cache Issues

1. Verify Redis connectivity: `redis-cli ping`
2. Check memory usage: `redis-cli info memory`
3. Monitor cache eviction: `redis-cli info stats`
4. Review TTL configuration

#### Service Unavailable

1. Check health endpoint: `curl http://localhost:8080/api/health`
2. Review application logs
3. Verify external dependencies
4. Check resource constraints

### Debug Mode

Enable debug logging for troubleshooting:

```bash
export LOG_LEVEL=DEBUG
python -m uvicorn api.trust_scoring_engine:app --reload
```

## Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/trust-enhancement`
3. Install development dependencies: `pip install -r requirements-dev.txt`
4. Make changes and add tests
5. Run tests: `pytest`
6. Submit pull request

### Code Standards

- Follow PEP 8 for Python code style
- Use type hints for all functions
- Write comprehensive docstrings
- Maintain test coverage > 90%
- Update documentation for API changes

## License

Copyright (c) 2024 iSECTECH. All rights reserved.

## Support

For technical support and questions:

- **Documentation**: [https://docs.isectech.com/trust-scoring](https://docs.isectech.com/trust-scoring)
- **Issues**: [GitHub Issues](https://github.com/isectech/trust-scoring-engine/issues)
- **Support**: [support@isectech.com](mailto:support@isectech.com)
- **Slack**: #trust-scoring-engine