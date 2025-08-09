# Resilience Patterns Design: Circuit Breakers and Bulkheads

## Executive Summary

This document outlines the implementation of resilience patterns for the iSECTECH platform, focusing on Circuit Breakers and Bulkheads to prevent cascading failures and ensure system stability under adverse conditions. These patterns are essential for achieving 99.99% uptime targets in a distributed microservices architecture handling 1M+ endpoints and 1B+ events/day.

## 1. Circuit Breaker Pattern Implementation

### 1.1 Overview

Circuit breakers monitor service health and prevent calls to failing services, providing fail-fast behavior and automatic recovery detection.

### 1.2 Circuit Breaker States

```go
type CircuitBreakerState int

const (
    Closed CircuitBreakerState = iota  // Normal operation
    Open                               // Failing, blocking requests
    HalfOpen                          // Testing recovery
)

type CircuitBreaker struct {
    Name                string
    MaxRequests         uint32        // Max requests in HalfOpen state
    Interval            time.Duration // Stat collection interval
    Timeout             time.Duration // Open state timeout
    ReadyToTrip         func(counts Counts) bool
    OnStateChange       func(name string, from State, to State)
    IsSuccessful        func(err error) bool

    mutex               sync.RWMutex
    state              CircuitBreakerState
    generation         uint64
    counts             Counts
    expiry             time.Time
}

type Counts struct {
    Requests             uint32
    TotalSuccesses       uint32
    TotalFailures        uint32
    ConsecutiveSuccesses uint32
    ConsecutiveFailures  uint32
}
```

### 1.3 Service-Specific Circuit Breaker Configuration

#### Critical Security Services (Strict Settings)

```yaml
authentication-service:
  failure_threshold: 3
  recovery_timeout: 30s
  success_threshold: 2
  timeout: 5s
  max_concurrent_requests: 100

threat-detection-service:
  failure_threshold: 5
  recovery_timeout: 60s
  success_threshold: 3
  timeout: 10s
  max_concurrent_requests: 200
```

#### External Integration Services (Lenient Settings)

```yaml
compliance-automation-service:
  failure_threshold: 10
  recovery_timeout: 120s
  success_threshold: 5
  timeout: 30s
  max_concurrent_requests: 50

business-continuity-service:
  failure_threshold: 8
  recovery_timeout: 90s
  success_threshold: 4
  timeout: 20s
  max_concurrent_requests: 75
```

### 1.4 Go Implementation with sony/gobreaker

```go
package resilience

import (
    "context"
    "fmt"
    "time"
    "github.com/sony/gobreaker"
    "github.com/prometheus/client_golang/prometheus"
)

type ServiceCircuitBreaker struct {
    breaker *gobreaker.CircuitBreaker
    metrics *CircuitBreakerMetrics
}

type CircuitBreakerMetrics struct {
    requestsTotal    *prometheus.CounterVec
    failuresTotal    *prometheus.CounterVec
    stateChanges     *prometheus.CounterVec
    currentState     *prometheus.GaugeVec
}

func NewServiceCircuitBreaker(serviceName string, config CircuitBreakerConfig) *ServiceCircuitBreaker {
    settings := gobreaker.Settings{
        Name:        serviceName,
        MaxRequests: config.MaxRequests,
        Interval:    config.Interval,
        Timeout:     config.Timeout,
        ReadyToTrip: func(counts gobreaker.Counts) bool {
            failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
            return counts.Requests >= config.MinRequests && failureRatio >= config.FailureThreshold
        },
        OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
            logger.Info().
                Str("service", name).
                Str("from_state", from.String()).
                Str("to_state", to.String()).
                Msg("Circuit breaker state changed")

            // Update Prometheus metrics
            metrics.stateChanges.WithLabelValues(name, from.String(), to.String()).Inc()
            metrics.currentState.WithLabelValues(name).Set(float64(to))
        },
        IsSuccessful: func(err error) bool {
            // Define success criteria based on error types
            if err == nil {
                return true
            }

            // Consider timeouts and 5xx errors as failures
            if isTimeoutError(err) || is5xxError(err) {
                return false
            }

            // 4xx errors might be successful from circuit breaker perspective
            return true
        },
    }

    return &ServiceCircuitBreaker{
        breaker: gobreaker.NewCircuitBreaker(settings),
        metrics: initCircuitBreakerMetrics(serviceName),
    }
}

func (scb *ServiceCircuitBreaker) Execute(ctx context.Context, req func() (interface{}, error)) (interface{}, error) {
    start := time.Now()
    defer func() {
        duration := time.Since(start)
        scb.metrics.requestsTotal.WithLabelValues(scb.breaker.Name).Inc()

        // Record latency metrics
        requestDuration.WithLabelValues(scb.breaker.Name).Observe(duration.Seconds())
    }()

    result, err := scb.breaker.Execute(req)
    if err != nil {
        scb.metrics.failuresTotal.WithLabelValues(scb.breaker.Name, classifyError(err)).Inc()
        return nil, fmt.Errorf("circuit breaker %s: %w", scb.breaker.Name, err)
    }

    return result, nil
}
```

### 1.5 Fallback Strategies

#### 1.5.1 Cached Response Fallback

```go
type CachedFallbackStrategy struct {
    cache Cache
    ttl   time.Duration
}

func (cfs *CachedFallbackStrategy) Execute(ctx context.Context, key string) (interface{}, error) {
    // Return cached data when circuit is open
    cachedData, err := cfs.cache.Get(ctx, key)
    if err != nil {
        return nil, fmt.Errorf("fallback cache miss: %w", err)
    }

    // Add staleness indicator
    return &FallbackResponse{
        Data:      cachedData,
        IsFallback: true,
        Timestamp: time.Now(),
    }, nil
}
```

#### 1.5.2 Degraded Response Fallback

```go
type DegradedResponseStrategy struct {
    defaultResponse interface{}
}

func (drs *DegradedResponseStrategy) Execute(ctx context.Context) (interface{}, error) {
    return &DegradedResponse{
        Data:       drs.defaultResponse,
        IsDegraded: true,
        Message:    "Service temporarily unavailable, returning default response",
    }, nil
}
```

## 2. Bulkhead Pattern Implementation

### 2.1 Overview

Bulkheads isolate critical resources to prevent failure in one area from affecting the entire system, similar to watertight compartments in ships.

### 2.2 Resource Pool Isolation

#### 2.2.1 Connection Pool Bulkheads

```go
type DatabaseBulkhead struct {
    criticalPool   *sql.DB // High-priority operations
    standardPool   *sql.DB // Normal operations
    backgroundPool *sql.DB // Background/batch operations
}

func NewDatabaseBulkhead(config DatabaseConfig) *DatabaseBulkhead {
    return &DatabaseBulkhead{
        criticalPool: createConnectionPool(DatabasePoolConfig{
            MaxOpenConns:    config.Critical.MaxConnections,
            MaxIdleConns:    config.Critical.MaxIdleConnections,
            ConnMaxLifetime: config.Critical.ConnectionLifetime,
            ConnMaxIdleTime: config.Critical.IdleTimeout,
        }),
        standardPool: createConnectionPool(DatabasePoolConfig{
            MaxOpenConns:    config.Standard.MaxConnections,
            MaxIdleConns:    config.Standard.MaxIdleConnections,
            ConnMaxLifetime: config.Standard.ConnectionLifetime,
            ConnMaxIdleTime: config.Standard.IdleTimeout,
        }),
        backgroundPool: createConnectionPool(DatabasePoolConfig{
            MaxOpenConns:    config.Background.MaxConnections,
            MaxIdleConns:    config.Background.MaxIdleConnections,
            ConnMaxLifetime: config.Background.ConnectionLifetime,
            ConnMaxIdleTime: config.Background.IdleTimeout,
        }),
    }
}

func (db *DatabaseBulkhead) GetConnection(priority Priority) *sql.DB {
    switch priority {
    case CriticalPriority:
        return db.criticalPool
    case StandardPriority:
        return db.standardPool
    case BackgroundPriority:
        return db.backgroundPool
    default:
        return db.standardPool
    }
}
```

#### 2.2.2 Thread Pool Bulkheads

```go
type ThreadPoolBulkhead struct {
    authenticationPool chan struct{} // Authentication requests
    threatAnalysisPool chan struct{} // Threat detection
    compliancePool     chan struct{} // Compliance reporting
    backgroundPool     chan struct{} // Background tasks
}

func NewThreadPoolBulkhead(config ThreadPoolConfig) *ThreadPoolBulkhead {
    return &ThreadPoolBulkhead{
        authenticationPool: make(chan struct{}, config.Authentication.PoolSize),
        threatAnalysisPool: make(chan struct{}, config.ThreatAnalysis.PoolSize),
        compliancePool:     make(chan struct{}, config.Compliance.PoolSize),
        backgroundPool:     make(chan struct{}, config.Background.PoolSize),
    }
}

func (tpb *ThreadPoolBulkhead) AcquireSlot(ctx context.Context, poolType PoolType) error {
    var pool chan struct{}

    switch poolType {
    case AuthenticationPool:
        pool = tpb.authenticationPool
    case ThreatAnalysisPool:
        pool = tpb.threatAnalysisPool
    case CompliancePool:
        pool = tpb.compliancePool
    case BackgroundPool:
        pool = tpb.backgroundPool
    default:
        return fmt.Errorf("unknown pool type: %v", poolType)
    }

    select {
    case pool <- struct{}{}:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}

func (tpb *ThreadPoolBulkhead) ReleaseSlot(poolType PoolType) {
    var pool chan struct{}

    switch poolType {
    case AuthenticationPool:
        pool = tpb.authenticationPool
    case ThreatAnalysisPool:
        pool = tpb.threatAnalysisPool
    case CompliancePool:
        pool = tpb.compliancePool
    case BackgroundPool:
        pool = tpb.backgroundPool
    default:
        return
    }

    select {
    case <-pool:
        // Successfully released
    default:
        // Pool was not full, nothing to release
    }
}
```

### 2.3 Kubernetes Resource Isolation

#### 2.3.1 Namespace-Based Bulkheads

```yaml
# Critical Services Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: isectech-critical
  labels:
    security-domain: 'critical'
    priority: 'high'
---
# Resource Quota for Critical Services
apiVersion: v1
kind: ResourceQuota
metadata:
  name: critical-services-quota
  namespace: isectech-critical
spec:
  hard:
    requests.cpu: '8'
    requests.memory: '16Gi'
    limits.cpu: '16'
    limits.memory: '32Gi'
    persistentvolumeclaims: '10'
---
# Standard Services Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: isectech-standard
  labels:
    security-domain: 'standard'
    priority: 'medium'
---
# Resource Quota for Standard Services
apiVersion: v1
kind: ResourceQuota
metadata:
  name: standard-services-quota
  namespace: isectech-standard
spec:
  hard:
    requests.cpu: '12'
    requests.memory: '24Gi'
    limits.cpu: '24'
    limits.memory: '48Gi'
    persistentvolumeclaims: '20'
```

#### 2.3.2 Pod Disruption Budgets

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: authentication-service-pdb
  namespace: isectech-critical
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: authentication-service
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: threat-detection-pdb
  namespace: isectech-critical
spec:
  minAvailable: 75%
  selector:
    matchLabels:
      app: threat-detection-service
```

## 3. Service-Specific Resilience Configuration

### 3.1 Authentication Service (Critical)

```yaml
resilience:
  circuit_breaker:
    failure_threshold: 3
    recovery_timeout: 30s
    success_threshold: 2
    timeout: 5s
  bulkhead:
    max_concurrent_requests: 100
    queue_size: 50
    timeout: 10s
  retry:
    max_attempts: 3
    backoff_strategy: exponential
    initial_delay: 100ms
    max_delay: 5s
  fallback:
    strategy: cached_response
    cache_ttl: 300s
```

### 3.2 Threat Detection Service (Critical)

```yaml
resilience:
  circuit_breaker:
    failure_threshold: 5
    recovery_timeout: 60s
    success_threshold: 3
    timeout: 10s
  bulkhead:
    max_concurrent_requests: 200
    queue_size: 100
    timeout: 30s
  retry:
    max_attempts: 2
    backoff_strategy: fixed
    delay: 1s
  fallback:
    strategy: degraded_response
    default_threat_level: 'medium'
```

### 3.3 Data Analytics Service (Standard)

```yaml
resilience:
  circuit_breaker:
    failure_threshold: 10
    recovery_timeout: 120s
    success_threshold: 5
    timeout: 30s
  bulkhead:
    max_concurrent_requests: 150
    queue_size: 200
    timeout: 60s
  retry:
    max_attempts: 5
    backoff_strategy: exponential
    initial_delay: 500ms
    max_delay: 30s
  fallback:
    strategy: cached_response
    cache_ttl: 3600s
```

## 4. Monitoring and Observability

### 4.1 Circuit Breaker Metrics

```go
var (
    circuitBreakerRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "circuit_breaker_requests_total",
            Help: "Total number of requests through circuit breaker",
        },
        []string{"service", "state", "outcome"},
    )

    circuitBreakerStateChanges = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "circuit_breaker_state_changes_total",
            Help: "Total number of circuit breaker state changes",
        },
        []string{"service", "from_state", "to_state"},
    )

    circuitBreakerCurrentState = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "circuit_breaker_state",
            Help: "Current state of circuit breaker (0=closed, 1=open, 2=half-open)",
        },
        []string{"service"},
    )
)
```

### 4.2 Bulkhead Metrics

```go
var (
    bulkheadActiveRequests = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "bulkhead_active_requests",
            Help: "Number of active requests in bulkhead",
        },
        []string{"service", "pool_type"},
    )

    bulkheadQueuedRequests = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "bulkhead_queued_requests",
            Help: "Number of queued requests in bulkhead",
        },
        []string{"service", "pool_type"},
    )

    bulkheadRejectedRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "bulkhead_rejected_requests_total",
            Help: "Total number of rejected requests due to bulkhead limits",
        },
        []string{"service", "pool_type", "reason"},
    )
)
```

### 4.3 Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "iSECTECH Resilience Patterns",
    "panels": [
      {
        "title": "Circuit Breaker States",
        "type": "stat",
        "targets": [
          {
            "expr": "circuit_breaker_state",
            "legendFormat": "{{service}}"
          }
        ]
      },
      {
        "title": "Circuit Breaker Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(circuit_breaker_requests_total[5m])",
            "legendFormat": "{{service}} - {{outcome}}"
          }
        ]
      },
      {
        "title": "Bulkhead Resource Utilization",
        "type": "graph",
        "targets": [
          {
            "expr": "bulkhead_active_requests / bulkhead_max_concurrent_requests * 100",
            "legendFormat": "{{service}} - {{pool_type}}"
          }
        ]
      }
    ]
  }
}
```

## 5. Testing and Validation

### 5.1 Chaos Engineering Tests

```go
package chaos

import (
    "context"
    "testing"
    "time"
)

func TestCircuitBreakerFailureScenario(t *testing.T) {
    // Setup service with circuit breaker
    service := setupTestService()

    // Inject failures to trigger circuit breaker
    for i := 0; i < 5; i++ {
        _, err := service.Call(context.Background(), "test-request")
        if err == nil {
            t.Error("Expected failure but got success")
        }
    }

    // Verify circuit breaker is open
    if service.circuitBreaker.State() != CircuitBreakerOpen {
        t.Error("Circuit breaker should be open")
    }

    // Wait for recovery timeout
    time.Sleep(service.config.RecoveryTimeout)

    // Verify circuit breaker moves to half-open
    if service.circuitBreaker.State() != CircuitBreakerHalfOpen {
        t.Error("Circuit breaker should be half-open")
    }
}

func TestBulkheadIsolation(t *testing.T) {
    bulkhead := setupTestBulkhead()

    // Fill critical pool
    for i := 0; i < bulkhead.config.CriticalPoolSize; i++ {
        err := bulkhead.AcquireSlot(context.Background(), CriticalPool)
        if err != nil {
            t.Errorf("Failed to acquire critical slot %d: %v", i, err)
        }
    }

    // Verify standard pool is still available
    err := bulkhead.AcquireSlot(context.Background(), StandardPool)
    if err != nil {
        t.Error("Standard pool should still be available")
    }

    // Verify critical pool is full
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()

    err = bulkhead.AcquireSlot(ctx, CriticalPool)
    if err != context.DeadlineExceeded {
        t.Error("Critical pool should be full")
    }
}
```

### 5.2 Load Testing

```yaml
# K6 Load Test Script
apiVersion: v1
kind: ConfigMap
metadata:
  name: resilience-load-test
data:
  script.js: |
    import http from 'k6/http';
    import { check } from 'k6';

    export let options = {
      stages: [
        { duration: '5m', target: 100 },   // Ramp up
        { duration: '10m', target: 500 },  // Normal load
        { duration: '5m', target: 1000 },  // Spike load
        { duration: '10m', target: 100 },  // Recovery
      ],
    };

    export default function() {
      let response = http.get('https://api.isectech.com/health');
      
      check(response, {
        'status is 200 or 503 (circuit breaker)': (r) => 
          r.status === 200 || r.status === 503,
        'response time < 5s': (r) => r.timings.duration < 5000,
      });
    }
```

## 6. Implementation Timeline

### Phase 1: Core Circuit Breaker Implementation (Week 1-2)

- Implement basic circuit breaker using sony/gobreaker
- Add Prometheus metrics collection
- Create configuration management
- Unit testing

### Phase 2: Bulkhead Pattern Implementation (Week 3-4)

- Implement connection pool bulkheads
- Add thread pool isolation
- Kubernetes resource quotas
- Integration testing

### Phase 3: Service Integration (Week 5-6)

- Integrate patterns into all microservices
- Configure service-specific thresholds
- End-to-end testing
- Performance optimization

### Phase 4: Monitoring and Operations (Week 7-8)

- Grafana dashboards
- Alerting rules
- Runbook documentation
- Chaos engineering tests

## 7. Operational Procedures

### 7.1 Circuit Breaker Management

```bash
# Check circuit breaker status
kubectl get circuitbreakers -n isectech-critical

# Force circuit breaker open (emergency)
kubectl patch circuitbreaker auth-service -p '{"spec":{"forceOpen":true}}'

# Reset circuit breaker
kubectl patch circuitbreaker auth-service -p '{"spec":{"forceOpen":false}}'
```

### 7.2 Bulkhead Scaling

```bash
# Scale bulkhead resources
kubectl patch resourcequota critical-services-quota -p '{"spec":{"hard":{"requests.cpu":"16","requests.memory":"32Gi"}}}'

# Monitor bulkhead utilization
kubectl top pods -n isectech-critical --sort-by=cpu
```

## 8. Success Metrics

### 8.1 Availability Metrics

- **System Uptime**: > 99.99% (target: 99.995%)
- **MTTR**: < 5 minutes (target: < 2 minutes)
- **MTBF**: > 30 days (target: > 90 days)

### 8.2 Performance Metrics

- **Response Time P95**: < 500ms during failures
- **Throughput Degradation**: < 20% during circuit breaker activation
- **Recovery Time**: < 30 seconds after service restoration

### 8.3 Resilience Metrics

- **Cascade Failure Prevention**: 0 incidents
- **Circuit Breaker Accuracy**: > 95% correct state transitions
- **Bulkhead Isolation Effectiveness**: > 99% containment rate

## Conclusion

This resilience patterns design provides comprehensive protection against failures in the iSECTECH platform. The combination of circuit breakers and bulkheads ensures system stability, prevents cascading failures, and maintains service availability even under adverse conditions. The implementation follows industry best practices and provides extensive monitoring and operational capabilities for production deployment.
