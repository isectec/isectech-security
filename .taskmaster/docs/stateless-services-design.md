# iSECTECH Protect - Stateless Services & External State Management Design

**Version:** 1.0  
**Date:** 2025-07-31  
**Status:** In Progress  
**Task Reference:** 26.6

## Executive Summary

This document defines the stateless microservice architecture and external state management patterns for the iSECTECH Protect platform. The design ensures horizontal scalability, fault tolerance, and security while handling 1B+ events per day across distributed infrastructure.

## Design Principles

### Stateless Service Principles

1. **No Local State:** Services retain no client-specific data between requests
2. **External State:** All state externalized to databases, caches, or message queues
3. **Idempotency:** Operations can be safely retried without side effects
4. **Horizontal Scaling:** Any instance can handle any request
5. **Fault Tolerance:** Instance failures don't result in data loss

### State Management Principles

1. **Separation of Concerns:** Clear boundaries between stateful and stateless components
2. **Data Ownership:** Each service owns its data and exposes it via APIs only
3. **Eventual Consistency:** Embrace eventual consistency for better performance
4. **Audit Trail:** All state changes tracked for compliance and debugging
5. **Multi-Tenancy:** Strict tenant isolation at all state layers

---

## 1. Stateless Service Architecture

### Service Design Patterns

#### Stateless Service Template

```go
// Go Service Template for Stateless Architecture
package service

type StatelessService struct {
    config     *Config
    logger     Logger
    metrics    MetricsCollector
    tracer     Tracer
    // No instance state - all dependencies injected
}

func NewStatelessService(deps Dependencies) *StatelessService {
    return &StatelessService{
        config:  deps.Config,
        logger:  deps.Logger,
        metrics: deps.Metrics,
        tracer:  deps.Tracer,
    }
}

func (s *StatelessService) HandleRequest(ctx context.Context, req Request) Response {
    // Extract all context from request
    tenantID := req.TenantID
    userID := req.UserID
    traceID := req.TraceID

    // Log request with correlation
    s.logger.Info("Processing request",
        zap.String("tenant_id", tenantID),
        zap.String("user_id", userID),
        zap.String("trace_id", traceID))

    // All state operations via external services
    externalState := s.getExternalState(ctx, req)
    result := s.processWithExternalState(ctx, req, externalState)
    s.updateExternalState(ctx, result)

    return Response{
        Result:  result,
        TraceID: traceID,
    }
}
```

#### Dependency Injection Pattern

```go
// Dependencies injected at startup - no global state
type Dependencies struct {
    Config      *Config
    Logger      Logger
    Metrics     MetricsCollector
    Tracer      Tracer
    Database    DatabaseClient
    Cache       CacheClient
    EventStore  EventStoreClient
    Validator   RequestValidator
}

// Service factory with all dependencies
func NewServiceWithDependencies(deps Dependencies) ServiceInterface {
    return &ConcreteService{
        dependencies: deps,
    }
}
```

### Request Context Management

#### Context Propagation

```go
// Request context carries all stateful information
type RequestContext struct {
    TenantID     string    `json:"tenant_id"`
    UserID       string    `json:"user_id"`
    SessionID    string    `json:"session_id"`
    TraceID      string    `json:"trace_id"`
    SpanID       string    `json:"span_id"`
    Timestamp    time.Time `json:"timestamp"`
    Permissions  []string  `json:"permissions"`
    UserRoles    []string  `json:"user_roles"`
    IPAddress    string    `json:"ip_address"`
    UserAgent    string    `json:"user_agent"`
}

// Extract context from JWT token
func ExtractContextFromJWT(jwtToken string) (*RequestContext, error) {
    claims, err := validateJWT(jwtToken)
    if err != nil {
        return nil, err
    }

    return &RequestContext{
        TenantID:    claims.TenantID,
        UserID:      claims.Subject,
        SessionID:   claims.SessionID,
        TraceID:     generateTraceID(),
        Timestamp:   time.Now(),
        Permissions: claims.Permissions,
        UserRoles:   claims.Roles,
    }, nil
}
```

#### Context Validation Middleware

```go
// Middleware ensures all requests have required context
func ContextValidationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()

        // Extract and validate context
        reqCtx, err := ExtractRequestContext(r)
        if err != nil {
            http.Error(w, "Invalid request context", http.StatusUnauthorized)
            return
        }

        // Validate tenant access
        if !validateTenantAccess(reqCtx.TenantID, reqCtx.UserID) {
            http.Error(w, "Unauthorized tenant access", http.StatusForbidden)
            return
        }

        // Add context to request
        ctx = context.WithValue(ctx, "request_context", reqCtx)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

---

## 2. Authentication & Session Management

### JWT-Based Stateless Authentication

#### JWT Token Structure

```json
{
  "iss": "isectech-auth-service",
  "sub": "user-12345",
  "aud": "isectech-api",
  "exp": 1643673600,
  "iat": 1643670000,
  "jti": "token-abc123",
  "tenant_id": "tenant-67890",
  "session_id": "session-xyz789",
  "permissions": ["read:alerts", "write:policies", "admin:users"],
  "roles": ["security_analyst", "admin"],
  "mfa_verified": true,
  "ip_whitelist": ["203.0.113.0/24"]
}
```

#### Token Management Service

```go
type TokenManager struct {
    signingKey   []byte
    tokenTTL     time.Duration
    refreshTTL   time.Duration
    redisClient  *redis.Client
}

func (tm *TokenManager) GenerateTokenPair(user User) (TokenPair, error) {
    // Generate access token
    accessClaims := jwt.MapClaims{
        "iss":         "isectech-auth-service",
        "sub":         user.ID,
        "aud":         "isectech-api",
        "exp":         time.Now().Add(tm.tokenTTL).Unix(),
        "iat":         time.Now().Unix(),
        "jti":         uuid.New().String(),
        "tenant_id":   user.TenantID,
        "session_id":  uuid.New().String(),
        "permissions": user.Permissions,
        "roles":       user.Roles,
        "mfa_verified": user.MFAVerified,
    }

    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, err := accessToken.SignedString(tm.signingKey)
    if err != nil {
        return TokenPair{}, err
    }

    // Generate refresh token
    refreshToken := uuid.New().String()
    refreshKey := fmt.Sprintf("refresh_token:%s", user.ID)

    // Store refresh token in Redis with TTL
    err = tm.redisClient.Set(ctx, refreshKey, refreshToken, tm.refreshTTL).Err()
    if err != nil {
        return TokenPair{}, err
    }

    return TokenPair{
        AccessToken:  accessTokenString,
        RefreshToken: refreshToken,
        ExpiresIn:    int(tm.tokenTTL.Seconds()),
    }, nil
}
```

### Token Revocation Strategy

#### Redis-Based Token Blacklist

```go
type TokenBlacklist struct {
    redisClient *redis.Client
}

func (tb *TokenBlacklist) RevokeToken(tokenID string, exp time.Time) error {
    // Calculate TTL based on token expiration
    ttl := time.Until(exp)
    if ttl <= 0 {
        return nil // Token already expired
    }

    blacklistKey := fmt.Sprintf("blacklist:token:%s", tokenID)
    return tb.redisClient.Set(ctx, blacklistKey, "revoked", ttl).Err()
}

func (tb *TokenBlacklist) IsTokenRevoked(tokenID string) (bool, error) {
    blacklistKey := fmt.Sprintf("blacklist:token:%s", tokenID)
    exists, err := tb.redisClient.Exists(ctx, blacklistKey).Result()
    return exists > 0, err
}
```

#### Multi-Factor Authentication State

```go
type MFAManager struct {
    redisClient *redis.Client
}

func (mfa *MFAManager) InitiateMFA(userID string, method string) (string, error) {
    challengeID := uuid.New().String()
    challenge := MFAChallenge{
        ID:       challengeID,
        UserID:   userID,
        Method:   method,
        Created:  time.Now(),
        Attempts: 0,
    }

    key := fmt.Sprintf("mfa:challenge:%s", challengeID)
    challengeData, _ := json.Marshal(challenge)

    // Store challenge with 5-minute TTL
    return challengeID, mfa.redisClient.Set(ctx, key, challengeData, 5*time.Minute).Err()
}

func (mfa *MFAManager) VerifyMFA(challengeID, code string) (bool, error) {
    key := fmt.Sprintf("mfa:challenge:%s", challengeID)
    challengeData, err := mfa.redisClient.Get(ctx, key).Result()
    if err != nil {
        return false, err
    }

    var challenge MFAChallenge
    json.Unmarshal([]byte(challengeData), &challenge)

    // Verify code and update attempts
    if verifyTOTP(code, challenge.UserID) {
        mfa.redisClient.Del(ctx, key) // Remove challenge
        return true, nil
    }

    challenge.Attempts++
    if challenge.Attempts >= 3 {
        mfa.redisClient.Del(ctx, key) // Remove after max attempts
        return false, errors.New("max attempts exceeded")
    }

    updatedData, _ := json.Marshal(challenge)
    mfa.redisClient.Set(ctx, key, updatedData, 5*time.Minute)
    return false, nil
}
```

---

## 3. Caching Strategy

### Distributed Caching Architecture

#### Redis Cache Configuration

```yaml
# Redis Cluster Configuration
redis_cluster:
  nodes:
    - redis-1.isectech.internal:6379
    - redis-2.isectech.internal:6379
    - redis-3.isectech.internal:6379
  settings:
    maxmemory: 8gb
    maxmemory_policy: allkeys-lru
    timeout: 300
    tcp_keepalive: 60
    cluster_enabled: true
    cluster_config_file: nodes.conf
    cluster_node_timeout: 15000
    cluster_require_full_coverage: false

# Tenant Isolation
tenant_isolation:
  strategy: key_prefix
  prefix_format: 'tenant:{tenant_id}:{key}'
  fallback_db: 0
  max_connections_per_tenant: 100
```

#### Cache Client Implementation

```go
type TenantAwareCacheClient struct {
    redisClient *redis.ClusterClient
}

func (c *TenantAwareCacheClient) Get(ctx context.Context, tenantID, key string) (string, error) {
    tenantKey := fmt.Sprintf("tenant:%s:%s", tenantID, key)
    return c.redisClient.Get(ctx, tenantKey).Result()
}

func (c *TenantAwareCacheClient) Set(ctx context.Context, tenantID, key, value string, expiration time.Duration) error {
    tenantKey := fmt.Sprintf("tenant:%s:%s", tenantID, key)
    return c.redisClient.Set(ctx, tenantKey, value, expiration).Err()
}

func (c *TenantAwareCacheClient) Delete(ctx context.Context, tenantID, key string) error {
    tenantKey := fmt.Sprintf("tenant:%s:%s", tenantID, key)
    return c.redisClient.Del(ctx, tenantKey).Err()
}

// Cache pattern: Write-through
func (c *TenantAwareCacheClient) SetWithWriteThrough(ctx context.Context,
    tenantID, key, value string,
    dbWriter func(context.Context, string, string) error) error {

    // Write to database first
    if err := dbWriter(ctx, key, value); err != nil {
        return err
    }

    // Then cache with TTL
    return c.Set(ctx, tenantID, key, value, 1*time.Hour)
}
```

### Cache Invalidation Patterns

#### Event-Driven Cache Invalidation

```go
type CacheInvalidationHandler struct {
    cacheClient *TenantAwareCacheClient
    eventBus    EventBusClient
}

func (h *CacheInvalidationHandler) HandleUserUpdatedEvent(event UserUpdatedEvent) {
    // Invalidate user-related cache entries
    patterns := []string{
        fmt.Sprintf("user:%s:profile", event.UserID),
        fmt.Sprintf("user:%s:permissions", event.UserID),
        fmt.Sprintf("tenant:%s:users", event.TenantID),
    }

    for _, pattern := range patterns {
        h.cacheClient.DeletePattern(context.Background(), event.TenantID, pattern)
    }
}

func (h *CacheInvalidationHandler) HandleTenantConfigUpdated(event TenantConfigUpdatedEvent) {
    // Invalidate tenant configuration cache
    h.cacheClient.Delete(context.Background(), event.TenantID, "config")

    // Publish cache invalidation event for other services
    invalidationEvent := CacheInvalidationEvent{
        TenantID: event.TenantID,
        Patterns: []string{"config", "policies", "settings"},
    }
    h.eventBus.Publish("cache.invalidation", invalidationEvent)
}
```

#### Cache-Aside Pattern Implementation

```go
func (s *SecurityEventService) GetThreatIntelligence(ctx context.Context,
    tenantID, indicator string) (*ThreatIntel, error) {

    // Try cache first
    cacheKey := fmt.Sprintf("threat_intel:%s", indicator)
    if cached, err := s.cache.Get(ctx, tenantID, cacheKey); err == nil {
        var intel ThreatIntel
        json.Unmarshal([]byte(cached), &intel)
        return &intel, nil
    }

    // Cache miss - fetch from database
    intel, err := s.database.GetThreatIntelligence(ctx, tenantID, indicator)
    if err != nil {
        return nil, err
    }

    // Update cache asynchronously
    go func() {
        if data, err := json.Marshal(intel); err == nil {
            s.cache.Set(context.Background(), tenantID, cacheKey, string(data), 30*time.Minute)
        }
    }()

    return intel, nil
}
```

---

## 4. Database Connection Management

### Connection Pooling Strategy

#### Per-Service Connection Pools

```go
type DatabaseConfig struct {
    PostgreSQL struct {
        Host            string `yaml:"host"`
        Port            int    `yaml:"port"`
        Database        string `yaml:"database"`
        Username        string `yaml:"username"`
        Password        string `yaml:"password"`
        MaxConnections  int    `yaml:"max_connections"`
        MinConnections  int    `yaml:"min_connections"`
        ConnMaxLifetime int    `yaml:"conn_max_lifetime"`
        ConnMaxIdleTime int    `yaml:"conn_max_idle_time"`
    } `yaml:"postgresql"`

    MongoDB struct {
        URI             string `yaml:"uri"`
        Database        string `yaml:"database"`
        MaxPoolSize     int    `yaml:"max_pool_size"`
        MinPoolSize     int    `yaml:"min_pool_size"`
        MaxConnIdleTime int    `yaml:"max_conn_idle_time"`
    } `yaml:"mongodb"`
}

type DatabaseManager struct {
    pgPool    *pgxpool.Pool
    mongoPool *mongo.Client
}

func NewDatabaseManager(config DatabaseConfig) (*DatabaseManager, error) {
    // PostgreSQL connection pool
    pgConfig, err := pgxpool.ParseConfig(buildPostgreSQLURL(config.PostgreSQL))
    if err != nil {
        return nil, err
    }

    pgConfig.MaxConns = int32(config.PostgreSQL.MaxConnections)
    pgConfig.MinConns = int32(config.PostgreSQL.MinConnections)
    pgConfig.MaxConnLifetime = time.Duration(config.PostgreSQL.ConnMaxLifetime) * time.Second
    pgConfig.MaxConnIdleTime = time.Duration(config.PostgreSQL.ConnMaxIdleTime) * time.Second

    pgPool, err := pgxpool.ConnectConfig(context.Background(), pgConfig)
    if err != nil {
        return nil, err
    }

    // MongoDB connection pool
    mongoOptions := options.Client().
        ApplyURI(config.MongoDB.URI).
        SetMaxPoolSize(uint64(config.MongoDB.MaxPoolSize)).
        SetMinPoolSize(uint64(config.MongoDB.MinPoolSize)).
        SetMaxConnIdleTime(time.Duration(config.MongoDB.MaxConnIdleTime) * time.Second)

    mongoClient, err := mongo.Connect(context.Background(), mongoOptions)
    if err != nil {
        return nil, err
    }

    return &DatabaseManager{
        pgPool:    pgPool,
        mongoPool: mongoClient,
    }, nil
}
```

#### Connection Health Monitoring

```go
func (dm *DatabaseManager) HealthCheck(ctx context.Context) error {
    // PostgreSQL health check
    if err := dm.pgPool.Ping(ctx); err != nil {
        return fmt.Errorf("postgresql health check failed: %w", err)
    }

    // MongoDB health check
    if err := dm.mongoPool.Ping(ctx, readpref.Primary()); err != nil {
        return fmt.Errorf("mongodb health check failed: %w", err)
    }

    return nil
}

func (dm *DatabaseManager) GetConnectionStats() ConnectionStats {
    pgStats := dm.pgPool.Stat()

    return ConnectionStats{
        PostgreSQL: PGStats{
            AcquireCount:         pgStats.AcquireCount(),
            AcquiredConns:        pgStats.AcquiredConns(),
            CanceledAcquireCount: pgStats.CanceledAcquireCount(),
            ConstructingConns:    pgStats.ConstructingConns(),
            EmptyAcquireCount:    pgStats.EmptyAcquireCount(),
            IdleConns:           pgStats.IdleConns(),
            MaxConns:            pgStats.MaxConns(),
            TotalConns:          pgStats.TotalConns(),
        },
    }
}
```

### Database Sharding & Multi-Tenancy

#### Tenant-Aware Database Router

```go
type TenantDatabaseRouter struct {
    defaultDB   *DatabaseManager
    tenantDBs   map[string]*DatabaseManager
    shardConfig ShardConfiguration
}

func (r *TenantDatabaseRouter) GetDatabaseForTenant(tenantID string) *DatabaseManager {
    // Check for dedicated tenant database
    if tenantDB, exists := r.tenantDBs[tenantID]; exists {
        return tenantDB
    }

    // Route to shard based on tenant ID
    shardKey := r.calculateShardKey(tenantID)
    if shardDB, exists := r.tenantDBs[shardKey]; exists {
        return shardDB
    }

    // Fallback to default database
    return r.defaultDB
}

func (r *TenantDatabaseRouter) calculateShardKey(tenantID string) string {
    hash := fnv.New32a()
    hash.Write([]byte(tenantID))
    shardIndex := hash.Sum32() % uint32(r.shardConfig.NumShards)
    return fmt.Sprintf("shard-%d", shardIndex)
}
```

#### Row-Level Security Implementation

```sql
-- PostgreSQL Row-Level Security for Multi-Tenancy
-- Enable RLS on all tenant tables
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;

-- Create policies to enforce tenant isolation
CREATE POLICY tenant_isolation_security_events
ON security_events
FOR ALL
TO application_role
USING (tenant_id = current_setting('app.current_tenant'));

CREATE POLICY tenant_isolation_vulnerabilities
ON vulnerabilities
FOR ALL
TO application_role
USING (tenant_id = current_setting('app.current_tenant'));

-- Set tenant context at connection level
SET app.current_tenant = 'tenant-12345';
```

---

## 5. State Persistence Patterns

### Event Sourcing Implementation

#### Event Store Design

```go
type EventStore struct {
    database *DatabaseManager
    kafka    *KafkaProducer
}

type Event struct {
    ID          string                 `json:"id"`
    Type        string                 `json:"type"`
    AggregateID string                 `json:"aggregate_id"`
    TenantID    string                 `json:"tenant_id"`
    Version     int64                  `json:"version"`
    Timestamp   time.Time              `json:"timestamp"`
    Data        map[string]interface{} `json:"data"`
    Metadata    map[string]interface{} `json:"metadata"`
}

func (es *EventStore) AppendEvent(ctx context.Context, event Event) error {
    // Persist event to database for durability
    query := `
        INSERT INTO events (id, type, aggregate_id, tenant_id, version, timestamp, data, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

    _, err := es.database.pgPool.Exec(ctx, query,
        event.ID, event.Type, event.AggregateID, event.TenantID,
        event.Version, event.Timestamp, event.Data, event.Metadata)
    if err != nil {
        return err
    }

    // Publish event to Kafka for real-time processing
    eventBytes, _ := json.Marshal(event)
    return es.kafka.Produce(ctx, KafkaMessage{
        Topic: fmt.Sprintf("events.%s", event.Type),
        Key:   event.AggregateID,
        Value: eventBytes,
    })
}

func (es *EventStore) GetEventsForAggregate(ctx context.Context,
    tenantID, aggregateID string, fromVersion int64) ([]Event, error) {

    query := `
        SELECT id, type, aggregate_id, tenant_id, version, timestamp, data, metadata
        FROM events
        WHERE tenant_id = $1 AND aggregate_id = $2 AND version >= $3
        ORDER BY version ASC`

    rows, err := es.database.pgPool.Query(ctx, query, tenantID, aggregateID, fromVersion)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var events []Event
    for rows.Next() {
        var event Event
        err := rows.Scan(&event.ID, &event.Type, &event.AggregateID,
            &event.TenantID, &event.Version, &event.Timestamp,
            &event.Data, &event.Metadata)
        if err != nil {
            return nil, err
        }
        events = append(events, event)
    }

    return events, nil
}
```

#### CQRS Read Model Projections

```go
type ReadModelProjector struct {
    eventStore   *EventStore
    readDatabase *DatabaseManager
    kafkaConsumer *KafkaConsumer
}

func (p *ReadModelProjector) ProcessSecurityIncidentEvents(ctx context.Context) error {
    return p.kafkaConsumer.Subscribe(ctx, []string{"events.SecurityIncidentCreated",
        "events.SecurityIncidentUpdated", "events.SecurityIncidentResolved"},
        func(message KafkaMessage) error {
            var event Event
            json.Unmarshal(message.Value, &event)

            switch event.Type {
            case "SecurityIncidentCreated":
                return p.createIncidentReadModel(ctx, event)
            case "SecurityIncidentUpdated":
                return p.updateIncidentReadModel(ctx, event)
            case "SecurityIncidentResolved":
                return p.resolveIncidentReadModel(ctx, event)
            }
            return nil
        })
}

func (p *ReadModelProjector) createIncidentReadModel(ctx context.Context, event Event) error {
    query := `
        INSERT INTO security_incident_read_model
        (id, tenant_id, title, severity, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`

    _, err := p.readDatabase.pgPool.Exec(ctx, query,
        event.AggregateID,
        event.TenantID,
        event.Data["title"],
        event.Data["severity"],
        "open",
        event.Timestamp,
        event.Timestamp)

    return err
}
```

### Idempotency Patterns

#### Idempotent API Operations

```go
type IdempotencyManager struct {
    cache *TenantAwareCacheClient
}

func (im *IdempotencyManager) EnsureIdempotent(ctx context.Context,
    tenantID, operationID string,
    operation func() (interface{}, error)) (interface{}, error) {

    // Check if operation already processed
    cacheKey := fmt.Sprintf("idempotency:%s", operationID)
    if cached, err := im.cache.Get(ctx, tenantID, cacheKey); err == nil {
        var result IdempotencyResult
        json.Unmarshal([]byte(cached), &result)

        if result.Status == "completed" {
            return result.Data, nil
        } else if result.Status == "processing" {
            return nil, errors.New("operation already in progress")
        }
    }

    // Mark operation as processing
    processingResult := IdempotencyResult{
        Status: "processing",
        Timestamp: time.Now(),
    }
    resultData, _ := json.Marshal(processingResult)
    im.cache.Set(ctx, tenantID, cacheKey, string(resultData), 1*time.Hour)

    // Execute operation
    result, err := operation()
    if err != nil {
        // Mark as failed
        failedResult := IdempotencyResult{
            Status: "failed",
            Error:  err.Error(),
            Timestamp: time.Now(),
        }
        failedData, _ := json.Marshal(failedResult)
        im.cache.Set(ctx, tenantID, cacheKey, string(failedData), 1*time.Hour)
        return nil, err
    }

    // Mark as completed
    completedResult := IdempotencyResult{
        Status: "completed",
        Data:   result,
        Timestamp: time.Now(),
    }
    completedData, _ := json.Marshal(completedResult)
    im.cache.Set(ctx, tenantID, cacheKey, string(completedData), 24*time.Hour)

    return result, nil
}
```

---

## 6. Service Discovery & Configuration

### External Configuration Management

#### Configuration Service

```go
type ConfigurationManager struct {
    consul     *consul.Client
    cache      *TenantAwareCacheClient
    encryption EncryptionService
}

func (cm *ConfigurationManager) GetConfiguration(ctx context.Context,
    tenantID, service, key string) (string, error) {

    // Try cache first
    cacheKey := fmt.Sprintf("config:%s:%s", service, key)
    if cached, err := cm.cache.Get(ctx, tenantID, cacheKey); err == nil {
        return cm.encryption.Decrypt(cached)
    }

    // Fetch from Consul
    consulKey := fmt.Sprintf("tenants/%s/services/%s/%s", tenantID, service, key)
    kv, _, err := cm.consul.KV().Get(consulKey, nil)
    if err != nil {
        return "", err
    }

    if kv == nil {
        return "", errors.New("configuration not found")
    }

    // Cache encrypted value
    go func() {
        cm.cache.Set(context.Background(), tenantID, cacheKey,
            string(kv.Value), 10*time.Minute)
    }()

    return cm.encryption.Decrypt(string(kv.Value))
}

func (cm *ConfigurationManager) WatchConfiguration(ctx context.Context,
    tenantID, service string,
    callback func(key, value string)) error {

    consulKey := fmt.Sprintf("tenants/%s/services/%s/", tenantID, service)

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
            pairs, _, err := cm.consul.KV().List(consulKey, nil)
            if err != nil {
                time.Sleep(5 * time.Second)
                continue
            }

            for _, pair := range pairs {
                key := strings.TrimPrefix(pair.Key, consulKey)
                value, _ := cm.encryption.Decrypt(string(pair.Value))
                callback(key, value)

                // Update cache
                cacheKey := fmt.Sprintf("config:%s:%s", service, key)
                cm.cache.Set(ctx, tenantID, cacheKey, string(pair.Value), 10*time.Minute)
            }

            time.Sleep(30 * time.Second)
        }
    }
}
```

### Service Registration & Discovery

#### Health Check Integration

```go
type ServiceRegistry struct {
    consul    *consul.Client
    serviceID string
    health    HealthChecker
}

func (sr *ServiceRegistry) RegisterService(ctx context.Context,
    serviceName, servicePort string) error {

    registration := &consul.AgentServiceRegistration{
        ID:      sr.serviceID,
        Name:    serviceName,
        Port:    servicePort,
        Address: getLocalIP(),
        Check: &consul.AgentServiceCheck{
            HTTP:                           fmt.Sprintf("http://%s:%s/health", getLocalIP(), servicePort),
            Interval:                       "10s",
            Timeout:                        "3s",
            DeregisterCriticalServiceAfter: "30s",
        },
        Meta: map[string]string{
            "version":    getServiceVersion(),
            "deployment": getDeploymentID(),
        },
    }

    return sr.consul.Agent().ServiceRegister(registration)
}

func (sr *ServiceRegistry) DiscoverServices(ctx context.Context,
    serviceName string) ([]ServiceInstance, error) {

    services, _, err := sr.consul.Health().Service(serviceName, "", true, nil)
    if err != nil {
        return nil, err
    }

    var instances []ServiceInstance
    for _, service := range services {
        instances = append(instances, ServiceInstance{
            ID:      service.Service.ID,
            Address: service.Service.Address,
            Port:    service.Service.Port,
            Meta:    service.Service.Meta,
        })
    }

    return instances, nil
}
```

---

## 7. Monitoring & Observability

### Stateless Service Metrics

#### Prometheus Metrics Collection

```go
type ServiceMetrics struct {
    requestsTotal     prometheus.CounterVec
    requestDuration   prometheus.HistogramVec
    activeConnections prometheus.GaugeVec
    cacheHitRate      prometheus.GaugeVec
    dbConnections     prometheus.GaugeVec
}

func NewServiceMetrics(serviceName string) *ServiceMetrics {
    return &ServiceMetrics{
        requestsTotal: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "http_requests_total",
                Help: "Total number of HTTP requests",
            },
            []string{"method", "endpoint", "status", "tenant_id"},
        ),
        requestDuration: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name:    "http_request_duration_seconds",
                Help:    "HTTP request duration in seconds",
                Buckets: prometheus.DefBuckets,
            },
            []string{"method", "endpoint", "tenant_id"},
        ),
        cacheHitRate: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Name: "cache_hit_rate",
                Help: "Cache hit rate percentage",
            },
            []string{"cache_type", "tenant_id"},
        ),
    }
}

func (sm *ServiceMetrics) RecordRequest(method, endpoint, status, tenantID string,
    duration time.Duration) {
    sm.requestsTotal.WithLabelValues(method, endpoint, status, tenantID).Inc()
    sm.requestDuration.WithLabelValues(method, endpoint, tenantID).Observe(duration.Seconds())
}
```

#### Distributed Tracing

```go
type TracingManager struct {
    tracer opentracing.Tracer
}

func (tm *TracingManager) TraceServiceCall(ctx context.Context,
    operationName string,
    fn func(context.Context) error) error {

    span, ctx := opentracing.StartSpanFromContext(ctx, operationName)
    defer span.Finish()

    // Add standard tags
    span.SetTag("service.name", getServiceName())
    span.SetTag("service.version", getServiceVersion())

    // Extract tenant context
    if reqCtx := GetRequestContext(ctx); reqCtx != nil {
        span.SetTag("tenant.id", reqCtx.TenantID)
        span.SetTag("user.id", reqCtx.UserID)
        span.SetTag("trace.id", reqCtx.TraceID)
    }

    // Execute function
    err := fn(ctx)
    if err != nil {
        span.SetTag("error", true)
        span.LogFields(
            log.String("event", "error"),
            log.String("message", err.Error()),
        )
    }

    return err
}
```

---

## 8. Security Considerations

### Multi-Tenant Data Isolation

#### Encryption at Rest

```go
type TenantEncryptionManager struct {
    kms        KMSClient
    encryptor  FieldEncryptor
}

func (tem *TenantEncryptionManager) EncryptSensitiveData(ctx context.Context,
    tenantID string, data []byte) ([]byte, error) {

    // Get tenant-specific encryption key
    keyID := fmt.Sprintf("tenant-%s-data-key", tenantID)
    dataKey, err := tem.kms.GetDataKey(ctx, keyID)
    if err != nil {
        return nil, err
    }

    // Encrypt data with tenant key
    return tem.encryptor.Encrypt(data, dataKey)
}

func (tem *TenantEncryptionManager) DecryptSensitiveData(ctx context.Context,
    tenantID string, encryptedData []byte) ([]byte, error) {

    keyID := fmt.Sprintf("tenant-%s-data-key", tenantID)
    dataKey, err := tem.kms.GetDataKey(ctx, keyID)
    if err != nil {
        return nil, err
    }

    return tem.encryptor.Decrypt(encryptedData, dataKey)
}
```

#### Secure State Transitions

```go
type SecureStateManager struct {
    eventStore     *EventStore
    authorization  AuthorizationService
    audit          AuditLogger
}

func (ssm *SecureStateManager) ProcessSecureStateTransition(ctx context.Context,
    command StateTransitionCommand) error {

    // Extract request context
    reqCtx := GetRequestContext(ctx)
    if reqCtx == nil {
        return errors.New("missing request context")
    }

    // Authorization check
    if !ssm.authorization.CanExecuteCommand(reqCtx, command) {
        ssm.audit.LogUnauthorizedAccess(reqCtx, command)
        return errors.New("unauthorized state transition")
    }

    // Validate state transition
    currentState, err := ssm.getCurrentState(ctx, command.AggregateID)
    if err != nil {
        return err
    }

    if !isValidTransition(currentState, command.TargetState) {
        return errors.New("invalid state transition")
    }

    // Create and persist event
    event := Event{
        ID:          uuid.New().String(),
        Type:        command.EventType,
        AggregateID: command.AggregateID,
        TenantID:    reqCtx.TenantID,
        Version:     currentState.Version + 1,
        Timestamp:   time.Now(),
        Data:        command.Data,
        Metadata: map[string]interface{}{
            "user_id":    reqCtx.UserID,
            "ip_address": reqCtx.IPAddress,
            "user_agent": reqCtx.UserAgent,
        },
    }

    err = ssm.eventStore.AppendEvent(ctx, event)
    if err != nil {
        return err
    }

    // Audit log
    ssm.audit.LogStateTransition(reqCtx, command, event)

    return nil
}
```

---

## 9. Performance Optimization

### Connection Pooling Optimization

#### Database Pool Sizing

```go
// Optimal pool sizing based on service characteristics
func calculateOptimalPoolSize(serviceType string, expectedConcurrency int) PoolConfig {
    switch serviceType {
    case "high_read_throughput":
        return PoolConfig{
            MaxConnections:  expectedConcurrency * 2,
            MinConnections:  expectedConcurrency / 4,
            ConnMaxLifetime: 30 * time.Minute,
            ConnMaxIdleTime: 5 * time.Minute,
        }
    case "high_write_throughput":
        return PoolConfig{
            MaxConnections:  expectedConcurrency / 2,
            MinConnections:  expectedConcurrency / 8,
            ConnMaxLifetime: 15 * time.Minute,
            ConnMaxIdleTime: 2 * time.Minute,
        }
    case "analytics":
        return PoolConfig{
            MaxConnections:  expectedConcurrency / 4,
            MinConnections:  2,
            ConnMaxLifetime: 60 * time.Minute,
            ConnMaxIdleTime: 10 * time.Minute,
        }
    default:
        return PoolConfig{
            MaxConnections:  expectedConcurrency,
            MinConnections:  expectedConcurrency / 8,
            ConnMaxLifetime: 30 * time.Minute,
            ConnMaxIdleTime: 5 * time.Minute,
        }
    }
}
```

### Cache Performance Optimization

#### Predictive Cache Warming

```go
type CacheWarmingService struct {
    cache        *TenantAwareCacheClient
    analytics    AnalyticsService
    scheduler    SchedulerService
}

func (cws *CacheWarmingService) WarmFrequentlyAccessedData(ctx context.Context,
    tenantID string) error {

    // Get access patterns from analytics
    patterns, err := cws.analytics.GetAccessPatterns(ctx, tenantID, 24*time.Hour)
    if err != nil {
        return err
    }

    // Identify frequently accessed keys
    frequentKeys := patterns.GetTopKeys(100) // Top 100 most accessed

    // Pre-load into cache
    for _, key := range frequentKeys {
        go func(k string) {
            if data, err := cws.fetchDataForKey(ctx, tenantID, k); err == nil {
                cws.cache.Set(ctx, tenantID, k, data, 2*time.Hour)
            }
        }(key)
    }

    return nil
}

func (cws *CacheWarmingService) SchedulePeriodicWarming(tenantID string) {
    cws.scheduler.Schedule(fmt.Sprintf("cache_warming_%s", tenantID),
        "0 */6 * * *", // Every 6 hours
        func() {
            cws.WarmFrequentlyAccessedData(context.Background(), tenantID)
        })
}
```

---

## 10. Implementation Guidelines

### Service Development Template

#### Stateless Service Checklist

- [ ] **No instance variables** for request-specific data
- [ ] **All dependencies injected** at construction time
- [ ] **Request context extracted** from headers/tokens
- [ ] **External state management** for all persistent data
- [ ] **Idempotent operations** with deduplication
- [ ] **Graceful degradation** when external services fail
- [ ] **Comprehensive logging** with correlation IDs
- [ ] **Health checks** implemented for all dependencies
- [ ] **Metrics collection** for performance monitoring
- [ ] **Circuit breaker patterns** for external calls

#### Code Review Guidelines

```go
// ❌ BAD: Storing state in service instance
type BadService struct {
    userSession map[string]UserSession // DON'T DO THIS
    requestData RequestData             // DON'T DO THIS
}

// ✅ GOOD: Stateless service with injected dependencies
type GoodService struct {
    cache     CacheClient    // Injected dependency
    database  DatabaseClient // Injected dependency
    eventBus  EventBusClient // Injected dependency
}

func (s *GoodService) ProcessRequest(ctx context.Context, req Request) Response {
    // Extract context from request
    reqCtx := GetRequestContext(ctx)

    // Use external state
    userData, err := s.cache.Get(ctx, reqCtx.TenantID, "user:"+reqCtx.UserID)

    // Return response without storing any state
    return Response{...}
}
```

### Migration Strategy

#### Legacy to Stateless Migration

1. **Phase 1:** Identify stateful components in existing services
2. **Phase 2:** Extract state to external stores (Redis, databases)
3. **Phase 3:** Implement stateless request processing
4. **Phase 4:** Add health checks and monitoring
5. **Phase 5:** Test horizontal scaling and failover
6. **Phase 6:** Production deployment with gradual rollout

---

## 11. Success Criteria

### Performance Criteria

- **Horizontal Scaling:** Linear performance increase with instance count
- **Response Time:** < 200ms P95 for stateless operations
- **Throughput:** Support 1M+ requests/second across service cluster
- **Resource Efficiency:** < 512MB memory per service instance

### Reliability Criteria

- **Fault Tolerance:** Zero data loss during instance failures
- **Recovery Time:** < 10 seconds for instance replacement
- **Cache Hit Rate:** > 80% for frequently accessed data
- **Database Connection Efficiency:** > 90% connection pool utilization

### Security Criteria

- **Tenant Isolation:** 100% data isolation between tenants
- **State Encryption:** All sensitive state encrypted at rest
- **Audit Compliance:** Complete audit trail for all state changes
- **Access Control:** Zero unauthorized cross-tenant access

---

**Next Steps:**

- Proceed to Task 26.7: Implement Resilience Patterns (Circuit Breakers and Bulkheads)
- Begin implementing stateless service templates
- Set up Redis cluster for external state management
- Configure database connection pools for each service
- Implement JWT-based authentication across all services
