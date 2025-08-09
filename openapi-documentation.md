# iSECTECH OpenAPI 3.1 Specifications

This document provides comprehensive OpenAPI 3.1 specifications for all iSECTECH API endpoints, including frontend APIs, backend microservices, and extended functionality.

## Overview

The iSECTECH platform provides a comprehensive set of APIs for security operations, compliance management, threat detection, and administrative functions. All APIs follow OpenAPI 3.1 standards with comprehensive documentation, examples, and validation schemas.

## API Specifications

### 1. Complete Frontend API (`app/api/openapi-complete.json`)

**Base URL**: `https://api.isectech.com/v2`

**Description**: Main frontend API endpoints accessed through the Next.js application

**Key Endpoints**:
- **Authentication**: `/auth/login`, `/auth/logout`, `/auth/verify`
- **Policy Evaluation**: `/policy/evaluate`, `/policy/batch`  
- **Notifications**: `/notifications` (CRUD operations)
- **Trust Scoring**: `/trust-score` (calculation and retrieval)
- **Compliance**: `/compliance/status` (status and actions)
- **Tenant Management**: `/tenants` (multi-tenant operations)
- **Onboarding**: `/onboarding` (workflow management)
- **System**: `/health`, `/metrics` (monitoring endpoints)

**Authentication**: Bearer JWT tokens, API key authentication

**Rate Limits**: 
- Authentication: 100 requests/minute
- Trust Score: 5000 requests/minute  
- Notifications: 1000 requests/minute
- General: 1000 requests/minute

### 2. Backend Services API (`backend/openapi-backend-services.json`)

**Base URL**: `https://api-services.isectech.com/v1`

**Description**: Backend microservices API for internal service communication

**Services Covered**:
- **Auth Service**: User authentication, MFA, session management
- **Asset Discovery**: Network scanning and asset identification
- **Asset Inventory**: Asset management and classification  
- **Event Processing**: Security event processing and correlation
- **Threat Detection**: Threat analysis and intelligence processing
- **Vulnerability Scanner**: Vulnerability scanning and assessment
- **Mobile Notification**: Push notification delivery
- **Security Agent**: Agent registration and management
- **Billing Service**: Subscription and payment processing
- **Migration Service**: Data migration from legacy systems
- **Security Training**: Training content management
- **Security Benchmarking**: Security scoring and benchmarks

**Authentication**: Bearer JWT tokens, Service API keys

**Communication**: Internal service-to-service communication with mTLS

### 3. Extended APIs (`app/api/openapi-extended-apis.json`)

**Base URL**: `https://api.isectech.com/v2`

**Description**: Additional frontend APIs for advanced functionality

**Key Features**:
- **Notification Templates**: Template management and rendering
- **Notification Analytics**: Advanced notification analytics
- **Trust Score Analytics**: Detailed trust score insights  
- **Trust Score WebSocket**: Real-time trust score updates
- **Policy Administration**: Policy bundle management
- **Compliance Management**: Advanced compliance operations
- **Performance Analytics**: System performance metrics
- **Advanced Onboarding**: Detailed workflow management

**Special Endpoints**:
- WebSocket endpoint for real-time updates: `/trust-score/websocket`
- Template rendering with localization: `/notifications/templates/render`
- Complex analytics with multiple dimensions: `/trust-score/analytics`

## Authentication & Authorization

### Authentication Schemes

1. **Bearer Authentication (JWT)**
   ```
   Authorization: Bearer <jwt_token>
   ```
   - Used for user authentication
   - Tokens expire after 8 hours (24 hours with "remember me")
   - Refresh tokens valid for 30 days

2. **API Key Authentication**
   ```
   X-API-Key: <api_key>
   ```
   - Used for service-to-service communication
   - Required for policy evaluation and batch operations
   - Different permission levels based on key type

### Security Features

- **Multi-Factor Authentication (MFA)**: TOTP, SMS, email, WebAuthn support
- **Tenant Isolation**: All operations scoped to tenant context
- **Role-Based Access Control (RBAC)**: Fine-grained permissions
- **Rate Limiting**: Per-endpoint limits with 429 responses
- **Request Validation**: Comprehensive input validation using JSON schemas
- **Audit Logging**: All API calls logged with correlation IDs

## Request/Response Patterns

### Standard Response Format

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "metadata": {
    "requestId": "req_123456789",
    "timestamp": "2024-01-01T12:00:00Z", 
    "processingTime": 150,
    "cached": false
  }
}
```

### Error Response Format

```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": [
    {
      "field": "email",
      "message": "Invalid email format",
      "code": "VALIDATION_ERROR"
    }
  ],
  "requestId": "req_123456789"
}
```

### Pagination Pattern

```json
{
  "data": {
    "items": [...],
    "total": 1000,
    "limit": 50,
    "offset": 0,
    "hasMore": true
  }
}
```

## Key Data Models

### User Profile
```json
{
  "id": "user_123",
  "email": "user@company.com", 
  "role": "admin",
  "tenantId": "tenant_456",
  "securityClearance": "high",
  "permissions": ["read:all", "write:security"],
  "mfaEnabled": true
}
```

### Trust Score
```json
{
  "id": "ts_123",
  "userId": "user_456",
  "score": 85.5,
  "riskLevel": "low",
  "factors": {
    "behavioral": {"score": 90, "weight": 0.3},
    "device": {"score": 85, "weight": 0.2},
    "network": {"score": 80, "weight": 0.2},
    "location": {"score": 95, "weight": 0.15},
    "threat": {"score": 75, "weight": 0.15}
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Policy Decision
```json
{
  "allow": true,
  "reasons": ["All policy checks passed"],
  "trust_score": 85.5,
  "risk_level": "low", 
  "context": {
    "evaluation_time_ms": 150,
    "policy_version": "1.0.0"
  },
  "audit_info": {
    "request_id": "req_789",
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

### Notification
```json
{
  "id": "notif_123",
  "title": "Security Alert",
  "message": "Suspicious login detected",
  "type": "security",
  "priority": "high",
  "status": "delivered",
  "recipients": [
    {
      "userId": "user_123",
      "channel": "push"
    }
  ],
  "createdAt": "2024-01-01T12:00:00Z"
}
```

## Integration Examples

### Authentication Flow

```javascript
// 1. Login
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@company.com',
    password: 'password',
    tenantId: 'tenant-uuid',
    mfaToken: '123456' // if MFA enabled
  })
});

// 2. Use JWT token for subsequent requests
const data = await response.json();
const token = data.user.accessToken;

// 3. Make authenticated requests
const protectedResponse = await fetch('/api/trust-score', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
});
```

### Policy Evaluation

```javascript
// Evaluate access request
const policyResponse = await fetch('/api/policy/evaluate', {
  method: 'POST',
  headers: {
    'X-API-Key': 'your-api-key',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    user: {
      id: 'user_123',
      tenant_id: 'tenant_456',
      roles: ['analyst'],
      authenticated: true
    },
    resource: 'security-events',
    action: 'read',
    tenant_id: 'tenant_456',
    context: {
      ip_address: '192.168.1.100',
      timestamp: Date.now() / 1000,
      session_id: 'session_789'
    }
  })
});
```

### Trust Score Calculation

```javascript
// Calculate trust score
const trustScoreResponse = await fetch('/api/trust-score', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    userId: 'user_123',
    deviceId: 'device_456',
    context: {
      location: {
        country: 'US',
        latitude: 37.7749,
        longitude: -122.4194
      },
      device: {
        platform: 'Windows',
        browser: 'Chrome'
      },
      behavior: {
        loginFrequency: 2.5,
        lastActivity: '2024-01-01T11:00:00Z'
      }
    }
  })
});
```

### Real-time Trust Score Updates (WebSocket)

```javascript
// Connect to WebSocket for real-time updates
const ws = new WebSocket('wss://api.isectech.com/v2/trust-score/websocket', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === 'trust_score_update') {
    console.log('New trust score:', data.payload);
  }
};

// Subscribe to specific users
ws.send(JSON.stringify({
  type: 'subscribe',
  payload: {
    userIds: ['user_123', 'user_456'],
    riskLevels: ['high', 'critical']
  }
}));
```

## Validation and Testing

### OpenAPI Validation

The specifications can be validated using various tools:

```bash
# Using Swagger CLI
swagger-codegen validate -i app/api/openapi-complete.json

# Using Redocly CLI  
redocly lint app/api/openapi-complete.json

# Using Spectral
spectral lint app/api/openapi-complete.json
```

### Integration Testing

```bash
# Run integration tests against OpenAPI specs
npm run test:integration

# Generate client SDKs
swagger-codegen generate -i app/api/openapi-complete.json -l javascript -o client-sdk/

# Generate documentation
redoc-cli build app/api/openapi-complete.json --output docs/api.html
```

## Error Handling

### Standard HTTP Status Codes

- **200**: Success
- **201**: Created successfully
- **400**: Bad Request - Invalid parameters
- **401**: Unauthorized - Authentication required
- **403**: Forbidden - Insufficient permissions
- **404**: Not Found - Resource doesn't exist
- **429**: Too Many Requests - Rate limit exceeded  
- **500**: Internal Server Error
- **503**: Service Unavailable

### Rate Limiting Headers

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1640995200
Retry-After: 60
```

## Performance Considerations

### Caching

- **GET endpoints**: ETags and Cache-Control headers
- **Trust scores**: Cached for 5 minutes by default
- **Policy decisions**: Cached based on context (1-15 minutes)
- **Static data**: Long-term caching with versioning

### Pagination

- Default limit: 50 items
- Maximum limit: 1000 items
- Use `offset` and `limit` parameters
- Response includes `hasMore` indicator

### Batch Operations

- **Trust score calculations**: Up to 100 requests per batch
- **Policy evaluations**: Up to 100 requests per batch
- **Notification sending**: Up to 1000 recipients per notification

## Security Best Practices

### API Security

1. **Always use HTTPS** in production
2. **Validate JWT tokens** on every request
3. **Implement proper CORS** headers
4. **Use API keys** for service-to-service communication
5. **Log all API access** with correlation IDs
6. **Implement rate limiting** per user/tenant
7. **Sanitize all inputs** using provided schemas
8. **Use tenant isolation** for all operations

### Data Privacy

- **PII encryption** for sensitive data
- **Data retention policies** for logs and user data
- **GDPR compliance** for European users
- **Audit trails** for compliance requirements

## Monitoring and Observability

### Metrics

- **Request latency**: p50, p95, p99 percentiles
- **Request rate**: requests per second
- **Error rate**: percentage of failed requests
- **Authentication success/failure rates**
- **Trust score calculation times**
- **Policy evaluation times**

### Alerting

- **High error rates** (>5% for 5 minutes)
- **High latency** (p99 > 2 seconds)  
- **Authentication failures** (>10% for 1 minute)
- **Rate limiting triggered** frequently
- **Service dependencies** unavailable

### Distributed Tracing

All requests include correlation IDs for distributed tracing:
```
X-Correlation-ID: req_123456789
X-Tenant-ID: tenant_456
X-User-ID: user_123
```

## Changelog and Versioning

### API Versioning Strategy

- **Semantic versioning**: Major.Minor.Patch format
- **Backward compatibility**: Maintained within major versions
- **Deprecation policy**: 6 months notice for breaking changes
- **Version headers**: `API-Version: 2.0.0`

### Current Version: 2.0.0

**Major Features**:
- OpenAPI 3.1 compliance
- Enhanced trust scoring with factor breakdown
- Real-time WebSocket endpoints
- Advanced notification templates
- Comprehensive compliance management
- Multi-tenant policy administration

## Support and Resources

### Documentation

- **API Reference**: Generated from OpenAPI specs
- **Integration Guides**: Step-by-step implementation guides
- **SDKs**: Available for JavaScript, Python, Go, Java
- **Postman Collections**: Pre-configured API collections

### Support Channels

- **Technical Support**: support@isectech.com
- **API Team**: api@isectech.com
- **Documentation**: https://docs.isectech.com
- **Status Page**: https://status.isectech.com

### Development Tools

- **Swagger UI**: Interactive API documentation
- **Postman Collections**: Ready-to-use API collections
- **SDK Generators**: Auto-generated client libraries
- **Mock Servers**: For development and testing

## Contributing

### Adding New Endpoints

1. Update appropriate OpenAPI specification file
2. Add comprehensive examples and documentation
3. Include proper error responses
4. Add integration tests
5. Update this documentation
6. Submit pull request for review

### Validation Requirements

- All schemas must include examples
- All endpoints must have operation IDs
- Security requirements must be specified
- Error responses must be documented
- Rate limiting must be considered

For detailed contribution guidelines, see `CONTRIBUTING.md`.