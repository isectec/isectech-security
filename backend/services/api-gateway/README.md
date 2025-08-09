# iSECTECH API Gateway

Production-grade API Gateway for the iSECTECH Security Platform, built with Go and designed for high-performance, security, and scalability in cloud-native environments.

## Features

### 🛡️ Security Features
- **Multi-Authentication Support**: JWT, API Keys, OAuth, Basic Auth, and custom authentication
- **Role-Based Access Control (RBAC)**: Fine-grained authorization with roles and scopes
- **Rate Limiting**: Intelligent rate limiting with Redis backend
- **Security Headers**: Comprehensive security headers (HSTS, CSP, etc.)
- **Request Validation**: Input validation and sanitization
- **IP Filtering**: Allow/block lists for IP-based access control

### 🚀 Performance Features
- **Circuit Breaker**: Fault tolerance with circuit breaker pattern
- **Load Balancing**: Multiple load balancing strategies (round-robin, weighted, etc.)
- **Caching**: Redis-based response caching
- **Connection Pooling**: Efficient connection management
- **Health Checks**: Comprehensive health monitoring for backends

### 📊 Observability Features
- **Prometheus Metrics**: Comprehensive metrics collection
- **Distributed Tracing**: OpenTelemetry integration
- **Structured Logging**: JSON-formatted logs with correlation IDs
- **Health Endpoints**: Kubernetes-compatible health checks

### 🔧 Operational Features
- **Dynamic Configuration**: Runtime configuration updates
- **Graceful Shutdown**: Zero-downtime deployments
- **Multi-Environment Support**: Development, staging, and production configurations
- **Cloud-Native**: Optimized for Kubernetes and Cloud Run

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │───▶│   API Gateway   │───▶│ Backend Services│
│                 │    │                 │    │                 │
│ • Web App       │    │ • Authentication│    │ • Auth Service  │
│ • Mobile App    │    │ • Authorization │    │ • SIEM Engine   │
│ • Third-party   │    │ • Rate Limiting │    │ • Threat Intel  │
│                 │    │ • Load Balancing│    │ • And more...   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                               │
                               ▼
                       ┌─────────────────┐
                       │ Infrastructure  │
                       │                 │
                       │ • Redis Cache   │
                       │ • PostgreSQL    │
                       │ • Monitoring    │
                       └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for development)
- Google Cloud CLI (for deployment)
- Redis (for caching)

### Local Development

1. **Clone and navigate to the API Gateway directory:**
   ```bash
   cd backend/services/api-gateway
   ```

2. **Start the development environment:**
   ```bash
   ./scripts/build-and-deploy.sh local
   ```
   Or manually with Docker Compose:
   ```bash
   docker-compose up -d
   ```

3. **Verify the service is running:**
   ```bash
   curl http://localhost:8080/health
   ```

### Manual Build and Run

1. **Build the application:**
   ```bash
   go build -o api-gateway ./cmd/api-gateway/
   ```

2. **Set environment variables:**
   ```bash
   export ENVIRONMENT=development
   export REDIS_HOST=localhost
   export REDIS_PORT=6379
   ```

3. **Run the application:**
   ```bash
   ./api-gateway
   ```

## Configuration

The API Gateway uses environment variables for configuration. Here are the key settings:

### Application Settings
```bash
ENVIRONMENT=production           # Environment: development, staging, production
SERVER_PORT=8080                # HTTP server port
LOG_LEVEL=info                  # Log level: debug, info, warn, error
LOG_FORMAT=json                 # Log format: json, console
```

### Security Settings
```bash
JWT_ENABLED=true                # Enable JWT authentication
JWT_SECRET=your-secret-key      # JWT secret for HMAC algorithms
API_KEY_ENABLED=true           # Enable API key authentication
SECURITY_REQUIRE_HTTPS=true    # Require HTTPS in production
CORS_ENABLED=true              # Enable CORS support
```

### Redis Configuration
```bash
REDIS_HOST=localhost           # Redis host
REDIS_PORT=6379               # Redis port
REDIS_PASSWORD=               # Redis password (if required)
REDIS_POOL_SIZE=10           # Connection pool size
```

### Rate Limiting
```bash
RATE_LIMIT_ENABLED=true       # Enable rate limiting
RATE_LIMIT_RPS=100           # Requests per second
RATE_LIMIT_BURST=200         # Burst size
RATE_LIMIT_WINDOW=60         # Window size in seconds
```

For a complete list of configuration options, see [config/config.go](config/config.go).

## API Endpoints

### Health and Status
- `GET /health` - Overall health check
- `GET /health/live` - Liveness probe (Kubernetes)
- `GET /health/ready` - Readiness probe (Kubernetes)
- `GET /metrics` - Prometheus metrics
- `GET /api/status` - Service status and information

### Administration (Requires Admin Role)
- `GET /api/admin/routes` - List all routes
- `POST /api/admin/routes` - Create new route
- `GET /api/admin/routes/:id` - Get route details
- `PUT /api/admin/routes/:id` - Update route
- `DELETE /api/admin/routes/:id` - Delete route

### Dynamic Routing
- `*` - All other paths are handled by the dynamic routing engine

## Authentication

The API Gateway supports multiple authentication methods:

### JWT Authentication
```bash
# Using Authorization header
curl -H "Authorization: Bearer <jwt-token>" http://localhost:8080/api/protected

# Using query parameter
curl "http://localhost:8080/api/protected?token=<jwt-token>"
```

### API Key Authentication
```bash
# Using X-API-Key header
curl -H "X-API-Key: <api-key>" http://localhost:8080/api/protected

# Using Authorization header
curl -H "Authorization: ApiKey <api-key>" http://localhost:8080/api/protected
```

### Basic Authentication
```bash
curl -u "username:password" http://localhost:8080/api/protected
```

## Deployment

### Docker Build
```bash
# Build development image
docker build -t isectech-api-gateway:dev .

# Build production image with proper tags
docker build \
  --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
  --build-arg BUILD_VERSION=v2.0.0 \
  --build-arg BUILD_COMMIT=$(git rev-parse HEAD) \
  -t isectech-api-gateway:v2.0.0 .
```

### Google Cloud Run
```bash
# Using the deployment script
./scripts/build-and-deploy.sh -p your-project-id -e production build-push-deploy

# Manual deployment
gcloud run deploy isectech-api-gateway \
  --image us-central1-docker.pkg.dev/your-project/isectech-production/api-gateway:prod-latest \
  --region us-central1 \
  --platform managed \
  --memory 1Gi \
  --cpu 1000m \
  --min-instances 1 \
  --max-instances 100
```

### Kubernetes
```bash
# Apply the deployment configuration
kubectl apply -f cloud-run-deployment.yaml
```

## Monitoring and Observability

### Prometheus Metrics
The gateway exposes comprehensive metrics at `/metrics`:
- Request duration and count
- Authentication success/failure rates
- Rate limiting metrics
- Circuit breaker states
- Backend health status

### Health Checks
- **Liveness**: `/health/live` - Basic service availability
- **Readiness**: `/health/ready` - Service ready to accept traffic
- **Health**: `/health` - Comprehensive health with dependency checks

### Logging
Structured JSON logging with correlation IDs:
```json
{
  "level": "info",
  "timestamp": "2024-01-01T12:00:00Z",
  "service": "isectech-api-gateway",
  "request_id": "req-123456",
  "method": "GET",
  "path": "/api/status",
  "status": 200,
  "duration": "5ms"
}
```

## Development

### Project Structure
```
api-gateway/
├── cmd/api-gateway/          # Application entry point
├── config/                   # Configuration management
├── delivery/                 # HTTP handlers and routes
│   └── http/
│       └── handlers/
├── domain/                   # Business entities
│   └── entity/
├── infrastructure/           # External dependencies
│   ├── cache/               # Redis implementation
│   ├── database/            # Database implementations
│   ├── middleware/          # HTTP middleware
│   └── monitoring/          # Metrics and monitoring
├── usecase/                 # Business logic
├── scripts/                 # Build and deployment scripts
├── Dockerfile              # Production container image
├── docker-compose.yml      # Local development environment
└── README.md              # This file
```

### Adding New Routes
Routes can be configured dynamically through the admin API or by implementing new route handlers:

```go
// Example route configuration
route := &entity.Route{
    Name:         "example-service",
    Path:         "/api/v1/example",
    Method:       "GET",
    AuthRequired: true,
    AuthType:     entity.AuthTypeJWT,
    RequiredRoles: []string{"user"},
    Backend: entity.BackendConfig{
        Type: entity.BackendTypeHTTP,
        Endpoints: []entity.EndpointConfig{
            {Host: "example-service", Port: 8080, Weight: 100},
        },
    },
}
```

### Testing
```bash
# Run unit tests
go test ./...

# Run integration tests with Docker Compose
docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit

# Load testing
curl -X POST http://localhost:8080/api/test/load -d '{"requests": 1000, "concurrent": 10}'
```

## Security

### Production Security Checklist
- [ ] Enable HTTPS/TLS termination
- [ ] Configure proper CORS origins
- [ ] Set up JWT with strong secrets or RSA keys
- [ ] Implement proper API key management
- [ ] Configure rate limiting based on capacity
- [ ] Set up IP filtering for sensitive endpoints
- [ ] Enable security headers (HSTS, CSP, etc.)
- [ ] Implement request size limits
- [ ] Set up monitoring and alerting
- [ ] Regular security scanning of container images

### Security Headers
The gateway automatically sets security headers:
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `X-XSS-Protection`
- `Referrer-Policy`

## Performance

### Optimization Settings
- **Connection Pooling**: Configurable pool sizes
- **Keep-Alive**: HTTP keep-alive support
- **Compression**: Gzip compression for responses
- **Caching**: Redis-based response caching
- **Circuit Breaker**: Fault tolerance for backend services

### Resource Requirements
| Environment | CPU | Memory | Instances |
|-------------|-----|--------|-----------|
| Development | 500m | 512Mi | 1 |
| Staging | 1000m | 1Gi | 1-5 |
| Production | 2000m | 2Gi | 3-100 |

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
docker-compose logs api-gateway

# Common causes:
# - Redis connection failure
# - Invalid configuration
# - Port already in use
```

#### Authentication Failures
```bash
# Verify JWT configuration
curl -v -H "Authorization: Bearer <token>" http://localhost:8080/api/protected

# Check logs for authentication errors
docker-compose logs api-gateway | grep "auth"
```

#### High Memory Usage
```bash
# Check metrics
curl http://localhost:8080/metrics | grep memory

# Adjust Redis pool size and other settings
```

### Debug Mode
Enable debug logging for troubleshooting:
```bash
export LOG_LEVEL=debug
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Create a pull request

## License

Internal use only - iSECTECH Security Platform

---

For more information, see the [iSECTECH Platform Documentation](../../README.md).