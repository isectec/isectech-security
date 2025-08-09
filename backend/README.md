# iSECTECH Platform Backend Services

This directory contains the Go-based backend microservices for the iSECTECH cybersecurity platform.

## Prerequisites

### Go Installation

This project requires **Go 1.21+**. To install Go:

#### macOS (using Homebrew)

```bash
brew install go
```

#### Alternative Installation Methods

1. **Download from official site**: https://golang.org/dl/
2. **Using asdf**: `asdf install golang 1.21.5`
3. **Using gvm**: `gvm install go1.21.5`

### Verify Installation

```bash
go version  # Should show Go 1.21 or higher
```

## Project Structure

```
backend/
├── go.mod                          # Root module with shared dependencies
├── services/                       # Microservices
│   ├── event-processor/            # Event processing engine (1M events/sec)
│   ├── asset-discovery/            # Network asset discovery and cataloging
│   ├── threat-detection/           # Real-time threat analysis
│   └── api-gateway/               # Request routing and authentication
├── shared/                        # Shared components
│   ├── common/                    # Common utilities and helpers
│   ├── proto/                     # Protocol buffer definitions
│   └── types/                     # Shared data types and interfaces
└── pkg/                          # Reusable packages
    ├── auth/                     # Authentication and authorization
    ├── metrics/                  # Prometheus metrics collection
    └── logging/                  # Structured logging (zap)
```

## Dependency Management

### Initial Setup

1. **Install all dependencies**:

   ```bash
   cd backend
   go mod download
   ```

2. **Initialize each service module**:
   ```bash
   # For each service
   cd services/event-processor && go mod tidy
   cd ../asset-discovery && go mod tidy
   cd ../threat-detection && go mod tidy
   cd ../api-gateway && go mod tidy
   ```

### Key Dependencies

#### Core Dependencies

- **gRPC**: `google.golang.org/grpc` - Inter-service communication
- **Protocol Buffers**: `google.golang.org/protobuf` - Message serialization
- **Zap**: `go.uber.org/zap` - Structured logging
- **Prometheus**: `github.com/prometheus/client_golang` - Metrics collection
- **Circuit Breaker**: `github.com/sony/gobreaker` - Resilience patterns

#### Service-Specific Dependencies

- **Kafka**: `github.com/segmentio/kafka-go` - Event streaming
- **MongoDB**: `go.mongodb.org/mongo-driver` - Document storage
- **Redis**: `github.com/go-redis/redis/v8` - Caching and sessions
- **PostgreSQL**: `github.com/lib/pq` - Relational data
- **JWT**: `github.com/golang-jwt/jwt/v5` - Authentication tokens
- **Gin**: `github.com/gin-gonic/gin` - HTTP framework (API Gateway)

#### Testing Dependencies

- **Testify**: `github.com/stretchr/testify` - Testing framework
- **Go Mock**: For service mocking and integration tests

### Dependency Update Procedures

#### Regular Updates (Monthly)

```bash
# Check for outdated dependencies
go list -u -m all

# Update to latest minor/patch versions
go get -u=patch ./...

# Update specific dependency
go get -u github.com/prometheus/client_golang@latest
```

#### Major Version Updates (Quarterly)

```bash
# Check for major version updates
go list -u -m all | grep "v[0-9]*\."

# Update with caution and test thoroughly
go get github.com/some-package/v2@latest
```

#### Security Updates (Immediate)

```bash
# Check for security vulnerabilities
go list -json -deps ./... | nancy sleuth

# Or use govulncheck (Go 1.18+)
govulncheck ./...
```

### Module Maintenance

#### Clean Up Dependencies

```bash
# Remove unused dependencies
go mod tidy

# Verify dependencies
go mod verify

# View dependency graph
go mod graph
```

#### Vendor Management (Optional)

```bash
# Create vendor directory for offline builds
go mod vendor

# Add to .gitignore if not committing vendor
echo "vendor/" >> .gitignore
```

## Development Workflow

### 1. Adding New Dependencies

```bash
# Navigate to the specific service
cd services/event-processor

# Add new dependency
go get github.com/new-package@latest

# Update go.mod
go mod tidy
```

### 2. Working with Local Packages

```bash
# Use replace directive for local development
go mod edit -replace github.com/isectech/platform=../../
```

### 3. Building Services

```bash
# Build specific service
cd services/event-processor
go build ./...

# Build all services
cd backend
go build ./...
```

### 4. Running Tests

```bash
# Test specific service
cd services/event-processor
go test ./...

# Test all services with coverage
cd backend
go test -cover ./...
```

## Environment Variables

### Required Environment Variables

```bash
# Database connections
export MONGODB_URI="mongodb://localhost:27017/isectech"
export REDIS_URL="redis://localhost:6379"
export POSTGRES_DSN="postgres://user:pass@localhost/isectech?sslmode=disable"

# Kafka configuration
export KAFKA_BROKERS="localhost:9092"
export KAFKA_GROUP_ID="isectech-platform"

# Service discovery
export CONSUL_ADDRESS="localhost:8500"

# Monitoring
export PROMETHEUS_PORT="8080"
export JAEGER_ENDPOINT="http://localhost:14268/api/traces"

# Security
export JWT_SECRET="your-jwt-secret"
export ENCRYPTION_KEY="your-32-byte-encryption-key"
```

## Docker Support

### Multi-stage Dockerfiles

Each service includes optimized Dockerfiles:

```dockerfile
# Example for event-processor
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o event-processor

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/event-processor .
CMD ["./event-processor"]
```

### Docker Compose

```bash
# Build and run all services
docker-compose up --build

# Run specific service
docker-compose up event-processor
```

## Troubleshooting

### Common Issues

1. **Module not found errors**:

   ```bash
   go clean -modcache
   go mod download
   ```

2. **Version conflicts**:

   ```bash
   go mod graph | grep conflicting-package
   go get package@specific-version
   ```

3. **Build failures**:
   ```bash
   go mod verify
   go mod tidy
   go clean -cache
   ```

### Development Tools

#### Recommended VS Code Extensions

- Go (official Google extension)
- Go Test Explorer
- Protocol Buffers support
- REST Client for API testing

#### Useful Go Tools

```bash
# Install development tools
go install golang.org/x/tools/gopls@latest          # Language server
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest  # Linter
go install golang.org/x/tools/cmd/goimports@latest  # Import management
go install github.com/securecodewarrior/go-mod-outdated@latest  # Dependency checking
```

## Performance Considerations

### Go-Specific Optimizations

- Use build constraints for environment-specific code
- Implement connection pooling for databases
- Use sync.Pool for object reuse
- Profile with `go tool pprof` for performance bottlenecks
- Optimize garbage collection with `GOGC` environment variable

### Microservice Best Practices

- Keep services focused and small
- Use context for request timeouts and cancellation
- Implement health checks for all services
- Use structured logging with correlation IDs
- Implement graceful shutdown mechanisms

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Backend Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - run: cd backend && go test -race -coverprofile=coverage.out ./...
      - run: cd backend && go vet ./...
```

## Security

### Dependency Security

- Regularly run `govulncheck ./...`
- Use `go list -json -deps ./... | nancy sleuth` for vulnerability scanning
- Keep dependencies updated with security patches
- Review dependency licenses for compliance

### Code Security

- Use static analysis tools (gosec, staticcheck)
- Implement proper input validation
- Use secure coding practices for cryptography
- Follow OWASP Go Security Guidelines

---

For specific service documentation, see the README files in each service directory.
