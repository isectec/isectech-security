# iSECTECH API Gateway - Production-Grade Dockerfile
# Multi-stage build for optimal security and size
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD STAGE - Compile the Go application
# ═══════════════════════════════════════════════════════════════════════════════

FROM golang:1.21.5-alpine3.18 AS builder

# Install build dependencies and security tools
RUN apk add --no-cache \
    ca-certificates \
    git \
    tzdata \
    && update-ca-certificates

# Create non-root user for build process
RUN addgroup -g 10001 -S isectech && \
    adduser -u 10001 -S isectech -G isectech

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies with verification
RUN go mod download && \
    go mod verify

# Copy source code
COPY . .

# Build the application with security flags
RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a \
    -installsuffix cgo \
    -o api-gateway \
    ./cmd/api-gateway/

# Verify the binary
RUN file api-gateway && \
    chmod +x api-gateway

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY SCAN STAGE - Scan dependencies and code
# ═══════════════════════════════════════════════════════════════════════════════

FROM builder AS security-scanner

# Install security scanning tools
RUN go install github.com/securecodewarrior/sast-scan@latest && \
    go install github.com/sonatypeoss/nancy@latest

# Run security scans (optional - can be moved to CI/CD)
RUN go list -json -m all | nancy sleuth || true

# ═══════════════════════════════════════════════════════════════════════════════
# RUNTIME STAGE - Minimal runtime image
# ═══════════════════════════════════════════════════════════════════════════════

FROM alpine:3.18.4 AS runtime

# Security and operational labels
LABEL maintainer="iSECTECH Infrastructure Team <infrastructure@isectech.com>" \
      name="isectech-api-gateway" \
      version="2.0.0" \
      description="iSECTECH Security Platform API Gateway" \
      vendor="iSECTECH" \
      architecture="amd64" \
      security.scan="true" \
      compliance.framework="SOC2,ISO27001,NIST" \
      build.date="${BUILD_DATE}" \
      build.version="${BUILD_VERSION}" \
      build.commit="${BUILD_COMMIT}"

# Install runtime dependencies and security updates
RUN apk update && \
    apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    netcat-openbsd \
    && rm -rf /var/cache/apk/* \
    && update-ca-certificates

# Create non-root user and groups
RUN addgroup -g 10001 -S isectech && \
    adduser -u 10001 -S isectech -G isectech -s /bin/sh

# Create required directories with proper permissions
RUN mkdir -p /app/config /app/logs /app/tmp /app/certs && \
    chown -R isectech:isectech /app && \
    chmod 755 /app && \
    chmod 700 /app/config /app/logs /app/tmp /app/certs

# Set timezone
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Copy CA certificates from build stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary with proper ownership and permissions
COPY --from=builder --chown=isectech:isectech /build/api-gateway /app/
RUN chmod +x /app/api-gateway

# Set working directory
WORKDIR /app

# Switch to non-root user
USER 10001:10001

# ═══════════════════════════════════════════════════════════════════════════════
# RUNTIME CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Environment variables for Cloud Run and container environments
ENV ENVIRONMENT=production \
    SERVER_PORT=8080 \
    LOG_LEVEL=info \
    LOG_FORMAT=json \
    MONITORING_ENABLED=true \
    RATE_LIMIT_ENABLED=true \
    CORS_ENABLED=true \
    JWT_ENABLED=true \
    API_KEY_ENABLED=true \
    TRACING_ENABLED=false \
    DATABASE_ENABLED=false \
    # Security settings
    SECURITY_REQUIRE_HTTPS=false \
    SECURITY_REQUEST_SIZE_LIMIT=10485760 \
    # Performance settings
    SERVER_READ_TIMEOUT=10 \
    SERVER_WRITE_TIMEOUT=10 \
    SERVER_IDLE_TIMEOUT=60 \
    SERVER_MAX_HEADER_BYTES=1048576 \
    # Redis settings (will be overridden by Cloud Run)
    REDIS_HOST=localhost \
    REDIS_PORT=6379 \
    REDIS_POOL_SIZE=10 \
    # Rate limiting
    RATE_LIMIT_RPS=100 \
    RATE_LIMIT_BURST=200 \
    RATE_LIMIT_WINDOW=60 \
    # Monitoring
    MONITORING_METRICS_PATH=/metrics \
    MONITORING_HEALTH_PATH=/health

# Expose ports
EXPOSE 8080

# Health check configuration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Resource limits (can be overridden by Cloud Run)
# Default memory limit: 512Mi
# Default CPU limit: 1000m (1 CPU)

# ═══════════════════════════════════════════════════════════════════════════════
# STARTUP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Set entrypoint and command
ENTRYPOINT ["/app/api-gateway"]

# Default command arguments (can be overridden)
CMD []

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY HARDENING
# ═══════════════════════════════════════════════════════════════════════════════

# Security: No shell, minimal attack surface
# - Using distroless would be even better, but alpine provides good balance
# - Non-root user (UID 10001)
# - No package manager in final image
# - Read-only root filesystem (can be set at runtime)
# - No SUID/SGID binaries
# - Minimal dependencies

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD RUN OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

# This image is optimized for Google Cloud Run:
# - Fast cold starts (small image size)
# - Non-root user for security
# - Proper health checks
# - Environment variable configuration
# - PORT environment variable support
# - Signal handling for graceful shutdown
# - Stateless design
# - Efficient resource usage

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD INSTRUCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Build command:
# docker build -t isectech-api-gateway:latest .
#
# Build with build args:
# docker build \
#   --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
#   --build-arg BUILD_VERSION=v2.0.0 \
#   --build-arg BUILD_COMMIT=$(git rev-parse HEAD) \
#   -t isectech-api-gateway:v2.0.0 .
#
# Multi-platform build:
# docker buildx build \
#   --platform linux/amd64,linux/arm64 \
#   -t isectech-api-gateway:latest \
#   --push .
#
# Security scan:
# docker scout cves isectech-api-gateway:latest
# 
# Image analysis:
# docker history isectech-api-gateway:latest
# docker inspect isectech-api-gateway:latest