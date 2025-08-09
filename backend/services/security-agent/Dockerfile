# iSECTECH Security Agent Dockerfile
# Multi-stage build for production-grade security agent

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
  git \
  ca-certificates \
  tzdata \
  gcc \
  musl-dev \
  linux-headers

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG BUILD_DATE
ARG GIT_COMMIT
ARG GIT_BRANCH

# Build the application with optimizations and security flags
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s \
  -X main.version=${VERSION} \
  -X main.buildDate=${BUILD_DATE} \
  -X main.gitCommit=${GIT_COMMIT} \
  -X main.gitBranch=${GIT_BRANCH} \
  -extldflags '-static'" \
  -a -installsuffix cgo \
  -tags netgo \
  -o security-agent \
  ./cmd/security-agent

# Verify the binary
RUN chmod +x security-agent && \
  ./security-agent -version

# Production stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
  ca-certificates \
  tzdata \
  curl \
  jq \
  sqlite \
  && rm -rf /var/cache/apk/*

# Create non-root user for security
RUN addgroup -g 1001 -S isectech && \
  adduser -u 1001 -S isectech -G isectech

# Create necessary directories
RUN mkdir -p /etc/isectech \
  /var/log/isectech \
  /var/lib/isectech \
  /var/quarantine \
  /app/data && \
  chown -R isectech:isectech /etc/isectech \
  /var/log/isectech \
  /var/lib/isectech \
  /var/quarantine \
  /app

# Copy certificates and update certificate store
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder stage
COPY --from=builder /app/security-agent /usr/local/bin/security-agent

# Copy configuration template
COPY --chown=isectech:isectech config.example.yaml /etc/isectech/config.yaml

# Set proper permissions
RUN chmod +x /usr/local/bin/security-agent && \
  chmod 640 /etc/isectech/config.yaml

# Switch to non-root user
USER isectech

# Set working directory
WORKDIR /app

# Environment variables
ENV ISECTECH_AGENT_CONFIG=/etc/isectech/config.yaml
ENV ISECTECH_AGENT_LOG_LEVEL=info
ENV ISECTECH_AGENT_LOG_FORMAT=json

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8081/health || exit 1

# Expose ports
EXPOSE 8080 8081 9090 9100

# Set resource limits (can be overridden)
ENV GOMAXPROCS=2
ENV GOMEMLIMIT=100MiB

# Default command
CMD ["security-agent", "-config", "/etc/isectech/config.yaml"]

# Metadata labels
LABEL maintainer="iSECTECH Engineering <engineering@isectech.com>" \
  org.opencontainers.image.title="iSECTECH Security Agent" \
  org.opencontainers.image.description="Production-grade endpoint security agent for comprehensive threat detection and response" \
  org.opencontainers.image.vendor="iSECTECH" \
  org.opencontainers.image.licenses="Proprietary" \
  org.opencontainers.image.version="${VERSION}" \
  org.opencontainers.image.created="${BUILD_DATE}" \
  org.opencontainers.image.revision="${GIT_COMMIT}" \
  org.opencontainers.image.source="https://github.com/isectech/security-platform" \
  org.opencontainers.image.documentation="https://docs.isectech.com/security-agent" \
  security.tls.cert.required="true" \
  security.capabilities.required="CAP_SYS_PTRACE,CAP_SYS_ADMIN" \
  security.seccomp.profile="runtime/default" \
  security.apparmor.profile="runtime/default"