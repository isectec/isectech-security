# Asset Discovery Service Dockerfile

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
  -a -installsuffix cgo \
  -ldflags '-extldflags "-static"' \
  -o asset-discovery \
  ./cmd/asset-discovery

# Runtime stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add \
  ca-certificates \
  tzdata \
  nmap \
  nmap-scripts

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
  adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/asset-discovery .

# Copy configuration files
COPY config.yaml ./config.yaml

# Create necessary directories
RUN mkdir -p /app/logs /app/data /app/migrations && \
  chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8080 9090 2112

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Set environment variables
ENV SERVICE_NAME=asset-discovery
ENV SERVICE_VERSION=1.0.0
ENV GIN_MODE=release

# Run the application
CMD ["./asset-discovery"]