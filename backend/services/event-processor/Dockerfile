# Build stage
FROM golang:1.21-alpine AS builder

# Install git and ca-certificates (needed for fetching modules)
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files first (for better caching)
COPY go.mod go.sum ./
COPY services/event-processor/go.mod services/event-processor/go.sum ./services/event-processor/

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
WORKDIR /app/services/event-processor
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags='-w -s -extldflags "-static"' \
  -a -installsuffix cgo \
  -o event-processor \
  ./cmd/event-processor

# Runtime stage
FROM alpine:3.18

# Install ca-certificates for HTTPS calls
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1001 appgroup && \
  adduser -u 1001 -G appgroup -s /bin/sh -D appuser

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/services/event-processor/event-processor .

# Copy config files if they exist
COPY --from=builder /app/services/event-processor/config ./config

# Create necessary directories
RUN mkdir -p /app/logs /app/data && \
  chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 8001 9001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8001/health || exit 1

# Set default environment variables
ENV SERVICE_NAME=event-processor \
  SERVICE_VERSION=1.0.0 \
  ENVIRONMENT=production \
  LOG_LEVEL=info \
  LOG_FORMAT=json

# Run the application
CMD ["./event-processor"]