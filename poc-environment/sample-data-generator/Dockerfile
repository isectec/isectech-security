# iSECTECH Sample Data Generator - Docker Configuration
# Production-Grade Multi-Stage Container Build
# Version: 1.0

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
    -ldflags '-extldflags "-static" -w -s' \
    -o main .

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -s /bin/sh appuser

# Create necessary directories
RUN mkdir -p /app/generated-data /app/schemas && \
    chown -R appuser:appuser /app

# Copy the binary
COPY --from=builder /app/main /app/main

# Copy schema files
COPY --from=builder /app/schemas /app/schemas

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 8082

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8082/api/v1/health || exit 1

# Set user
USER appuser

# Set environment variables
ENV PORT=8082
ENV TZ=UTC
ENV DATA_OUTPUT_PATH=/app/generated-data

# Run the application
ENTRYPOINT ["/app/main"]