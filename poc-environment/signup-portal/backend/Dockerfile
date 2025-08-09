# iSECTECH POC Signup Portal - Backend Dockerfile
# Production-Grade Multi-Stage Go Application Container
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
FROM scratch

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy SSL certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/main /app/main

# Copy static files if any
COPY --from=builder /app/docs /app/docs

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/main", "healthcheck"] || exit 1

# Set user
USER 1000:1000

# Set environment variables
ENV GIN_MODE=release
ENV PORT=8080
ENV TZ=UTC

# Run the application
ENTRYPOINT ["/app/main"]